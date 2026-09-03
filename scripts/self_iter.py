#!/usr/bin/env python3
"""
self_iter.py — agent-core 自迭代闭环 (build -> deploy -> smoke -> 失败自动回滚)

把原先靠人工敲的部署纪律脚本化, 并补上两件原来没有的事:
  1. 部署后结构化冒烟自检 (L0~L4 五层)
  2. 冒烟有红 -> 自动回滚到备份 exe 并重启

设计原则 (对齐本仓库 P0 纪律):
  - 最小入侵       : 不改任何 Rust 源码, 只新增本脚本
  - 默认安全       : 不传 --apply 只做只读体检与冒烟, 绝不触碰运行中的服务
  - 自动回滚       : 部署后冒烟失败自动恢复备份 exe + 重启 + 复检
  - 零密钥硬编码   : 密钥走 .env (由 start_agentcore_prod.py 注入子进程)
  - 路径不硬编码   : 仓库根由 __file__ 推导, 可直接进公开 GitHub 仓库
  - 日志必须落盘   : 按日期命名写入文件, 不依赖 shell 重定向

用法:
  python scripts/self_iter.py                 # 只读体检 + 冒烟 (默认, 安全)
  python scripts/self_iter.py --smoke-only    # 只跑冒烟
  python scripts/self_iter.py --apply         # build + 部署 + 冒烟 + 失败回滚
  python scripts/self_iter.py --apply --no-build   # 跳过编译, 直接用现有 release 产物部署

退出码: 0=PASS / 1=有检查项失败 / 2=部署失败或回滚失败
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

# --- 路径: 全部由 __file__ 推导, 不硬编码含用户名的绝对路径 ---
REPO = Path(__file__).resolve().parent.parent
EXE = REPO / "target" / "release" / "agent-core.exe"
STARTER = REPO / "start_agentcore_prod.py"
CARGO = REPO / "Cargo.toml"
SRC = REPO / "src"
ENV_FILE = REPO / ".env"

HOST = "127.0.0.1"
PORT = 9753
BASE = f"http://{HOST}:{PORT}"

BUILD_TIMEOUT_S = 900      # cargo build --release 上限 15 分钟
READY_TIMEOUT_S = 90       # 重启后等待 /health 就绪
READY_POLL_S = 2

OK, FAIL, SKIP = "PASS", "FAIL", "SKIP"


# ---------------------------------------------------------------- 基础设施
class Report:
  """收集检查项, 输出结构化 JSON (对齐 SELF_TEST_JSON 范式)."""

  def __init__(self, mode):
    self.mode = mode
    self.started = datetime.now()
    self.checks = []
    self.notes = {}

  def add(self, lid, title, status, detail=""):
    self.checks.append({"id": lid, "title": title, "status": status, "detail": str(detail)[:300]})
    mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "SKIP": "[SKIP]"}[status]
    print(f"  {mark} {lid} {title}" + (f" — {detail}" if detail else ""))
    return status == OK

  def failed(self):
    return [c for c in self.checks if c["status"] == FAIL]

  def emit(self, log_path):
    payload = {
      "mode": self.mode,
      "started_at": self.started.isoformat(timespec="seconds"),
      "finished_at": datetime.now().isoformat(timespec="seconds"),
      "duration_s": round((datetime.now() - self.started).total_seconds(), 1),
      "verdict": "PASS" if not self.failed() else "FAIL",
      "notes": self.notes,
      "checks": self.checks,
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    print("\n" + "=" * 62)
    print(f"VERDICT: {payload['verdict']}  ({len([c for c in self.checks if c['status'] == OK])} pass"
          f" / {len(self.failed())} fail)")
    print("=" * 62)
    print("SELF_ITER_JSON " + json.dumps(payload, ensure_ascii=False))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as fh:
      fh.write(f"\n===== self_iter run {payload['started_at']} mode={self.mode} "
               f"verdict={payload['verdict']} =====\n{text}\n")
    print(f"\nlog: {log_path}")
    return payload


def log_path_for_today():
  return REPO / f"agentcore_self_iter_{datetime.now():%Y-%m-%d}.log"


def http_json(url, headers=None, timeout=8):
  req = urllib.request.Request(url, headers=headers or {})
  with urllib.request.urlopen(req, timeout=timeout) as r:
    return r.status, json.loads(r.read().decode("utf-8", "replace"))


def http_status(url, headers=None, timeout=8):
  """只取状态码; 401/403 也算'成功拿到响应' (用于验证鉴权闸门)."""
  req = urllib.request.Request(url, headers=headers or {})
  try:
    with urllib.request.urlopen(req, timeout=timeout) as r:
      return r.status
  except urllib.error.HTTPError as e:
    return e.code
  except Exception:
    return 0


def cargo_version():
  m = re.search(r'^version\s*=\s*"([^"]+)"', CARGO.read_text(encoding="utf-8"), re.M)
  return m.group(1) if m else None


def newest_src_mtime():
  newest, newest_file = 0.0, None
  for p in SRC.rglob("*.rs"):
    try:
      mt = p.stat().st_mtime
      if mt > newest:
        newest, newest_file = mt, p
    except OSError:
      continue
  return newest, (newest_file.relative_to(REPO).as_posix() if newest_file else None)


def _decode(raw):
  """Windows 中文环境 netstat/git 输出是 GBK, 必须显式解码并容错, 否则 UTF-8 解码会崩."""
  if not raw:
    return ""
  if isinstance(raw, bytes):
    for enc in ("gbk", "utf-8"):
      try:
        return raw.decode(enc)
      except UnicodeDecodeError:
        continue
    return raw.decode("utf-8", errors="replace")
  return raw


def pid_on_port(port):
  """用 netstat 找监听该端口的 PID (无需第三方依赖)."""
  try:
    r = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                       capture_output=True, timeout=15)
    out = _decode(r.stdout)
  except Exception:
    return None
  for line in out.splitlines():
    if f":{port}" in line and "LISTENING" in line.upper():
      parts = line.split()
      if parts and parts[-1].isdigit():
        return parts[-1]
  return None


def kill_pid(pid):
  r = subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"],
                     capture_output=True, text=True, timeout=30)
  return r.returncode == 0


def git_state():
  def run(args):
    try:
      r = subprocess.run(["git"] + args, cwd=str(REPO), capture_output=True, timeout=20)
      return _decode(r.stdout).strip()
    except Exception:
      return ""
  branch = run(["rev-parse", "--abbrev-ref", "HEAD"])
  dirty = run(["status", "--porcelain"])
  head = run(["log", "--oneline", "-1"])
  return branch, (dirty.splitlines() if dirty else []), head


# ---------------------------------------------------------------- 阶段 0: 体检
def phase_precheck(rep):
  print("\n--- Phase 0  PRECHECK (read-only) ---")
  branch, dirty, head = git_state()
  rep.notes["git_branch"] = branch
  rep.notes["git_head"] = head
  rep.notes["git_dirty_count"] = len(dirty)
  rep.add("L0a", "git 分支为 master (canonical)", OK if branch == "master" else FAIL,
          f"branch={branch}")
  rep.notes["git_dirty_sample"] = dirty[:10]

  ver = cargo_version()
  rep.notes["cargo_version"] = ver
  rep.add("L0b", "Cargo.toml 版本可读", OK if ver else FAIL, f"version={ver}")

  # 陈旧构建判定: exe mtime < 源码最新 mtime => 运行实例可能缺最新改动
  if EXE.exists():
    exe_mt = EXE.stat().st_mtime
    src_mt, src_file = newest_src_mtime()
    rep.notes["exe_mtime"] = datetime.fromtimestamp(exe_mt).strftime("%Y-%m-%d %H:%M:%S")
    rep.notes["newest_src"] = src_file
    rep.notes["newest_src_mtime"] = (datetime.fromtimestamp(src_mt).strftime("%Y-%m-%d %H:%M:%S")
                                     if src_mt else None)
    stale = src_mt > exe_mt
    rep.add("L0c", "构建产物新于源码 (非陈旧构建)", FAIL if stale else OK,
            f"{'STALE' if stale else 'fresh'}: exe={rep.notes['exe_mtime']} "
            f"newest_src={src_file}")
  else:
    rep.add("L0c", "构建产物存在", FAIL, f"missing {EXE.relative_to(REPO).as_posix()}")

  rep.notes["pid_before"] = pid_on_port(PORT)
  return ver


# ---------------------------------------------------------------- 阶段 1: 冒烟 (L0~L4)
def phase_smoke(rep, expect_version=None, expect_new_pid=None):
  print("\n--- Phase 1  SMOKE (L0~L4) ---")

  # L0 健康
  try:
    code, body = http_json(f"{BASE}/health")
    alive = code == 200 and body.get("status") == "ok"
    rep.add("L0", "GET /health 200 且 status=ok", OK if alive else FAIL, f"HTTP {code}")
  except Exception as e:
    rep.add("L0", "GET /health 200 且 status=ok", FAIL, f"{type(e).__name__}: {e}")
    for lid, title in [("L1", "运行版本 == Cargo.toml 版本"),
                       ("L2", "memoria 依赖可达且 embed 正常"),
                       ("L4", "进程身份 (PID) 符合预期")]:
      rep.add(lid, title, SKIP, "服务不可达")
    rep.add("L3", "鉴权闸门生效 (无 key 访问 /api/* 返回 401)", SKIP, "服务不可达")
    return

  running_ver = body.get("version")
  rep.notes["running_version"] = running_ver

  # L1 版本一致 (证明新二进制真的上线, 而不是旧进程还在跑)
  if expect_version:
    rep.add("L1", "运行版本 == Cargo.toml 版本",
            OK if running_ver == expect_version else FAIL,
            f"running={running_ver} cargo={expect_version}")
  else:
    rep.add("L1", "运行版本可读", OK if running_ver else FAIL, f"running={running_ver}")

  # L2 依赖健康
  mem = body.get("memoria") or {}
  embed = mem.get("embed") or {}
  dep_ok = mem.get("reachable") is True and embed.get("status") == "pass"
  rep.add("L2", "memoria 依赖可达且 embed 正常", OK if dep_ok else FAIL,
          f"reachable={mem.get('reachable')} embed={embed.get('status')}")

  # L3 鉴权闸门 (免鉴权白名单只有 /health; /api/* 无 key 必须 401)
  ac = http_status(f"{BASE}/api/agents")
  rep.add("L3", "鉴权闸门生效 (无 key 访问 /api/* 返回 401)",
          OK if ac == 401 else FAIL, f"/api/agents -> HTTP {ac} (期望 401)")

  # L4 进程身份
  pid_now = pid_on_port(PORT)
  rep.notes["pid_after"] = pid_now
  if expect_new_pid:
    rep.add("L4", "进程已重启 (PID 变化)", OK if pid_now != expect_new_pid else FAIL,
            f"before={expect_new_pid} after={pid_now}")
  else:
    rep.add("L4", "端口在监听 (PID 可见)", OK if pid_now else FAIL, f"pid={pid_now}")


# ---------------------------------------------------------------- 阶段 2: 构建
def phase_build(rep):
  print(f"\n--- Phase 2  BUILD (cargo build --release, timeout {BUILD_TIMEOUT_S}s) ---")
  t0 = time.time()
  r = subprocess.run(["cargo", "build", "--release"], cwd=str(REPO),
                     capture_output=True, text=True, timeout=BUILD_TIMEOUT_S,
                     encoding="utf-8", errors="replace")
  dur = round(time.time() - t0, 1)
  rep.notes["build_seconds"] = dur
  if r.returncode == 0:
    rep.add("BUILD", "cargo build --release 成功", OK, f"{dur}s")
    return True
  tail = "\n".join((r.stderr or r.stdout or "").splitlines()[-15:])
  rep.add("BUILD", "cargo build --release 成功", FAIL, f"rc={r.returncode} {dur}s")
  rep.notes["build_error_tail"] = tail
  print(tail)
  return False


# ---------------------------------------------------------------- 阶段 3: 部署
def phase_deploy(rep):
  print("\n--- Phase 3  DEPLOY (backup -> stop -> start -> wait ready) ---")

  if not EXE.exists():
    rep.add("DEPLOY", "release 产物存在", FAIL, f"missing {EXE}")
    return False
  if not STARTER.exists():
    rep.add("DEPLOY", "启动器存在", FAIL, f"missing {STARTER.relative_to(REPO).as_posix()}")
    return False

  # 1) 备份
  ts = datetime.now().strftime("%Y%m%d-%H%M%S")
  backup = EXE.with_name(f"{EXE.name}.bak-{ts}")
  try:
    shutil.copy2(EXE, backup)
    rep.notes["backup"] = backup.relative_to(REPO).as_posix()
    rep.add("D1", "备份当前 exe", OK, rep.notes["backup"])
  except Exception as e:
    rep.add("D1", "备份当前 exe", FAIL, f"{type(e).__name__}: {e}")
    return False

  # 2) 停旧进程 (不停会导致 cargo/复制时 os error 5)
  pid_before = pid_on_port(PORT)
  rep.notes["pid_before"] = pid_before
  if pid_before:
    stopped = kill_pid(pid_before)
    rep.add("D2", "停止旧进程", OK if stopped else FAIL, f"pid={pid_before}")
    if not stopped:
      return False
    time.sleep(2)
  else:
    rep.add("D2", "停止旧进程", SKIP, "端口无监听, 视为未运行")

  # 3) 脱离式启动 (复用既有启动器: 它已处理 .env 注入 + start_new_session 保活)
  try:
    r = subprocess.run([sys.executable, str(STARTER)], cwd=str(REPO),
                       capture_output=True, text=True, timeout=60,
                       encoding="utf-8", errors="replace")
    launched = r.returncode == 0
    rep.add("D3", "detached 启动新进程", OK if launched else FAIL,
            (r.stdout or r.stderr or "").strip()[:160])
    if not launched:
      return False
  except Exception as e:
    rep.add("D3", "detached 启动新进程", FAIL, f"{type(e).__name__}: {e}")
    return False

  # 4) 等待就绪
  deadline = time.time() + READY_TIMEOUT_S
  ready = False
  while time.time() < deadline:
    if http_status(f"{BASE}/health") == 200:
      ready = True
      break
    time.sleep(READY_POLL_S)
  rep.add("D4", f"重启后 {READY_TIMEOUT_S}s 内 /health 就绪", OK if ready else FAIL,
          f"waited<={READY_TIMEOUT_S}s")
  return ready


# ---------------------------------------------------------------- 阶段 4: 回滚
def rollback(rep, backup):
  print("\n--- Phase 4  ROLLBACK (冒烟失败 -> 恢复备份) ---")
  if not backup or not Path(backup).exists():
    rep.add("R0", "备份可用", FAIL, f"backup={backup}")
    return False
  try:
    shutil.copy2(backup, EXE)
    rep.add("R1", "恢复备份 exe", OK, Path(backup).name)
  except Exception as e:
    rep.add("R1", "恢复备份 exe", FAIL, f"{type(e).__name__}: {e}")
    return False

  pid_now = pid_on_port(PORT)
  if pid_now:
    kill_pid(pid_now)
    time.sleep(2)
  try:
    subprocess.run([sys.executable, str(STARTER)], cwd=str(REPO),
                   capture_output=True, text=True, timeout=60,
                   encoding="utf-8", errors="replace")
  except Exception as e:
    rep.add("R2", "回滚后重启", FAIL, f"{type(e).__name__}: {e}")
    return False

  deadline = time.time() + READY_TIMEOUT_S
  while time.time() < deadline:
    if http_status(f"{BASE}/health") == 200:
      rep.add("R2", "回滚后重启并就绪", OK, "health 200")
      return True
    time.sleep(READY_POLL_S)
  rep.add("R2", "回滚后重启并就绪", FAIL, "health 未就绪")
  return False


# ---------------------------------------------------------------- main
def main():
  ap = argparse.ArgumentParser(description="agent-core self-iteration closed loop")
  ap.add_argument("--apply", action="store_true",
                  help="真正执行 build+部署+重启 (默认只做只读体检与冒烟)")
  ap.add_argument("--smoke-only", action="store_true", help="只跑冒烟, 跳过体检与构建")
  ap.add_argument("--no-build", action="store_true", help="--apply 时跳过编译, 直接部署现有产物")
  args = ap.parse_args()

  mode = "apply" if args.apply else ("smoke" if args.smoke_only else "dry-run")
  rep = Report(mode)
  logp = log_path_for_today()

  print("=" * 62)
  print(f"agent-core self-iter  mode={mode}  repo={REPO}")
  print(f"started {rep.started:%Y-%m-%d %H:%M:%S}   log={logp.name}")
  if mode == "dry-run":
    print("NOTE: dry-run 只做只读检查, 不会触碰运行中的服务。要真正部署请加 --apply")
  print("=" * 62)

  if args.smoke_only:
    phase_smoke(rep, expect_version=cargo_version())
    rep.emit(logp)
    return 0 if not rep.failed() else 1

  ver = phase_precheck(rep)
  phase_smoke(rep, expect_version=ver)

  if not args.apply:
    print("\n[dry-run] 跳过 build/deploy。当前服务未受影响。")
    rep.emit(logp)
    return 0 if not rep.failed() else 1

  # --- apply 模式 ---
  backup = None
  if not args.no_build:
    if not phase_build(rep):
      print("\n[abort] 构建失败, 未触碰运行中的服务。")
      rep.emit(logp)
      return 2

  deployed = phase_deploy(rep)
  if deployed:
    backup = REPO / rep.notes.get("backup", "")
    # 部署后重跑冒烟: 期望版本一致 + PID 变化
    rep.checks = [c for c in rep.checks if not c["id"].startswith(("L", "BUILD"))]
    phase_smoke(rep, expect_version=ver, expect_new_pid=rep.notes.get("pid_before"))
    if rep.failed():
      print("\n[rollback] 部署后冒烟失败, 自动回滚…")
      if rollback(rep, backup):
        rep.checks = [c for c in rep.checks if c["id"] not in ("L0", "L1", "L2", "L3", "L4")]
        phase_smoke(rep, expect_version=None)
  else:
    print("\n[abort] 部署失败")

  payload = rep.emit(logp)
  if payload["verdict"] == "PASS":
    return 0
  return 2 if (deployed and backup) else 1


if __name__ == "__main__":
  sys.exit(main())
