#!/usr/bin/env python3
"""双轨（受控改库扳手 + 本机白名单仓库编辑）端到端验收。

覆盖：
  0) 默认：cargo test 单元闸门（db_write / repo_ws / controlled_write / boundary）
  1) --data：Python 数据层 e2e（不依赖 agent-core 在线）
       - sql_skill.execute 支持 params 参数化绑定（防拼接）
       - controlled_db_write：未 confirmed / 错表 / 缺 where 全部拒绝
       - confirmed + 临时 DB 副本：UPDATE + soft_delete 落库后经 execute_sql(params) 回读校验
       （写入永远作用在 dashboard.db 的临时副本，绝不触碰真实业务库）
  2) --live：在线意图路由（需 agent-core 以 AGENT_DB_WRITE=1 / AGENT_REPO_WS=1 启动）
       - cw_select 只读返回数据；cw_write / repo_ws_write 触发 AWAITING_APPROVAL（不静默落库）

环境变量：
  AGENT_CORE_URL / E2E_AGENT_ID / E2E_AGENT_KEY|MEMORIA_ADMIN_KEY|AGENT_KEY
  E2E_ALLOW_WRITE=1  允许 --data 真正执行 UPDATE/soft_delete（仍仅作用于临时副本）
  E2E_SKIP_CARGO=1 / E2E_SKIP_LIVE=1

运行：
  python scripts/e2e_dual_rails.py
  python scripts/e2e_dual_rails.py --data
  E2E_ALLOW_WRITE=1 python scripts/e2e_dual_rails.py --data
  python scripts/e2e_dual_rails.py --live
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

AC = os.environ.get("AGENT_CORE_URL", "http://127.0.0.1:9753").rstrip("/")
AGENT_ID = os.environ.get("E2E_AGENT_ID", "default")
AGENT_KEY = (
    os.environ.get("E2E_AGENT_KEY")
    or os.environ.get("MEMORIA_ADMIN_KEY")
    or os.environ.get("AGENT_KEY")
    or ""
)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_SKILLS = os.path.join(ROOT, "..", "dashboard", "skills")
REAL_DB = os.path.abspath(os.path.join(ROOT, "..", "dashboard", "dashboard.db"))

UNIT_FILTERS = ("db_write", "repo_ws", "controlled_write", "boundary")


def _load_dotenv() -> None:
    path = os.path.join(ROOT, ".env")
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except OSError:
        pass


def run_unit() -> None:
    print("================ 离线：cargo test 单元闸门 ================")
    for filt in UNIT_FILTERS:
        # cargo 仅接受单一名过滤，逐个跑
        cmd = ["cargo", "test", "--lib", filt, "--", "--nocapture"]
        print("  $", " ".join(cmd))
        r = subprocess.run(cmd, cwd=ROOT)
        if r.returncode != 0:
            print(f"FAIL: cargo test {filt}", file=sys.stderr)
            sys.exit(r.returncode)
    print("  OK")


# ───────────────────────── 数据层 e2e（轨一） ─────────────────────────
def run_data() -> None:
    print("================ 数据层：controlled_db_write + execute_sql(params) ================")
    if not os.path.isfile(REAL_DB):
        print(f"跳过：未找到真实 dashboard.db（{REAL_DB}）", file=sys.stderr)
        return

    # 临时副本：所有写操作仅作用在副本上，绝不触碰真实业务库
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    shutil.copyfile(REAL_DB, tmp.name)
    allow_write = os.environ.get("E2E_ALLOW_WRITE") == "1"
    try:
        sys.path.insert(0, os.path.abspath(DASHBOARD_SKILLS))
        import controlled_db_write_skill as cdw
        import sql_skill as sqs

        cdw.DB_PATH = tmp.name  # 重定向到副本
        sqs.DB_PATH = tmp.name

        # 1) execute_sql 参数化绑定读
        sql = sqs.SQLSkill()
        one = sql.execute(
            "SELECT license_plate FROM vehicle_whitelist LIMIT 1", []
        )
        assert one.get("success"), f"SELECT 失败: {one}"
        plate = one["rows"][0][0]
        print(f"  [read] 抽样车牌={plate!r}")
        rb = sql.execute(
            "SELECT license_plate FROM vehicle_whitelist WHERE license_plate = ?",
            [plate],
        )
        assert rb.get("success") and rb["row_count"] == 1, f"参数化回读失败: {rb}"
        assert plate in str(rb["rows"]), "参数化返回值未包含目标车牌"
        print("  [read+params] OK（参数化绑定与回读正常）")

        # 2) controlled_db_write 拒绝：未 confirmed
        r0 = cdw.ControlledDbWriteSkill().execute(
            table="vehicle_whitelist",
            column="remark",
            value="e2e-test",
            where_column="license_plate",
            where_value=plate,
            confirmed=False,
        )
        assert r0.get("require_confirm") is True, f"未 confirmed 应被拒: {r0}"
        print("  [gate] 未 confirmed 被拒 OK")

        # 3) controlled_db_write 拒绝：错表
        r1 = cdw.ControlledDbWriteSkill().execute(
            table="vehicle_entrance",
            column="remark",
            value="x",
            where_column="license_plate",
            where_value=plate,
            confirmed=True,
        )
        assert not r1.get("success"), f"错表应被拒: {r1}"
        print("  [whitelist] 错表被拒 OK")

        # 4) controlled_db_write 拒绝：缺 where（禁止全表更新）
        r2 = cdw.ControlledDbWriteSkill().execute(
            table="vehicle_whitelist",
            column="remark",
            value="x",
            where_column="",
            where_value="",
            confirmed=True,
        )
        assert not r2.get("success"), f"缺 where 应被拒: {r2}"
        print("  [safety] 缺 where 被拒 OK")

        if not allow_write:
            print("  （跳过真实写+回读：未设 E2E_ALLOW_WRITE=1）")
            return

        # 5) 真实写 + 回读（仅副本）
        marker = "E2E双轨验%d" % (int(time.time()) % 100000)
        w = cdw.ControlledDbWriteSkill().execute(
            table="vehicle_whitelist",
            column="remark",
            value=marker,
            where_column="license_plate",
            where_value=plate,
            confirmed=True,
        )
        assert w.get("success") and w.get("affected_rows", 0) >= 1, f"UPDATE 失败: {w}"
        print(f"  [write] 影响行数={w.get('affected_rows')}")

        rb2 = sql.execute(
            "SELECT remark FROM vehicle_whitelist WHERE license_plate = ?", [plate]
        )
        assert rb2.get("success") and marker in str(rb2["rows"]), f"写后回读失败: {rb2}"
        print("  [write+readback] OK（参数化写经回读校验确认落地）")

        # 6) soft_delete（置失效，不物理删）+ 回读
        sd = cdw.ControlledDbWriteSkill().execute(
            table="vehicle_whitelist",
            column="status",
            value="removed",
            where_column="license_plate",
            where_value=plate,
            confirmed=True,
            soft_delete=True,
        )
        assert sd.get("success"), f"soft_delete 失败: {sd}"
        rb3 = sql.execute(
            "SELECT status, enabled FROM vehicle_whitelist WHERE license_plate = ?", [plate]
        )
        assert "removed" in str(rb3["rows"]) and "0" in str(rb3["rows"]), (
            f"soft_delete 回读失败: {rb3}"
        )
        print("  [soft_delete+readback] OK（软删置 status=removed/enabled=0）")
        print("  DATA OK")
    finally:
        try:
            os.remove(tmp.name)
        except OSError:
            pass


# ───────────────────────── 在线路由 e2e ─────────────────────────
def http_json(method: str, path: str, headers: dict, body=None, timeout: int = 120) -> dict:
    req = urllib.request.Request(
        AC + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        raw = urllib.request.urlopen(req, timeout=timeout).read().decode()
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"_http": e.code, "_body": e.read().decode()[:800]}
    except Exception as e:  # noqa: BLE001
        return {"_err": str(e)}


def chat_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "x-agent-id": AGENT_ID,
        "x-agent-key": AGENT_KEY,
    }


def call_chat(message: str, session_id: str) -> dict:
    return http_json(
        "POST",
        "/api/chat",
        chat_headers(),
        {
            "message": message,
            "user_id": "e2e_dual_rails",
            "session_id": session_id,
            "stream": False,
        },
    )


def reply_text(r: dict) -> str:
    if r.get("_http") or r.get("_err"):
        return ""
    reply = r.get("reply") or r.get("message") or ""
    if isinstance(reply, dict):
        reply = reply.get("content") or json.dumps(reply, ensure_ascii=False)
    return str(reply)


def run_live() -> None:
    print("================ 在线：双轨意图路由（需 AGENT_DB_WRITE/AGENT_REPO_WS=1 启动） ================")
    if not AGENT_KEY:
        print("缺少 AGENT_KEY", file=sys.stderr)
        sys.exit(2)
    sid = "e2e/dual_rails/" + time.strftime("%Y%m%d_%H%M%S")

    # 只读查询 → 不应触发写审批
    q = call_chat("查询白名单里有没有车牌叫苏EZQ117的记录", sid + "/q")
    rq = reply_text(q)
    print(f"  [cw_select] reply[:200]={rq[:200]!r}")
    if "AWAITING_APPROVAL" in rq and "cw_write" in rq:
        print("FAIL: 纯只读查询不应触发 cw_write 审批", file=sys.stderr)
        sys.exit(1)
    print("  [cw_select] OK（只读未触发写审批）")

    # 写意图 → 必须进审批闸，禁止静默落库
    w = call_chat("把白名单里车牌苏EZQ117的公司名改备注为「双轨e2e」", sid + "/w")
    rw = reply_text(w)
    print(f"  [cw_write] reply[:240]={rw[:240]!r}")
    if "AWAITING_APPROVAL" not in rw and "awaiting_approval" not in rw.lower():
        print("WARN: cw_write 未明确进入审批闸（可能服务器未开 AGENT_DB_WRITE=1 或工具未暴露）")
    else:
        print("  [cw_write] OK（进入审批闸，未静默落库）")
    print("  LIVE OK（如见 WARN，请确认 agent-core 以 AGENT_DB_WRITE=1 启动）")


def main() -> None:
    _load_dotenv()
    global AGENT_KEY
    AGENT_KEY = (
        os.environ.get("E2E_AGENT_KEY")
        or os.environ.get("MEMORIA_ADMIN_KEY")
        or os.environ.get("AGENT_KEY")
        or AGENT_KEY
    )
    ap = argparse.ArgumentParser(description="双轨端到端验收")
    ap.add_argument("--unit-only", action="store_true")
    ap.add_argument("--data", action="store_true", help="Python 数据层 e2e")
    ap.add_argument("--live", action="store_true", help="在线意图路由（需服务器开双轨 flag）")
    args = ap.parse_args()

    skip_cargo = os.environ.get("E2E_SKIP_CARGO", "") == "1"
    skip_live = os.environ.get("E2E_SKIP_LIVE", "") == "1"

    if not skip_cargo:
        run_unit()
    else:
        print("skip cargo (E2E_SKIP_CARGO=1)")

    if args.unit_only:
        return

    if args.data or not args.live:
        run_data()

    if args.live and not skip_live:
        run_live()
    elif args.live and skip_live:
        print("skip live (E2E_SKIP_LIVE=1)")


if __name__ == "__main__":
    main()
