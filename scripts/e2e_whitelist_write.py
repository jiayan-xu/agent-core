#!/usr/bin/env python3
"""白名单受控写回归（task 651）。

覆盖两层：
  1) 离线：cargo test（DSML fallback + 预路由抽取 + 诚实结果分类）
  2) 在线（可选）：对运行中的 agent-core 发改名/加车意图，断言走
     sync_whitelist_plates 审批闸门（AWAITING_APPROVAL），而非 memory_remember 假成功。

密钥全部走环境变量，禁止硬编码。

环境变量：
  AGENT_CORE_URL     默认 http://127.0.0.1:9753
  E2E_AGENT_ID       默认 default
  E2E_AGENT_KEY      或 MEMORIA_ADMIN_KEY / AGENT_KEY（在线模式必填）
  E2E_SKIP_LIVE=1    只跑离线 cargo test
  E2E_SKIP_CARGO=1   跳过 cargo test（仅在线）

运行：
  python scripts/e2e_whitelist_write.py
  python scripts/e2e_whitelist_write.py --live
  python scripts/e2e_whitelist_write.py --unit-only
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
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

UNIT_FILTERS = ("dsml_tests", "whitelist_preroute_tests")


def run_unit() -> None:
    print("================ 离线：cargo test (650/651 unit) ================")
    for filt in UNIT_FILTERS:
        cmd = ["cargo", "test", "--lib", filt, "--", "--nocapture"]
        print("  $", " ".join(cmd))
        r = subprocess.run(cmd, cwd=ROOT)
        if r.returncode != 0:
            print(f"FAIL: cargo test {filt}", file=sys.stderr)
            sys.exit(r.returncode)
    print("  OK")


def call_chat(message: str, session_id: str) -> dict:
    body = {
        "message": message,
        "user_id": "e2e_whitelist",
        "session_id": session_id,
        "stream": False,
    }
    req = urllib.request.Request(
        AC + "/api/chat",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "x-agent-id": AGENT_ID,
            "x-agent-key": AGENT_KEY,
        },
        method="POST",
    )
    try:
        raw = urllib.request.urlopen(req, timeout=120).read().decode()
        return json.loads(raw)
    except urllib.error.HTTPError as e:
        return {"_http": e.code, "_body": e.read().decode()[:600]}
    except Exception as e:
        return {"_err": str(e)}


def assert_approval_path(label: str, reply: str, expect_plate: str) -> None:
    print(f"  [{label}] reply[:240]={reply[:240]!r}")
    low = reply.lower()
    if "awaiting_approval" not in low and "AWAITING_APPROVAL" not in reply:
        print(f"FAIL: 期望 AWAITING_APPROVAL，实际未进入审批闸门", file=sys.stderr)
        sys.exit(1)
    if "sync_whitelist_plates" not in reply:
        print(f"FAIL: 期望工具 sync_whitelist_plates，实际未提及", file=sys.stderr)
        sys.exit(1)
    if expect_plate and expect_plate not in reply:
        print(f"FAIL: 期望回复含车牌 {expect_plate}", file=sys.stderr)
        sys.exit(1)
    # 假成功信号：只读记忆写入被当成业务写成功
    fake_ok = ("memory_remember" in reply) and ("成功" in reply) and ("AWAITING_APPROVAL" not in reply)
    if fake_ok:
        print("FAIL: 疑似 memory_remember 假成功路径", file=sys.stderr)
        sys.exit(1)
    print(f"  [{label}] OK")


def run_live() -> None:
    print("================ 在线：白名单预路由 → 审批闸门 ================")
    if not AGENT_KEY:
        print(
            "缺少 E2E_AGENT_KEY / MEMORIA_ADMIN_KEY / AGENT_KEY，无法跑在线用例",
            file=sys.stderr,
        )
        sys.exit(2)

    sid = "e2e/whitelist/" + time.strftime("%Y%m%d_%H%M%S")

    # 1) 改公司名
    msg_upd = "把白名单里车牌苏EZQ117的公司名统一为「佳士能环境工程有限公司」"
    r1 = call_chat(msg_upd, sid + "/upd")
    if r1.get("_http") or r1.get("_err"):
        print("FAIL chat update:", r1, file=sys.stderr)
        sys.exit(1)
    reply1 = r1.get("reply") or r1.get("message") or ""
    if isinstance(reply1, dict):
        reply1 = reply1.get("content") or json.dumps(reply1, ensure_ascii=False)
    assert_approval_path("update_company", str(reply1), "苏EZQ117")

    # 2) 添加新车（合法车牌长度：省+字母+4~6位；仅走到审批，不自动批准写入）
    msg_add = "把「佳士能」的新车苏E2ET01添加到白名单"
    r2 = call_chat(msg_add, sid + "/add")
    if r2.get("_http") or r2.get("_err"):
        print("FAIL chat add:", r2, file=sys.stderr)
        sys.exit(1)
    reply2 = r2.get("reply") or r2.get("message") or ""
    if isinstance(reply2, dict):
        reply2 = reply2.get("content") or json.dumps(reply2, ensure_ascii=False)
    assert_approval_path("add", str(reply2), "苏E2ET01")

    # 3) 负向：纯查询不应进审批写闸门
    msg_q = "查询白名单里苏EZQ117的公司名是什么"
    r3 = call_chat(msg_q, sid + "/q")
    reply3 = ""
    if not (r3.get("_http") or r3.get("_err")):
        reply3 = r3.get("reply") or r3.get("message") or ""
        if isinstance(reply3, dict):
            reply3 = reply3.get("content") or json.dumps(reply3, ensure_ascii=False)
        reply3 = str(reply3)
    print(f"  [query] reply[:200]={reply3[:200]!r}")
    if "AWAITING_APPROVAL" in reply3 and "sync_whitelist_plates" in reply3:
        # 查询被误路由成写审批是回归
        print("FAIL: 纯查询不应触发 sync_whitelist_plates 审批", file=sys.stderr)
        sys.exit(1)
    print("  [query] OK（未误触发写审批）")
    print("  LIVE OK")


def main() -> None:
    ap = argparse.ArgumentParser(description="白名单受控写回归 (task 651)")
    ap.add_argument("--unit-only", action="store_true", help="只跑 cargo test")
    ap.add_argument("--live", action="store_true", help="额外跑在线 /api/chat")
    args = ap.parse_args()

    skip_cargo = os.environ.get("E2E_SKIP_CARGO", "") == "1"
    skip_live = os.environ.get("E2E_SKIP_LIVE", "") == "1"

    if not skip_cargo:
        run_unit()
    else:
        print("skip cargo (E2E_SKIP_CARGO=1)")

    if args.unit_only:
        return

    if args.live or (not skip_live and AGENT_KEY):
        if skip_live and not args.live:
            print("skip live (E2E_SKIP_LIVE=1)")
        else:
            run_live()
    else:
        print("skip live（未提供 AGENT_KEY 且未传 --live；离线用例已覆盖核心断言）")


if __name__ == "__main__":
    main()
