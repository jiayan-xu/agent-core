#!/usr/bin/env python3
"""白名单受控写回归（task 651 + 写后回读）。

覆盖：
  1) 离线：cargo test（DSML / 预路由 / v1_compat / controlled_write）
  2) --live：意图 → AWAITING_APPROVAL（不写库）
  3) --full：批准 → 确认执行 → 断言回读校验 → 尽量还原公司名
     （需 E2E_ALLOW_WRITE=1，会短暂改写真实白名单）

密钥全部走环境变量，禁止硬编码。

环境变量：
  AGENT_CORE_URL / E2E_AGENT_ID / E2E_AGENT_KEY|MEMORIA_ADMIN_KEY|AGENT_KEY
  E2E_ADMIN_KEY     审批 API 用（默认同 AGENT_KEY / MEMORIA_ADMIN_KEY）
  E2E_SKIP_LIVE=1 / E2E_SKIP_CARGO=1
  E2E_ALLOW_WRITE=1  允许 --full 真写入
  E2E_PLATE          默认 苏EZQ117
  E2E_RESTORE_COMPANY  还原用公司名（缺省则从写前查询回复里尽力抽取）

运行：
  python scripts/e2e_whitelist_write.py
  python scripts/e2e_whitelist_write.py --live
  python scripts/e2e_whitelist_write.py --full
"""
from __future__ import annotations

import argparse
import json
import os
import re
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
ADMIN_KEY = (
    os.environ.get("E2E_ADMIN_KEY")
    or os.environ.get("MEMORIA_ADMIN_KEY")
    or AGENT_KEY
)
PLATE = os.environ.get("E2E_PLATE", "苏EZQ117")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UNIT_FILTERS = (
    "dsml_tests",
    "whitelist_preroute_tests",
    "v1_compat",
    "controlled_write",
)


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
    print("================ 离线：cargo test ================")
    for filt in UNIT_FILTERS:
        cmd = ["cargo", "test", "--lib", filt, "--", "--nocapture"]
        print("  $", " ".join(cmd))
        r = subprocess.run(cmd, cwd=ROOT)
        if r.returncode != 0:
            print(f"FAIL: cargo test {filt}", file=sys.stderr)
            sys.exit(r.returncode)
    print("  OK")


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
    except Exception as e:
        return {"_err": str(e)}


def chat_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "x-agent-id": AGENT_ID,
        "x-agent-key": AGENT_KEY,
    }


def admin_headers() -> dict:
    return {"Content-Type": "application/json", "x-agent-key": ADMIN_KEY}


def call_chat(message: str, session_id: str) -> dict:
    return http_json(
        "POST",
        "/api/chat",
        chat_headers(),
        {
            "message": message,
            "user_id": "e2e_whitelist",
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


def assert_approval_path(
    label: str, reply: str, expect_plate: str, expect_tool: str = "sync_whitelist_plates"
) -> None:
    print(f"  [{label}] reply[:240]={reply[:240]!r}")
    if "AWAITING_APPROVAL" not in reply and "awaiting_approval" not in reply.lower():
        print("FAIL: 期望 AWAITING_APPROVAL", file=sys.stderr)
        sys.exit(1)
    if expect_tool not in reply:
        print(f"FAIL: 期望工具 {expect_tool}", file=sys.stderr)
        sys.exit(1)
    if expect_plate and expect_plate not in reply:
        print(f"FAIL: 期望回复含车牌 {expect_plate}", file=sys.stderr)
        sys.exit(1)
    fake_ok = ("memory_remember" in reply) and ("成功" in reply) and ("AWAITING_APPROVAL" not in reply)
    if fake_ok:
        print("FAIL: 疑似 memory_remember 假成功路径", file=sys.stderr)
        sys.exit(1)
    print(f"  [{label}] OK")


def list_pending() -> list:
    r = http_json("GET", "/api/approval/pending", admin_headers())
    if r.get("_http") or r.get("_err"):
        print("FAIL pending:", r, file=sys.stderr)
        sys.exit(1)
    return r.get("items") or []


def approve_item(item: dict) -> None:
    aid = item.get("approval_id")
    oh = item.get("operation_hash")
    if not aid or not oh:
        print("FAIL: pending 缺 approval_id/operation_hash", item, file=sys.stderr)
        sys.exit(1)
    r = http_json(
        "POST",
        f"/api/approval/{aid}/respond",
        admin_headers(),
        {"approved": True, "reason": "e2e_whitelist_write --full", "operation_hash": oh},
    )
    if r.get("_http") or r.get("_err") or not r.get("ok"):
        print("FAIL approve:", r, file=sys.stderr)
        sys.exit(1)
    print(f"  [approve] {aid} OK")


def extract_company_guess(text: str) -> str:
    """从查询回复尽力抽公司名：优先含「有限公司/公司」的加粗或表格值。"""
    cands: list[str] = []
    for m in re.finditer(r"\*\*([^*]{2,80})\*\*", text):
        cands.append(m.group(1).strip())
    for m in re.finditer(r"公司名[称]?\s*[|：:]\s*\*?\*?([^\n*|]+)", text):
        cands.append(m.group(1).strip().strip("`").strip())
    for c in cands:
        if "有限公司" in c or (c.endswith("公司") and "数据" not in c and "来源" not in c):
            return c
    for c in cands:
        if "苏" not in c and "数据" not in c and len(c) >= 4:
            return c
    return ""


def reject_stale_whitelist_pending(plate: str) -> int:
    """测试前清掉同车牌残留 pending，避免批准错项。"""
    n = 0
    for it in list_pending():
        if it.get("tool_name") != "sync_whitelist_plates":
            continue
        args = it.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if args.get("plate") != plate:
            continue
        aid, oh = it.get("approval_id"), it.get("operation_hash")
        if not aid or not oh:
            continue
        r = http_json(
            "POST",
            f"/api/approval/{aid}/respond",
            admin_headers(),
            {"approved": False, "reason": "e2e cleanup", "operation_hash": oh},
        )
        if r.get("ok"):
            n += 1
    return n


def find_pending_for_plate(
    plate: str, action: str | None = None, company_name: str | None = None
) -> dict | None:
    for it in list_pending():
        if it.get("tool_name") != "sync_whitelist_plates":
            continue
        args = it.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if args.get("plate") != plate:
            continue
        if action and args.get("action") != action:
            continue
        if company_name and args.get("company_name") != company_name:
            continue
        return it
    return None


def safe_print(s: str) -> None:
    try:
        print(s)
    except UnicodeEncodeError:
        print(s.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))


def run_live() -> None:
    print("================ 在线：预路由 → 审批闸门（不写库） ================")
    if not AGENT_KEY:
        print("缺少 AGENT_KEY", file=sys.stderr)
        sys.exit(2)

    sid = "e2e/whitelist/" + time.strftime("%Y%m%d_%H%M%S")

    msg_upd = f"把白名单里车牌{PLATE}的公司名统一为「佳士能环境工程有限公司」"
    r1 = call_chat(msg_upd, sid + "/upd")
    assert_approval_path("update_company", reply_text(r1), PLATE)

    msg_add = "把「佳士能」的新车苏E2ET01添加到白名单"
    r2 = call_chat(msg_add, sid + "/add")
    assert_approval_path("add", reply_text(r2), "苏E2ET01")

    msg_waste = f"把白名单车牌{PLATE}的固废种类改为「农林垃圾」"
    r_w = call_chat(msg_waste, sid + "/waste")
    assert_approval_path("update_waste_type", reply_text(r_w), PLATE, "manage_whitelist")

    msg_rm = "从白名单删除车牌苏E2ET99"
    r_rm = call_chat(msg_rm, sid + "/rm")
    assert_approval_path("remove", reply_text(r_rm), "苏E2ET99")

    msg_exc = "请把异常修正同步到数据库和入厂日志"
    r_exc = call_chat(msg_exc, sid + "/exc")
    reply_exc = reply_text(r_exc)
    print(f"  [exception_sync] reply[:240]={reply_exc[:240]!r}")
    if "AWAITING_APPROVAL" not in reply_exc and "awaiting_approval" not in reply_exc.lower():
        print("FAIL: 异常同步期望 AWAITING_APPROVAL", file=sys.stderr)
        sys.exit(1)
    if "sync_exception_correction" not in reply_exc:
        print("FAIL: 期望工具 sync_exception_correction", file=sys.stderr)
        sys.exit(1)
    print("  [exception_sync] OK")

    # 短确认写意图：上文含 suggested_fix → 须进审批，禁止假成功
    sid_sc = sid + "/short_confirm"
    seed = (
        '诊断备忘 suggested_fix: {"canonical_company_name":"佳士能（常熟）环境科技有限公司",'
        '"plates_to_update":["苏EZQ117"],"operation":"update_company"}'
    )
    _ = call_chat(seed, sid_sc)
    r_sc = call_chat("确认统一为全称", sid_sc)
    reply_sc = reply_text(r_sc)
    print(f"  [short_confirm] reply[:240]={reply_sc[:240]!r}")
    if "AWAITING_APPROVAL" not in reply_sc and "awaiting_approval" not in reply_sc.lower():
        # 失败闭合也可接受（无上下文时明示未写）；不可假成功
        if "未执行任何写操作" in reply_sc:
            print("  [short_confirm] OK (fail-closed, no durable context)")
        else:
            print("FAIL: 短确认须进审批或明示未写，禁止假成功", file=sys.stderr)
            sys.exit(1)
    else:
        if "sync_whitelist_plates" not in reply_sc:
            print("FAIL: 短确认期望 sync_whitelist_plates", file=sys.stderr)
            sys.exit(1)
        if PLATE not in reply_sc:
            print(f"FAIL: 短确认期望还原车牌 {PLATE}", file=sys.stderr)
            sys.exit(1)
        if "操作已执行成功" in reply_sc and "diagnose_data_gap" in reply_sc:
            print("FAIL: 短确认假成功（只读 diagnose）", file=sys.stderr)
            sys.exit(1)
        print("  [short_confirm] OK")

    msg_q = f"查询白名单里{PLATE}的公司名是什么"
    reply3 = reply_text(call_chat(msg_q, sid + "/q"))
    print(f"  [query] reply[:200]={reply3[:200]!r}")
    if "AWAITING_APPROVAL" in reply3 and "sync_whitelist_plates" in reply3:
        print("FAIL: 纯查询不应触发写审批", file=sys.stderr)
        sys.exit(1)
    print("  [query] OK")
    print("  LIVE OK")


def run_full() -> None:
    print("================ 全链路：批准 → 执行 → 回读 → 还原 ================")
    if os.environ.get("E2E_ALLOW_WRITE") != "1":
        print("拒绝：未设置 E2E_ALLOW_WRITE=1（会改写真实白名单）", file=sys.stderr)
        sys.exit(2)
    if not AGENT_KEY or not ADMIN_KEY:
        print("缺少 AGENT_KEY / ADMIN_KEY", file=sys.stderr)
        sys.exit(2)

    sid = "e2e/whitelist/full/" + time.strftime("%Y%m%d_%H%M%S")
    marker = f"E2E验{time.strftime('%H%M%S')}工程有限公司"

    cleaned = reject_stale_whitelist_pending(PLATE)
    if cleaned:
        print(f"  [cleanup] rejected {cleaned} stale pending(s)")

    # 写前查询，拿还原公司名
    restore = os.environ.get("E2E_RESTORE_COMPANY", "").strip()
    q0 = reply_text(call_chat(f"查询白名单里{PLATE}的公司名是什么，只回答公司全称", sid + "/q0"))
    safe_print(f"  [pre-query] {q0[:220]!r}")
    if not restore:
        restore = extract_company_guess(q0)
    if not restore:
        print("FAIL: 无法确定还原公司名，请设 E2E_RESTORE_COMPANY", file=sys.stderr)
        sys.exit(1)
    safe_print(f"  [restore target] {restore!r}")

    # 发起改名 → 审批闸
    msg = f"把白名单里车牌{PLATE}的公司名统一为「{marker}」"
    r1 = call_chat(msg, sid + "/upd")
    assert_approval_path("full_update", reply_text(r1), PLATE)

    item = find_pending_for_plate(PLATE, "update_company", company_name=marker)
    if not item:
        print("FAIL: pending 中未找到 marker 对应 update_company", file=sys.stderr)
        sys.exit(1)
    approve_item(item)

    exec_reply = reply_text(call_chat("确认", sid + "/confirm"))
    safe_print(f"  [execute] reply[:360]={exec_reply[:360]!r}")
    if "回读校验通过" not in exec_reply:
        print("FAIL: 期望「回读校验通过」", file=sys.stderr)
        sys.exit(1)
    print("  [execute+verify] OK")

    # 还原
    msg_r = f"把白名单里车牌{PLATE}的公司名统一为「{restore}」"
    r_rest = call_chat(msg_r, sid + "/restore")
    assert_approval_path("restore_gate", reply_text(r_rest), PLATE)
    item2 = find_pending_for_plate(PLATE, "update_company", company_name=restore)
    if not item2:
        # 公司名可能被 resolve 成全称，放宽匹配
        item2 = find_pending_for_plate(PLATE, "update_company")
    if not item2:
        print("FAIL: 还原审批项缺失", file=sys.stderr)
        sys.exit(1)
    approve_item(item2)
    rest_reply = reply_text(call_chat("确认", sid + "/restore_confirm"))
    safe_print(f"  [restore exec] reply[:240]={rest_reply[:240]!r}")
    if "回读校验通过" not in rest_reply:
        print("WARN: 还原回读未明确通过，请人工核对白名单", file=sys.stderr)
    else:
        print("  [restore] OK")
    print("  FULL OK")


def main() -> None:
    _load_dotenv()
    global AGENT_KEY, ADMIN_KEY
    AGENT_KEY = (
        os.environ.get("E2E_AGENT_KEY")
        or os.environ.get("MEMORIA_ADMIN_KEY")
        or os.environ.get("AGENT_KEY")
        or AGENT_KEY
    )
    ADMIN_KEY = (
        os.environ.get("E2E_ADMIN_KEY")
        or os.environ.get("MEMORIA_ADMIN_KEY")
        or AGENT_KEY
    )

    ap = argparse.ArgumentParser(description="白名单受控写回归")
    ap.add_argument("--unit-only", action="store_true")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--full", action="store_true", help="批准+执行+回读+还原（需 E2E_ALLOW_WRITE=1）")
    args = ap.parse_args()

    skip_cargo = os.environ.get("E2E_SKIP_CARGO", "") == "1"
    skip_live = os.environ.get("E2E_SKIP_LIVE", "") == "1"

    if not skip_cargo:
        run_unit()
    else:
        print("skip cargo (E2E_SKIP_CARGO=1)")

    if args.unit_only:
        return

    if args.full:
        run_full()
        return

    if args.live or (not skip_live and AGENT_KEY):
        if skip_live and not args.live:
            print("skip live (E2E_SKIP_LIVE=1)")
        else:
            run_live()
    else:
        print("skip live（未提供 KEY 且未传 --live）")


if __name__ == "__main__":
    main()
