#!/usr/bin/env python3
"""协作收件箱 E2E（密钥全部走环境变量，禁止硬编码）。

前置：
  - agent-core :9753 与 Memoria :9003 已启动
  - 环境变量：
      AGENT_CORE_URL          默认 http://127.0.0.1:9753
      E2E_DASH_ID / E2E_DASH_KEY   发起方（默认 jarvis + MEMORIA_ADMIN_KEY）
      E2E_OFFICE_ID / E2E_OFFICE_KEY 办公室身份（须在 COLLAB_ORG_BROADCASTERS 或默认 office-agent）
      COLLAB_ORG_BROADCASTERS  可选，逗号分隔；公司广播白名单

运行：
  python scripts/e2e_collab.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

AC = os.environ.get("AGENT_CORE_URL", "http://127.0.0.1:9753").rstrip("/")
DASH_ID = os.environ.get("E2E_DASH_ID", "jarvis")
DASH_KEY = os.environ.get("E2E_DASH_KEY") or os.environ.get("MEMORIA_ADMIN_KEY", "")
OFF_ID = os.environ.get("E2E_OFFICE_ID", "office-agent")
OFF_KEY = os.environ.get("E2E_OFFICE_KEY", "")

if not DASH_KEY or not OFF_KEY:
    print("缺少 E2E_DASH_KEY/MEMORIA_ADMIN_KEY 或 E2E_OFFICE_KEY，退出", file=sys.stderr)
    sys.exit(2)

DASH = {"Content-Type": "application/json", "x-agent-id": DASH_ID, "x-agent-key": DASH_KEY}
OFF = {"Content-Type": "application/json", "x-agent-id": OFF_ID, "x-agent-key": OFF_KEY}


def call(method, path, hdrs, body=None):
    req = urllib.request.Request(
        AC + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=hdrs,
        method=method,
    )
    try:
        raw = urllib.request.urlopen(req, timeout=15).read().decode()
        return json.loads(raw)
    except urllib.error.HTTPError as e:
        return {"_http": e.code, "_body": e.read().decode()[:400]}
    except Exception as e:
        return {"_err": str(e)}


def inbox(who, hdrs):
    r = call("GET", "/api/collab/inbox", hdrs)
    items = r.get("items", []) if isinstance(r, dict) else []
    print(f"  [{who}] total={r.get('total')} unread={r.get('unread_count')}")
    for m in items[:8]:
        print(
            f"    - {m.get('type')} | scope={m.get('scope')} | from={m.get('from_agent')} | subj={m.get('subject')}"
        )
    return items


print("================ 负向：普通成员不可公司广播 ================")
r = call(
    "POST",
    "/api/collab/send",
    DASH,
    {
        "scope": "org",
        "type": "notify",
        "scope_id": "cs-pufa-2nd-thermal",
        "subject": "应被拒",
        "body": "dashboard 默认不在广播白名单",
    },
)
print("  dash org notify ->", r.get("_http") or r.get("error") or r)
assert r.get("_http") == 403, "非白名单成员发公司广播应 403"
print("  OK")

print("\n================ M3 单点（dash → office）================")
r = call(
    "POST",
    "/api/collab/send",
    DASH,
    {
        "scope": "agent",
        "type": "notify",
        "to_agent": OFF_ID,
        "subject": "单点测试通知",
        "body": "点对点通知",
    },
)
print("  send ->", r)
assert r.get("sent", 0) >= 1, r

off_items = inbox(OFF_ID, OFF)
assert any(
    m.get("from_agent") == DASH_ID and m.get("type") == "notify" for m in off_items
), "点对点未送达或 type 未保留（检查 Memoria content 存储）"
print("  OK 结构化 type=notify")

print("\n================ M4 公司 fan-out（office）================")
r = call(
    "POST",
    "/api/collab/send",
    OFF,
    {
        "scope": "org",
        "type": "notify",
        "scope_id": "cs-pufa-2nd-thermal",
        "subject": "国庆放假通知",
        "body": "10月1日-7日放假（组织广播）",
    },
)
print("  send ->", r)
assert r.get("sent", 0) >= 1, "office fan-out 失败（确认 office 在白名单且有 badge）"
print("  OK fan-out sent=%s" % r.get("sent"))

print("\n================ M2 审批回写（非会话自动续跑）================")
r = call(
    "POST",
    "/api/collab/send",
    DASH,
    {
        "scope": "agent",
        "type": "approval_request",
        "to_agent": OFF_ID,
        "subject": "删除测试数据审批",
        "body": "请求删除临时文件",
        "payload": {"approval_id": "apr_e2e_1", "tool": "delete_file"},
    },
)
assert r.get("sent", 0) >= 1, r
reqs = [m for m in inbox(OFF_ID, OFF) if m.get("type") == "approval_request"]
assert reqs, "未收到 approval_request"
req_id = reqs[0]["id"]
r = call(
    "POST",
    "/api/collab/approval",
    OFF,
    {"id": req_id, "decision": "approve", "reason": "可以执行"},
)
print("  approval ->", r)
assert r.get("ok") is True, r
resp = [m for m in inbox(DASH_ID, DASH) if m.get("type") == "approval_response"]
assert resp, "requester 未收到 approval_response（回写完成 ≠ chat 会话自动续跑）"
print("  OK 回写信封（会话续跑另测）")

print("\n================ org+query 负向 ================")
r = call(
    "POST",
    "/api/collab/send",
    OFF,
    {
        "scope": "org",
        "type": "query",
        "scope_id": "cs-pufa-2nd-thermal",
        "subject": "x",
        "body": "y",
    },
)
assert r.get("_http") == 403, r
print("  OK")

print("\n================ dept 缺 scope_id 负向 ================")
r = call(
    "POST",
    "/api/collab/send",
    DASH,
    {"scope": "dept", "type": "notify", "subject": "x", "body": "y"},
)
assert r.get("_http") == 403, r
print("  OK")

print("\n========= e2e_collab 通过 =========")
