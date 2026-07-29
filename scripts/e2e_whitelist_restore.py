#!/usr/bin/env python3
"""紧急还原白名单公司名（E2E 失败后用）。密钥走环境变量/.env。"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AC = os.environ.get("AGENT_CORE_URL", "http://127.0.0.1:9753").rstrip("/")
PLATE = os.environ.get("E2E_PLATE", "苏EZQ117")
RESTORE = os.environ.get("E2E_RESTORE_COMPANY", "佳士能（常熟）环境科技有限公司")


def load_dotenv() -> None:
    path = os.path.join(ROOT, ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def http(method: str, path: str, headers: dict, body=None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(AC + path, data=data, headers=headers, method=method)
    return json.loads(urllib.request.urlopen(req, timeout=120).read().decode())


def main() -> None:
    load_dotenv()
    key = (
        os.environ.get("E2E_ADMIN_KEY")
        or os.environ.get("MEMORIA_ADMIN_KEY")
        or os.environ.get("AGENT_KEY")
        or ""
    )
    if not key:
        print("missing key", file=sys.stderr)
        sys.exit(2)
    h = {"Content-Type": "application/json", "x-agent-id": "default", "x-agent-key": key}
    ah = {"Content-Type": "application/json", "x-agent-key": key}
    sid = "e2e/whitelist/emergency/" + time.strftime("%H%M%S")

    def chat(msg: str, s: str) -> str:
        r = http(
            "POST",
            "/api/chat",
            h,
            {"message": msg, "user_id": "e2e", "session_id": s, "stream": False},
        )
        return str(r.get("reply") or "")

    print("gate:", chat(f"把白名单里车牌{PLATE}的公司名统一为「{RESTORE}」", sid + "/g")[:240])
    pend = http("GET", "/api/approval/pending", ah)
    item = None
    for it in pend.get("items") or []:
        args = it.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if (
            it.get("tool_name") == "sync_whitelist_plates"
            and args.get("plate") == PLATE
            and args.get("action") == "update_company"
        ):
            item = it
            break
    if not item:
        print("no pending item", pend, file=sys.stderr)
        sys.exit(1)
    print(
        "approve:",
        http(
            "POST",
            f"/api/approval/{item['approval_id']}/respond",
            ah,
            {
                "approved": True,
                "reason": "emergency restore",
                "operation_hash": item["operation_hash"],
            },
        ),
    )
    out = chat("确认", sid + "/c")
    print("exec:", out[:600])
    if "回读校验通过" in out or RESTORE in out:
        print("RESTORE OK")
    else:
        print("RESTORE DONE (please verify manually)", file=sys.stderr)


if __name__ == "__main__":
    main()
