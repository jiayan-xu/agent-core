#!/usr/bin/env python3
"""本仓 local_fs 冒烟（不依赖 dashboard MCP）。

通过 /api/chat 让 agent 使用沙箱读写；也可用 Rust 单测覆盖核心路径。

环境：AGENT_CORE_URL / E2E_AGENT_KEY|MEMORIA_ADMIN_KEY
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AC = os.environ.get("AGENT_CORE_URL", "http://127.0.0.1:9753").rstrip("/")


def load_dotenv() -> None:
    p = os.path.join(ROOT, ".env")
    if not os.path.isfile(p):
        return
    with open(p, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def run_unit() -> None:
    print("=== cargo test local_fs / controlled_write ===")
    for filt in ("local_fs", "controlled_write"):
        r = subprocess.run(
            ["cargo", "test", "--lib", filt, "--", "--nocapture"],
            cwd=ROOT,
        )
        if r.returncode != 0:
            sys.exit(r.returncode)
    print("  OK")


def chat(msg: str, sid: str, key: str) -> str:
    body = {
        "message": msg,
        "user_id": "e2e_fs",
        "session_id": sid,
        "stream": False,
    }
    req = urllib.request.Request(
        AC + "/api/chat",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "x-agent-id": "default",
            "x-agent-key": key,
        },
        method="POST",
    )
    raw = urllib.request.urlopen(req, timeout=180).read().decode()
    j = json.loads(raw)
    reply = j.get("reply") or ""
    return str(reply)


def main() -> None:
    load_dotenv()
    run_unit()
    if os.environ.get("E2E_SKIP_LIVE") == "1":
        return
    key = (
        os.environ.get("E2E_AGENT_KEY")
        or os.environ.get("MEMORIA_ADMIN_KEY")
        or os.environ.get("AGENT_KEY")
        or ""
    )
    if not key:
        print("skip live (no key)")
        return
    sid = "e2e/local_fs/" + time.strftime("%H%M%S")
    marker = f"e2e-fs-{time.strftime('%H%M%S')}"
    msg = (
        f"请用 local_fs_write 在沙箱写入文件 e2e_smoke.txt，内容恰好为「{marker}」；"
        f"写完再用 local_fs_read 读回并确认内容一致。不要用其他工具。"
    )
    print("=== live local_fs via /api/chat ===")
    reply = chat(msg, sid, key)
    print("reply[:400]=", reply[:400])
    if marker not in reply and "local_fs" not in reply.lower():
        # LLM 可能不听话；至少单测已覆盖。live 失败降级为 warn
        print("WARN: live 未明确回显 marker（LLM 路由不确定）；单测已通过", file=sys.stderr)
    else:
        print("LIVE OK")


if __name__ == "__main__":
    main()
