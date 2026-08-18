#!/usr/bin/env python3
"""通道 A PoC 端到端验证：agent-core /api/chat → LLM → send_artifact (MCP 包装)。

验证目标：agent-core 的现有 MCP client 成功加载 dsh-artifact 移植的
send_artifact 工具，并由 LLM 端到端调用成功（Delivered ... 返回）。
密钥只从 .env 读取，不打印。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AC = "http://127.0.0.1:9753"
# 目标交付文件：从环境变量读（本机绝对路径不进公开仓库）
TARGET = os.environ.get("POC_DELIVERABLE", "test_deliverable.md")


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
    return json.loads(urllib.request.urlopen(req, timeout=180).read().decode())


def main() -> None:
    load_dotenv()
    key = os.environ.get("MEMORIA_ADMIN_KEY") or os.environ.get("AGENT_KEY") or ""
    if not key:
        print("missing MEMORIA_ADMIN_KEY", file=sys.stderr)
        sys.exit(2)
    h = {"Content-Type": "application/json", "x-agent-id": "default", "x-agent-key": key}
    sid = "poc/send-artifact/" + time.strftime("%H%M%S")

    msg = (
        f"请执行写入操作：调用 send_artifact 工具，把已存在的文件 {TARGET} 交付给用户，caption 写 'PoC deliverable'。\n"
        f"不要自己创建文件，直接交付这个已有文件。\n"
        f"重要：必须使用以下 DSML 格式调用工具（这是本系统唯一支持的工具调用格式，"
        f"禁止使用 <tool_calls>、<invoke> 等其他任何标签格式）：\n"
        f"<|DSML|tool_calls>\n"
        f"  <|DSML|invoke name=\"send_artifact\">\n"
        f"    <|DSML|parameter name=\"path\" string=\"true\">{TARGET}</|DSML|parameter>\n"
        f"    <|DSML|parameter name=\"caption\" string=\"true\">PoC deliverable</|DSML|parameter>\n"
        f"  </|DSML|invoke>\n"
        f"</|DSML|tool_calls>\n"
        f"工具调用后，根据工具返回结果简短回复即可。"
    )
    # 第一轮：可能命中「复述确认闸」→ 拿到复述文本
    r1 = http("POST", "/api/chat", h, {"message": msg, "user_id": "poc", "session_id": sid, "stream": False})
    reply1 = str(r1.get("reply") or "")
    print("=== round1 (rephrase gate) ===")
    print(reply1[:200])
    # 第二轮：确认执行（若第一轮已是执行结果则直接判断）
    if "方向对吗" in reply1 or "确认" in reply1:
        r2 = http("POST", "/api/chat", h, {"message": "确认执行", "user_id": "poc", "session_id": sid, "stream": False})
        reply = str(r2.get("reply") or "")
    else:
        reply = reply1
    # 第三轮：危险工具审批流（AWAITING_APPROVAL → dashboard 审批台批准 → 再「确认」执行）
    if reply.startswith("AWAITING_APPROVAL"):
        # 1) admin 审批 API 批准（无 x-agent-id，走 admin 通道）
        ah = {"Content-Type": "application/json", "x-agent-key": key}
        pend = http("GET", "/api/approval/pending", ah)
        item = None
        # 必须与本次操作的参数精确关联（arguments.path == TARGET），避免批错
        # 队列里其它/遗留的 send_artifact 请求（评审指正；参照 sibling e2e 脚本）
        for it in (pend.get("items") or []):
            if it.get("tool_name") != "send_artifact":
                continue
            args = it.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if (args or {}).get("path") == TARGET:
                item = it
                break
        if item:
            http(
                "POST",
                f"/api/approval/{item['approval_id']}/respond",
                ah,
                {"approved": True, "reason": "PoC verification", "operation_hash": item["operation_hash"]},
            )
            print("=== approved via dashboard API ===")
            # 2) 再「确认」→ pending_action 恢复 → 执行
            r4 = http("POST", "/api/chat", h, {"message": "确认", "user_id": "poc", "session_id": sid, "stream": False})
            reply = str(r4.get("reply") or "")
        else:
            print("no pending approval item found", pend)
    print("=== final reply ===")
    print(reply[:300])
    print("=== verdict ===")
    # 交付文件名随 TARGET 动态变化（不硬编码，评审指正）
    delivered_name = os.path.basename(TARGET)
    if f"Delivered {delivered_name}" in reply or f"Delivered {TARGET}" in reply:
        print("PASS: agent-core -> LLM -> send_artifact (MCP wrapper) 端到端调用成功")
    else:
        print("FAIL: 回复中未出现 Delivered 证据；检查 send-artifact 是否注册或 LLM 是否调用")
        print("raw:", json.dumps({"r1": reply1[:150], "r2": reply[:150]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
