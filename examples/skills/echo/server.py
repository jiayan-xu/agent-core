#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""echo —— 最小 stdio MCP 示例服务（Agent-Core 兼容）。

证明「空核心 + 赋权」理念：agent-core 自身不提供任何业务工具，
能力完全由外部 MCP 源赋予。本服务零机密、零副作用，仅回显输入，
用于验证 agent-core ↔ MCP 的 stdio 链路是否连通。

通信协议（与 agent-core src/mcp_client.rs 对齐，非标准 MCP，属本项目自定义形状）：
  - 启动后向 stdout 打印一行就绪信号（被 agent-core 读取后即丢弃）。
  - 之后每条来自 stdin 的请求为单行 JSON-RPC，服务必须向 stdout 打印
    恰好一行 JSON-RPC 响应（不可有多余 stdout 输出，日志请走 stderr）。
  - tools/list 返回：result.tools[].function.{name,description,parameters}
  - tools/call  返回：result.content[0].text  或  error

运行（被 agent-core 以 stdio 拉起，无需手动跑）：
  python examples/skills/echo/server.py
"""
import sys
import json

# 暴露给 agent-core 的工具清单（自定义 function 形状）
TOOLS = [
    {
        "function": {
            "name": "echo",
            "description": "回显输入文本。用于验证 MCP 链路连通性，无副作用、无业务机密。",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "要回显的文本"}
                },
                "required": ["text"],
            },
        }
    }
]


def handle_tools_list(req_id):
    return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}


def handle_tools_call(req_id, params):
    name = params.get("name")
    arguments = params.get("arguments", {}) or {}
    if name == "echo":
        text = arguments.get("text", "")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": "echo: {}".format(text)}]},
        }
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": "unknown tool: {}".format(name)},
    }


def main():
    # 就绪信号（agent-core 读取此首行后丢弃）
    sys.stdout.write("ready\n")
    sys.stdout.flush()

    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:  # noqa: BLE001
            sys.stderr.write("parse error: {}\n".format(e))
            continue

        method = req.get("method")
        req_id = req.get("id")
        if method == "tools/list":
            resp = handle_tools_list(req_id)
        elif method == "tools/call":
            resp = handle_tools_call(req_id, req.get("params", {}) or {})
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": "unsupported method: {}".format(method)},
            }

        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
