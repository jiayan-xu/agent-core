#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""calculator —— 最小 stdio MCP 示例服务（Agent-Core 兼容）。

另一个「空核心 + 赋权」的最小示范：提供一个安全的四则运算工具，
用于验证 agent-core 能正确把自然语言问题路由到外部 MCP 工具并取回结果。

安全说明：
  - 不使用 eval()；用 ast 白名单解析，仅允许数字与 + - * / ( ) 运算符，
    杜绝代码注入。这是「赋权但受边界约束」理念的最小体现。
  - 零业务机密、无外部依赖。

协议细节见 echo/server.py 顶部注释（与 agent-core src/mcp_client.rs 对齐）。
"""
import sys
import json
import ast
import operator

_ALLOWED_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

TOOLS = [
    {
        "function": {
            "name": "calculator",
            "description": "安全四则运算（仅支持 + - * / 与括号，不使用 eval）。输入如 \"(1+2)*3\"。",
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "算术表达式，例如 \"1+2*3\" 或 \"(10-4)/2\"",
                    }
                },
                "required": ["expression"],
            },
        }
    }
]


def _eval_node(node):
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant):  # 数字
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("仅支持数字常量")
    if isinstance(node, ast.BinOp):
        op = _ALLOWED_BINOPS.get(type(node.op))
        if op is None:
            raise ValueError("不支持的运算符")
        return op(_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_eval_node(node.operand)
    raise ValueError("不支持的语法")


def safe_calc(expression):
    tree = ast.parse(expression, mode="eval")
    return _eval_node(tree)


def handle_tools_list(req_id):
    return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}


def handle_tools_call(req_id, params):
    name = params.get("name")
    arguments = params.get("arguments", {}) or {}
    if name != "calculator":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": "unknown tool: {}".format(name)},
        }
    expression = arguments.get("expression", "")
    try:
        result = safe_calc(expression)
        text = "{} = {}".format(expression, result)
    except Exception as e:  # noqa: BLE001
        text = "计算失败：{}".format(e)
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {"content": [{"type": "text", "text": text}]},
    }


def main():
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
