"""Office-basic MCP server for agent-core (A/B dual-track pilot).

Implements the same custom JSON-RPC-over-stdio protocol as the dashboard MCP
server (protocol 2026-07-28, OpenAI-style tools/list). Tools:
  - read_text   read a UTF-8 text file
  - write_text  create/overwrite a UTF-8 text file
  - append_text append a line to a UTF-8 text file
  - excel_group_sum  openpyxl group-by aggregation
"""
import json
import os
import sys
from pathlib import Path

from openpyxl import load_workbook

DENY_COMPONENTS = {".ssh", ".gnupg", ".aws", ".azure", ".config/gcloud"}
DENY_FILENAMES = {
    "id_ed25519", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519.pub", "credentials", "gserviceaccount.json",
}


def safe_path(raw: str) -> Path:
    """Reject sensitive paths and (when configured) paths outside the sandbox root."""
    p = Path(raw).expanduser()
    if not p.is_absolute():
        raise ValueError(f"path must be absolute: {raw}")
    # 先做符号链接解析（与 Rust 侧 normalize 一致），再做敏感段匹配，
    # 否则 /tmp/link -> ~/.ssh 这类链接路径会绕过 deny 列表。
    p = p.resolve(strict=False)
    parts = [part.lower() for part in p.parts if part]
    for comp in DENY_COMPONENTS:
        segs = comp.split("/")
        if any(parts[i:i + len(segs)] == segs for i in range(len(parts) - len(segs) + 1)):
            raise ValueError(f"path hits a sensitive directory: {raw}")
    if p.name.lower() in DENY_FILENAMES or p.name.lower().endswith((".pem", ".key")):
        raise ValueError(f"path hits a sensitive file: {raw}")
    root = os.environ.get("AGENT_SANDBOX_ROOT")
    if root:
        try:
            root_resolved = Path(root).resolve(strict=False)
            if not p.is_relative_to(root_resolved):
                raise ValueError(f"path is outside sandbox root {root}: {raw}")
        except OSError:
            raise
    return p

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_text",
            "description": "读取一个 UTF-8 文本文件并返回内容。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件绝对路径"},
                    "max_chars": {"type": "number", "description": "最大返回字符数，默认 8000"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_text",
            "description": "创建或覆盖一个 UTF-8 文本文件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件绝对路径"},
                    "content": {"type": "string", "description": "完整写入内容"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "append_text",
            "description": "向 UTF-8 文本文件追加一行。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件绝对路径"},
                    "content": {"type": "string", "description": "追加内容"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "excel_group_sum",
            "description": "读取 xlsx 并按指定列分组求和，返回从高到低的排名。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "xlsx 文件绝对路径"},
                    "group_col": {"type": "string", "description": "分组列名，默认 product"},
                    "value_col": {"type": "string", "description": "求和列名，默认 qty"},
                },
                "required": ["path"],
            },
        },
    },
]


def handle(req):
    if not isinstance(req, dict):
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32600, "message": "invalid request: expected a JSON object"}}
    rid = req.get("id", 1)
    method = req.get("method", "")
    raw_params = req.get("params")
    params = raw_params if isinstance(raw_params, dict) else {}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2026-07-28", "capabilities": {"tools": {}},
            "serverInfo": {"name": "office-basic", "version": "0.1"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        try:
            if name == "read_text":
                path = safe_path(args["path"])
                text = path.read_text(encoding="utf-8", errors="replace")
                cap = max(0, int(args.get("max_chars", 8000)))
                if len(text) > cap:
                    text = text[:cap] + "\n...[truncated]"
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": text}]}}
            if name == "write_text":
                path = safe_path(args["path"])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(args["content"], encoding="utf-8")
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": json.dumps({"ok": True, "path": str(path)}, ensure_ascii=False)}]}}
            if name == "append_text":
                path = safe_path(args["path"])
                with open(path, "a", encoding="utf-8") as f:
                    f.write(args["content"] + "\n")
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": json.dumps({"ok": True, "path": str(path)}, ensure_ascii=False)}]}}
            if name == "excel_group_sum":
                path = safe_path(args["path"])
                wb = load_workbook(path, read_only=True, data_only=True)
                try:
                    ws = wb.active
                    rows = ws.iter_rows(values_only=True)
                    header_row = next(rows, None)
                    if header_row is None:
                        return {"jsonrpc": "2.0", "id": rid, "result": {
                            "content": [{"type": "text", "text": json.dumps({"ranking": []}, ensure_ascii=False)}]}}
                    header = [str(c) for c in header_row]
                    gc = args.get("group_col", "product")
                    vc = args.get("value_col", "qty")
                    gi = header.index(gc)
                    vi = header.index(vc)
                    agg = {}
                    for row in rows:
                        key = str(row[gi])
                        try:
                            val = float(row[vi] or 0)
                        except (TypeError, ValueError):
                            val = 0
                        agg[key] = agg.get(key, 0) + val
                    ranking = [{"group": k, "total": v} for k, v in
                               sorted(agg.items(), key=lambda kv: kv[1], reverse=True)]
                    return {"jsonrpc": "2.0", "id": rid, "result": {
                        "content": [{"type": "text", "text": json.dumps({"ranking": ranking}, ensure_ascii=False)}]}}
                finally:
                    wb.close()
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": f"unknown tool {name}"}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": str(e)}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"unknown method {method}"}}


def main():
    print(json.dumps({"jsonrpc": "2.0", "type": "ready", "tools": len(TOOLS)}), flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        print(json.dumps(resp, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
