#!/usr/bin/env python3
"""PFAiX 个人智能体平台 · 演示助手（交互式菜单）。

用途：推广演示时扮演"同事的本机智能体"，持令牌实时调用平台各能力，
让观众亲眼看到 绑定→记忆→协作→工具→审批 的完整形态。

用法：
  # 演示准备（演示者一次性，创建演示绑定并把令牌存本地）：
  python scripts/demo_assistant.py --setup 演示助手A
  python scripts/demo_assistant.py --setup 演示助手B

  # 演示运行（每个助手一个终端窗口）：
  python scripts/demo_assistant.py --token-file ~/.demo_assistant_A.token
  python scripts/demo_assistant.py --token-file ~/.demo_assistant_B.token

安全：仅允许访问回环 agent-core；令牌文件落在用户目录（演示后可删）。
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ENV = pathlib.Path.home() / ".svc-secrets" / "agent-core.env"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "http" or host not in ALLOWED_HOSTS:
        raise ValueError("base-url 只允许 http://127.0.0.1 或 http://localhost")
    return url


def load_admin_key() -> str:
    for line in DEFAULT_ENV.read_text(encoding="utf-8-sig").splitlines():
        if line.startswith("MEMORIA_ADMIN_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit(f"MEMORIA_ADMIN_KEY not found in {DEFAULT_ENV}")


def request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    admin_key: str | None = None,
    body: dict | bytes | None = None,
    timeout: int = 60,
) -> tuple[int, dict | bytes]:
    url = validate_url(url)
    headers = {"Accept": "application/json"}
    data = None
    if isinstance(body, bytes):
        data = body
        headers["Content-Type"] = "application/octet-stream"
    elif body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if admin_key:
        headers["X-Agent-Id"] = "admin"
        headers["X-Agent-Key"] = admin_key
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            if "octet-stream" in resp.headers.get("Content-Type", ""):
                return resp.status, payload
            raw = payload.decode("utf-8", "replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, {"error": raw[:200]}


def setup(base: str, name: str) -> int:
    """演示准备：创建绑定、存令牌、打印使用说明。"""
    admin_key = load_admin_key()
    token_file = pathlib.Path.home() / f".demo_assistant_{name}.token"
    status, payload = request(
        "POST", base + "/api/assistants/bindings", admin_key=admin_key,
        body={
            "assistant_type": "demo",
            "assistant_name": name,
            "device_id": f"demo-{int(time.time())}",
            "capabilities": ["演示", "问答", "数据查询"],
            "scopes": ["assistant:heartbeat", "memory:read:self", "memory:write:self",
                       "a2a:send", "a2a:receive", "tools:call:read"],
            "public_key": "",
        },
    )
    if status != 201:
        print(f"✗ 绑定创建失败（{status}）: {payload}")
        return 1
    binding = payload["binding"]
    token = payload["token"]
    token_file.write_text(token["access_token"], encoding="utf-8")
    refresh_file = pathlib.Path.home() / f".demo_assistant_{name}.refresh"
    refresh_file.write_text(token["refresh_token"], encoding="utf-8")
    print(f"✓ 演示助手「{name}」就绪")
    print(f"  binding_id : {binding['binding_id']}（A2A 互发时把它告诉对方）")
    print(f"  令牌文件   : {token_file}（24h 有效；过期用 {refresh_file.name} 轮换）")
    print(f"\n启动演示： python scripts/demo_assistant.py --token-file \"{token_file}\"")
    return 0


def show_me(base: str, token: str) -> None:
    st, d = request("GET", base + "/api/assistants/me", token=token)
    b = d.get("binding", d) if isinstance(d, dict) else {}
    print(f"  状态 {st} | 助手: {b.get('assistant_name')}（{b.get('assistant_type')}）")
    print(f"  主人: {b.get('user_id')}")
    print(f"  scopes: {', '.join(b.get('scopes', []))}")
    st, _ = request("POST", base + "/api/assistants/heartbeat", token=token)
    print(f"  心跳已上报（{st}）——通讯录在线绿点就是这个")


def write_memory(base: str, token: str) -> None:
    text = input("  要记住什么？> ").strip() or "演示记忆：本条由演示助手写入。"
    st, d = request("POST", base + "/api/agent/memory", token=token, body={
        "content": text, "memory_type": "episodic",
        "category": "demo", "importance": 3,
    })
    print(f"  状态 {st} | 服务端注入 ns={d.get('namespace','')[:44]}… source={d.get('source')}")
    print("  → 助手不能自选命名空间/伪造来源；记忆归主人个人 NS")


def read_context(base: str, token: str) -> None:
    q = input("  检索什么？> ").strip() or "工作偏好"
    st, d = request("GET", base + "/api/agent/context?q=" + urllib.parse.quote(q) + "&limit=5", token=token)
    print(f"  状态 {st} | 命中 {len(d.get('result', {}).get('results', []) if isinstance(d.get('result'), dict) else [])} 条（换新助手也能读到——记忆跟着人）")


def call_tool(base: str, token: str) -> None:
    st, d = request("GET", base + "/api/agent/tools", token=token)
    tools = d.get("tools", [])
    print(f"  可用只读工具: {', '.join(tools)}")
    tool = input("  工具名（回车=pipeline_status）> ").strip() or "pipeline_status"
    st, d = request("POST", base + "/api/agent/tools/call", token=token,
                    body={"tool": tool, "arguments": {}})
    print(f"  状态 {st}")
    r = d.get("result", d)
    if isinstance(r, str):
        try:
            r = json.loads(r)
        except Exception:
            pass
    print("  结果:", json.dumps(r, ensure_ascii=False, default=str)[:300])


def a2a_task(base: str, token: str, peer: str) -> None:
    peer = peer or input("  对方 binding_id（setup 时打印过）> ").strip()
    if not peer:
        print("  ✗ 需要对方 binding_id")
        return
    subject = input("  任务主题（回车=演示任务）> ").strip() or "演示协作任务"
    st, d = request("POST", base + "/api/a2a/tasks", token=token, body={
        "target_binding": peer, "task_type": "demo",
        "subject": subject, "body": "由演示助手发起的 A2A 协作任务。",
    })
    print(f"  状态 {st} | task={d.get('task', {}).get('task_id', '')[:24]}… 状态={d.get('task', {}).get('status')}")
    print("  → 任务已持久化并投进对方收件箱（对方离线也不丢）")


def inbox(base: str, token: str) -> None:
    st, d = request("GET", base + "/api/a2a/inbox", token=token)
    msgs = d.get("messages", [])
    print(f"  状态 {st} | 收件箱 {len(msgs)} 条（最近 5 条）:")
    for m in msgs[:5]:
        print(f"   - [{m.get('created_at','')}] from={str(m.get('from_binding',''))[:18]}… {str(m.get('body',''))[:60]}")
    if not msgs:
        print("   （空——让另一个演示助手给你发个任务）")


MENU = """
──────────────────────────────────────────
 PFAiX 演示助手 · 菜单
  1) 我是谁 + 心跳（身份与在线）
  2) 写一条记忆（进主人个人 NS）
  3) 检索我的上下文（换助手记忆不丢）
  4) 调用平台工具（数据管道，只读）
  5) 发 A2A 协作任务给另一个助手
  6) 查看我的收件箱
  q) 退出
──────────────────────────────────────────"""


def run(base: str, token_file: pathlib.Path, peer: str) -> int:
    if not token_file.exists():
        print(f"✗ 令牌文件不存在: {token_file}（先用 --setup 创建演示助手）")
        return 1
    token = token_file.read_text(encoding="utf-8").strip()
    while True:
        print(MENU)
        choice = input(" 选择> ").strip().lower()
        try:
            if choice == "1":
                show_me(base, token)
            elif choice == "2":
                write_memory(base, token)
            elif choice == "3":
                read_context(base, token)
            elif choice == "4":
                call_tool(base, token)
            elif choice == "5":
                a2a_task(base, token, peer)
            elif choice == "6":
                inbox(base, token)
            elif choice in ("q", "quit", "exit"):
                return 0
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            print(f"  ✗ {exc}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:9753")
    parser.add_argument("--token-file", default="")
    parser.add_argument("--setup", default="", help="创建演示绑定（传助手名）")
    parser.add_argument("--peer-binding", default="", help="A2A 对方 binding_id（可选）")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    validate_url(base + "/health")
    if args.setup:
        return setup(base, args.setup)
    if not args.token_file:
        # 默认找最常见的演示令牌
        tf = pathlib.Path.home() / ".demo_assistant_演示助手A.token"
        args.token_file = str(tf)
    return run(base, pathlib.Path(args.token_file), args.peer_binding)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
