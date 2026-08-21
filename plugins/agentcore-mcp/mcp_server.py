#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agentcore-mcp —— 把整个 agent-core 暴露为标准 MCP 工具（dsh 插件）。

覆盖 agent-core（127.0.0.1:9753）路由表的全部能力：
  对话/会话 · 审批 · 协作A2A · 分身 · 会议/圆桌 · 运维观测 · 身份/更新 ·
  记忆反馈 · 记忆元进化 · 代码进化

标准插件接口：
  - 传输：MCP JSON-RPC over stdio（换行分隔）
  - 方法：initialize / notifications/initialized / ping / tools/list / tools/call
  - 协议版本：优先 2026-07-28，回退 2024-11-05
  - 零第三方依赖：HTTP/SSE 全部使用 Python 标准库

凭据（只从环境变量读，绝不落盘/日志）：
  AGENTCORE_BASE_URL     默认 http://127.0.0.1:9753
  AGENTCORE_AGENT_ID     agent 身份（受保护 API）
  AGENTCORE_AGENT_KEY    agent badge 密钥（X-Agent-Key）
  AGENTCORE_ADMIN_ID     管理身份，默认 "admin"
  AGENTCORE_ADMIN_KEY    Memoria 管理密钥（审批/运维类工具需要；缺省回退 AGENTCORE_AGENT_KEY）
  AGENTCORE_EVOLVE_KEY   /api/evolve 专用进化密钥（x-evolve-key）

安全纪律：
  - 破坏性/危险操作带 confirm 字面确认（DELETE/KILL/SAVE/APPLY/APPROVE/REJECT）
  - 所有 agent-core 服务端门禁（审批黄线、隔离仓、dry_run、allow_commit、
    operation_hash、可达策略、配额、熔断）原样保留，本插件只透传不绕过。
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

SERVER_NAME = "agentcore-mcp"
SERVER_VERSION = "0.2.0"
SUPPORTED_PROTOCOLS = ["2026-07-28", "2024-11-05"]

DEFAULT_BASE_URL = "http://127.0.0.1:9753"
DEFAULT_HTTP_TIMEOUT_SECS = 30
MAX_EVENT_TEXT_CHARS = 12000
MAX_EVENTS_IN_RESULT = 300
MAX_JOINED_REPLY_CHARS = 100_000


# ── 基础工具 ────────────────────────────────────────────────────────────


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def log(*args) -> None:  # stdout 保持纯 JSON-RPC 流，日志只走 stderr
    sys.stderr.write("[agentcore-mcp] " + " ".join(str(a) for a in args) + "\n")
    sys.stderr.flush()


class ToolError(Exception):
    """业务/传输错误 → 以 isError 内容返回给模型。"""


def base_url() -> str:
    return (env("AGENTCORE_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


def require_credential(name: str, fallback: str = "") -> str:
    value = env(name) or env(fallback)
    if not value:
        raise ToolError("缺少环境变量 %s（凭据只在运行时读取，不落盘）" % name)
    return value


def agent_headers() -> dict:
    return {
        "X-Agent-Id": require_credential("AGENTCORE_AGENT_ID"),
        "X-Agent-Key": require_credential("AGENTCORE_AGENT_KEY"),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def admin_headers() -> dict:
    # 审批/运维 handler 的 is_admin 判定：x-agent-key == AGENTCORE_ADMIN_KEY
    # fail-closed（ADR-016 D6）：不回退 AGENT_KEY——挂载进 L1 槽位（dsh）的场景
    # 禁止隐式持有 admin 能力；缺 ADMIN_KEY 即启动报错，而非静默降权复用。
    return {
        "X-Agent-Id": env("AGENTCORE_ADMIN_ID") or "admin",
        "X-Agent-Key": require_credential("AGENTCORE_ADMIN_KEY"),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def pick_fields(args: dict, fields) -> dict:
    """按声明字段从参数抽取请求体；跳过空值（None/空串）。"""
    out = {}
    for src, dst in fields:
        value = args.get(src)
        if value is None or value == "":
            continue
        out[dst] = value
    return out


def pick_query(args: dict, fields) -> dict:
    out = {}
    for src, dst in fields:
        value = args.get(src)
        if value is None or value == "":
            continue
        out[dst] = str(value)
    return out


def confirm_gate(args: dict, word: str) -> None:
    if (args.get("confirm") or "") != word:
        raise ToolError("危险操作需要显式确认参数 confirm=%r（不改数据、只做保护）" % word)


def http_json(
    method: str,
    path: str,
    payload=None,
    query=None,
    headers_extra=None,
    public: bool = False,
    admin: bool = False,
    timeout_secs: int = DEFAULT_HTTP_TIMEOUT_SECS,
):
    url = base_url() + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = admin_headers() if admin else ({"Accept": "application/json"} if public else agent_headers())
    if headers_extra:
        headers.update(headers_extra)
    # POST/PUT body 必须带 Content-Type（public=True 时 headers 仅有 Accept，漏了会 415）
    if data is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_secs) as resp:
            status = getattr(resp, "status", 200)
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        raise ToolError("%s %s 请求失败: %s" % (method, path, e)) from e

    parsed = None
    if raw.strip():
        try:
            parsed = json.loads(raw)
        except Exception:  # noqa: BLE001
            parsed = None
    if status >= 400:
        detail = ""
        if isinstance(parsed, dict):
            detail = str(parsed.get("error") or parsed.get("message") or "")
        elif parsed is None and raw.strip():
            detail = raw.strip()[:500]
        raise ToolError("HTTP %s %s %s %s" % (status, method, path, detail).strip())
    return {"status": status, "json": parsed, "raw": raw}


def sse_events(
    path: str,
    payload=None,
    query=None,
    headers_extra=None,
    admin: bool = False,
    method: str = "POST",
    headers_base=None,
):
    """消费一个会自然结束的 SSE 流，返回 [{event, data}]。"""
    url = base_url() + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    if headers_base is not None:
        headers = dict(headers_base)  # 仅用给定基础头（如 evolve 只带 x-evolve-key）
    else:
        headers = admin_headers() if admin else agent_headers()
    headers["Accept"] = "text/event-stream"
    if headers_extra:
        headers.update(headers_extra)
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    # body 必带 Content-Type：headers_base 路径（如 /api/evolve 只有 x-evolve-key）
    # 不补会退化成 form-urlencoded，被 axum Json extractor 拒 415（review 指正）
    if data is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    events = []
    event_name = "message"
    data_lines = []
    event_seen = False  # 本块内是否出现过显式 event: 行

    def flush():
        nonlocal event_name, data_lines, event_seen
        # 只要见到过 event: 行（即使无 data 行）就应产出事件——
        # termination 用 `event: done` + 空 data 表示，漏掉了会丢 done（review 指正）
        if event_seen or data_lines:
            if data_lines:
                raw_data = "\n".join(data_lines)
                # 仅当块明显是 JSON（{ 或 [ 开头）才尝试结构化；纯文本原样保留
                if raw_data.lstrip().startswith(("{", "[")):
                    try:
                        parsed = json.loads(raw_data)
                    except Exception:  # noqa: BLE001
                        parsed = raw_data
                else:
                    parsed = raw_data
            else:
                parsed = ""  # 纯 event 标记（如 done）无 data
            events.append({"event": event_name, "data": parsed})
        event_name = "message"
        data_lines = []
        event_seen = False

    try:
        # 长任务用「读超时」而非「总超时」：总超时会把长时间空闲的流按已超时杀掉。
        # 每行读取都复位计时，仅当读操作超过该秒数才判定超时（默认 300s，可用 env 调整）。
        read_timeout = int(os.environ.get("AGENTCORE_SSE_READ_TIMEOUT_SECS") or "300") or None
        with urllib.request.urlopen(req, timeout=read_timeout) as resp:  # 长任务不设总超时
            for raw in resp:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":
                    flush()
                elif line.startswith("event:"):
                    event_name = line[len("event:"):].strip()
                    event_seen = True
                elif line.startswith("data:"):
                    # RFC 8202 §3：data: 后仅一个空格是分隔符，多余空格属于 payload。
                    # .lstrip(' ') 会误删所有前导空格，损坏缩进代码块/格式化 JSON 等有效数据。
                    raw_data = line[len('data:'):]
                    data_lines.append(raw_data[1:] if raw_data.startswith(' ') else raw_data)
            flush()
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        raise ToolError("HTTP %s %s: %s" % (e.code, path, raw[:300])) from e
    except Exception as e:  # noqa: BLE001
        raise ToolError("SSE 流 %s 中断: %s（已收到 %d 个事件）" % (path, e, len(events))) from e
    return events


def truncate_text(text: str, limit: int = MAX_EVENT_TEXT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[截断，原文更长]"


# ── 工具实现 ────────────────────────────────────────────────────────────


def _redact_badge_token(body, include_token: bool) -> None:
    """凭据脱敏：register/login 响应含长期 badge_token，默认不送回模型/日志，
    仅当调用方显式 include_token=true 才原样回显（review 指正：规避凭据泄露）。
    body 原地修改；返回前调用方无需处理。
    """
    if not isinstance(body, dict) or not body.get("badge_token"):
        return
    if include_token:
        body["_warning"] = "badge_token 已按 include_token=true 原样返回，属长期凭据，务必勿写入日志"
    else:
        body["badge_token"] = "[REDACTED: 用 include_token=true 重放可获取，但不可记录到日志]"



def tool_tool_execute(args: dict) -> dict:
    # 模型偶发双层嵌套 {"arguments": {"tool": ..., "arguments": ...}}——防御性展开
    if isinstance(args.get("arguments"), dict) and "tool" in args["arguments"] and not args.get("tool"):
        args = args["arguments"]
    if not args.get("tool"):
        return {"content": [{"type": "text", "text": "参数错误：必须提供 tool（工具名）与 arguments（参数对象），不要把整个请求再包进 arguments 键。"}], "isError": True}
    """R1 网关（ADR-016 §2）：无头工具执行。三态：
    200 executed（result 直接返回）/ 202 pending_approval（approval_id + operation_hash，
    人在 dashboard 审批台批准后可轮询终态）/ 4xx 错误文本原样透出。"""
    body = {
        "tool": args.get("tool", ""),
        "arguments": args.get("arguments") or {},
    }
    for k in ("persona_id", "session_id", "trace_id", "idempotency_key"):
        if args.get(k):
            body[k] = args[k]
    resp = http_json("POST", "/api/tool/execute", payload=body)
    status, data = resp["status"], resp["json"]
    # 统一成文本：executed 带 result；202 pending 带 approval 指引（错误路径 http_json 抛 ToolError）
    if status == 202 and isinstance(data, dict):
        merged = dict(data)
        merged["_hint"] = (
            "工具进入人工审批（approval_id=%s）。请告知用户在 PFAiX 审批台批准；"
            "批准后用 agentcore_tool_execute_status 轮询终态。" % merged.get("approval_id")
        )
        return {"content": [{"type": "text", "text": json.dumps(merged, ensure_ascii=False)}]}
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False) if data is not None else resp["raw"]}]}


def tool_tool_execute_status(args: dict) -> dict:
    """查询网关执行终态（202 审批单批准后的轮询入口）。"""
    eid = args.get("execution_id", "")
    resp = http_json("GET", "/api/tool/execute/" + urllib.parse.quote(eid))
    data = resp["json"]
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False) if data is not None else resp["raw"]}]}


def tool_health(_args: dict) -> dict:
    res = http_json("GET", "/health", public=True, timeout_secs=10)
    return {"ok": True, "health": res["json"]}


def tool_config(_args: dict) -> dict:
    res = http_json("GET", "/api/config", public=True, timeout_secs=10)
    return {"ok": True, "config": res["json"]}


def tool_updates_latest(_args: dict) -> dict:
    res = http_json("GET", "/updates/pfaix/latest.json", public=True, timeout_secs=10)
    return {"ok": True, "latest": res["json"]}


def tool_register_agent(args: dict) -> dict:
    for key in ("name", "department", "company"):
        if not (args.get(key) or "").strip():
            raise ToolError("%s 必填" % key)
    payload = pick_fields(
        args,
        [
            ("name", "name"), ("department", "department"), ("company", "company"),
            ("project", "project"), ("div", "div"),
            ("display_name", "display_name"), ("department_display", "department_display"),
        ],
    )
    res = http_json("POST", "/api/register", payload, public=True, timeout_secs=60)
    body = res["json"] or {}
    _redact_badge_token(body, str(args.get("include_token", "")).strip().lower() in ("1", "true", "yes", "y"))
    return {"ok": bool(body.get("ok")), "result": body}


def tool_register_user(args: dict) -> dict:
    for key in ("user_id", "password"):
        if not (args.get(key) or "").strip():
            raise ToolError("%s 必填" % key)
    payload = pick_fields(
        args,
        [
            ("user_id", "user_id"), ("password", "password"),
            ("display_name", "display_name"), ("namespace", "namespace"),
            ("admin_key", "admin_key"),
        ],
    )
    res = http_json("POST", "/api/register_user", payload, public=True, timeout_secs=60)
    body = res["json"] or {}
    _redact_badge_token(body, str(args.get("include_token", "")).strip().lower() in ("1", "true", "yes", "y"))
    return {"ok": bool(body.get("ok")), "result": body}


def tool_login(args: dict) -> dict:
    for key in ("user_id", "password"):
        if not (args.get(key) or "").strip():
            raise ToolError("%s 必填" % key)
    payload = pick_fields(args, [("user_id", "user_id"), ("password", "password")])
    res = http_json("POST", "/api/login", payload, public=True, timeout_secs=60)
    body = res["json"] or {}
    _redact_badge_token(body, str(args.get("include_token", "")).strip().lower() in ("1", "true", "yes", "y"))
    return {"ok": bool(body.get("ok")), "result": body}


def tool_approval_pending(_args: dict) -> dict:
    res = http_json("GET", "/api/approval/pending", admin=True)
    return {"ok": True, "result": res["json"]}


def tool_approval_history(_args: dict) -> dict:
    # 路由公开但内部 authenticate：走 agent badge 即可
    res = http_json("GET", "/api/approval/history")
    return {"ok": True, "result": res["json"]}


def tool_approval_respond(args: dict) -> dict:
    approval_id = (args.get("id") or "").strip()
    if not approval_id:
        raise ToolError("id 必填（审批项 id）")
    approved = False
    raw_approved = args.get("approved")
    if isinstance(raw_approved, str):
        approved = raw_approved.strip().lower() in ("1", "true", "yes", "approve", "批准", "是")
    else:
        approved = bool(raw_approved)
    required_confirm = "APPROVE" if approved else "REJECT"
    confirm_gate(args, required_confirm)
    operation_hash = (args.get("operation_hash") or "").strip()
    if not operation_hash:
        raise ToolError("operation_hash 必填：必须回显审批项创建时的指纹，防操作被偷换")
    payload = {
        "approved": approved,
        "operation_hash": operation_hash,
        "reason": (args.get("reason") or "").strip() or None,
    }
    res = http_json(
        "POST", "/api/approval/%s/respond" % urllib.parse.quote(approval_id, safe=""),
        payload, admin=True,
    )
    return {"ok": True, "result": res["json"]}


def tool_chat(args: dict) -> dict:
    message = (args.get("message") or "").strip()
    if not message:
        raise ToolError("message 必填")
    payload = {"message": message}
    session_id = (args.get("session_id") or "").strip()
    if session_id:
        payload["session_id"] = session_id
    res = http_json("POST", "/api/chat", payload, timeout_secs=600)
    return {"ok": True, "result": res["json"]}


def tool_chat_stream(args: dict) -> dict:
    message = (args.get("message") or "").strip()
    if not message:
        raise ToolError("message 必填")
    query = {"message": message}
    session_id = (args.get("session_id") or "").strip()
    if session_id:
        query["session_id"] = session_id
    events = sse_events("/api/chat/stream", query=query, method="GET")
    chunks = [
        e["data"] for e in events
        if e["event"] == "text" and isinstance(e["data"], str)
    ]
    reply = "".join(chunks)
    done = any(e["event"] == "done" for e in events)
    return {
        "ok": done,
        "reply": truncate_text(reply, MAX_JOINED_REPLY_CHARS),
        "chunk_count": len(chunks),
        "truncated": len(reply) > MAX_JOINED_REPLY_CHARS,
    }


def tool_v1_chat(args: dict) -> dict:
    messages = args.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ToolError("messages 必填（OpenAI 格式数组）")
    payload = {"messages": messages}
    model = (args.get("model") or "").strip()
    if model:
        payload["model"] = model
    # 只支持非流式（流式会返回 SSE，不适合 MCP 工具阻塞消费）
    payload["stream"] = False
    res = http_json("POST", "/v1/chat/completions", payload, timeout_secs=600)
    return {"ok": True, "result": res["json"]}


def tool_memory_feedback(args: dict) -> dict:
    kind = (args.get("kind") or "").strip()
    content = (args.get("content") or "").strip()
    if kind not in ("preference", "decision", "affirm"):
        raise ToolError("kind 必须是 preference | decision | affirm")
    if not content:
        raise ToolError("content 必填")
    payload = pick_fields(
        args,
        [("kind", "kind"), ("content", "content"), ("tag", "tag"), ("namespace", "namespace")],
    )
    res = http_json("POST", "/api/memory/feedback", payload)
    return {"ok": True, "result": res["json"]}


def tool_meta_evolution_status(_args: dict) -> dict:
    res = http_json("GET", "/api/meta-evolution/status")
    return {"ok": True, "result": res["json"]}


def tool_meta_evolution_run(args: dict) -> dict:
    payload = pick_fields(args, [("namespace", "namespace")])
    res = http_json("POST", "/api/meta-evolution/run", payload or None, timeout_secs=300)
    body = res["json"]
    status = body.get("status") if isinstance(body, dict) else None
    return {"ok": status != "skipped", "skipped": status == "skipped", "result": body}


def _run_code_evolve(args: dict, apply_flag: bool) -> dict:
    target_path = (args.get("target_path") or "").strip()
    if not target_path:
        raise ToolError("target_path 必填（必须通过 agent-core 隔离仓校验）")
    payload = {"target_path": target_path, "apply": apply_flag}
    for key in ("fn_name", "goal"):
        value = (args.get(key) or "").strip()
        if value:
            payload[key] = value
    generations = args.get("generations")
    if isinstance(generations, int) and generations > 0:
        payload["generations"] = generations
    headers = {"x-evolve-key": require_credential("AGENTCORE_EVOLVE_KEY")}
    events = sse_events("/api/evolve", payload, headers_extra=headers, headers_base={})

    done = next((e for e in events if e["event"] == "done"), None)
    fatal = ("error", "budget_break", "circuit_break", "gate_failed")
    summary = {
        "ok": done is not None and not any(e["event"] in fatal for e in events),
        "apply": apply_flag,
        "done": (done or {}).get("data"),
        "event_count": len(events),
        "events": [],
        "veto_diffs": [],
        "commits": [],
    }
    for event in events[:MAX_EVENTS_IN_RESULT]:
        name = event["event"]
        data = event["data"]
        if name == "veto" and isinstance(data, dict) and data.get("diff"):
            summary["veto_diffs"].append({
                "gen": data.get("gen"), "bench_ms": data.get("bench_ms"),
                "diff": truncate_text(str(data.get("diff", ""))),
            })
        elif name == "committed" and isinstance(data, dict):
            summary["commits"].append({
                "gen": data.get("gen"), "commit": data.get("commit"),
                "bench_ms": data.get("bench_ms"),
            })
        else:
            if isinstance(data, dict):
                compact = dict(data)
                for field in ("code", "diff", "log"):
                    if isinstance(compact.get(field), str):
                        compact[field] = truncate_text(compact[field], 4000)
                summary["events"].append({"event": name, "data": compact})
            else:
                summary["events"].append({"event": name, "data": data})
    return summary


def tool_code_evolve_dry_run(args: dict) -> dict:
    return _run_code_evolve(args, False)


def tool_code_evolve_apply(args: dict) -> dict:
    confirm_gate(args, "APPLY")
    return _run_code_evolve(args, True)


def tool_collab_approval(args: dict) -> dict:
    decision = (args.get("decision") or "").strip()
    required_confirm = {"approve": "APPROVE", "reject": "REJECT"}.get(decision)
    if required_confirm is None:
        raise ToolError("decision 必须是 approve | reject")
    confirm_gate(args, required_confirm)
    payload = pick_fields(
        args,
        [
            ("id", "id"), ("decision", "decision"), ("reason", "reason"),
            ("operation_hash", "operation_hash"),
        ],
    )
    if not payload.get("id"):
        raise ToolError("id 必填（收件箱中待响应消息 id）")
    res = http_json("POST", "/api/collab/approval", payload)
    return {"ok": True, "result": res["json"]}


def tool_roundtable(args: dict) -> dict:
    topic = (args.get("topic") or "").strip()
    if not topic:
        raise ToolError("topic 必填")
    payload = {"topic": topic}
    for key in ("chair", "session_id", "visibility", "scope"):
        value = (args.get(key) or "").strip()
        if value:
            payload[key] = value
    personas = args.get("personas")
    if isinstance(personas, list) and personas:
        payload["personas"] = personas
    participants = args.get("participants")
    if isinstance(participants, list) and participants:
        payload["participants"] = participants
    events = sse_events("/api/roundtable", payload)

    summary = {
        "ok": any(e["event"] == "done" for e in events),
        "event_count": len(events),
        "stances": [],
        "consensus": None,
        "events": [],
    }
    for event in events[:MAX_EVENTS_IN_RESULT]:
        if event["event"] == "stance":
            summary["stances"].append(event["data"])
        elif event["event"] == "consensus":
            summary["consensus"] = event["data"]
        elif event["event"] == "done":
            summary["done"] = event["data"]
        else:
            summary["events"].append(event)
    return summary


def _json_handler(method, path_template, *, public=False, admin=False,
                  body_fields=None, query_fields=None, confirm_word=None,
                  timeout_secs=DEFAULT_HTTP_TIMEOUT_SECS):
    """数据驱动通用工具：GET/POST/PUT/DELETE + 路径参数 {id} + 确认闸。"""
    def handler(args: dict) -> dict:
        if confirm_word:
            confirm_gate(args, confirm_word)
        path = path_template
        if "{id}" in path_template:
            rid = (args.get("id") or "").strip()
            if not rid:
                raise ToolError("id 必填")
            path = path_template.format(id=urllib.parse.quote(rid, safe=""))
        payload = pick_fields(args, body_fields or []) or None
        query = pick_query(args, query_fields or []) or None
        res = http_json(method, path, payload, query, public=public, admin=admin,
                        timeout_secs=timeout_secs)
        return {"ok": True, "result": res["json"]}
    return handler


# ── 工具清单 ────────────────────────────────────────────────────────────

def P(type_: str, desc: str, **extra) -> dict:
    prop = {"type": type_, "description": desc}
    prop.update(extra)
    return prop


def schema(props: dict, required=None):
    return {
        "type": "object",
        "properties": props,
        "required": required or [],
        "additionalProperties": False,
    }


# 每组一个 handler 工厂调用，再集中列进 TOOL_SPECS。
TOOL_SPECS = [
    # ── 系统 / 公开 ──
    dict(name="agentcore_health", description="检查 agent-core 服务健康状态（公开端点，无副作用）。返回服务版本、Memoria 可达性、embedding 状态与最近 dream 心跳。", handler=tool_health, schema=schema({})),
    dict(name="agentcore_config", description="读取 agent-core 当前配置摘要（公开）：configured / agent_id / server。不包含密钥。", handler=tool_config, schema=schema({})),
    dict(name="agentcore_updates_latest", description="读取 agent-core 最新版本更新信息（公开，PFAiX 更新清单）。", handler=tool_updates_latest, schema=schema({})),
    dict(name="agentcore_register_agent", description="注册一个新 agent（POST /api/register，公开）。返回 badge_token 等长期凭据——结果需妥善保管，不要写入日志。", handler=tool_register_agent,
         schema=schema({
             "name": P("string", "姓名（必填）"),
             "department": P("string", "技术部门码（必填）"),
             "company": P("string", "公司（必填）"),
             "project": P("string", "项目，可选"),
             "div": P("string", "业务线，可选"),
             "display_name": P("string", "展示用中文姓名，可选"),
             "department_display": P("string", "展示用部门名，可选"),
         }, ["name", "department", "company"])),
    dict(name="agentcore_register_user", description="注册个人账号（公开）。password 为敏感输入；响应含 badge_token，妥善保管勿入日志。", handler=tool_register_user,
         schema=schema({
             "user_id": P("string", "用户 id（必填）"),
             "password": P("string", "密码（必填）"),
             "display_name": P("string", "展示名，可选"),
             "namespace": P("string", "预置命名空间，仅携带合法 admin_key 时生效"),
             "admin_key": P("string", "管理密钥，可选"),
         }, ["user_id", "password"])),
    dict(name="agentcore_login", description="个人账号登录（公开）。返回 badge_token 与 namespace；凭据敏感，妥善保管。", handler=tool_login,
         schema=schema({
             "user_id": P("string", "用户 id（必填）"),
             "password": P("string", "密码（必填）"),
         }, ["user_id", "password"])),

    # ── 审批 ──
    dict(name="agentcore_approval_pending", description="列出待人工审批项（仅 admin：x-agent-key 须等于 MEMORIA_ADMIN_KEY，即环境变量 AGENTCORE_ADMIN_KEY）。", handler=tool_approval_pending, schema=schema({})),
    dict(name="agentcore_approval_history", description="审批历史（最近 100 条）。任意已注册 agent badge 可读。", handler=tool_approval_history, schema=schema({})),
    dict(name="agentcore_approval_respond", description="对审批项做决定（仅 admin）。approved=true 须 confirm=\"APPROVE\"，false 须 confirm=\"REJECT\"；operation_hash 必须回显审批项的指纹（防操作偷换）。", handler=tool_approval_respond,
         schema=schema({
             "id": P("string", "审批项 id（必填）"),
             "approved": P("boolean", "true=批准执行该工具，false=拒绝（必填）"),
             "operation_hash": P("string", "审批项创建时的操作指纹，必须原样回显（必填）"),
             "reason": P("string", "批准/拒绝理由，可选"),
             "confirm": P("string", "APPROVE 或 REJECT，与 approved 对应（必填）"),
         }, ["id", "approved", "operation_hash", "confirm"])),

    # ── 对话 / 会话 ──
    dict(name="agentcore_chat", description="调用 agent-core 的 agent 完成一轮对话（POST /api/chat）。走完整安全管线：意图分类、工具路由、审批、配额、审计。默认会话 default。", handler=tool_chat,
         schema=schema({
             "message": P("string", "发给 agent 的消息（必填）"),
             "session_id": P("string", "会话 id，默认 default"),
         }, ["message"])),
    dict(name="agentcore_chat_stream", description="流式聊天（GET /api/chat/stream）：消费完整 SSE 后合并返回 reply 文本。适合需要逐字体验但 MCP 阻塞式调用可接受的场景。", handler=tool_chat_stream,
         schema=schema({
             "message": P("string", "发给 agent 的消息（必填）"),
             "session_id": P("string", "会话 id，默认 default"),
         }, ["message"])),
    dict(name="agentcore_sessions", description="列出当前身份可见的会话（最近 50 条，按命名空间隔离）。", handler=_json_handler("GET", "/api/sessions"),
         schema=schema({})),
    dict(name="agentcore_session_load", description="读取指定会话的完整消息历史（仅返回调用方命名空间覆盖的会话）。", handler=_json_handler("GET", "/api/sessions/{id}"),
         schema=schema({"id": P("string", "会话 id（必填）")}, ["id"])),
    dict(name="agentcore_session_delete", description="删除指定会话（破坏性，需 confirm=\"DELETE\"）。服务端仍会校验会话归属。", handler=_json_handler("DELETE", "/api/sessions/{id}", confirm_word="DELETE"),
         schema=schema({
             "id": P("string", "会话 id（必填）"),
             "confirm": P("string", "必须显式传 DELETE"),
         }, ["id", "confirm"])),
    dict(name="agentcore_v1_chat", description="OpenAI 兼容对话（POST /v1/chat/completions，仅非流式）。messages 为 OpenAI 格式数组；agent-core 会折叠 system 与历史。适合把 agent-core 当 LLM 后端调用。", handler=tool_v1_chat,
         schema=schema({
             "messages": P("array", "OpenAI 格式消息数组 [{role, content}]（必填）"),
             "model": P("string", "模型名，可选（默认 agent-core）"),
         }, ["messages"])),

    # ── 运维 / admin ──
    dict(name="agentcore_metrics", description="运行指标快照（/api/metrics）：请求/LLM/错误计数、门控特性触发次数、checkpoint 统计、时延。", handler=_json_handler("GET", "/api/metrics"),
         schema=schema({})),
    dict(name="agentcore_agent_events", description="后台事件队列增量查询（since/limit），用于观测 dream/consolidate 等心跳。", handler=_json_handler("GET", "/api/agent/events", query_fields=[("since", "since"), ("limit", "limit")]),
         schema=schema({
             "since": P("integer", "事件 id 游标，默认 0"),
             "limit": P("integer", "条数 1-200，默认 50"),
         })),
    dict(name="agentcore_save_config", description="保存 agent-core 基础配置（agent_id/api_key/server）。破坏性写配置：需 confirm=\"SAVE\"；api_key 为敏感输入；服务端已配置后要求鉴权。", handler=_json_handler("POST", "/api/save-config", body_fields=[("agent_id", "agent_id"), ("api_key", "api_key"), ("server", "server")], confirm_word="SAVE"),
         schema=schema({
             "agent_id": P("string", "agent 标识（必填）"),
             "api_key": P("string", "LLM API key（必填，敏感）"),
             "server": P("string", "Memoria 地址，可选"),
             "confirm": P("string", "必须显式传 SAVE"),
         }, ["agent_id", "api_key", "confirm"])),
    dict(name="agentcore_admin_degrade", description="查看降级收缩状态（仅 admin）：MCP 源健康、降级模式、killswitch 状态。", handler=_json_handler("GET", "/api/admin/degrade", admin=True),
         schema=schema({})),
    dict(name="agentcore_admin_killswitch", description="切换全局 killswitch（仅 admin，破坏性：true=全局禁用工具调用，需 confirm=\"KILL\"）。", handler=_json_handler("POST", "/api/admin/killswitch", admin=True, body_fields=[("enabled", "enabled")], confirm_word="KILL"),
         schema=schema({
             "enabled": P("boolean", "true=拉闸，false=恢复（必填）"),
             "confirm": P("string", "必须显式传 KILL"),
         }, ["enabled", "confirm"])),
    dict(name="agentcore_admin_quota_get", description="查看命名空间配额用量（仅 admin）。", handler=_json_handler("GET", "/api/admin/quota", admin=True),
         schema=schema({})),
    dict(name="agentcore_admin_quota_put", description="临时调整某命名空间配额策略（仅 admin）。三个限制项至少提供一个。", handler=_json_handler("PUT", "/api/admin/quota", admin=True, body_fields=[("namespace", "namespace"), ("max_tool_rounds", "max_tool_rounds"), ("daily_token_budget", "daily_token_budget"), ("max_concurrent_sessions", "max_concurrent_sessions")]),
         schema=schema({
             "namespace": P("string", "命名空间（必填）"),
             "max_tool_rounds": P("integer", "每日工具轮次上限，可选"),
             "daily_token_budget": P("integer", "每日 token 预算，可选"),
             "max_concurrent_sessions": P("integer", "并发会话上限，可选"),
         }, ["namespace"])),
    dict(name="agentcore_admin_audit", description="审计事件只读查询（仅 admin）：支持 trace_id / event 过滤，敏感字段已脱敏。", handler=_json_handler("GET", "/api/admin/audit", admin=True, query_fields=[("trace_id", "trace_id"), ("event", "event"), ("limit", "limit")]),
         schema=schema({
             "trace_id": P("string", "按链路 id 过滤，可选"),
             "event": P("string", "按事件类型过滤，可选"),
             "limit": P("integer", "条数，默认 50 上限 500"),
         })),
    dict(name="agentcore_admin_consolidate", description="手动触发记忆巩固 Dream（仅 admin）。body 可指定 namespaces，默认按环境变量/自身命名空间；随后可选触发元进化（受 CONSOLIDATE_SKIP_META 控制）。", handler=_json_handler("POST", "/api/admin/consolidate", admin=True, body_fields=[("namespaces", "namespaces")], timeout_secs=600),
         schema=schema({"namespaces": P("array", "要巩固的命名空间数组，可选")})),
    dict(name="agentcore_admin_harness_activate", description="批准并激活待审批的 Harness 蒸馏模板（仅 admin，破坏性：含危险工具模板须人工批准，需 confirm=\"ACTIVATE\"）。", handler=_json_handler("POST", "/api/admin/harness/activate", admin=True, body_fields=[("id", "id")], confirm_word="ACTIVATE"),
         schema=schema({"id": P("integer", "Harness 模板 id（必填）")}, ["id"])),
    dict(name="agentcore_agent_repair", description="修复已注册 agent 的协作档案（admin）：更新 display_name / namespace / permission，不更换 badge_token。", handler=_json_handler("POST", "/api/admin/agent/repair", admin=True, body_fields=[("agent_id", "agent_id"), ("department", "department"), ("project", "project"), ("display_name", "display_name"), ("department_display", "department_display"), ("permission", "permission")]),
         schema=schema({
             "agent_id": P("string", "要修复的 agent_id（必填）"),
             "department": P("string", "技术部门码，可选"),
             "project": P("string", "项目，可选"),
             "display_name": P("string", "展示姓名，可选"),
             "department_display": P("string", "展示部门名，可选"),
             "permission": P("string", "权限，可选"),
         }, ["agent_id"])),

    # ── 协作 A2A ──
    dict(name="agentcore_collab_inbox", description="协作收件箱（A2A）：按 type/scope 过滤、分页、未读计数，可选 mark_seen。", handler=_json_handler("GET", "/api/collab/inbox", query_fields=[("types", "types"), ("scopes", "scopes"), ("page", "page"), ("limit", "limit"), ("mark_seen", "mark_seen")]),
         schema=schema({
             "types": P("string", "逗号分隔类型白名单，可选"),
             "scopes": P("string", "逗号分隔 scope 白名单（org,dept,proj,agent），可选"),
             "page": P("integer", "页码，从 0 开始"),
             "limit": P("integer", "每页 1-200"),
             "mark_seen": P("string", "传 1/true 表示读后标记已读"),
         })),
    dict(name="agentcore_collab_send", description="向其他 agent 发送 A2A 协作消息。scope=agent 需 to_agent；scope=org/dept/proj 按命名空间可达策略 fan-out；type 白名单 query|query_result|notify|announcement|approval_request|message。", handler=_json_handler("POST", "/api/collab/send", body_fields=[("to_agent", "to_agent"), ("scope", "scope"), ("scope_id", "scope_id"), ("type", "type"), ("subject", "subject"), ("body", "body"), ("payload", "payload"), ("thread_id", "thread_id")]),
         schema=schema({
             "scope": P("string", "org|dept|proj|agent（必填）"),
             "to_agent": P("string", "单点收件人 agent_id（scope=agent 必填）"),
             "scope_id": P("string", "org 公司根 / dept 部门名 / proj 项目名"),
             "type": P("string", "信封类型（必填）"),
             "subject": P("string", "主题（必填）"),
             "body": P("string", "正文（必填）"),
             "payload": P("object", "结构化载荷，可选"),
             "thread_id": P("string", "关联线程 id，可选"),
         }, ["scope", "type", "subject", "body"])),
    dict(name="agentcore_collab_approval", description="响应收件箱中的 approval_request 协作审批。decision=approve 须 confirm=\"APPROVE\"，reject 须 confirm=\"REJECT\"；A2A 路径强制校验 operation_hash（本地 L2 项由 admin 兜底）。", handler=tool_collab_approval,
         schema=schema({
             "id": P("string", "待响应消息 id（必填）"),
             "decision": P("string", "approve|reject（必填）"),
             "reason": P("string", "理由，可选"),
             "operation_hash": P("string", "操作指纹，A2A 路径必填"),
             "confirm": P("string", "与 decision 对应：APPROVE 或 REJECT（必填）"),
         }, ["id", "decision", "confirm"])),
    dict(name="agentcore_collab_delete", description="删除收件箱中的一条消息（通知清理）。", handler=_json_handler("POST", "/api/collab/delete", body_fields=[("id", "id")]),
         schema=schema({"id": P("string", "消息 id（必填）")}, ["id"])),
    dict(name="agentcore_collab_peers", description="协作通讯录：按公司范围列出可通信的 agent peers。", handler=_json_handler("GET", "/api/collab/peers"),
         schema=schema({})),

    # ── 分身 ──
    dict(name="agentcore_persona_create", description="运行时创建分身。owner 由鉴权身份推导（请求体无法伪造）；可设工具白名单、专属记忆命名空间、专属 LLM。", handler=_json_handler("POST", "/api/persona", body_fields=[("persona_id", "persona_id"), ("display_name", "display_name"), ("is_private", "is_private"), ("tool_allowlist", "tool_allowlist"), ("memory_namespace", "memory_namespace"), ("llm", "llm")]),
         schema=schema({
             "persona_id": P("string", "分身 id，不能为 default（必填）"),
             "display_name": P("string", "展示名，默认同 id"),
             "is_private": P("boolean", "是否私有，默认 false"),
             "tool_allowlist": P("array", "工具白名单数组，空=不限制"),
             "memory_namespace": P("string", "专属记忆命名空间"),
             "llm": P("object", "专属 LLM 配置对象"),
         }, ["persona_id"])),
    dict(name="agentcore_persona_list", description="列出当前身份可见的分身（公开/拥有者/admin）。", handler=_json_handler("GET", "/api/persona"),
         schema=schema({})),
    dict(name="agentcore_persona_get", description="查看单个分身详情（含目标栈；私有分身仅拥有者/admin 可见）。", handler=_json_handler("GET", "/api/persona/{id}"),
         schema=schema({"id": P("string", "分身 id（必填）")}, ["id"])),
    dict(name="agentcore_persona_delete", description="删除分身（破坏性，需 confirm=\"DELETE\"）。私有分身仅拥有者/admin 可删。", handler=_json_handler("DELETE", "/api/persona/{id}", confirm_word="DELETE"),
         schema=schema({
             "id": P("string", "分身 id（必填）"),
             "confirm": P("string", "必须显式传 DELETE"),
         }, ["id", "confirm"])),
    dict(name="agentcore_persona_goal_push", description="给分身压入一个目标，驱动其真实 tick 执行。", handler=_json_handler("POST", "/api/persona/{id}/goal", body_fields=[("goal", "goal")]),
         schema=schema({
             "id": P("string", "分身 id（必填）"),
             "goal": P("string", "目标描述（必填）"),
         }, ["id", "goal"])),
    dict(name="agentcore_session_persona_bind", description="把会话绑定到某分身（之后该会话以分身身份/白名单/记忆运行）。", handler=_json_handler("POST", "/api/session/persona", body_fields=[("session_id", "session_id"), ("persona_id", "persona_id")]),
         schema=schema({
             "session_id": P("string", "会话 id（必填）"),
             "persona_id": P("string", "分身 id（必填）"),
         }, ["session_id", "persona_id"])),

    # ── 会议 / 圆桌 ──
    dict(name="agentcore_meetings_list", description="列出当前身份可见的圆桌会议（含消息与共识）。", handler=_json_handler("GET", "/api/meetings"),
         schema=schema({})),
    dict(name="agentcore_meeting_delete", description="删除会议（破坏性，需 confirm=\"DELETE\"）。私有会议仅拥有者/admin 可删；不存在与无权统一 403。", handler=_json_handler("DELETE", "/api/meetings/{id}", confirm_word="DELETE"),
         schema=schema({
             "id": P("string", "会议 id（必填）"),
             "confirm": P("string", "必须显式传 DELETE"),
         }, ["id", "confirm"])),
    dict(name="agentcore_meeting_message", description="以真人身份向会议发言；发言会 A2A 投递给其余 participant_agents 收件箱。发言身份强制绑定鉴权 caller。", handler=_json_handler("POST", "/api/meetings/{id}/message", body_fields=[("content", "content")]),
         schema=schema({
             "id": P("string", "会议 id（必填）"),
             "content": P("string", "发言内容（必填）"),
         }, ["id", "content"])),
    dict(name="agentcore_meeting_end", description="结束会议并回填共识。请求者身份绑定鉴权 caller；consensus 可选。", handler=_json_handler("POST", "/api/meetings/{id}/end", body_fields=[("consensus", "consensus")]),
         schema=schema({
             "id": P("string", "会议 id（必填）"),
             "consensus": P("string", "共识文本，可选"),
         }, ["id"])),
    dict(name="agentcore_meeting_heartbeat", description="会议在线心跳：返回 15 秒内在线的参会者列表。", handler=_json_handler("POST", "/api/meetings/{id}/heartbeat"),
         schema=schema({"id": P("string", "会议 id（必填）")}, ["id"])),
    dict(name="agentcore_roundtable", description="发起多分身圆桌（POST /api/roundtable，SSE 直到 done）：各分身表态 → 主席收敛共识 → 最佳努力写 Memoria。支持 personas 筛选、visibility、scope、真人 participants。", handler=tool_roundtable,
         schema=schema({
             "topic": P("string", "议题（必填）"),
             "chair": P("string", "主席分身 id，默认 default"),
             "session_id": P("string", "会话 id，可选"),
             "personas": P("array", "参与分身 id 数组，空=全部"),
             "visibility": P("string", "public 或省略（默认私有）"),
             "scope": P("string", "dept:<id> / org:<company>，可选"),
             "participants": P("array", "真人参会 agent_id 数组"),
         }, ["topic"])),
    dict(name="agentcore_documents_archive", description="把本机文件归档到部门共享文档（Memoria /api/documents）。path 须为本机绝对路径；仅允许 pdf/docx/xlsx/xls 等白名单扩展名。", handler=_json_handler("POST", "/api/documents/archive", body_fields=[("path", "path"), ("filename", "filename"), ("namespace", "namespace")]),
         schema=schema({
             "path": P("string", "本机绝对文件路径（必填）"),
             "filename": P("string", "归档文件名，默认取路径文件名"),
             "namespace": P("string", "目标命名空间，默认固废部门共享 ns"),
         }, ["path"])),

    # ── 记忆反馈 / 进化 ──
    dict(name="agentcore_memory_feedback", description="向 agent-core 的 agent 写记忆反馈（importance=5, confidence=85）。kind=preference 立偏好/规矩（tag 可加 hard_rule|pref|style）；decision 记决策；affirm 表肯定。这是写给 agent-core 的 agent，不是 dsh 自己的记忆库。", handler=tool_memory_feedback,
         schema=schema({
             "kind": P("string", "preference|decision|affirm（必填）"),
             "content": P("string", "反馈正文（必填）"),
             "tag": P("string", "可选 tag"),
             "namespace": P("string", "目标命名空间，默认 agent/{agent_id}"),
         }, ["kind", "content"])),
    dict(name="agentcore_meta_evolution_status", description="查询记忆元进化状态：enabled / approval_mode / prompt hash / 样本数 / 上次运行时间 / 参数。只读。", handler=tool_meta_evolution_status, schema=schema({})),
    dict(name="agentcore_meta_evolution_run", description="手动触发一轮记忆元进化。status=skipped 表示被开关/限流跳过（不是错误），要原样解释 reason。", handler=tool_meta_evolution_run,
         schema=schema({"namespace": P("string", "目标命名空间，默认 agent/{agent_id}")})),
    dict(name="agentcore_code_evolve_dry_run", description="对隔离仓库目标函数跑代码进化并只出 diff（apply=false，服务端自动 revert）。安全默认入口：veto 事件携带 diff 供人审。需 AGENTCORE_EVOLVE_KEY。", handler=tool_code_evolve_dry_run,
         schema=schema({
             "target_path": P("string", "隔离仓库内目标源文件路径（必填）"),
             "fn_name": P("string", "函数名，默认 agent.toml 配置"),
             "generations": P("integer", "代数，默认 agent.toml 配置", minimum=1),
             "goal": P("string", "优化目标说明"),
         }, ["target_path"])),
    dict(name="agentcore_code_evolve_apply", description="代码进化并允许提交（apply=true）。必须先 dry-run 人审 diff，再传 confirm=\"APPLY\"；真正落盘仍受 allow_commit 双闸保护。", handler=tool_code_evolve_apply,
         schema=schema({
             "target_path": P("string", "隔离仓库内目标源文件路径（必填）"),
             "fn_name": P("string", "函数名"),
             "generations": P("integer", "代数", minimum=1),
             "goal": P("string", "优化目标说明"),
             "confirm": P("string", "必须显式传 APPLY"),
         }, ["target_path", "confirm"])),

    dict(name="agentcore_tool_execute", description="业务工具执行网关（唯一合法业务工具通道）：提交工具调用给 agent-core 治理管线（鉴权/边界/审批/配额/审计，无 LLM）。三态：executed(直接返回结果)/pending_approval(202，需 PFAiX 审批台人工批准后轮询)/错误。问业务数据（入厂车次/吨位/库存等）一律用本工具。", handler=tool_tool_execute,
         schema=schema({
             "tool": P("string", "工具名，如 query_entrance（必填）"),
             "arguments": P("object", "工具参数对象", additional_properties=True),
             "persona_id": P("string", "分身 id，默认 default"),
             "session_id": P("string", "会话归属，默认 gateway/{caller}"),
             "trace_id": P("string", "链路追踪 id，缺省网关生成"),
             "idempotency_key": P("string", "写类幂等键"),
         }, ["tool"])),
    dict(name="agentcore_tool_execute_status", description="查询网关执行终态：审批单批准/拒绝后轮询执行结果（executed/denied/failed）。", handler=tool_tool_execute_status,
         schema=schema({
             "execution_id": P("string", "执行 id（ex_...，必填）"),
         }, ["execution_id"])),
]


# ── D5 白名单强制点：AGENTCORE_EXPOSE_ADMIN=0 时对 dsh 槽位隐藏 admin/审批决定工具 ──
# 不靠提示词自律——tools/list 直接不含，隐藏项调用也拒绝。
ADMIN_HIDDEN_TOOLS = {
    "agentcore_approval_respond",
    "agentcore_collab_approval",
    "agentcore_admin_degrade",
    "agentcore_admin_killswitch",
    "agentcore_admin_quota_put",
    "agentcore_admin_audit",
    "agentcore_admin_consolidate",
    "agentcore_admin_harness_activate",
    "agentcore_agent_repair",
    "agentcore_meta_evolution_run",
    "agentcore_code_evolve_apply",
    "agentcore_register_agent",
    "agentcore_save_config",
}


def admin_hidden() -> bool:
    return env("AGENTCORE_EXPOSE_ADMIN") == "0"


def visible_tools() -> list:
    if admin_hidden():
        return [t for t in TOOLS if t["name"] not in ADMIN_HIDDEN_TOOLS]
    return TOOLS


TOOL_HANDLERS = {spec["name"]: spec["handler"] for spec in TOOL_SPECS}
TOOLS = [
    {"name": spec["name"], "description": spec["description"], "inputSchema": spec["schema"]}
    for spec in TOOL_SPECS
]


# ── MCP JSON-RPC 处理 ───────────────────────────────────────────────────


def rpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def rpc_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_initialize(req_id, params):
    # params 可能是任意 JSON 值；非 object 按空处理避免 .get 崩溃（review 指正）
    if not isinstance(params, dict):
        params = {}
    client_protocol = str((params or {}).get("protocolVersion") or "")
    protocol = client_protocol if client_protocol in SUPPORTED_PROTOCOLS else "2024-11-05"
    return rpc_result(req_id, {
        "protocolVersion": protocol,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    })


def handle_tools_list(req_id):
    return rpc_result(req_id, {"tools": visible_tools()})


def handle_tools_call(req_id, params):
    # params 可能是任意 JSON 值（array/string/...），非 object 时按空处理避免 .get 崩溃
    if not isinstance(params, dict):
        params = {}
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        arguments = {}
    if admin_hidden() and name in ADMIN_HIDDEN_TOOLS:
        return rpc_result(req_id, {
            "content": [{"type": "text", "text": "tool %s is hidden on this mount (AGENTCORE_EXPOSE_ADMIN=0)" % name}],
            "isError": True,
        })
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return rpc_result(req_id, {
            "content": [{"type": "text", "text": "unknown tool: %s" % name}],
            "isError": True,
        })
    try:
        payload = handler(arguments)
        return rpc_result(req_id, {
            "content": [{
                "type": "text",
                "text": json.dumps(payload, ensure_ascii=False, indent=2),
            }],
            "isError": False,
        })
    except ToolError as e:
        return rpc_result(req_id, {
            "content": [{"type": "text", "text": "ERROR: %s" % e}],
            "isError": True,
        })
    except Exception as e:  # noqa: BLE001
        log("tool %s unexpected error: %r" % (name, e))
        return rpc_result(req_id, {
            "content": [{"type": "text", "text": "INTERNAL ERROR: %s" % e}],
            "isError": True,
        })


def dispatch(req):
    # JSON-RPC 帧必须是 JSON object；合法 JSON 可能是数组/标量 → 拒绝而非崩溃
    # （review 指正：json.loads 成功 ≠ dict，main() 只 try 了 loads 没包 dispatch）
    if not isinstance(req, dict):
        return rpc_error(None, -32600, "invalid request: JSON-RPC frame must be an object")
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params")

    if method == "initialize":
        return handle_initialize(req_id, params)
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return rpc_result(req_id, {})
    if method == "tools/list":
        return handle_tools_list(req_id)
    if method == "tools/call":
        return handle_tools_call(req_id, params)
    if req_id is None:
        return None
    return rpc_error(req_id, -32601, "unsupported method: %s" % method)


def main():
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:  # noqa: BLE001
            log("stdin parse error: %r" % (e,))
            # 非法帧也要回 JSON-RPC Parse error（-32700），否则客户端会干等（review 指正）
            sys.stdout.write(json.dumps(rpc_error(None, -32700, "Parse error"), ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue
        resp = dispatch(req)
        if resp is None:
            continue
        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)
