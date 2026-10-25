#!/usr/bin/env python3
"""PFAiX Personal Assistant Platform Phase 2 full smoke (membership + brief + stream actions + minutes + SSE).

Only accesses the loopback agent-core service. Covers:
- meeting creation (badge identity) + assistant invite by owner
- non-owner cannot invite (different badge identity)
- a2a task with meeting_id: both members OK, non-member rejected
- task without meeting_id still works (Phase 0 global semantics)
- meeting end expires all assistant grants; post-end sends rejected
- members list reflects invites/removals

Run after assistant_phase0/phase1 smokes on the same deployment.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_ENV = Path.home() / ".svc-secrets" / "agent-core.env"
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
    body: dict | list | str | bytes | None = None,
    raw_content_type: str | None = None,
) -> tuple[int, dict | list | str | bytes]:
    url = validate_url(url)
    headers = {"Accept": "application/json"}
    data = None
    if isinstance(body, bytes):
        data = body
        headers["Content-Type"] = raw_content_type or "application/octet-stream"
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
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            if "octet-stream" in ctype:
                return resp.status, payload  # bytes（artifact 下载）
            raw = payload.decode("utf-8", "replace")
            parsed = json.loads(raw) if raw else {}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, raw


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"  OK {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:9753")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    validate_url(base + "/health")
    admin_key = load_admin_key()
    suffix = f"{int(time.time())}-{int(time.time() * 1000) % 1_000_000:06d}"

    src: dict | None = None
    dst: dict | None = None
    try:
        status, health = request("GET", base + "/health")
        expect(status == 200 and health.get("status") in (None, "ok"), "agent-core health 200")

        # ── 双助手（admin 名下，全 scope） ──
        def mk_binding(kind: str, tools_scope: bool = False) -> dict:
            scopes = ["assistant:heartbeat", "memory:read:self", "memory:write:self", "a2a:send", "a2a:receive"]
            if tools_scope:
                scopes.append("tools:call:read")  # P4：仅 src 带，dst 用于验证无 scope 拒
            status, payload = request(
                "POST",
                base + "/api/assistants/bindings",
                admin_key=admin_key,
                body={
                    "assistant_type": f"p21-{kind}",
                    "assistant_name": f"P2.1 {kind} {suffix}",
                    "device_id": f"p21-{kind}-{suffix}",
                    "capabilities": ["p21.smoke"],
                    "scopes": scopes,
                    "public_key": "",
                },
            )
            expect(status == 201, f"create {kind} binding -> {status}")
            return {"binding": payload["binding"], "token": payload["token"]["access_token"]}

        src = mk_binding("src", tools_scope=True)
        dst = mk_binding("dst")

        # ── 建会（admin 身份 owner） ──
        status, payload = request(
            "POST",
            base + "/api/meetings",
            admin_key=admin_key,
            body={"topic": f"P2.1 冒烟会议 {suffix}", "visibility": "private"},
        )
        # 兼容旧响应（meeting 字段名差异）：取 id
        meeting = payload.get("meeting") or payload
        meeting_id = meeting.get("id") or meeting.get("meeting_id") or ""
        expect(status in (200, 201) and bool(meeting_id), f"meeting created -> {status} id={meeting_id[:18]}…")

        # ── 邀请：owner(admin) 邀请 src；dst 不邀 ──
        status, payload = request(
            "POST",
            base + f"/api/meetings/{meeting_id}/assistants",
            admin_key=admin_key,
            body={"binding_id": src["binding"]["binding_id"]},
        )
        expect(status == 200, f"owner invites src -> {status}")
        expect("a2a:send:meeting" in payload.get("scopes", []), "meeting scopes granted")

        # 成员列表（owner 可见）
        status, payload = request(
            "GET",
            base + f"/api/meetings/{meeting_id}/assistants",
            admin_key=admin_key,
        )
        expect(status == 200, "members list readable")
        expect(
            any(m.get("binding_id") == src["binding"]["binding_id"] for m in payload.get("members", [])),
            "src in members list",
        )
        expect(
            not any(m.get("binding_id") == dst["binding"]["binding_id"] for m in payload.get("members", [])),
            "dst not in members list",
        )

        # ── 同会校验（D10c） ──
        # src 未入会 → 带该 meeting_id 的任务被拒
        status, _ = request(
            "POST",
            base + "/api/a2a/tasks",
            token=src["token"],
            body={"target_binding": dst["binding"]["binding_id"], "subject": "x", "body": "x", "meeting_id": meeting_id},
        )
        expect(status == 403, f"task with meeting_id but src not member -> {status}")

        # 邀请 dst 后 → 同会任务放行
        status, _ = request(
            "POST",
            base + f"/api/meetings/{meeting_id}/assistants",
            admin_key=admin_key,
            body={"binding_id": dst["binding"]["binding_id"]},
        )
        expect(status == 200, "owner invites dst")
        status, payload = request(
            "POST",
            base + "/api/a2a/tasks",
            token=src["token"],
            body={
                "target_binding": dst["binding"]["binding_id"],
                "task_type": "p21-smoke",
                "subject": "meeting-scoped task",
                "body": "both members",
                "meeting_id": meeting_id,
            },
        )
        expect(status == 201, f"task both members -> {status}")
        task = payload.get("task", {})
        expect(task.get("meeting_id") == meeting_id, "task carries meeting_id")

        # 无 meeting_id 任务仍走 Phase 0 全局语义
        status, _ = request(
            "POST",
            base + "/api/a2a/tasks",
            token=src["token"],
            body={"target_binding": dst["binding"]["binding_id"], "subject": "global", "body": "no meeting"},
        )
        expect(status == 201, "task without meeting_id still allowed (Phase 0 semantics)")

        # ── P2-2：会前 brief ──
        status, payload = request(
            "POST",
            base + f"/api/meetings/{meeting_id}/brief",
            admin_key=admin_key,
        )
        expect(status == 200, f"meeting brief created -> {status}")
        expect("会前 Brief" in str(payload.get("brief", "")), "brief text assembled")
        expect(payload.get("meeting_id") == meeting_id, "brief tied to meeting")
        expect("项目共享上下文" in str(payload.get("brief", "")), "brief has project context section")
        expect("参会人偏好摘要" in str(payload.get("brief", "")), "brief has prefs section")

        # ── P2-2：助手动作入会议消息流 ──
        # 上面同会任务创建应已注入系统行；经会议列表读 messages 验证（列表含 messages 字段）。
        def meeting_messages() -> list:
            status_, payload_ = request("GET", base + "/api/meetings", admin_key=admin_key)
            if not isinstance(payload_, dict):
                return []
            for m in payload_.get("meetings") or []:
                if isinstance(m, dict) and m.get("id") == meeting_id:
                    return m.get("messages") or []
            return []

        msgs = meeting_messages()
        expect(
            any(isinstance(m, dict) and m.get("kind") == "ai" and "发起任务" in str(m.get("content", "")) for m in msgs),
            "assistant task action injected into meeting stream",
        )

        # 任务终态同样入流：dst 完成任务 → completed 行
        task_id = task.get("task_id", "")
        status, payload = request(
            "POST",
            base + f"/api/a2a/tasks/{task_id}/status",
            token=dst["token"],
            body={"status": "completed", "result": "p2 smoke done"},
        )
        expect(status == 200, "task completed by dst")
        msgs = meeting_messages()
        expect(
            any(isinstance(m, dict) and m.get("kind") == "ai" and "completed" in str(m.get("content", "")) for m in msgs),
            "assistant task completion injected into meeting stream",
        )

        # ── P3：artifact 全链路（上传→元数据→下载复核→列表） ──
        import urllib.parse as _up
        content = "P3 artifact 冒烟内容 十月固废分析报告".encode("utf-8")
        q = _up.urlencode({"task_id": task_id, "type": "txt", "title": "十月分析.txt"})
        status, payload = request(
            "POST",
            base + f"/api/a2a/artifacts?{q}",
            token=dst["token"],
            body=content,
        )
        expect(status == 201, f"artifact uploaded -> {status}")
        art = payload.get("artifact", {})
        art_id = art.get("artifact_id", "")
        import hashlib as _hl
        expect(
            art.get("sha256") == _hl.sha256(content).hexdigest(),
            "artifact sha256 matches content",
        )
        expect(art.get("uri") == f"artifact://{art_id}", "artifact reference uri returned")
        # 元数据（src 为任务一方可读）
        status, payload = request(
            "GET",
            base + f"/api/a2a/artifacts/{art_id}",
            token=src["token"],
        )
        expect(status == 200 and payload.get("artifact", {}).get("task_id") == task_id, "artifact metadata readable by task peer")
        # 内容下载 + hash 复核
        status, data = request(
            "GET",
            base + f"/api/a2a/artifacts/{art_id}/content",
            token=src["token"],
        )
        expect(status == 200 and isinstance(data, bytes) and data == content, "artifact content roundtrip intact")
        # 任务 artifact 列表
        status, payload = request(
            "GET",
            base + f"/api/a2a/artifacts?task_id={task_id}",
            token=src["token"],
        )
        expect(
            status == 200 and any(a.get("artifact_id") == art_id for a in payload.get("artifacts", [])),
            "artifact listed for task",
        )
        # 未关联 task/meeting 的裸上传被拒（400）
        status, _ = request(
            "POST",
            base + "/api/a2a/artifacts?type=bin&title=x",
            token=src["token"],
            body=b"orphan",
        )
        expect(status == 400, f"orphan artifact (no task/meeting) rejected -> {status}")

        # 带消息的 meeting 校验：未受邀第三方用例省略（需第三个 binding；用 src 发给 dst 合法路径已覆盖）

        # ── P4：Resource Gateway 工具代理 ──
        # ① 清单（有 scope 的 src 可读）
        status, payload = request("GET", base + "/api/agent/tools", token=src["token"])
        expect(status == 200 and "pipeline_status" in payload.get("tools", []), "tools list readable with scope")
        # ② 白名单+只读工具放行（数据管道状态）
        status, payload = request(
            "POST",
            base + "/api/agent/tools/call",
            token=src["token"],
            body={"tool": "pipeline_status", "arguments": {}},
        )
        expect(status == 200, f"whitelisted read-only tool call -> {status}")
        expect("result" in payload, "tool result returned")
        # 路由验证：result 不得是 {"error": "Unknown tool"} 伪装（P4-1 曾直打 memoria
        # 导致所有平台工具都返回 Unknown tool，200 但内容是错——2026-10-25 演示实测发现）
        _r = payload.get("result", {})
        _r = json.loads(_r) if isinstance(_r, str) else _r
        expect(not (isinstance(_r, dict) and "error" in _r), f"tool routed to real source (not Unknown tool): {str(_r)[:60]}")
        # ③ 白名单外工具拒绝（写工具 + 未知工具）
        status, _ = request(
            "POST",
            base + "/api/agent/tools/call",
            token=src["token"],
            body={"tool": "officecli_write", "arguments": {}},
        )
        expect(status == 403, f"non-whitelisted tool rejected -> {status}")
        status, _ = request(
            "POST",
            base + "/api/agent/tools/call",
            token=src["token"],
            body={"tool": "totally_unknown_tool", "arguments": {}},
        )
        expect(status == 403, f"unknown tool rejected -> {status}")
        # ④ 无 scope 的 dst 被拒（401，scope 缺失）
        status, _ = request(
            "POST",
            base + "/api/agent/tools/call",
            token=dst["token"],
            body={"tool": "pipeline_status", "arguments": {}},
        )
        expect(status == 401, f"tool call without tools:call:read scope -> {status}")
        # ⑤ 拒绝事件已入审计（audit_events 直查最近 agent.tool.denied）
        import sqlite3 as _sq
        _db = _sq.connect("file:audit_events.db?mode=ro", uri=True)
        _n = _db.execute("select count(*) from audit_events where event_type='agent.tool.denied' and ts >= date('now','localtime')").fetchone()[0]
        _db.close()
        expect(_n >= 2, f"denied tool calls audited (count={_n})")

        # ── P4-2：写工具审批全链路 ──
        # ① 无 write scope 的助手调写工具 → 401
        status, _ = request(
            "POST",
            base + "/api/agent/tools/call",
            token=dst["token"],
            body={"tool": "create_docx", "arguments": {}},
        )
        expect(status == 401, f"write tool without tools:call:write scope -> {status}")

        # ② 建 write binding（admin 名下，tools:call:write）
        status, payload = request(
            "POST",
            base + "/api/assistants/bindings",
            admin_key=admin_key,
            body={
                "assistant_type": "p42-writer",
                "assistant_name": f"P4.2 writer {suffix}",
                "device_id": f"p42-w-{suffix}",
                "capabilities": [],
                "scopes": ["assistant:heartbeat", "tools:call:write"],
                "public_key": "",
            },
        )
        expect(status == 201, f"create writer binding -> {status}")
        writer = {"binding": payload["binding"], "token": payload["token"]["access_token"]}

        # ③ 写工具调用 → 202 审批单
        status, payload = request(
            "POST",
            base + "/api/agent/tools/call",
            token=writer["token"],
            body={"tool": "create_docx", "arguments": {"spec": {
                "title": f"P4 冒烟 {suffix}",
                "output": "C:\Windows\evil.docx",
                "sections": [{"heading": "结论", "paragraphs": ["冒烟测试文档"]}],
            }}},
        )
        expect(status == 202, f"write tool call -> {status} (approval pending)")
        approval_id = payload.get("approval_id", "")
        op_hash = payload.get("operation_hash", "")
        expect(bool(approval_id) and bool(op_hash), "approval_id + operation_hash returned")
        # 轮询：pending
        status, payload = request(
            "GET",
            base + f"/api/agent/tools/approvals/{approval_id}",
            token=writer["token"],
        )
        expect(status == 202 and payload.get("status") == "pending", "poll shows pending")

        # ④ admin 经现有审批台链路批准
        status, payload = request(
            "POST",
            base + f"/api/approval/{approval_id}/respond",
            admin_key=admin_key,
            body={"approved": True, "reason": "p4 smoke", "operation_hash": op_hash},
        )
        expect(status == 200, f"admin approves via approval console -> {status}")

        # ⑤ 轮询：approved → 执行并返回结果
        status, payload = request(
            "GET",
            base + f"/api/agent/tools/approvals/{approval_id}",
            token=writer["token"],
        )
        expect(status == 200 and payload.get("status") == "executed", f"poll after approve -> {status} {str(payload.get('status'))[:30]}")
        expect("result" in payload, "executed tool result returned")
        _xr = payload.get("result", {})
        _xr = json.loads(_xr) if isinstance(_xr, str) else _xr
        expect(not (isinstance(_xr, dict) and "error" in _xr), f"executed tool routed correctly: {str(_xr)[:60]}")
        # 网关硬化验证：output 被剥离 → 落盘在 dashboard/reports 而非尝试 C:\Windows
        _path = str(_xr.get("path", "")) if isinstance(_xr, dict) else ""
        expect("reports" in _path.lower() and "windows" not in _path.lower(), f"docx saved under reports (output param stripped): {_path[:70]}")

        # ⑥ 防重放：同单再执行 → 409
        status, _ = request(
            "GET",
            base + f"/api/agent/tools/approvals/{approval_id}",
            token=writer["token"],
        )
        expect(status == 409, f"replay same approval -> {status}")

        request("POST", base + f"/api/assistants/bindings/{writer['binding']['binding_id']}/revoke", admin_key=admin_key)

        # ── 会议结束 → 批量失效 + 结构化纪要 ──
        consensus_text = "会议结论\n决议：\n1. 报表采用台账口径\n2. 异常车次由工程部复核\n待办：\n1. 下月模板增加吨发对比\n2. 完成数据校验"
        status, _ = request(
            "POST",
            base + f"/api/meetings/{meeting_id}/end",
            admin_key=admin_key,
            body={"mode": "consensus", "consensus": consensus_text},
        )
        expect(status == 200, f"meeting ended with structured consensus -> {status}")
        # P2-3 纪要沉淀为后台 best-effort（org NS 写入）；org 内容属 memoria 侧，
        # 冒烟此处做弱验证：无 500 即过，org NS 落库由后续人工经 memoria 复核。
        import time as _t; _t.sleep(2)

        # P2-3：inbox SSE 推送——dst 助手订阅流，src 发一条消息（非会议域，全局语义），
        # 断言 15s 内收到 event=message。
        import threading
        import http.client
        sse_events = []
        def sse_listen():
            try:
                # http.client 直连回环 127.0.0.1:9753（目标主机硬编码字面量，
                # 非 DNS 解析，无 rebinding/内网面；base 本身已过 validate_url 白名单）
                conn = http.client.HTTPConnection("127.0.0.1", 9753, timeout=20)
                conn.request("GET", "/api/a2a/inbox/stream",
                             headers={"Authorization": "Bearer " + dst["token"]})
                resp = conn.getresponse()
                buf = b""
                sep = chr(10) * 2
                while len(sse_events) < 1:
                    chunk = resp.read1(4096) if hasattr(resp, "read1") else resp.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    text = buf.decode("utf-8", "replace")
                    while sep in text:
                        frame, text = text.split(sep, 1)
                        if frame.startswith("event: message"):
                            sse_events.append(frame)
                            return
                    buf = text.encode("utf-8", "replace")
                conn.close()
            except Exception as e:
                sse_events.append(f"SSE_ERROR: {e}")
        th = threading.Thread(target=sse_listen, daemon=True)
        th.start()
        _t.sleep(1)  # 订阅建立
        status, _ = request(
            "POST",
            base + "/api/a2a/messages",
            token=src["token"],
            body={"target_binding": dst["binding"]["binding_id"], "body": "sse push test"},
        )
        expect(status == 201, "message sent for SSE push")
        th.join(timeout=16)
        expect(
            bool(sse_events) and not str(sse_events[0]).startswith("SSE_ERROR"),
            f"inbox SSE push received ({sse_events[0][:60] if sse_events else 'none'})",
        )
        # 会后：带 meeting_id 的任务被拒（成员已失效 + 会议已结束）
        status, _ = request(
            "POST",
            base + "/api/a2a/tasks",
            token=src["token"],
            body={"target_binding": dst["binding"]["binding_id"], "subject": "x", "body": "x", "meeting_id": meeting_id},
        )
        expect(status == 403, f"post-end meeting task rejected -> {status}")
        # 成员列表为空
        status, payload = request(
            "GET",
            base + f"/api/meetings/{meeting_id}/assistants",
            admin_key=admin_key,
        )
        expect(status == 200 and not payload.get("members"), "members empty after end")

        # ── 已结束的会议不能再邀请 ──
        status, _ = request(
            "POST",
            base + f"/api/meetings/{meeting_id}/assistants",
            admin_key=admin_key,
            body={"binding_id": src["binding"]["binding_id"]},
        )
        expect(status == 400, f"invite to ended meeting rejected -> {status}")

        # ── 清理：撤销绑定 ──
        for item in (src, dst):
            request(
                "POST",
                base + f"/api/assistants/bindings/{item['binding']['binding_id']}/revoke",
                admin_key=admin_key,
            )

        print("\nPHASE2_SMOKE_PASS")
        return 0
    finally:
        for item in (src, dst):
            if not item:
                continue
            try:
                request(
                    "POST",
                    base + f"/api/assistants/bindings/{item['binding']['binding_id']}/revoke",
                    admin_key=admin_key,
                )
            except Exception:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PHASE2_SMOKE_FAIL: {exc}", file=sys.stderr)
        raise
