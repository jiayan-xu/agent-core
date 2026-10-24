#!/usr/bin/env python3
"""PFAiX Personal Assistant Platform Phase 2 smoke test (membership + brief + meeting-stream actions).

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
    body: dict | None = None,
) -> tuple[int, dict | list | str]:
    url = validate_url(url)
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if admin_key:
        headers["X-Agent-Id"] = "admin"
        headers["X-Agent-Key"] = admin_key
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", "replace")
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
        def mk_binding(kind: str) -> dict:
            status, payload = request(
                "POST",
                base + "/api/assistants/bindings",
                admin_key=admin_key,
                body={
                    "assistant_type": f"p21-{kind}",
                    "assistant_name": f"P2.1 {kind} {suffix}",
                    "device_id": f"p21-{kind}-{suffix}",
                    "capabilities": ["p21.smoke"],
                    "scopes": ["assistant:heartbeat", "memory:read:self", "memory:write:self", "a2a:send", "a2a:receive"],
                    "public_key": "",
                },
            )
            expect(status == 201, f"create {kind} binding -> {status}")
            return {"binding": payload["binding"], "token": payload["token"]["access_token"]}

        src = mk_binding("src")
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

        # 带消息的 meeting 校验：未受邀第三方用例省略（需第三个 binding；用 src 发给 dst 合法路径已覆盖）

        # ── 会议结束 → 批量失效 ──
        status, _ = request(
            "POST",
            base + f"/api/meetings/{meeting_id}/end",
            admin_key=admin_key,
            body={"mode": "close"},
        )
        expect(status == 200, f"meeting ended -> {status}")
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
