#!/usr/bin/env python3
"""PFAiX Personal Assistant Platform Phase 0 local smoke test.

Only accesses the loopback agent-core service. Creates two synthetic assistant
bindings, verifies scoped-token heartbeat, A2A task/inbox/status persistence,
Memory Proxy source injection, platform events, and binding revocation.
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
# 冒烟脚本只允许访问本机 agent-core；CLI base-url 不能变成任意 SSRF 目标。
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


def create_binding(base: str, admin_key: str, kind: str, suffix: str) -> tuple[dict, str]:
    status, payload = request(
        "POST",
        base + "/api/assistants/bindings",
        admin_key=admin_key,
        body={
            "assistant_type": "synthetic-" + kind,
            "assistant_name": f"Phase0 {kind} {suffix}",
            "device_id": f"phase0-{kind}-{suffix}",
            "capabilities": ["phase0.smoke"],
            "scopes": [
                "assistant:heartbeat",
                "memory:read:self",
                "memory:write:self",
                "a2a:send",
                "a2a:receive",
            ],
            "public_key": "",
        },
    )
    expect(status == 201, f"create {kind} binding -> {status}")
    binding = payload["binding"]
    token = payload["token"]["access_token"]
    expect(bool(binding["binding_id"]), "binding_id returned")
    expect(bool(token), "opaque scoped token returned")
    expect("memory:write:self" in binding["scopes"], "memory self scope granted")
    return binding, token


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:9753")
    parser.add_argument("--skip-memory", action="store_true")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    # 先统一校验，后续所有 request 只在这个受控 base 下拼接路径。
    validate_url(base + "/health")
    admin_key = load_admin_key()
    suffix = f"{int(time.time())}-{int(time.time() * 1000) % 1_000_000:06d}"

    source: tuple[dict, str] | None = None
    target: tuple[dict, str] | None = None
    try:
        status, health = request("GET", base + "/health")
        expect(status == 200 and health.get("status") in (None, "ok"), "agent-core health 200")

        source = create_binding(base, admin_key, "source", suffix)
        target = create_binding(base, admin_key, "target", suffix)

        status, _ = request("POST", base + "/api/assistants/heartbeat", token=source[1])
        expect(status == 200, "source heartbeat 200")

        status, payload = request(
            "POST",
            base + "/api/a2a/tasks",
            token=source[1],
            body={
                "target_binding": target[0]["binding_id"],
                "task_type": "phase0-smoke",
                "subject": "Phase0 A2A persistence",
                "body": "Verify task/inbox/status persistence.",
            },
        )
        expect(status == 201, f"A2A task created -> {status}")
        task = payload["task"]
        task_id = task["task_id"]
        expect(task["status"] == "queued", "task initial status queued")

        status, payload = request("GET", base + "/api/a2a/inbox", token=target[1])
        expect(status == 200, "target inbox read")
        messages = payload.get("messages", [])
        expect(any(m.get("task_id") == task_id for m in messages), "task delivered to inbox")

        status, payload = request(
            "POST",
            base + f"/api/a2a/tasks/{task_id}/status",
            token=target[1],
            body={"status": "working"},
        )
        expect(status == 200 and payload["task"]["status"] == "working", "task -> working")
        status, payload = request(
            "POST",
            base + f"/api/a2a/tasks/{task_id}/status",
            token=target[1],
            body={"status": "completed", "result": "phase0 ok"},
        )
        expect(status == 200 and payload["task"]["status"] == "completed", "task -> completed")

        if not args.skip_memory:
            marker = f"Phase0 Memory Proxy smoke {suffix}"
            status, payload = request(
                "POST",
                base + "/api/agent/memory",
                token=source[1],
                body={
                    "content": marker,
                    "memory_type": "episodic",
                    "category": "assistant_phase0_smoke",
                    "importance": 2,
                    "tags": ["phase0", "smoke"],
                },
            )
            expect(status == 200, f"Memory Proxy write -> {status}")
            expect(payload.get("namespace") == "agent/admin", "server-side namespace injected")
            expect(payload.get("source") == "synthetic-source", "server-side source injected")
            context_url = base + "/api/agent/context?q=" + urllib.parse.quote(marker) + "&limit=3"
            status, _ = request("GET", context_url, token=source[1])
            expect(status == 200, "Memory Proxy context read")

        status, payload = request("GET", base + "/api/assistants/events", admin_key=admin_key)
        expect(status == 200, "assistant events readable")
        events = payload.get("events", [])
        expect(any(e.get("event_type") == "assistant.binding.created" for e in events), "binding audit event found")
        expect(any(e.get("event_type") == "a2a.task.created" for e in events), "task audit event found")

        status, payload = request(
            "POST",
            base + f"/api/assistants/bindings/{source[0]['binding_id']}/revoke",
            admin_key=admin_key,
        )
        expect(status == 200 and payload["binding"]["status"] == "revoked", "source binding revoked")
        status, _ = request("POST", base + "/api/assistants/heartbeat", token=source[1])
        expect(status == 401, "revoked token rejected")

        print("\nPHASE0_SMOKE_PASS")
        return 0
    finally:
        for item in (source, target):
            if not item:
                continue
            try:
                request(
                    "POST",
                    base + f"/api/assistants/bindings/{item[0]['binding_id']}/revoke",
                    admin_key=admin_key,
                )
            except Exception:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PHASE0_SMOKE_FAIL: {exc}", file=sys.stderr)
        raise
