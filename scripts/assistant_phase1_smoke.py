#!/usr/bin/env python3
"""PFAiX Personal Assistant Platform Phase 1 local smoke test.

Only accesses the loopback agent-core service. Covers:
- refresh token rotation (single-use, old access dies)
- visibility policy get/set/whitelist
- assistant directory summary (self view, active-only after revoke)
- handover brief creation (written into personal NS, readable via context)
- governance audit event_type column carries real event names (Custom fix)

Run after assistant_phase0_smoke.py on the same deployment.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_ENV = Path.home() / ".svc-secrets" / "agent-core.env"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
AUDIT_DB = Path(__file__).resolve().parent.parent / "audit_events.db"


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
    parser.add_argument("--skip-memory", action="store_true")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    validate_url(base + "/health")
    admin_key = load_admin_key()
    suffix = f"{int(time.time())}-{int(time.time() * 1000) % 1_000_000:06d}"

    binding: dict | None = None
    try:
        status, health = request("GET", base + "/health")
        expect(status == 200 and health.get("status") in (None, "ok"), "agent-core health 200")

        # ── 1. 绑定（拿全 access+refresh） ──
        status, payload = request(
            "POST",
            base + "/api/assistants/bindings",
            admin_key=admin_key,
            body={
                "assistant_type": "phase1-smoke",
                "assistant_name": f"Phase1 Smoke {suffix}",
                "device_id": f"phase1-{suffix}",
                "capabilities": ["phase1.smoke", "冒烟测试"],
                "scopes": ["assistant:heartbeat", "memory:read:self", "memory:write:self"],
                "public_key": "",
            },
        )
        expect(status == 201, f"create phase1 binding -> {status}")
        binding = payload["binding"]
        access1 = payload["token"]["access_token"]
        refresh1 = payload["token"]["refresh_token"]
        expect(bool(refresh1), "refresh token returned")

        status, _ = request("POST", base + "/api/assistants/heartbeat", token=access1)
        expect(status == 200, "initial access token works")

        # ── 2. refresh 轮换 ──
        status, payload = request(
            "POST",
            base + "/api/assistants/token/refresh",
            body={"refresh_token": refresh1},
        )
        expect(status == 200, f"token refresh -> {status}")
        access2 = payload["token"]["access_token"]
        refresh2 = payload["token"]["refresh_token"]
        expect(access2 != access1 and refresh2 != refresh1, "rotation issues new pair")
        status, _ = request("POST", base + "/api/assistants/heartbeat", token=access1)
        expect(status == 401, "old access token rejected after rotation")
        status, _ = request("POST", base + "/api/assistants/heartbeat", token=access2)
        expect(status == 200, "new access token works")
        status, _ = request(
            "POST",
            base + "/api/assistants/token/refresh",
            body={"refresh_token": refresh1},
        )
        expect(status == 401, "old refresh token replay rejected (single-use)")
        status, _ = request(
            "POST",
            base + "/api/assistants/token/refresh",
            body={"refresh_token": access2},
        )
        expect(status == 401, "access token cannot be used as refresh")

        # ── 3. 可见性 ──
        status, payload = request("GET", base + "/api/assistants/visibility", admin_key=admin_key)
        expect(status == 200 and payload.get("level") in ("dept", "company", "off"), "visibility readable")
        original_level = payload.get("level", "dept")
        status, payload = request(
            "PUT",
            base + "/api/assistants/visibility",
            admin_key=admin_key,
            body={"level": "company"},
        )
        expect(status == 200 and payload["level"] == "company", "visibility set company")
        status, payload = request(
            "PUT",
            base + "/api/assistants/visibility",
            admin_key=admin_key,
            body={"level": "everyone"},
        )
        expect(status == 400, "invalid visibility level rejected")
        status, _ = request(
            "PUT",
            base + "/api/assistants/visibility",
            admin_key=admin_key,
            body={"level": original_level},
        )
        expect(status == 200, "visibility restored")

        # ── 4. 目录摘要（本人视角） ──
        status, payload = request("GET", base + "/api/assistants/directory", admin_key=admin_key)
        expect(status == 200, "assistant directory readable")
        users = payload.get("users", [])
        mine = next((u for u in users if u.get("is_self")), None)
        expect(mine is not None, "directory contains self entry")
        expect(
            any(a.get("assistant_type") == "phase1-smoke" for a in mine.get("assistants", [])),
            "self entry shows active phase1 binding summary",
        )
        expect(
            all("scopes" not in a for u in users for a in u.get("assistants", [])),
            "directory exposes capability summary only (no scopes)",
        )

        # ── 5. 交接 brief ──
        status, payload = request(
            "POST",
            base + "/api/assistants/handover-brief",
            admin_key=admin_key,
        )
        expect(status == 200, f"handover brief created -> {status}")
        expect(payload.get("stored") is True, "brief stored into personal NS")
        expect("助手交接" in str(payload.get("brief", "")), "brief text assembled")
        if not args.skip_memory:
            q = urllib.parse.quote("handover-brief 助手交接")
            status, payload = request(
                "GET",
                base + f"/api/agent/context?q={q}&limit=5",
                token=access2,
            )
            expect(status == 200, "assistant context read after brief")
            expect(
                "助手交接" in json.dumps(payload, ensure_ascii=False),
                "new assistant can retrieve handover brief via context",
            )

        # ── 6. 治理审计 event_type 列真实事件名（Custom 修复验证） ──
        expect(AUDIT_DB.exists(), f"audit_events.db present at {AUDIT_DB}")
        con = sqlite3.connect(f"file:{AUDIT_DB}?mode=ro", uri=True)
        try:
            cur = con.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type='assistant.binding.created' "
                "AND ts >= date('now','localtime','-1 day')"
            )
            expect(cur.fetchone()[0] > 0, "governance audit column has assistant.binding.created")
            cur = con.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type='assistant.token.refreshed' "
                "AND ts >= date('now','localtime','-1 day')"
            )
            expect(cur.fetchone()[0] > 0, "governance audit column has assistant.token.refreshed")
        finally:
            con.close()

        # ── 7. 撤销后目录不再展示 ──
        status, _ = request(
            "POST",
            base + f"/api/assistants/bindings/{binding['binding_id']}/revoke",
            admin_key=admin_key,
        )
        expect(status == 200, "phase1 binding revoked")
        status, payload = request("GET", base + "/api/assistants/directory", admin_key=admin_key)
        mine = next((u for u in payload.get("users", []) if u.get("is_self")), None)
        expect(
            mine is None or all(a.get("assistant_type") != "phase1-smoke" for a in mine.get("assistants", [])),
            "revoked binding no longer in directory",
        )

        print("\nPHASE1_SMOKE_PASS")
        return 0
    finally:
        if binding:
            try:
                request(
                    "POST",
                    base + f"/api/assistants/bindings/{binding['binding_id']}/revoke",
                    admin_key=admin_key,
                )
            except Exception:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PHASE1_SMOKE_FAIL: {exc}", file=sys.stderr)
        raise
