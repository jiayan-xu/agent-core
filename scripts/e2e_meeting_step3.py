"""Step3 实时同步 E2E 冒烟：SSE 订阅 → 心跳 → 发言(增量) → 删除(终止广播)。

严格时序：先建立 SSE 订阅并确认收到 snapshot，再依次触发事件，最后断言事件均已抵达。
用法：python scripts/e2e_meeting_step3.py [base_url]
"""

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9753"
MID = "mtg_e2e_step3"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def agent_key() -> str:
    """从 .env 读取 AGENT_API_KEY，绝不硬编码密钥。"""
    path = os.path.join(ROOT, ".env")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("AGENT_API_KEY="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("AGENT_API_KEY 未在 .env 中找到")


KEY = agent_key()
HDR = {"x-agent-id": "agent/admin", "x-agent-key": KEY}


def req(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = dict(HDR)
    if data:
        headers["content-type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


events = []          # [(event_name, data_str)]
raw_lines = []
stop = threading.Event()


def subscribe():
    r = urllib.request.Request(f"{BASE}/api/meetings/{MID}/stream", headers=HDR)
    with urllib.request.urlopen(r, timeout=30) as resp:
        name = None
        for bline in resp:
            if stop.is_set():
                break
            line = bline.decode("utf-8", "replace").rstrip("\r\n")
            raw_lines.append(line)
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                events.append((name or "message", line[5:].strip()))
                name = None


def wait_for(pred, timeout=10.0, label=""):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.1)
    print(f"  !! 超时未等到: {label}")
    return False


def kinds():
    return [k for k, _ in events]


def main() -> int:
    t = threading.Thread(target=subscribe, daemon=True)
    t.start()
    ok = True

    print("1) SSE 初始快照")
    ok &= wait_for(lambda: "snapshot" in kinds(), 8, "snapshot")
    snap = next((d for k, d in events if k == "snapshot"), "{}")
    assert_no_phase = '"phase"' not in snap
    print(f"   snapshot 收到；旧数据 phase 键省略 = {assert_no_phase}")
    ok &= assert_no_phase

    print("2) 心跳鉴权")
    s1, _ = req("POST", f"/api/meetings/{MID}/heartbeat")
    s2, _ = req("POST", "/api/meetings/mtg_fake_zzz/heartbeat")
    print(f"   真实会议={s1}(期望200) 不存在会议={s2}(期望403)")
    ok &= (s1 == 200 and s2 == 403)

    print("3) presence 应包含 agent/admin")
    got_presence = wait_for(
        lambda: any(k == "presence" and "agent/admin" in d for k, d in events), 8, "presence"
    )
    ok &= got_presence

    print("4) 发言 → message 增量事件")
    s3, b3 = req("POST", f"/api/meetings/{MID}/message",
                 {"from": "agent/admin", "content": "第一条真人发言"})
    print(f"   POST message -> {s3} {b3}")
    ok &= wait_for(lambda: "message" in kinds(), 8, "message 事件")
    msg_ev = next((d for k, d in events if k == "message"), "")
    try:
        p = json.loads(msg_ev)
        is_delta = "message" in p and "messages" not in p
        print(f"   payload 为增量(不含完整历史) = {is_delta}; phase={p.get('phase')}")
        ok &= is_delta and p.get("phase") == "discussing"
    except Exception as e:  # noqa: BLE001
        print(f"   !! message payload 解析失败: {e}")
        ok = False

    print("5) 删除 → ended 终止广播")
    s4, b4 = req("DELETE", f"/api/meetings/{MID}")
    print(f"   DELETE -> {s4} {b4}")
    ok &= wait_for(lambda: "ended" in kinds(), 8, "ended 事件")
    end_ev = next((d for k, d in events if k == "ended"), "")
    print(f"   ended payload = {end_ev}")
    ok &= '"deleted":true' in end_ev.replace(" ", "")

    print("6) 心跳注释行保活存在")
    has_ping = any(line.startswith(": ping") or line == ":ping" for line in raw_lines)
    print(f"   注释行 ': ping' 存在 = {has_ping}")
    ok &= has_ping

    stop.set()
    print("\n事件序列:", kinds())
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
