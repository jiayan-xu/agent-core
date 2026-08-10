"""Step3 实时同步 E2E 冒烟：SSE 订阅 → 心跳 → 发言(增量) → 删除(终止广播)。

严格时序：先建立 SSE 订阅并确认收到 snapshot，再依次触发事件，最后断言事件均已抵达。
用法：python scripts/e2e_meeting_step3.py [base_url]

注意（幂等与重跑）：本脚本依赖 meetings.json 中预置的旧格式种子会议 `mtg_e2e_step3`
（phase 键省略，验证 skip_serializing_if 旧数据兼容）。Step5 的 DELETE 会通过
`remove_meeting` + `save_meetings` 把删除持久化到 meetings.json，因此**单次运行会销毁该
种子会议**；重跑前需由外部（harness / CI）重新写入种子（ phase 省略）并重启服务。
脚本本身不负责重置种子，避免与运行实例的内存状态不一致。
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9753").rstrip("/")
MID = "mtg_e2e_step3"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 跨线程共享状态的同步原语：subscribe 守护线程只追加、main 读数，统一在锁保护下操作，
# 杜绝自由线程 / 无 GIL 解释器下的数据竞争（finding: 跨线程共享可变状态无同步）。
_lock = threading.Lock()
events: list[tuple[str, str]] = []  # [(event_name, data_str)]
raw_lines: list[str] = []
stop = threading.Event()


def _append_event(name: str, data: str) -> None:
    with _lock:
        events.append((name, data))


def _append_raw(line: str) -> None:
    with _lock:
        raw_lines.append(line)


def _snapshot_events() -> list[tuple[str, str]]:
    with _lock:
        return list(events)


def _snapshot_raw() -> list[str]:
    with _lock:
        return list(raw_lines)


def agent_key() -> str:
    """取 AGENT_API_KEY，绝不硬编码密钥。

    解析规则与 `start_agent_core.py`（服务端启动器）逐条对齐，否则同一份 .env 会被
    两边解释成不同的值，导致 E2E 拿到与服务实际加载的不一致的 key 而 403：
      - 环境变量**存在即权威**：启动器仅在 `AGENT_API_KEY` 不在 env 时才读 .env；
        故 env 中已设置直接返回、不回退 .env，避免两边解释不一致而 403；
        但**空串视为配置错误**（reviewer round-17 #2）：不返回空 key，立即失败，
        以免带着空 key 跑到 403 才暴露；
      - 按 `=` 首次出现切分，key / value 两侧 strip（支持 `AGENT_API_KEY = xxx`）；
      - value 剥去成对包裹的引号（支持 `AGENT_API_KEY="xxx"` / `'xxx'`）；
      - 跳过空行、`#` 注释行、不含 `=` 的行；utf-8-sig 自动剔除 BOM。
    """
    # env 中存在即权威（与启动器一致），含空值视为配置错误立即失败，不回退 .env
    if "AGENT_API_KEY" in os.environ:
        key = os.environ["AGENT_API_KEY"]
        # reviewer round-17 #2：env 中键存在但值为空串 = 配置错误，应尽早清晰失败，
        # 而非带着空 key 跑到 403 才暴露（与下方 .env 空值分支一致的守卫）。
        if not key:
            print("  !! AGENT_API_KEY 在环境中为空值（配置错误）")
            raise SystemExit(1)
        return key

    path = os.path.join(ROOT, ".env")
    try:
        with open(path, "r", encoding="utf-8-sig") as f:  # utf-8-sig 自动剔除 BOM
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() != "AGENT_API_KEY":
                    continue
                key = v.strip().strip('"').strip("'")
                if key:
                    return key
                # 空值等同于缺失：配置错误应尽早清晰失败，而非带着空 key 跑到 403 才暴露
                print("  !! AGENT_API_KEY 在 .env 中为空值")
                raise SystemExit(1)
    except OSError as e:
        print(f"  !! 无法读取 .env 文件（{path}）：{e}")
        raise SystemExit(1)
    except UnicodeDecodeError as e:
        print(f"  !! .env 文件编码异常（{path}）：{e}")
        raise SystemExit(1)
    print("  !! AGENT_API_KEY 未在环境变量与 .env 中找到")
    raise SystemExit(1)


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
    except urllib.error.URLError as e:
        # 连接被拒 / DNS 失败 / 超时：返回 (0, 错误描述) 由调用方判定 FAIL，而非抛出原始 traceback
        return 0, f"connection_error: {e.reason}"
    except Exception as e:  # noqa: BLE001
        return 0, f"request_error: {e}"


def subscribe():
    try:
        r = urllib.request.Request(f"{BASE}/api/meetings/{MID}/stream", headers=HDR)
        with urllib.request.urlopen(r, timeout=30) as resp:
            # SSE 规范解析（reviewer round-15 #5，bug·high）：
            # axum 0.8 的 Sse 序列化器每个事件块写 wire 格式 `data:{...}\nevent:{name}\n\n`，
            # 即 `data:` **先于** `event:`。若在收到 `data:` 行时就用「上一块的 event 名」立即
            # 派发，会把每个事件的载荷错记到上一个事件名下（snapshot→message、presence→snapshot…）。
            # 正确做法：缓冲当前块的 event/data 字段，在**空行终止符**（`\n\n`）处结算并派发。
            name = None
            data = None
            for bline in resp:
                if stop.is_set():
                    break
                line = bline.decode("utf-8", "replace").rstrip("\r\n")
                _append_raw(line)
                if line == "":
                    # 空行 = 事件块结束：结算当前缓冲的 event/data。
                    # 注意（reviewer round-26 #1，bug·high）：axum 0.8.9 对仅含 comment 的 `: ping`
                    # 心跳块也会先写一行 `data:`（data 为空串），若用 `if data is not None:` 会把
                    # 空 payload 也派发成 `("message", "")` 伪事件——首个 tick 紧接 snapshot 触发，
                    # 步骤4的 wait_for 会因 _kinds() 已含 "message" 立即返回，随后 json.loads("")
                    # 抛 JSONDecodeError，测试**确定性误报 FAIL** 且从未校验真实广播。改为仅当
                    # data **非空**才结算：所有真实事件（snapshot/message/state/ended/presence）
                    # 都携带 JSON data，空串只可能是 comment 块的伪 data:。
                    if data:
                        _append_event(name or "message", data)
                    name, data = None, None
                elif line.startswith("event:"):
                    name = line[6:].strip()
                elif line.startswith("data:"):
                    piece = line[5:].strip()
                    # 多行 data 按 SSE 规范用换行拼接
                    data = f"{data}\n{piece}" if data is not None else piece
            # 流结束（服务端关闭）时若仍有未结算缓冲，一并结算，避免丢最后一个事件。
            # 与上方块结算同一守卫：仅 data 非空才派发（comment 块的伪空 data: 不派发）。
            if data:
                _append_event(name or "message", data)
    except urllib.error.HTTPError as e:
        # 403 等：清晰记录失败并立即打印，由 main 的超时断言判 FAIL，不抛原始 traceback
        _append_raw(f": error {e.code}")
        print(f"  [subscribe] HTTPError {e.code}（期望 200/403，见 main 断言）")
    except urllib.error.URLError as e:
        _append_raw(f": error connection {e.reason}")
        print(f"  [subscribe] 连接错误: {e.reason}")
    except Exception as e:  # noqa: BLE001
        _append_raw(f": error {e}")
        print(f"  [subscribe] 异常: {e}")


def wait_for(pred, timeout=10.0, label=""):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.1)
    print(f"  !! 超时未等到: {label}")
    return False


def _kinds() -> list[str]:
    return [k for k, _ in _snapshot_events()]


def main() -> int:
    t = threading.Thread(target=subscribe, daemon=True)
    t.start()
    ok = True

    print("1) SSE 初始快照")
    got_snap = wait_for(lambda: "snapshot" in _kinds(), 8, "snapshot")
    if not got_snap:
        # 未收到快照时**不**回退到伪造的空快照，而是明确判失败，避免误报成功
        print("   !! 未收到 snapshot，跳过 phase 断言（不回退到伪造空快照）")
        ok = False
    else:
        snap = next((d for k, d in _snapshot_events() if k == "snapshot"), "")
        try:
            snap_obj = json.loads(snap)
            phase = snap_obj.get("phase")
            # 种子会议为旧格式（meetings.json 省略 phase 键）→ 反序列化为 None，
            # 验证 skip_serializing_if 旧数据兼容：快照不含 phase 或值为 null。
            # 断言实际 phase 值而非仅"键缺失"，避免会议改为运行时创建(总带 phase)时误报 PASS。
            assert_no_phase = phase is None
            print(f"   snapshot 收到；phase={phase!r}（旧格式种子应为 None）= {assert_no_phase}")
            ok &= assert_no_phase
        except Exception as e:  # noqa: BLE001
            print(f"   !! snapshot 解析失败: {e}")
            ok = False

    print("2) 心跳鉴权")
    s1, _ = req("POST", f"/api/meetings/{MID}/heartbeat")
    s2, _ = req("POST", "/api/meetings/mtg_fake_zzz/heartbeat")
    print(f"   真实会议={s1}(期望200) 不存在会议={s2}(期望403)")
    ok &= (s1 == 200 and s2 == 403)

    print("3) presence 应包含 agent/admin")
    got_presence = wait_for(
        lambda: any(k == "presence" and "agent/admin" in d for k, d in _snapshot_events()),
        8,
        "presence",
    )
    ok &= got_presence

    print("4) 发言 → message 增量事件")
    s3, b3 = req(
        "POST",
        f"/api/meetings/{MID}/message",
        {"from": "agent/admin", "content": "第一条真人发言"},
    )
    print(f"   POST message -> {s3} {b3}")
    ok &= wait_for(lambda: "message" in _kinds(), 8, "message 事件")
    msg_ev = next((d for k, d in _snapshot_events() if k == "message"), "")
    try:
        p = json.loads(msg_ev)
        is_delta = "message" in p and "messages" not in p
        phase = p.get("phase")
        print(f"   payload 为增量(不含完整历史) = {is_delta}; phase={phase}")
        # phase 推进到 discussing：任一真人发言都推进（reviewer round-17 #7），
        # 且 msg.from 被强制绑定到已认证 caller=agent/admin。若断言失败，
        # 先核对服务是否正常响应发言，勿误判为状态机回归。
        ok &= is_delta and phase == "discussing"
        if phase != "discussing":
            print("   !! phase 未推进到 discussing：请核对种子 mtg_e2e_step3 的 participant_agents"
                  " 是否含 agent/admin（前置条件，见 apply_message）")
        # reviewer round-17 #1：增量广播必须携带刚发的消息本身（内容 + 发送者），
        # 而非仅「有一条 message 事件」——否则订阅端收不到实际发言内容即视为缺陷。
        inner = p.get("message")
        got_msg = (
            isinstance(inner, dict)
            and inner.get("content") == "第一条真人发言"
            and inner.get("from") == "agent/admin"
        )
        print(f"   广播携带发言内容+发送者 = {got_msg}")
        ok &= got_msg
        if not got_msg:
            print("   !! message 增量未携带预期发言（content=第一条真人发言, from=agent/admin）"
                  f"，实际内层: {inner if inner is not None else '(无 message 键)'}")
    except Exception as e:  # noqa: BLE001
        print(f"   !! message payload 解析失败: {e}")
        ok = False

    print("5) 删除 → ended 终止广播")
    s4, b4 = req("DELETE", f"/api/meetings/{MID}")
    print(f"   DELETE -> {s4} {b4}")
    ok &= wait_for(lambda: "ended" in _kinds(), 8, "ended 事件")
    end_ev = next((d for k, d in _snapshot_events() if k == "ended"), "")
    print(f"   ended payload = {end_ev}")
    # 解析 JSON 断言（避免字符串拼接误判；reviewer round-11 F3）
    end_obj: dict = {}
    try:
        end_obj = json.loads(end_ev)
    except Exception as e:  # noqa: BLE001
        print(f"   !! ended payload 解析失败: {e}")
        ok = False
    # 【reviewer round-26 #3 bug·low】仅 try/except 包住 json.loads 不够：若 ended 事件被服务端
    # payload 形状改成了**非对象** JSON（布尔/数组/字符串，甚至 `null`），上面的 try 成功、但
    # 下方 `end_obj.get("deleted")` 会对非 dict 调用 `.get` 抛 AttributeError，以裸 traceback
    # 崩溃脚本，违背「清晰 FAIL 而非异常」的 E2E 诊断目标。故在此显式把解析结果约束为 dict：
    # 非 dict 视为形状不符、降级为 FAIL（并打印诊断），而不是让属性访问抛异常。
    # 注意（reviewer round-26 二轮 #4 bug·low）：不能用 `is not None and not isinstance(...)`——
    # `json.loads("null")` 返回 `None`，会通过该条件让 `end_obj` 保持 `None`，下一行 `.get()`
    # 仍抛 AttributeError。必须**无条件**把所有非 dict（含 null）统一归一为 `{}`。
    if not isinstance(end_obj, dict):
        print(f"   !! ended payload 非对象 JSON（形状不符），实际类型: {type(end_obj).__name__}")
        end_obj = {}
        ok = False
    # 简化为直接比较（reviewer round-19 #5 style·low：bool(x is True) 冗余）
    ok &= end_obj.get("deleted") is True

    print("6) 心跳注释行保活存在")
    has_ping = any(line.startswith(": ping") or line == ":ping" for line in _snapshot_raw())
    print(f"   注释行 ': ping' 存在 = {has_ping}")
    ok &= has_ping

    stop.set()
    print("\n事件序列:", _kinds())
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
