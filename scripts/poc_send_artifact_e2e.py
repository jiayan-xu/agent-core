#!/usr/bin/env python3
"""通道 A PoC 端到端验证：agent-core /api/chat → LLM → send_artifact (MCP 包装)。

验证目标：agent-core 的现有 MCP client 成功加载 dsh-artifact 移植的
send_artifact 工具，并由 LLM 端到端调用成功（Delivered ... 返回）。
密钥只从 .env 读取，不打印。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AC = "http://127.0.0.1:9753"

def target() -> str:
    # 运行时读取，避免模块导入先于 load_dotenv() 导致读不到 .env 里的值（review 指正）
    return os.environ.get("POC_DELIVERABLE", "test_deliverable.md")


def load_dotenv() -> None:
    path = os.path.join(ROOT, ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def http(method: str, path: str, headers: dict, body=None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(AC + path, data=data, headers=headers, method=method)
    try:
        raw = urllib.request.urlopen(req, timeout=180).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        # 401/502 等在 .read()/json.loads 之前抛 HTTPError，必须在此捕获（review 指正）
        return {"_http": e.code, "_body": e.read().decode("utf-8", "replace")[:300]}
    except Exception as e:  # noqa: BLE001
        return {"_err": str(e)}
    # 非 JSON body 不硬崩，返回可读诊断
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"status": "error", "raw": raw[:300]}


def chat_reply(resp: dict, stage: str) -> str:
    """从 /api/chat 响应提取 reply；传输/HTTP 层失败时显式 FAIL，而非静默当空回复
    （review 指正：不检查 _http/_err 会遮蔽真实的服务/网络故障）。"""
    if not isinstance(resp, dict):
        print("FAIL: %s 非预期响应: %r" % (stage, resp), file=sys.stderr)
        sys.exit(1)
    if "_http" in resp or "_err" in resp:
        print("FAIL: %s 请求失败: %s" % (stage, json.dumps(resp, ensure_ascii=False)), file=sys.stderr)
        sys.exit(1)
    return str(resp.get("reply") or "")


def main() -> None:
    load_dotenv()
    # load_dotenv() 之后才能确定目标路径（评审指正：模块导入时 .env 尚未加载）
    TARGET = target()
    key = os.environ.get("MEMORIA_ADMIN_KEY") or os.environ.get("AGENT_KEY") or ""
    if not key:
        print("missing MEMORIA_ADMIN_KEY", file=sys.stderr)
        sys.exit(2)
    h = {"Content-Type": "application/json", "x-agent-id": "default", "x-agent-key": key}
    # 毫秒级精度，避免同秒并发运行的 session 碰撞（review 指正）
    sid = "poc/send-artifact/" + time.strftime("%H%M%S") + f"{time.time() % 1:07.6f}"[2:5]

    msg = (
        f"请执行写入操作：调用 send_artifact 工具，把已存在的文件 {TARGET} 交付给用户，caption 写 'PoC deliverable'。\n"
        f"不要自己创建文件，直接交付这个已有文件。\n"
        f"重要：必须使用以下 DSML 格式调用工具（这是本系统唯一支持的工具调用格式，"
        f"禁止使用 <tool_calls>、<invoke> 等其他任何标签格式）：\n"
        f"<|DSML|tool_calls>\n"
        f"  <|DSML|invoke name=\"send_artifact\">\n"
        f"    <|DSML|parameter name=\"path\" string=\"true\">{TARGET}</|DSML|parameter>\n"
        f"    <|DSML|parameter name=\"caption\" string=\"true\">PoC deliverable</|DSML|parameter>\n"
        f"  </|DSML|invoke>\n"
        f"</|DSML|tool_calls>\n"
        f"工具调用后，根据工具返回结果简短回复即可。"
    )
    # 第一轮：可能命中「复述确认闸」→ 拿到复述文本
    r1 = http("POST", "/api/chat", h, {"message": msg, "user_id": "poc", "session_id": sid, "stream": False})
    reply1 = chat_reply(r1, "round1 chat")
    print("=== round1 (rephrase gate) ===")
    print(reply1[:200])
    # 第二轮：确认执行（若第一轮已是执行结果则直接判断）
    # rephrase 闸回复以「方向对吗？」等复述确认结尾；用该特征判定，不用过宽的「确认」
    if "方向对吗" in reply1 or "应该支持" in reply1 or "可以吗" in reply1:
        r2 = http("POST", "/api/chat", h, {"message": "确认执行", "user_id": "poc", "session_id": sid, "stream": False})
        reply = chat_reply(r2, "round2 confirm")
    else:
        reply = reply1
    # 第三轮：危险工具审批流（AWAITING_APPROVAL → dashboard 审批台批准 → 再「确认」执行）
    if reply.startswith("AWAITING_APPROVAL"):
        # 1) admin 审批 API 批准（无 x-agent-id，走 admin 通道）
        ah = {"Content-Type": "application/json", "x-agent-key": key}
        pend = http("GET", "/api/approval/pending", ah)
        # pending 查询本身失败（传输层）时显式 FAIL，不静默当「无待批项」（review 指正）
        if "_http" in pend or "_err" in pend:
            print("FAIL: approval/pending 查询失败: %s" % json.dumps(pend, ensure_ascii=False), file=sys.stderr)
            sys.exit(1)
        item = None
        # 三重绑定：tool_name + arguments.path + session_id == sid——
        # 确保批准的是「本次运行」自己的审批项，杜绝 stale/并发项（review 指正）
        for it in (pend.get("items") or []):
            if it.get("tool_name") != "send_artifact":
                continue
            if it.get("session_id") != sid:
                continue
            args = it.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if (args or {}).get("path") == TARGET:
                item = it
                break
        if item:
            # 用 .get() + 校验，stale/legacy 条目缺字段不崩（review 指正）
            item_aid = item.get("approval_id")
            item_hash = item.get("operation_hash")
            if not item_aid or not item_hash:
                print("FAIL: approval item missing approval_id/operation_hash", file=sys.stderr)
                sys.exit(1)
            resp_approve = http(
                "POST",
                f"/api/approval/{item_aid}/respond",
                ah,
                {"approved": True, "reason": "PoC verification", "operation_hash": item_hash},
            )
            # 批准结果不能丢弃：传输层 4xx/5xx、异常、或 200 但应用级失败
            # （如 {"error":"agent not ready"}）都要如实判定（review 指正；参照 sibling）
            if resp_approve.get("_http") or resp_approve.get("_err") or not resp_approve.get("ok"):
                print("FAIL: approval respond error: %s" % json.dumps(resp_approve, ensure_ascii=False))
                sys.exit(1)
            print("=== approved via dashboard API ===")
            # 2) 再「确认」→ pending_action 恢复 → 执行
            r4 = http("POST", "/api/chat", h, {"message": "确认", "user_id": "poc", "session_id": sid, "stream": False})
            reply = chat_reply(r4, "round4 confirm")
        else:
            # 不打印全量 pend（含其它审批项的敏感字段），只打印摘要（review 指正）
            pend_summary = {
                "count": len(pend.get("items") or []),
                "tools": sorted({it.get("tool_name") for it in (pend.get("items") or [])}),
            }
            print("no pending approval item found: %s" % json.dumps(pend_summary, ensure_ascii=False))
    print("=== final reply ===")
    print(reply[:300])
    print("=== verdict ===")
    # 交付文件名随 TARGET 动态变化（不硬编码，评审指正）
    delivered_name = os.path.basename(TARGET)
    if f"Delivered {delivered_name}" in reply or f"Delivered {TARGET}" in reply:
        print("PASS: agent-core -> LLM -> send_artifact (MCP wrapper) 端到端调用成功")
    else:
        print("FAIL: 回复中未出现 Delivered 证据；检查 send-artifact 是否注册或 LLM 是否调用")
        print("raw:", json.dumps({"r1": reply1[:150], "r2": reply[:150]}, ensure_ascii=False))
        # 失败必须以非零码退出，否则 CI/调用方误判成功（review 指正）
        sys.exit(1)


if __name__ == "__main__":
    main()
