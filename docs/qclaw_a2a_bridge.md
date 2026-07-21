# qclaw 接入 agent-core A2A 桥 · 设计方案

> 状态：设计稿（基于 2026-07-18 已验证事实 C + B）
> 目标：让 WorkBuddy/Nova（编排者）能经 Memoria a2a 总线向 qclaw（工作节点）派工，qclaw 经 agent-core 的 MCP server 统一执行工具并回执，整条链路可审计、有边界门控。

---

## 1. 已验证的事实（非假设）

| 项 | 结果 | 验证方式 |
|---|---|---|
| C1 | qclaw 已在 Memoria 注册：`agent_id=qclaw`，`namespace=agent/qclaw`，badge_token 已发（有效期 2027-07-18） | `register_agent` |
| C2 | "Nova 派工 → qclaw 收得到" 端到端成立 | admin 发 `a2a_send(to=qclaw)` → 用 qclaw 凭证 `a2a_recv(namespace=agent/qclaw)` 命中 |
| C3 | **关键坑**：`a2a_recv` 必须带接收方授权 namespace，默认 `default` 会报 `Namespace 'default' not authorized` | 实测报错 + 带 ns 后成功 |
| B1 | agent-core 已暴露 MCP server：单 POST `/mcp`，复用 `auth_middleware` | 新增 `src/mcp_server.rs` + `main.rs` 路由 |
| B2 | 外部 agent（qclaw 身份）initialize / tools/list / agent_status 全通过 | raw curl 实测 |
| B3 | `agent_call_tool` 执行后端工具成功返回真实数据（`db_stats`），证明 MCP→`call_tool_routed`→后端→审计 全链路通 | raw curl 实测 |
| B4 | 无鉴权请求 `/mcp` 返回 HTTP 401 | raw curl 实测 |

---

## 2. 角色与数据流

```
            a2a 派工 (Memoria :9003)               MCP 执行 (agent-core :9753)
 Nova ──────────────────────────────► qclaw ───────────────────────────────► agent-core
 (编排者,                         (工作节点,                        (执行+边界+审计,
  admin 身份)                       agent_id=qclaw)                    agent_id=jarvis)
      ◄────────────────────────────── 回执 (a2a_send) ◄──────────────────── 执行结果
```

- **Nova**：经 Memoria `a2a_send(to=qclaw, …)` 派发任务；经 `a2a_recv` 收 qclaw 回执。
- **qclaw**：常驻 loop 收任务 → 本地能做的本地做（IDE/代码侧动作）→ 重工具/事实查询经 `agent-core /mcp` 的 `agent_call_tool` 执行 → `a2a_send(to=admin, …)` 回执。
- **agent-core**：唯一执行权威，`call_tool_routed` 走 boundary 权限门控 + audit 审计。

> 设计原则：**qclaw 不直连 Memoria 后端工具**，所有工具执行统一归口 agent-core，保证边界与审计一致。

---

## 3. 注册与凭证（qclaw 侧）

qclaw 在 Memoria 已注册，凭证：

- `agent_id = "qclaw"`
- `namespace = "agent/qclaw"`
- `badge_token`（鉴权 key，存于 Memoria，qclaw 启动时拉取/注入）

qclaw 启动后须持有两路凭证：
1. **Memoria 凭证**：`X-Agent-Id: qclaw` + `X-Agent-Key: <badge_token>`（用于 a2a 收发）。
2. **agent-core 凭证**：复用同一 `x-agent-id: qclaw` + `x-agent-key: <badge_token>`（agent-core `auth_middleware` 会拿这对向 Memoria 查 `get_allowed_ns` 得到 `agent/qclaw`）。

> 注意：本 WorkBuddy 连接器当前以 `admin` 身份发 a2a（归因 `from=agent:admin`），这是配置细节，不影响链路；若要求 qclaw 回执能精确路由回 Nova，建议给 Nova 也注册独立 `workbuddy` 身份（**已注册**，见会话记录），派工统一用 `workbuddy` 身份，回执 `to=workbuddy`。

---

## 4. 常驻 Loop 协议（qclaw 侧伪代码）

```
loop forever:
    msgs = a2a_recv(limit=5, namespace="agent/qclaw")   # C3：必须带 ns
    for m in msgs:
        if m.subject startswith "task:":
            try:
                result = execute(m)          # 见 §5
                a2a_send(to=m.from, subject="receipt:"+m.subject,
                         body=json({status:"done", result, trace:m.id}))
            except e:
                a2a_send(to=m.from, subject="receipt:"+m.subject,
                         body=json({status:"error", error:str(e), trace:m.id}))
    sleep(poll_interval)   # 建议 2~5s
```

- 幂等：qclaw 应记录已处理 `m.id`（本地去重表），防止重复执行（a2a 当前无自动 ack/删除语义，需 receiver 自管）。
- 心跳（可选）：周期性 `a2a_send(to=workbuddy, subject="heartbeat", body={ts})` 让 Nova 感知在线。

---

## 5. 执行通道：agent-core /mcp

qclaw 执行任务时，对"需要后端工具/事实"的部分调 agent-core MCP：

| MCP 工具 | 用途 | 边界 |
|---|---|---|
| `agent_call_tool` | 经 `call_tool_routed` 执行后端工具，按调用者 `allowed_ns` 过滤可见工具 | 走 boundary + audit（B3 已验证） |
| `agent_chat` | 走完整 agent loop（含 LLM） | 走完整流水线 |
| `agent_status` | 连通性探活 | 无副作用 |

调用示例（qclaw → agent-core）：
```
POST http://127.0.0.1:9753/mcp
  Headers: x-agent-id: qclaw, x-agent-key: <badge_token>
  Body: {"jsonrpc":"2.0","id":1,"method":"tools/call",
         "params":{"name":"agent_call_tool",
                   "arguments":{"tool_name":"db_stats","arguments":{}}}}
```

- qclaw 本地能直接完成的动作（如读自己工作区文件、跑本地命令）可本地执行，不必过 agent-core。
- 凡涉及共享记忆/实体图谱/跨 agent 的动作，一律过 agent-core（或直接走 Memoria MCP，但优先 agent-core 以保持审计一致）。

---

## 6. 任务 / 回执消息格式（a2a）

**派工（Nova → qclaw）**
```json
{
  "subject": "task:<短标识>",
  "body": {
    "intent": "一句话任务描述",
    "steps": ["步骤1", "步骤2"],
    "constraints": {"ns": "agent/qclaw", "read_only": true},
    "callback_subject": "receipt:task:<短标识>"
  }
}
```

**回执（qclaw → Nova）**
```json
{
  "subject": "receipt:task:<短标识>",
  "body": {
    "status": "done | error | partial",
    "result": "<执行结果或摘要>",
    "trace": "<原消息 id>",
    "executed_via": "agent-core | local",
    "ts": "<ISO8601>"
  }
}
```

---

## 7. 错误处理与审计

- **收件箱隔离**：qclaw 必须带 `namespace=agent/qclaw` 收信（C3），否则 `Namespace 'default' not authorized`。
- **执行失败**：qclaw 捕获异常，回执 `status=error`，不静默丢弃。
- **审计**：所有经 `agent_call_tool` 的执行由 agent-core `audit_logger` 落 `audit_events.db`（A3），无需 qclaw 额外实现。
- **越权**：若 qclaw 请求的 `tool_name` 不在其 `allowed_ns`，`call_tool_routed` 在 agent-core 侧硬拒（B 的 boundary），qclaw 收到 `isError` 回执。

---

## 8. 上线步骤

1. qclaw 实现 §4 常驻 loop（建议先做最小版：仅 `a2a_recv` + 回执 echo，验证闭环）。
2. qclaw 注入 Memoria + agent-core 两路凭证（§3）。
3. Nova 侧派工改用 `workbuddy` 身份（`a2a_send(to=qclaw, …)`）。
4. 验证：Nova 派一条 `task:ping` → qclaw 回 `receipt:task:ping` → Nova `a2a_recv` 命中。
5. 进阶：qclaw 经 `agent_call_tool` 执行一个只读工具，确认 `allowed_ns` 正确。

---

## 9. 待确认项

- qclaw 是否已有常驻进程模型（daemon / 长连接）？loop 的 `poll_interval` 与去重策略需与其运行时对齐。
- a2a 是否需要"已读/ack"语义（当前靠 receiver 去重，无服务端删除）——若任务量大，建议给 Memoria 加 `a2a_ack`。
- 是否要支持 **多 worker**（多个 qclaw 实例）竞争同一收件箱？若需，需在 `a2a_recv` 加领取锁。
- Nova 派工身份统一为 `workbuddy` 后，回执路由需 qclaw 读 `m.from`（已验证 `from=agent:admin` 字段存在）。

---

## 10. 与 OpenClaw 吸收的关系

给 agent-core 补 MCP server（B）即补上了 OpenClaw 吸收评估里的 🟡 项"外部 agent 接入"的执行端。A2A 桥（本方案 A）是其上层的"派工/回执"编排层。两者合并后，本栈的跨终端协作能力完整：

- WorkBuddy（已连 Memoria MCP + 本会话）
- Cursor（已连 Memoria MCP）
- qclaw（A2A 桥 + agent-core MCP，待 qclaw 实现 loop）

## 11. 实测修正（2026-07-18 落地验证）

实现 `qclaw_a2a_loop.py` 并实测后，对上文两处修正：

1. **回执通道不能走 a2a（namespace 限制）**。实测：`agent/qclaw` 命名空间下 `a2a_send(to=admin/workbuddy)` 被拒（`无权向该 Agent 发送消息（超出命名空间授权范围）`）；且每个 agent 只能读自己箱（admin 读 `namespace=agent/qclaw` 仍返回 admin 自身箱）。即当前模型是**单向**：admin(`*`)→qclaw 可派工，但 qclaw→admin 回执被拦。
   - **修正**：loop 的 `send_receipt` 先试 a2a（将来把 qclaw 命名空间扩到与编排方共享即直接生效），被拒则**回退写共享记忆 `memory_remember`**（经 agent-core 调 Memoria 后端工具），Nova 侧 `memory_search(tags=['receipt','qclaw'])` 即可读到。实测回执经 memory 通道成功回传并被 Nova 检索到。
2. **Memoria 业务错误不放顶层 `error`**。a2a_send 被拒时返回 `result.content[0].text={"status":"error",...}`，顶层无 `error` 键。判定成功必须解析文本里的 `status`。loop 已加 `_resp_ok()` 修正，否则会误判 a2a 成功而跳过回退（初版曾踩此坑）。

> 结论：qclaw 跑本脚本即成为活工作节点，闭环为「Nova(a2a派工)→qclaw(loop收)→agent-core(agent_call_tool执行,走boundary+审计)→memory_remember(回执)→Nova(memory_search读)」。脚本位置：`C:/Users/user/qclaw/workspace/qclaw_a2a_loop.py`。
