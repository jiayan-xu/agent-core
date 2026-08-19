# ADR-016: agent-core 收敛为 Tool Gateway，推理主循环移交 dsh

## Status
Proposed

## Date
2026-08-15

## Context

dsh 已经具备完整的推理、编排与多体能力（LLM 主循环、skills、workflow、subagent、
goal 循环），而 agent-core 当前仍是一个自带 LLM 主循环的完整 agent 引擎（`chat()`
内部完成意图判断 → 工具路由 → 边界 → 审批 → 执行）。继续双引擎运行的代价：

1. **能力重复**：dsh 和 agent-core 各有一套"思考 + 选工具"逻辑，同一任务两套决策。
2. **上下文双份**：dsh 的 session 与 agent-core 的 session 各存一份历史，难对齐。
3. **治理价值被锁在循环里**：agent-core 真正不可替代的部分是 7 条红线、人工审批、
   审计、命名空间配额、受控写回读——但 `call_tool_routed` 埋在 `agent.rs` 的
   chat 循环内，外部调用方（dsh）无法只借用治理、不借用 LLM。

同时已有 `plugins/agentcore-mcp`（49 个 MCP 工具的 REST 代理）证明 dsh 可以通过
标准 MCP 接口驱动 agent-core 的管理面；但它调用 `agentcore_chat` 时，agent-core
内部仍在自己跑 LLM——这是"双引擎"，不是"dsh 替代 agent-core"。

**目标态**：dsh 成为唯一推理主循环；agent-core 收敛为"工具调用网关 + 企业治理
平面"（Tool Gateway / Governance Plane），LLM 按用途分类剥离（主对话移交、自治
维护保留、多体协作退役）。

## Decision

1. **agent-core 新增无头工具执行接口** `POST /api/tool/execute`：外部 caller（dsh）
   提交工具调用，agent-core 只执行 `鉴权 → 工具解析 → 边界 → 审批（可能挂起）→
   配额 → 执行 → 审计`，**不经过任何 LLM**。
2. **LLM 分类剥离**：
   - **移交 dsh**：主对话、意图/任务分解、工具选择、多分身/圆桌、回复净化。
   - **保留 agent-core（维护路径，默认关或受控）**：meta_evolve、code_evolve、
     harness 蒸馏、memory_extract——它们不是主循环 LLM，保留不违反"dsh 是唯一主循环"。
   - **退役/冻结**：LATS、TTC、MultiAgent Compose、组合路由、chat 循环的 BoN。
3. **治理逻辑不重写、只提取**：网关复用 `call_tool_routed`（执行内核）与
   `boundary.check_tool` / `ApprovalManager`（ADR-008 / ADR-015），不复制一套新边界。
4. **审批保持异步**：危险工具进入审批时立即返回 `202 + approval_id + operation_hash`，
   dsh 轮询执行状态或消费现有 `/api/approval/pending`；网关绝不阻塞等待审批。
5. **审批批准后自动执行**：复用 ADR-015 的 `approvals` 权威表，新增"执行关联"字段，
   批准后由执行队列调用 `call_tool_routed` 并写回结果；拒绝则终态 `denied`。
6. **兼容保留**：现有 `/api/chat`、`/v1/chat/completions` 与全部既有 API 在
   Phase 4 之前保持可用，作为回滚与旧客户端（PFAiX/Jan）通道。
7. **PFAiX 壳保留并转型**：dsh 替代的是 agent-core 的推理主循环，**不是** PFAiX。
   壳保留为"企业治理网关的人机终端"（审批台、文档归档、会议/圆桌真人参与、
   更新分发、用户身份）；其对话引擎在 Phase 3 起可选迁移到 dsh（优先走
   agent-core 转发，壳零改动），详见 Design §9。

## Design

### 1. 目标架构

```text
┌─────────────────────────────┐      ┌──────────────────────────────────┐
│ dsh（唯一推理主循环）          │      │ agent-core（Tool Gateway）        │
│ LLM · skills · workflow      │ HTTP │ 鉴权 → 工具解析 → 7红线 → 审批    │
│ subagent · goal 循环          │─────▶│ → 配额 → call_tool_routed → 审计  │
└─────────────────────────────┘      └──────────────┬───────────────────┘
                                                     │ MCP（HTTP/stdio）
                                                     ▼
                              公司级 / 部门级 / 项目级 MCP 源（dashboard、memoria…）
```

禁止形态：dsh 绕过 agent-core 直连业务 MCP（会旁路红线/审批/配额/审计）。

### 2. 接口契约 v1：`POST /api/tool/execute`

路由：受保护路由（auth_middleware，`X-Agent-Id` + `X-Agent-Key`）。

请求头：

| 头 | 必填 | 说明 |
|---|---|---|
| `X-Agent-Id` / `X-Agent-Key` | 是 | 现有统一鉴权（ADR-003） |
| `X-Trace-Id` | 否 | dsh 传入链路 id；缺省 agent-core 生成，贯穿审计 |
| `X-Execution-Chain` | 否 | 逗号分隔的 `caller:execution_id` 链，防环（见 §6） |
| `X-Idempotency-Key` | 否 | 写类工具幂等键（24h 窗口） |

请求体：

```json
{
  "tool": "query_entrance",
  "arguments": { "start": "2026-08-01", "end": "2026-08-15" },
  "persona_id": "default",
  "session_id": "gateway/dsh/default",
  "trace_id": "tr_...",
  "idempotency_key": "ik_..."
}
```

| 字段 | 必填 | 约束 |
|---|---|---|
| `tool` | 是 | 已注册 MCP 工具名；经 `resolve_tool_name_middleware` 解析与纠错 |
| `arguments` | 是 | JSON object，经工具 schema 校验（严格模式沿用现有开关） |
| `persona_id` | 否 | 默认 `default`；受分身工具白名单约束 |
| `session_id` | 否 | 默认 `gateway/{caller_agent_id}`；只用于审计与 checkpoint 归属 |
| `trace_id` | 否 | 与头一致时以头为准 |
| `idempotency_key` | 否 | ≤128 字符，仅写类工具生效 |

响应三态：

**a) 直接执行完成 — `200`**

```json
{
  "status": "executed",
  "execution_id": "ex_20260815_xxxx",
  "tool": "query_entrance",
  "result": "<call_tool_routed 的字符串结果>",
  "verification": null,
  "audit": { "trace_id": "tr_...", "level": "read" }
}
```

`verification`：受控写工具（`controlled_write` 注册表内）执行后的回读证明；
非受控写为 `null`。

**b) 进入人工审批 — `202`**

```json
{
  "status": "pending_approval",
  "execution_id": "ex_20260815_xxxx",
  "approval_id": "ap_...",
  "operation_hash": "<创建时指纹，审批响应必须原样回显>",
  "approver": "dashboard-admin",
  "poll": { "path": "/api/tool/execute/ex_20260815_xxxx", "after_ms": 2000 }
}
```

**c) 拒绝 — `4xx/5xx`（见错误表）**

错误表：

| 状态码 | 场景 |
|---|---|
| `400` | 参数非法 / 工具不存在且纠错失败 / 参数 schema 不通过 |
| `401` | 鉴权失败（ADR-003 现有行为） |
| `403` | 边界拒绝（红线 / 命名空间不可见 / 无审批人的危险工具 / safe_mode） |
| `409` | 幂等键冲突（返回首次 execution_id）/ 进化任务并发 / 执行链环 |
| `429` | 命名空间配额超限（轮次 / token / 并发） |
| `503` | killswitch / 降级模式拒绝工具 / agent 未就绪 |

### 3. 查询接口：`GET /api/tool/execute/{execution_id}`

受保护路由。返回与提交一致的终态结构：

```json
{
  "status": "executed | pending_approval | denied | failed | expired",
  "execution_id": "ex_...",
  "approval_id": "ap_...",
  "result": "...",
  "verification": null,
  "error": null,
  "created_at": "...",
  "updated_at": "..."
}
```

- `pending_approval`：审批未决，dsh 轮询（建议 2s 起步 + 指数退避，上限 30s）。
- `expired`：执行 TTL（默认 24h）内未批准，资源回收。
- 终态结果保留 7 天，之后仅留审计。

### 4. 执行状态机

```text
submitted ──边界/配额拒绝──▶ rejected（4xx/5xx 直接返回）
    │
    ├─ 只读/普通写 ──▶ executing ──▶ executed
    │
    └─ 危险/红线（有审批通道）──▶ awaiting_approval ──批准──▶ executing ──▶ executed
                                                   └─拒绝──▶ denied
```

关键规则：

1. **预检在网关、执行在内核**：网关做 `resolve_tool_name` → persona 白名单 →
   `boundary.check_tool` → 审批判定；实际执行调 `call_tool_routed`（其内部仍保留
   执行期 ns 校验 / killswitch / local_fs / repo_ws / cw 特殊处理，双保险）。
2. **避免配额双扣**：`call_tool_routed` 内部含 `quota.check_tool_round`。实现时抽取
   `call_tool_routed_inner(prechecked=true)`（跳过重复配额扣减）仅供网关使用；
   chat 路径行为零变化。
3. **审批判定逻辑提取**：把 chat 循环内"dangerous → create_request_for_session"的
   判定抽为 `ToolCallGate::submit(...)` 公共函数，网关与 chat 循环共用，防止两套边界
   漂移（对齐 ADR-008"同一套硬规则覆盖所有路径"）。
4. **批准后执行不阻塞审批接口**：`/api/approval/{id}/respond` 只更新 ApprovalRecord
   （ADR-015 现状）并投递一个"待执行"标记；由执行队列（复用 `scheduler` tick 或
   专用 1s 轮询）消费 `Approved` 且未消费的 gateway 执行项，调用内核后写结果。
5. **审计链**：`created → decided → executed/denied` 三类审批事件 + `ToolInvocation`
   事件全部带同一 `trace_id`；gateway 请求缺 trace 时生成 `gw_<ulid>` 并回传。

### 5. 存储：`gateway_executions` 表（挂 `checkpoints.db`，同库异表）

沿用 ADR-015 的"同库异表"策略，不新增数据库文件：

```text
gateway_executions {
  execution_id     TEXT PK
  caller_agent_id  TEXT NOT NULL
  tool_name        TEXT NOT NULL
  arguments_json   TEXT NOT NULL
  persona_id       TEXT NOT NULL DEFAULT 'default'
  session_id       TEXT
  trace_id         TEXT NOT NULL
  status           TEXT NOT NULL  -- Submitted|Executing|Executed
                                  -- |AwaitingApproval|Denied|Failed|Rejected
  approval_id      TEXT           -- FK → approvals.approval_id
  operation_hash   TEXT
  result_json      TEXT
  verification_json TEXT
  error            TEXT
  idempotency_key  TEXT           -- UNIQUE（仅写类）
  idem_expires_at  INTEGER
  created_at / updated_at
}
```

审批权威仍只在 `approvals` 表（ADR-015）；本表只是"执行"真相源，与审批 FK 关联。

### 6. 防环与调用链

dsh → gateway → 下游 MCP 工具，若某工具再次回调 `/api/tool/execute`（例如 dashboard
MCP 里的 agent 工具），形成环。v1 三层防御：

1. **身份**：只有经 auth_middleware 的外部 agent badge 可调用（现有行为）。
2. **链检测**：请求头 `X-Execution-Chain: dsh:ex_a, dsh:ex_b`；若 `(caller, trace_id)`
   对已在链中出现 → `409` 拒绝。
3. **深度上限**：链长度 > 8 → `409`；实现后由安全评审确认阈值。

### 7. LLM 剥离清单（决策 2 的具体化）

| 模块 | 处置 | 说明 |
|---|---|---|
| `agent.rs` chat 主循环 | 移交 dsh | 网关不调用；`/api/chat`、`/v1` 保留为 legacy 兼容 |
| 意图分类/工具选择/组合路由 | 移交 dsh | dsh 的 LLM + skills 承接 |
| 分身、圆桌、会议立场 | 移交 dsh | dsh subagent / workflow 承接；会议数据 API 保留 |
| `reply_polish` | 移交 dsh | dsh 输出侧净化 |
| `lats` / `ttc` / `multiagent` | 退役/冻结 | `[features]` 保持 false，代码保留但不再演进 |
| `meta_evolve` / `code_evolve` / `harness` / `memory_extract` | 保留（维护路径） | 后台/受控触发，不进工具执行热路径 |
| `llm.rs` provider 池 | 保留（缩小） | 仅供上述维护路径与 legacy chat 使用 |

### 8. 特性开关与灰度

| 变量 | 默认 | 含义 |
|---|---|---|
| `GATEWAY_ENABLED` | `0` | 总开关；关=路由不存在 |
| `GATEWAY_ALLOW_WRITE` | `0` | 0=仅 read 级工具；1=开放 write（dangerous 仍走审批） |
| `GATEWAY_EXECUTION_TTL_SECS` | `86400` | 未批准/未完成执行的过期时间 |
| `GATEWAY_IDEMPOTENCY_WINDOW_SECS` | `86400` | 幂等键去重窗口 |
| `GATEWAY_MAX_CHAIN_DEPTH` | `8` | 调用链深度上限 |

灰度顺序：read 工具 → write 工具 → dangerous（永远审批）→ dsh 主循环全量切换。

### 9. PFAiX 壳的角色演进

PFAiX 当前经 agent-core 侧代码事实承担的角色：`/v1/chat/completions` 对话
（含 `x-user-tag` / `x-conversation-id` 上下文隔离）、`/approval-console` 与
`/api/approval/*` 审批台、`/api/documents/archive` 对话栏附件归档、
`/api/register_user` / `/api/login` 用户身份、meetings heartbeat / participants
会议真人参会 UI、`/updates/pfaix/*` 更新分发。

演进原则：**dsh 抢走"脑子"，PFAiX 守住"脸和手"。**

| 阶段 | PFAiX 状态 |
|---|---|
| Phase 0–2 | 完全不动：继续走 `/v1/chat` legacy 通道，零迁移、零风险 |
| Phase 2–3 | 转型而不是废弃：审批台与 dsh 的 `agentcore_approval_respond` 共用同一 `approvals` 权威表（ADR-015），两边都能审批；文档归档、会议真人参与、更新分发继续由壳承担 |
| Phase 3 起 | 对话引擎二选一：**路线 A（推荐）** PFAiX 仍连 `/v1/chat`，agent-core 把请求转发 dsh（壳零改动）；**路线 B** PFAiX 直连 dsh 用户侧 API 成为瘦客户端（需 dsh 先具备多用户会话/鉴权，暂不做） |
| Phase 4 | 壳作为"企业终端"长期存在；后台引擎与 dsh 解耦 |

约束：

1. Phase 4 之前不得删除 `/v1/chat/completions`、`/api/approval/*`、
   `/api/documents/archive`、`/updates/pfaix/*` 任一 PFAiX 依赖接口。
2. 路线 A 的转发实现必须保持 `x-user-tag` / `x-conversation-id` 会话隔离语义
   （对齐 `v1_compat.rs` 折叠规则），否则不得切换。
3. dsh 与 PFAiX 审批共用同一权威表，禁止在壳里重建第二套审批存储。

## Alternatives Considered

| 方案 | 结论 |
|---|---|
| A. agent-core 收敛为 Tool Gateway，LLM 分类剥离（本 ADR） | **采纳** |
| B. 彻底删除 agent-core 全部 LLM（含进化/蒸馏/记忆提取） | 否决：损失自治维护能力，且改动面最大、无灰度路径 |
| C. dsh 直连业务 MCP（dashboard/memoria），不用 agent-core | 否决：7 红线/审批/配额/审计全部旁路，等于重新实现治理 |
| D. 保持双引擎共存（现状 Phase 0） | 暂缓：作为过渡与回滚基线，不是目标态 |

## Consequences

- **正面**：单一推理主循环；治理与推理解耦，agent-core 成为可独立加固/审计的网关；
  旧客户端兼容保留；灰度可回滚。
- **代价**：一次 HTTP 跳转延迟；执行状态/审批联动新增一个存储表与队列；
  dsh 侧需实现轮询与 operation_hash 回显纪律。
- **风险**：
  1. 审批挂起 + 轮询放大负载 → 用指数退避与执行 TTL 控制。
  2. 网关与 chat 两套预检漂移 → 决策 3 强制抽取公共 `ToolCallGate`。
  3. 幂等窗口内写工具重放 → 仅写类工具启用幂等键，且受控写仍有写后回读兜底。
  4. 审计链断裂 → trace_id 由网关统一生成并回传，dsh 插件透传。
  5. PFAiX 用户体验在对话引擎切换时退化 → 路线 A 无感转发 + legacy 通道回滚；
     会话隔离语义（`x-user-tag` / `x-conversation-id`）纳入 Phase 3 验收。

## 迁移四阶段与验收

### Phase 0 — 双引擎过渡（已完成）
- 交付 `plugins/agentcore-mcp`（49 工具标准 MCP 代理）；dsh 使用 agent-core 管理面，
  对话仍走 `agentcore_chat`。
- 验收：MCP 握手 + 公开工具冒烟通过（已实测）。

### Phase 1 — 网关核心（预计 2–3 周）
- 实现 `/api/tool/execute` + `GET /api/tool/execute/{id}`、`gateway_executions` 表、
  审批批准回调 + 执行队列、幂等与防环。
- 灰度：`GATEWAY_ENABLED=1`、`GATEWAY_ALLOW_WRITE=0`（只读工具）。
- 验收：
  - [ ] 单测：三态响应、幂等、配额、边界拒绝、审批批准/拒绝终态
  - [ ] e2e：只读工具全链路（dsh 插件 → gateway → MCP → 审计）
  - [ ] 回归：`scripts/e2e_controlled_write.py` 与既有 chat 路径全绿
  - [ ] 审计链：同 trace_id 贯穿 created/decided/executed

### Phase 2 — dsh 主循环切换（预计 2 周）
- dsh 侧：推理/选工具在 dsh，执行统一走 `agentcore_tool_execute`（新增 MCP 工具）；
  写类工具开放（`GATEWAY_ALLOW_WRITE=1`）。
- 验收：
  - [ ] 真实业务流量 X% 经网关执行（X 由灰度决定，起步 10%）
  - [ ] 危险工具审批闭环在 dsh 内完成（pending → 人审 → 轮询取结果）
  - [ ] chat legacy 随时可回退
  - [ ] PFAiX 壳全程无感（对话/审批/归档/更新接口零改动）

### Phase 3 — 收敛 agent-core（预计 2 周）
- `[features]` 全 false（LATS/TTC/MultiAgent/skill_library 冻结）；
  meta/code evolve 保持后台可选；圆桌/分身调用迁至 dsh subagent。
- 验收：
  - [ ] `/api/metrics` 中 chat 热路径 LLM 调用归零（维护路径除外）
  - [ ] PFAiX/Jan 旧客户端经 `/v1/chat` 仍可用
  - [ ] 路线 A（agent-core 转发 dsh）经 PFAiX 实测通过，且 `x-user-tag` /
        `x-conversation-id` 会话隔离语义不变

### Phase 4 — 终态清理（可选，另行评审）
- chat 主循环代码降级为 legacy feature-gate 或移除；agent-core 对外定位更名为
  "Tool Gateway / 治理平面"。
- 验收：代码评审 + 安全红队（重点：绕网关直连 MCP、审批自批、幂等重放、链环）。

## Non-Goals（明确不做）

1. 不在 dsh 侧重建 7 红线 / 审批 / 配额——治理只在 agent-core。
2. 不做 LLM provider 代理网关（不接模型路由、不替换 OpenAI 网关）。
3. 网关不阻塞等待审批（无同步审批模式）；不提供 v1 流式工具结果（SSE 留 v2）。
4. 不迁移 dashboard/memoria 等业务 MCP 本身；不动 Memoria 存储层。
5. 不删除 `/api/chat` 与 `/v1/chat/completions`（至少保留至 Phase 4 评审）。
6. 不支持多实例分布式执行：单 agent-core 实例 + SQLite 真相源。
7. 不要求 PFAiX 在 Phase 3 之前改版；不在壳内重建审批存储或治理逻辑。

## Rollback

- Phase 1/2：`GATEWAY_ENABLED=0` 即完全回到现状；chat 路径零改动（仅新增公共函数
  抽取，行为不变）。
- Phase 3：恢复 `[features]` 开关与 chat 调用即可回退到双引擎。
- 回退红线：`scripts/e2e_controlled_write.py`、审批 e2e、现有单测全绿才允许前进到
  下一阶段。

## References

- ADR-003 统一鉴权与本机默认
- ADR-004 Checkpoint 控制面
- ADR-008 危险工具硬闸门
- ADR-015 审批单一真相源
- `src/routes.rs`（路由装配）、`src/agent.rs::call_tool_routed`
- `plugins/agentcore-mcp/`（Phase 0 交付物）
- 讨论：2026-08-15「agent-core 作为 dsh 插件 / dsh 替代 agent-core / LLM 剥离」
