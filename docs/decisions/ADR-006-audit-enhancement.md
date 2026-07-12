# ADR-006: 审计增强（Unified Audit Event Model）

## Status
Accepted

## Date
2026-07-12

## Context
P0/P1 阶段已零散埋点（鉴权失败、边界拒绝、审批），但事件类型不统一、无链路 `trace_id`、查询只能翻 Memoria 远端，本地排障慢。W3「可开源示范版」要求一次请求可从 `trace_id` 还原「LLM → 边界 → MCP → 结果」全链。

## Decision
1. **统一事件模型**：`audit.rs` 定义 9 类 `AuditEventType`（serde `snake_case` 稳定字符串）：`AuthFail` / `BoundaryDeny` / `ApprovalCreated` / `ApprovalApproved` / `ApprovalRejected` / `McpRetry` / `CheckpointResume` / `HarnessHit` / `ToolInvocation` / `IdentityChange`。
2. **链路 `trace_id`**：`new_trace_id()` = 纳秒时间戳 + `AtomicU64` 自增序号（免 `uuid` 依赖）；一次 `chat()` 生成并下穿 `llm_loop` → `call_tool_routed`，同链事件共享。
3. **双写**：事件异步写 Memoria `memory_observe`（耐久，失败忽略）+ 本地有界环形缓冲 `Mutex<VecDeque<AuditEvent>>`（容量 `RING_CAPACITY=2000`），供即时查询。
4. **只读查询 API**：`GET /api/admin/audit`（需鉴权）支持 `trace_id` / `event` / `limit` 过滤。
5. **脱敏**：`redact()` 对 `admin_key` / `api_key` / `token` / `password` / `secret` / `authorization` 等值的敏感字段替换为 `***`，默认不落明文凭证。

## Design
- `AuditLogger { mcp: Option<MemoriaClient>, events: Mutex<VecDeque<AuditEvent>> }`；`record_event` 先脱敏 → 入环 → 写 Memoria。
- 类型化便捷方法：`auth_fail` / `boundary_deny` / `approval_event` / `mcp_retry` / `checkpoint_resume` / `harness_hit`；保留旧 `log_decision` / `log_identity` / `log_tool_call` 兼容。
- 埋点位置：`chat()` 生成 `trace_id`；`llm_loop` 边界拒绝改 `boundary_deny(trace_id, session_id)`、审批创建 `approval_event("created", ...)`；`call_tool_routed` 实际执行 `mcp_retry`；`restore_checkpoint` `CheckpointResume`；`try_harness_match` 命中 `HarnessHit`；鉴权中间件失败 `auth_fail`。

## Alternatives Considered
- **仅写远端 Memoria**：本地排障需网络且不可即时过滤 → 否决，保留本地环形缓冲。
- **引入 uuid crate**：仅为一个序号引入依赖 → 否决，用纳秒时间戳 + `AtomicU64`。

## Consequences
- **正面**：任意一次 chat 可凭 `trace_id` 全链还原；本地即时查询，无网络依赖。
- **代价**：每条事件多一次本地锁写入（2000 容量有界，O(1) 入队）。
- **风险**：环形缓冲被大量事件撑满 → 旧事件自然淘汰（仅影响本地即时查询，Memoria 远端仍耐久）。

## Future Work
- 可选导出 OTLP，与 tracing span 对齐同一 `trace_id`。
- 敏感字段脱敏规则可配置（按命名空间策略）。
