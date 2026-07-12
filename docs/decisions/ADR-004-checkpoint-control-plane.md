# ADR-004: Checkpoint 控制面落盘（Control-Plane Persistence）

## Status
Accepted

## Date
2026-07-11

## Context
W2（P1）前，agent-core 的「对话进度」只存在于内存（`chat_history` 数据面）。一旦进程崩溃或重启，进行中的多步组合计划、待确认/待审批状态全部丢失，用户必须从头再来——对「可运营版」是不可接受的。

但对话原文（数据面）与「执行进度/审批状态」（控制面）性质不同：数据面可丢（重聊即可），控制面必须可恢复（否则重复执行危险动作或丢失审批上下文）。

## Decision
引入**控制面 / 数据面分离**的 Checkpoint 机制：

1. 新增 `checkpoints` 表（SQLite，`checkpoints.db`），与 `chat_history` 完全独立。
2. 状态机 `CheckpointState`：`New → AwaitingConfirmation → Confirmed → PendingApproval → ExecutingPlan → PlanPreview → Done / Failed`。
3. **双写**：每次控制面状态变更，同步写内存 + SQLite（`save`）。
4. **恢复**：`chat()` 入口调用 `restore_checkpoint(session_id)`，按持久化状态把内存拉回，实现 **at-least-once 续跑**。
5. PlanPreview / ExecutingPlan 态额外持久化 `in_progress_plan` 与各步结果，崩溃后从断点继续而非重跑。

## Design
- `CheckpointStore`：`open` / `open_memory` / `init_schema` / `save` / `load` / `delete` / `list_stale` / `purge_stale`。
- `restore_checkpoint` 覆盖全状态恢复逻辑：AwaitingConfirmation（重发确认提示）、Confirmed（继续）、PendingApproval（重发审批）、ExecutingPlan（复用 plan + 已完步结果续跑）、PlanPreview（重渲染预览）、Done/Failed（直接给结论）。
- 陈旧 checkpoint 由 `list_stale` / `purge_stale` 定期清理。

## Alternatives Considered
- **把进度塞进 chat_history**：混用数据面，恢复时难以区分「原文」与「状态」→ 否决。
- **纯内存 + 重启丢**：最简单但违背「可运营」目标 → 否决。

## Consequences
- **正面**：崩溃/重启后用户进度不丢，且危险动作不会因续跑而重复执行（从断点续）。
- **代价**：每次状态变更多一次 SQLite 写（先正确后优化，可用同连接事务/异步写）。
- **风险**：双写不一致 → 以 SQLite 为权威，内存为其缓存，恢复时以 SQLite 为准。

## Future Work
- 异步批量写降低延迟。
- Checkpoint 与 Memoria `dream_state` 打通，实现跨进程/跨 agent 的恢复。
