# ADR-013: 降级收缩策略显式化（Degrade Contraction）

## Status
Accepted

## Date
2026-07-11

## Context
「降级收缩」是设计理念（计划 §0）之一——故障时缩权限、切备用，而不是裸崩或无限重试。P1-5 之前这套策略散落各处、无状态机、无统一日志，混沌场景下行为不可预期。

## Decision
把降级收缩写成**显式状态机**并打日志（`degrade.rs`）：

| 触发 | 行为 |
|------|------|
| 某 MCP 源连续失败 ≥ `UNHEALTHY_THRESHOLD`(=3) | 标记 source unhealthy，工具列表剔除该源，写审计（`HarnessHit`/MCP 类事件复用 ADR-006） |
| 全部业务 MCP 不可用 | 仅保留 Memoria 只读记忆检索 + 纯聊天（`MemoriaReadonlyChat`） |
| LLM 主 provider 超时 | 切备用；仍失败则返回可重试错误 |
| Kill switch | 全局拒绝工具，仅系统状态查询（`/api/metrics` / `/api/admin/quota`） |

- `DegradeMode` 枚举表达上述档位；`set_kill_switch(on)` 由 admin 端点触发。
- 降级前后均写 trace（P0-3），便于事后复盘。

## Design
- `degrade.rs:17` `pub const UNHEALTHY_THRESHOLD: u32 = 3;`
- `degrade.rs:21` `pub enum DegradeMode { ... }`
- `degrade.rs:66` 连续失败计数达阈值 → `unhealthy` 标记（原子 `Ordering::SeqCst`）。
- `degrade.rs:153` `pub fn set_kill_switch(&self, on: bool)`。

## Alternatives Considered
- **裸崩 / 无限重试**：违背「降级收缩」理念、用户体验差 → 否决。
- **降级时静默丢请求**：无审计无 trace，事后不可查 → 否决，强制写事件。

## Consequences
- **正面**：混沌场景（停 dashboard MCP / LLM 全挂）行为可预期、有 trace、有审计。
- **代价**：需维护 unhealthy 计数与恢复逻辑。
- **风险**：误判健康源为 unhealthy → 阈值设为 3 次且恢复后可重置，避免过度收缩。

## Future Work
- 降级档位可配置（阈值、是否自动恢复）。
- 与 Memoria `dream_state` 联动，降级期仍可做记忆蒸馏（低峰）。
