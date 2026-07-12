# ADR-014: 命名空间级配额与成本（Namespace Quota & Cost）

## Status
Accepted

## Date
2026-07-12

## Context
P2-1 之前仅有全局 `max_tool_rounds`，无命名空间级轮次 / 日 token / 并发会话约束，也无本机仪表。多租户（公司 / 部门 / 项目三级 MCP）下，单命名空间失控会拖垮整体，且成本不可观测。

## Decision
1. **每 ns 配额策略** `NsQuotaPolicy { max_tool_rounds, daily_token_budget, max_concurrent_sessions }`；默认值 `16` / `500000` / `8`。
2. **用量记账**：`NsQuotaStore` 维护 `NsQuotaUsage { day, tool_rounds, token_used, active_sessions }`；跨天（`day` 变更）自动重置日维度用量。
3. **超限硬拒 + 审计**：`check_tool_round` 超限返回 `Err`（不进入下一轮）；`check_token_budget` + `record_token` 控制日 token；`enter_session` / `leave_session`（`SessionQuotaGuard` RAII，Drop 中 `leave_session`）约束并发会话。超限事件写入审计（ADR-006）。
4. **仪表与管理**：`GET /api/metrics` 返回 `{quota, degrade}`；`GET /api/admin/quota` 返回默认策略 + 已配置策略 + 各 ns 用量；`PUT /api/admin/quota` 按 ns 覆盖策略（需鉴权）。
5. **token 估算**：`LlmResponse` 无 token usage 字段，用 `字符数 / 4` 估算，足够做预算闸门。

## Design
- `quota.rs`：`NsQuotaStore { policies: HashMap, usage: HashMap, default_policy }`；方法 `set_policy` / `get_policy` / `check_tool_round` / `check_token_budget` / `record_token` / `enter_session` / `leave_session` / `status()`。
- `agent.rs`：chat 入口并发会话守卫；`llm_loop` 日 token 预算检查（结果先绑定局部变量，避免 `MutexGuard` 跨 `.await` 的 Send 错误）；`call_tool_routed` 工具轮次门控。
- `main.rs`：`/api/metrics` + `/api/admin/quota`（GET/PUT）handler。

## Alternatives Considered
- **接入真实 token 计数 API**：`LlmResponse` 当前无该字段 → 暂用字符/4 估算，后续可替换。
- **全局单一配额**：无法隔离多租户 → 否决，按 ns 隔离。

## Consequences
- **正面**：单 ns 失控被隔离；成本（轮次 / token / 并发）本机可见可管。
- **代价**：每次工具轮次 / token 多一次配额检查（HashMap 锁，轻量）。
- **风险**：字符/4 估算偏差 → 仅作预算闸门，非精确计费。

## Future Work
- 接入 LLM 真实 token usage 后替换估算。
- 配额超限事件接入告警（admin webhook）。
