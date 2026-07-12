# ADR-012: LLM / 工具契约硬化（LLM–Tool Contract Hardening）

## Status
Accepted

## Date
2026-07-11

## Context
P1-4 之前曾出现「工具名写死错位导致断连」类 bug（system prompt 里写死 `query_sql` / `query_plate`，而实际 MCP 暴露 `execute_sql` / `fuzzy_match_plate`）。根因：工具清单来自两处（写死的 prompt vs 真实 MCP），且参数无 schema 校验，错误参数直接打到 MCP 才报错。

## Decision
1. **唯一真实来源**：每次 `llm_loop` **动态注入**真实 `list_tools`（`agent.rs` `list_tools_healthy`），禁止 system prompt 写死过期工具名（收口为唯一来源）。
2. **Schema 校验**：`agent.rs` config `strict_schema: bool`（默认开）；工具参数 JSON Schema 校验失败 → **不调用 MCP**，直接把错误回灌 LLM 或返回明确错误码（可配）。
3. **Failover 可观测**：主 provider 超时切备用，记录到 tracing span（P0-3）；备用 provider 配置文档化。
4. **Prompt 注入保持**：`prompt_injection` 模块持续生效；确认 / 计划文本同样过检测（与 P0-2 / P1-2 联动）。

## Design
- `agent.rs:68` `pub strict_schema: bool`；`agent.rs:1178` `if self.config.strict_schema { /* schema 校验 */ }` 失败则短路。
- `agent.rs:1758` `async fn list_tools_healthy(...)` 聚合健康 MCP 源的工具，注入 LLM 上下文。
- `llm.complete` span 记录 model / failover 次数 / latency。

## Alternatives Considered
- **保持写死工具名**：已被证明是断连根因 → 否决，强制动态注入。
- **schema 失败仍调 MCP 让远端报错**：调试困难、浪费调用 → 否决，前置校验。

## Consequences
- **正面**：「工具名错位导致断连」类 bug 归零；参数错误在本地即被发现，错误码明确。
- **代价**：`strict_schema` 对某些 LLM 的弱 schema 遵从需调 prompt（已有回灌机制缓解）。
- **风险**：动态注入工具过多撑爆上下文 → `list_tools_healthy` 仅列健康源，必要时按命名空间裁剪。

## Future Work
- 工具参数 Schema 由 MCP `tools/list` 的 `inputSchema` 直接复用，免手写。
- Failover 策略可配（按延迟 / 错误率）。
