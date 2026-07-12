# ADR-005: Tracing 可观测底盘（Observability Substrate）

## Status
Accepted

## Date
2026-07-11

## Context
W1（P0）前，agent-core 的日志零散、无统一 trace_id、关键路径（HTTP 请求、LLM 调用、工具路由、审批）无法串联。出问题时只能靠 `println` 式日志大海捞针，且容易误打密钥头。

「可运营版」要求：每个请求可追踪、每个工具调用可归因、故障可定位，同时默认不泄露隐私。

## Decision
1. **统一 subscriber**：启动时 `tracing_subscriber::fmt()` 初始化，过滤级别来自 `AGENT_CORE_LOG` / `RUST_LOG`（默认 `info`）。
2. **请求级 trace_id**：`trace_middleware` 为每个入站请求生成 `x-trace-id`（贯穿响应头与 span），span 字段含 `method` / `path`。
3. **关键路径挂 span**：`http.request` / `agent.chat` / `llm.complete` / `llm provider failover` / `mcp call` 均带结构化字段（`tool`、`provider_index`、`failover_to` 等）。
4. **隐私硬约束**：工具 args 脱敏；**禁止记录鉴权头（x-agent-key 等）**；默认 INFO，不落 DEBUG 敏感内容。

## Design
- `init_tracing()`：`EnvFilter::try_from_env("AGENT_CORE_LOG").or(RUST_LOG).unwrap_or("info")`。
- `trace_middleware`：`rand` 生成 128-bit hex trace_id，注入 `tracing::info_span!`。
- failover 日志升级为 `tracing::info!` 并带 `failover_to` / `provider_index` span 字段（原仅 `warn!` 无字段）。
- 工具参数校验失败：`tracing::info!(tool, error, "工具参数 schema 校验失败，回灌 LLM 修正")`。

## Alternatives Considered
- **OpenTelemetry 全量导出**：能力强但引入重依赖与采集后端，违背「轻量」→ 暂缓（OTLP 可选，不在 P0 强制）。
- **裸 println**：无结构、无 trace_id → 否决。

## Consequences
- **正面**：请求可串联、故障可定位、failover/降级可见。
- **代价**：少量 span 开销（INFO 级别可忽略）。
- **风险**：误打密钥 → 由「禁止记录鉴权头 + args 脱敏」硬约束规避。

## Future Work
- 可选 OTLP exporter（运维侧按需开启）。
- trace_id 与 Memoria 审计事件关联查询（见 P2-2）。
