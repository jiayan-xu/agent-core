# ADR-011: 场景回归评测集（Scenario Eval Suite）

## Status
Accepted

## Date
2026-07-11

## Context
单元测试覆盖函数级逻辑，但无法覆盖「越权 / 外发 / 工具名幻觉 / 命名空间」等行为契约。每次重构（尤其 P0-2 / P0-4 / P1-4 这类安全相关改动）缺固定回归集，红线易悄悄退步。

## Decision
1. **固定 fixture 集**：`eval/cases.json` 定义场景（E01–E10+），每条含 `scenario` / `request` / `expect`（期望 HTTP 码、是否调用 MCP、是否允许工具等）。
   - E01 无身份 chat → 401；E02 只读查 → 允许仅 SELECT 类；E03 注入诱导 → 拦截/降级；E04 export/send_email → 硬拒或 pending；E05 跨 ns 工具 → 不可见/不允许；E06 错误工具名 → 不 panic；E07 MCP 宕机 → 降级收缩；E08 Harness 命中危险模板 → 仍过 boundary；E09 Composer 多步 → 预览态不执行；E10 杀进程 → checkpoint 续跑。
2. **CI 可跑**：`tests/eval.rs` 加载 `eval/cases.json` 逐条断言；可选 `eval` feature 下可 mock MCP（不依赖真实服务）。
3. **新增红线必须加对应 case**：PR 检查清单（计划 §9）要求「有对应单测或 eval case」。

## Design
- `eval/cases.json`：`[{ "id":"E01", "name":..., "expect": { "http": 401, "mcp_calls": 0, ... } }]`。
- `tests/eval.rs`：`#[test] fn eval_suite()` 遍历 cases，对本地 agent-core 实例（或 mock）发请求并断言 `expect`。

## Alternatives Considered
- **只靠单元测试**：无法表达跨模块行为契约 → 否决。
- **绑云评测 SaaS**：引入外部依赖与隐私外传风险 → 否决，用本地 fixture。

## Consequences
- **正面**：安全相关改动有固定回归红绿灯；越权 / 外发场景失败即红。
- **代价**：维护 fixture 需随能力演进补充。
- **风险**：fixture 与真实 MCP 行为漂移 → 保留 mock 选项并定期用真实源抽样校验。

## Future Work
- 把 `trace_id` 关联进 eval 报告，便于失败 case 直接跳到审计链路。
- 覆盖率门禁（新增安全路径必须有 case）。
