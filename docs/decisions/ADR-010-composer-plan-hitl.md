# ADR-010: Composer 计划 HITL 产品化（Plan Human-in-the-Loop）

## Status
Accepted

## Date
2026-07-11

## Context
ADR-002 已定「计划可见」，但工程上多步组合计划默认直接执行，用户无「先看后批」的一等公民入口。对「可运营版」需把计划预览 / 驳回 / 编辑做成默认体验开关，且不增加单步只读请求的延迟。

## Decision
1. **预览开关**：`compositional_routing.preview = true|false`（企业默认 true）。
2. **流程**：`Confirmed` → 生成 plan（`composer.rs` `try_parse_plan` 解析 LLM 结构化计划）→ **返回计划给用户**（结构化 JSON + 人话摘要）→ 用户「确认执行 / 修改 / 取消」→ 再 `execute_plan`（在 `agent.rs` 中，需访问 `call_tool_routed`）。
3. **取消与修改进审计 / 仍过边界**：修改仅允许改 `args` / 删步；不允许注入未授权 tool 名 —— 改后每步仍过 `boundary.check_tool`（复用 P0-2 硬闸门）。取消写入审计（ADR-006）。
4. **避免「确认两遍」**：简单单工具请求可跳过计划预览（配置阈值），直接走任务确认状态机。

## Design
- `composer.rs`：`ExecutionPlan` / `try_parse_plan`（兼容 ```json 围栏、前后噪声文本、缺字段修复）。
- 状态机新增 `PlanPreview` / `ExecutingPlan` 控制面态（`checkpoint.rs`，与 `ADR-004` 控制面落盘联动）：预览态不调用任何 MCP；执行态持久化 `in_progress_plan` 与各步结果，崩溃续跑。
- 用户「确认执行」前，`call_tool_routed` 调用计数为 0。

## Alternatives Considered
- **永远先执行再汇报**：违背 HITL 原则、危险动作无撤销 → 否决。
- **每次请求都弹预览**：单步只读被过度摩擦 → 否决，按复杂度阈值跳过。

## Consequences
- **正面**：多步 / 危险计划默认「人先看到再批」；取消/删步后危险工具绝不调用；与 checkpoint 续跑一致。
- **代价**：多一步往返延迟（仅多步 / 危险场景，单步只读可跳过）。
- **风险**：LLM 计划解析失败 → `try_parse_plan` 多重回退（围栏 / 裸 JSON / 修复），失败则降级为单步确认。

## Future Work
- 计划可视化（壳侧渲染结构化 plan）。
- 编辑后的计划差异 diff 展示。
