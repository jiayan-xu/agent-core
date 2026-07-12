# ADR-007: Harness 蒸馏质量（Distillation Quality Gate）

## Status
Accepted

## Date
2026-07-12

## Context
`harness.rs` 的 `distill_from_logs` 会把**每一次**成功组合路由蒸馏成模板并**自动激活**（`is_active=1`）。这有两处风险：①偶发一次成功就被蒸馏上线，模板质量无保证；②若蒸馏出的步骤含危险/外发工具，会自动获得执行权限，绕过 P0-2 硬闸门。

## Decision
1. **蒸馏触发门槛提升**：agent 侧调用 `distill_from_logs(&logs, 3)`（N=3 次成功组合路由佐证），偶发成功不再过早蒸馏。
2. **危险模板永不自动激活**：新增 `boundary::is_dangerous_tool(name)`（内置危险清单 + `delete_` / `batch_delete` / `shutdown_` 高危前缀）。`distill_from_logs` 若合并出的步骤含危险工具，则该模板置 `is_active=0`（待审批），**绝不自动激活**。安全模板（只读/写）仍自动激活。
3. **审批激活路径**：`HarnessStore::activate(id)`（逆向 `deactivate`）+ 新增 `POST /api/admin/harness/activate`（需鉴权）供人工 / admin 批准上线。
4. **可观测**：Harness 命中写入 `match_score` + `harness` 名到 tracing span；`call_tool_routed` 的 harness 步骤与 `llm_loop` 的工具调用均把 `boundary` 的 `allowed` / `level` / `reason` 写入 span。

## Design
- `is_dangerous_tool` 复用 `ToolClassifier` 的危险/未知判定，使蒸馏门槛与执行期硬闸门同一套准则。
- `distill_from_logs` 在 `save` 前判断 `has_dangerous`，危险则 `is_active=0`。
- `activate(id)` 直接 `UPDATE harnesses SET is_active = 1 WHERE id = ?`，与 `deactivate` 对称。

## Alternatives Considered
- **蒸馏后统一进人工审核队列**：更严谨但增加运维负担 → 折中：仅危险模板需审批，安全模板仍自动，平衡安全与自治。
- **直接禁止蒸馏含危险工具的日志**：丢失了「危险流程也可被记录学习」的价值 → 否决，改为「可蒸馏但不可自动激活」。

## Consequences
- **正面**：蒸馏模板质量随频次佐证提升；危险流程不会静默获得执行权。
- **代价**：含危险步骤的高频成功流程需一次人工激活。
- **风险**：`is_dangerous_tool` 清单漏判新危险前缀 → 由 P0-4 外发前缀检测 + 执行期 `boundary.check_tool` 兜底（蒸馏激活不等于绕过硬闸门）。

## Future Work
- 蒸馏模板置信度（`confidence`）门槛联动自动激活策略。
- 人工激活操作本身写入审计（复用 `ApprovalApproved` 事件）。
