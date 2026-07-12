# ADR-008: 危险工具硬闸门（Dangerous-Tool Hard Gate）

## Status
Accepted

## Date
2026-07-11

## Context
P0 之前，`REQUIRES_REVIEW` 类工具主要靠 LLM「听话」而软阻断——无 `approver_id` 时危险操作（删除、外发）仍可能被绕过。红线形同虚设。目标：把「软劝退」改为「无审批人即硬拒绝，且不调用 MCP」。

## Decision
1. **分类与硬拒**：`boundary.rs` `check_tool` 返回 `allow` 标志。`ToolClassifier::classify` 分 `read` / `write` / `dangerous` / `unknown`。DANGEROUS / 外发类工具若**无 `approver_id`** → `allow=false`，直接返回错误给调用方，**不进入 LLM 下一轮「假装遵守」**，也**不调用任何 MCP**。
2. **同一套硬规则覆盖所有路径**：Harness 快速路径（`try_harness_match` 执行步骤）与 Composer `execute_plan` **都调用 `boundary.check_tool`**，禁止旁路（见 P0-4 / ADR-009）。
3. **审批状态机**：`approval.rs` 定义 `PendingApproval { approver_id, ... }`，状态 `PendingApproval → 通过 / 拒绝`；拒绝写入审计（见 ADR-006）。有 `approver_id` 时进入 pending，未批准前 MCP 调用计数为 0。

## Design
- `boundary.rs`：`dangerous_tools: HashSet<String>`（内置清单）+ `classify`；`check_tool` 综合权限树、`allowed_ns`、工具分类、`approver_id` 给出 `allow` / `level` / `reason`。
- `agent.rs` / `composer.rs` / `harness.rs` 执行前统一 `let check = boundary.check_tool(...); if !check.allow { /* 硬拒，记录 reason */ }`。

## Alternatives Considered
- **仅用 LLM 系统提示要求「不得执行危险工具」**：已被多次证明不可靠 → 否决，改代码层硬闸。
- **危险工具一律禁止（含审批）**：过度限制合理运维流程 → 否决，保留「有审批人可放行」。

## Consequences
- **正面**：越权 / 无审批危险操作在代码层被拦截，不依赖 LLM 服从度。
- **代价**：需为合法危险操作配置审批人（`approver_id`）。
- **风险**：分类清单漏判 → 由 P0-4 外发前缀检测 + `is_dangerous_tool`（ADR-007）多层兜底。

## Future Work
- 审批人可配置为「命名空间管理员」或「指定人工」；审批动作接入 A2A（`build_a2a_request`）。
