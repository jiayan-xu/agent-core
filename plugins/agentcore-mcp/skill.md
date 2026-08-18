---
name: agentcore-mcp
kind: mcp-skill
transport: stdio
security: elevated  # 含写记忆、审批、协作发送、受控代码进化；破坏性工具需 confirm
namespace: global    # 可按需收窄到具体命名空间
tools:
  - name: agentcore_health
    description: 检查 agent-core 服务健康状态（公开、无副作用）
    required_args: []
  - name: agentcore_chat
    description: 调用 agent-core 的 agent 完成一轮带安全边界的对话
    required_args: [message]
  - name: agentcore_approval_pending
    description: 列出待人工审批项（admin）
    required_args: []
  - name: agentcore_approval_respond
    description: 批准/拒绝审批项（需 operation_hash 回显 + APPROVE/REJECT 确认）
    required_args: [id, approved, operation_hash, confirm]
  - name: agentcore_memory_feedback
    description: 向 agent-core 的 agent 写偏好/决策/肯定（importance=5）
    required_args: [kind, content]
  - name: agentcore_meta_evolution_status
    description: 查询记忆元进化状态（只读）
    required_args: []
  - name: agentcore_meta_evolution_run
    description: 触发一轮记忆元进化（skipped 表示被开关/限流跳过）
    required_args: []
  - name: agentcore_code_evolve_dry_run
    description: 隔离仓库代码进化并只出 diff（安全默认入口）
    required_args: [target_path]
  - name: agentcore_code_evolve_apply
    description: 隔离仓库代码进化并允许提交（必须先 dry-run 人审）
    required_args: [target_path, confirm]
  - name: agentcore_roundtable
    description: 发起多分身圆桌并收敛共识
    required_args: [topic]
---

# agent-core（dsh 插件）使用规则

本插件把整个 agent-core 作为 dsh 的后端能力。使用纪律：

1. **对话优先走 agent-core**：涉及企业数据查询、受控工具、需审计的任务，优先
   `agentcore_chat`（它会走意图分类、工具路由、审批、配额、审计完整管线），
   而不是绕过它直接调底层工具。

2. **审批闭环**：`agentcore_approval_pending` 查看待批项 → 核对 operation_hash 原样回显 →
   `agentcore_approval_respond` 决定。批准传 `confirm="APPROVE"`，拒绝传 `"REJECT"`；
   绝不允许"帮 agent 自行批准"（防 LLM 自批）。

3. **记忆反馈**：写的是 agent-core 的 agent 命名空间（默认 `agent/{agent_id}`），
   不要和 dsh 自己的记忆工具混用。kind：偏好/规矩→`preference`（硬规矩加 tag hard_rule）、
   决策→`decision`、肯定→`affirm`。

4. **代码进化双步人审**：先 `agentcore_code_evolve_dry_run` 把 `veto_diffs` 完整呈现给
   用户；用户明确同意后才能 `agentcore_code_evolve_apply`（`confirm="APPLY"`）。
   不得在用户未看 diff 时 apply，不得绕过任何服务端门禁。

5. **元进化**：先 `agentcore_meta_evolution_status`；`run` 返回 `skipped` 不是错误，
   原样解释 reason。

6. **破坏性操作**：`*_delete`、`save_config`、`killswitch` 等工具都有 confirm 闸，
   必须先向用户说明后果再执行；拿不准就停下问。

7. **凭据纪律**：badge_token 只出现在 register/login 的返回值里，向用户复述结果时
   不要展开完整 token；不要把它们写进任何文件或日志。
