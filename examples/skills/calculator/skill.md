---
name: calculator-demo
kind: mcp-skill
transport: stdio
security: sandboxed  # 用 ast 白名单，禁用 eval，杜绝代码注入
namespace: global
tools:
  - name: calculator
    description: 安全四则运算（仅 + - * / 与括号）
    required_args: [expression]
---

# calculator 技能描述

安全运算工具。展示「赋权但受边界约束」：外部 MCP 源提供能力，但自身必须做好输入白名单。
agent-core 的 `boundary.rs` 在此之上再做命名空间 / 危险动作门控。
