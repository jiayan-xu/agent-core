---
name: echo-demo
kind: mcp-skill
transport: stdio
security: none  # 无副作用、无业务机密
namespace: global  # 建议全局可见；可按需缩到具体命名空间
tools:
  - name: echo
    description: 回显输入文本，验证 MCP 链路连通性
    required_args: [text]
---

# echo 技能描述

最小连通性验证工具。agent-core 将其作为「空核心 + 赋权」理念的第一个示范。
无危险动作、无外发、无密钥接触，可安全全局开放。
