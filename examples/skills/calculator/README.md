# calculator — 示例 MCP 技能（stdio）

安全四则运算的最小 MCP 服务，演示 agent-core 把自然语言问题路由到外部工具并取回结果。
零业务机密、无第三方依赖（纯标准库）。

## 它证明了什么

1. **空核心 + 赋权**：运算能力不在 agent-core 内，而在外部 MCP 源。
2. **边界约束的最小体现**：服务用 `ast` 白名单解析，**不使用 `eval()`**，
   仅允许数字与 `+ - * / ( )`，从根本上杜绝代码注入——这正是「赋权但受约束」的工程示范。

## 接线到 agent.toml

```toml
[[mcp_source]]
name = "calculator-demo"
url = ""
command = "python"
args = ["examples/skills/calculator/server.py"]
# 如需鉴权：token = "${CALC_MCP_TOKEN}"
# 如需限定可见范围：namespace = "org/<组织>/div/<业务线>/dept/<部门>"
```

启动后向 agent-core 提问「算一下 (1+2)*3」，它会路由到 `calculator` 工具并返回 `7`。

## 协议形状（与 agent-core 对齐，非标准 MCP）

- 请求：`{"jsonrpc":"2.0","id":N,"method":"tools/call","params":{"name":"calculator","arguments":{"expression":"(1+2)*3"}}}`
- 响应：`{"jsonrpc":"2.0","id":N,"result":{"content":[{"type":"text","text":"(1+2)*3 = 9"}]}}`
- `tools/list` 返回 `result.tools[].function.{name,description,parameters}`
