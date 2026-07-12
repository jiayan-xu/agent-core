# echo — 示例 MCP 技能（stdio）

零机密、零副作用的最小 MCP 服务，仅回显输入，用于验证 agent-core ↔ MCP 的 stdio 链路。

## 它证明了什么

agent-core 自身是「空核心」——不内置任何业务工具。能力**完全由外部 MCP 源赋予**。
`echo` 演示了这条「赋权」链路的最小可运行单元：

```
agent-core  ──stdin/stdout JSON-RPC──▶  echo/server.py
（推理 + 边界 + 路由）              （实际工具执行）
```

## 接线到 agent.toml

在 `agent.toml` 的 `[[mcp_source]]` 中加：

```toml
[[mcp_source]]
name = "echo-demo"
url = ""
command = "python"
args = ["examples/skills/echo/server.py"]
```

> 路径相对 agent-core 启动目录（cwd）。也可写绝对路径或换成虚拟环境里的 python。

## 验证

启动 agent-core 后，向它提问「帮我 echo 一句 hello」，agent-core 会路由到 `echo` 工具并返回 `echo: hello`。
也可直接看 `../docs`（或 `cargo test`）确认 MCP 源健康探测通过。

## 协议形状（与 agent-core 对齐，非标准 MCP）

- 请求：`{"jsonrpc":"2.0","id":N,"method":"tools/call","params":{"name":"echo","arguments":{"text":"..."}}}`
- 响应：`{"jsonrpc":"2.0","id":N,"result":{"content":[{"type":"text","text":"echo: ..."}]}}`
- `tools/list` 返回 `result.tools[].function.{name,description,parameters}`

详见 `server.py` 顶部注释与 `../../docs/decisions/` 中的相关 ADR。
