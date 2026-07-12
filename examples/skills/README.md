# examples/skills — 示例 MCP 技能

本目录证明 agent-core 的核心设计理念：**空核心 + 赋权（Minimal Core, Maximal Extension）**。

- agent-core **不内置任何业务工具**。它只负责推理、工具路由、安全边界、会话与记忆。
- 所有实际能力由**外部 MCP 源（技能）**提供。一个技能 = 一个 MCP 服务（stdio 或 HTTP）。
- 管理员按角色/命名空间把技能装配给不同的调用者——「在其职责范围内有能力，且仅此而已」。

## 目录

| 技能 | 传输 | 说明 | 机密 |
|------|------|------|------|
| [`echo/`](./echo) | stdio | 回显文本，验证链路连通 | 无 |
| [`calculator/`](./calculator) | stdio | 安全四则运算（禁 `eval`） | 无 |

两者均为**零业务机密**的最小可运行示范，可直接接线，用于：

- 验证你本地的 agent-core ↔ MCP stdio 链路是否通；
- 作为你自研技能的模板（照着 `server.py` 改即可）；
- 理解「自定义 JSON-RPC 形状」如何与 agent-core 对接。

## 自定义协议形状（与标准 MCP 的差异）

agent-core 出于历史与 OpenAI 工具调用兼容性，使用**非标准 MCP 形状**（见 `src/mcp_client.rs`）：

- `tools/list` 响应：`result.tools[].function.{name, description, parameters}`
  （标准 MCP 为 `result.tools[].{name, description, inputSchema}`）
- `tools/call` 请求：`{method:"tools/call", params:{name, arguments}}`
- `tools/call` 响应：取 `result.content[0].text`（标准 MCP 同构，但本项目要求此形状）

写自己的 MCP 服务时，请照 `echo/server.py` / `calculator/server.py` 的形状返回，
否则 agent-core 无法识别你的工具。

## 写一个新技能（模板）

1. 复制 `echo/` 目录，改名。
2. 在 `server.py` 的 `TOOLS` 里改 `function.name/description/parameters`，在 `handle_tools_call` 里实现逻辑。
3. **安全铁律**：
   - 任何执行动作前，先确认调用者有权（agent-core 的 `boundary.rs` 会再做一层门控，但源侧也应收紧）。
   - 禁止 `eval` / `exec` 用户输入；做输入白名单。
   - 外发类动作（`export_/send_/upload_/webhook_` 等前缀）需审批，见 `boundary.rs`。
4. 在 `agent.toml` 的 `[[mcp_source]]` 中加一条接线（注意 `namespace` 控制可见范围）。
5. 绝不在技能里硬编码密钥——用 `${ENV_VAR}`（agent-core 支持 `${ENV}` 插值，见 P2-6）。
