# agentcore-mcp —— 把整个 agent-core 作为 dsh 插件（标准 MCP server）

将 agent-core（`http://127.0.0.1:9753`）的**全部 HTTP 能力**封装为标准 MCP server
（stdio），dsh 按普通 MCP 插件挂载后即拥有一个带安全边界、记忆、审批和协作的
企业级 agent 引擎。零第三方依赖，仅 Python 3 标准库。

## 工具清单（49 个，按域分组）

| 域 | 工具 | 说明 |
|---|---|---|
| 系统/公开 | `agentcore_health` `agentcore_config` `agentcore_updates_latest` | 健康/配置摘要/更新清单，无需凭据 |
| 身份 | `agentcore_register_agent` `agentcore_register_user` `agentcore_login` | 注册 agent、注册用户、登录；响应含 badge_token（勿入日志） |
| 审批 | `agentcore_approval_pending` `agentcore_approval_history` `agentcore_approval_respond` | 人工审批闭环；respond 需 APPROVE/REJECT 确认 + operation_hash 防偷换 |
| 对话/会话 | `agentcore_chat` `agentcore_chat_stream` `agentcore_sessions` `agentcore_session_load` `agentcore_session_delete` `agentcore_v1_chat` | 完整 agent 对话管线；v1 为 OpenAI 兼容（非流式） |
| 运维/admin | `agentcore_metrics` `agentcore_agent_events` `agentcore_save_config` `agentcore_admin_degrade` `agentcore_admin_killswitch` `agentcore_admin_quota_get` `agentcore_admin_quota_put` `agentcore_admin_audit` `agentcore_admin_consolidate` `agentcore_admin_harness_activate` `agentcore_agent_repair` | 观测、配额、降级、拉闸、审计、记忆巩固 |
| 协作 A2A | `agentcore_collab_inbox` `agentcore_collab_send` `agentcore_collab_approval` `agentcore_collab_delete` `agentcore_collab_peers` | 与其他 agent 收发消息、响应协作审批 |
| 分身 | `agentcore_persona_create` `agentcore_persona_list` `agentcore_persona_get` `agentcore_persona_delete` `agentcore_persona_goal_push` `agentcore_session_persona_bind` | 多分身 CRUD、目标压入、会话绑定 |
| 会议/圆桌 | `agentcore_meetings_list` `agentcore_meeting_delete` `agentcore_meeting_message` `agentcore_meeting_end` `agentcore_meeting_heartbeat` `agentcore_roundtable` | 会议管理、真人发言、多分身圆桌（SSE 到 done） |
| 文档 | `agentcore_documents_archive` | 本机文件归档到部门共享文档 |
| 记忆/进化 | `agentcore_memory_feedback` `agentcore_meta_evolution_status` `agentcore_meta_evolution_run` `agentcore_code_evolve_dry_run` `agentcore_code_evolve_apply` | 立规矩、记忆自进化、代码自进化（先 dry-run 后 apply） |

未封装的端点（有意排除）：`/api/meetings/{id}/stream`（永不结束的订阅流）、
`/approval-console`（HTML 页面）、`/v1/chat/completions` 的 `stream=true`（改走
`agentcore_chat_stream`）。

## 挂载到 dsh（标准 MCP stdio）

```json
{
  "mcpServers": {
    "agentcore": {
      "command": "python",
      "args": ["plugins/agentcore-mcp/mcp_server.py"],
      "env": {
        "AGENTCORE_BASE_URL": "http://127.0.0.1:9753",
        "AGENTCORE_AGENT_ID": "your-agent-id",
        "AGENTCORE_AGENT_KEY": "your-agent-key",
        "AGENTCORE_ADMIN_ID": "admin",
        "AGENTCORE_ADMIN_KEY": "memoria-admin-key",
        "AGENTCORE_EVOLVE_KEY": "evolve-key"
      }
    }
  }
}
```

凭据语义：

- `AGENTCORE_AGENT_ID` / `AGENTCORE_AGENT_KEY`：受保护 API 的 agent 身份（Memoria 注册 badge）
- `AGENTCORE_ADMIN_ID` / `AGENTCORE_ADMIN_KEY`：审批/运维 admin 工具专用（服务端要求
  `x-agent-key == MEMORIA_ADMIN_KEY`）；`ADMIN_KEY` 缺省回退 `AGENTCORE_AGENT_KEY`
- `AGENTCORE_EVOLVE_KEY`：`[code_evolution] evolve_key` 的对应值

## 安全约定

1. 凭据只在调用时读环境变量，不落盘、不写日志、不出现在工具返回体（badge_token 除外，
   那是服务端正常业务返回，工具描述中已要求调用方妥善保管）。
2. 破坏性操作带 `confirm` 字面确认：`DELETE` / `KILL` / `SAVE` / `APPLY` / `APPROVE` / `REJECT`。
3. 所有 agent-core 服务端门禁（审批黄线、隔离仓、dry_run、allow_commit、operation_hash、
   协作可达策略、配额、熔断、四预算）原样保留，插件只透传不绕过。
4. 本目录遵守仓库 AGENTS.md：不写绝对路径、不写密钥、推送走 PR 流程。

## 冒烟测试

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"agentcore_health","arguments":{}}}' \
  | python mcp_server.py
```
