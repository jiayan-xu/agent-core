# Agent-Core 代码审查报告

- **日期**：2026-07-06
- **审查对象**：`C:\Users\user\agent-core`（Rust axum + tao/wry 桌面 Agent，5980 行，端口 9753）
- **定位**：固废运营台 AI 助手桌面端。内置 7 条红线 `ComplianceBoundary`，chat 经 LLM 多轮 tool-calling 路由到 Memoria / Dashboard MCP。
- **方法**：独立安全 + 代码质量走查，覆盖 `main.rs` / `agent.rs` / `boundary.rs` / `harness.rs` / `session.rs` 及全 `src` 注入/执行 sink 扫描。

---

## 裁决

**2 个 P0（今日必须堵），4 个 P1，6 个 P2。**

> 与 dashboard / memoria 同源问题：暴露面默认全网卡 `0.0.0.0` + 部分接口无鉴权。但本项目的 `/api/chat` 是**执行路径**（驱动 agent 跑工具链），危害比前两者（只读）更大。

---

## P0（必须立即修复）

### P0-1 多个业务/写接口无鉴权 + 默认 `0.0.0.0` + permissive CORS
- **位置**：`src/main.rs:236-249`（路由表）、`main.rs:139`（`addr=0.0.0.0:{port}`）、`main.rs:248`（`CorsLayer::permissive()`）。
- **事实**：以下路由**无任何 auth 校验**（仅 `/v1/chat` 有 X-Agent-Id/Key 校验）：
  - `src/main.rs:355` `/api/chat` — 触发 `agent.chat()` 执行工具链
  - `src/main.rs:369` `/api/chat/stream` — 同上（SSE）
  - `src/main.rs:333` `/api/save-config` — **写配置（含 api_key）**
  - `src/main.rs:324` `/api/config` — 泄露 agent_id/server
  - `src/main.rs:634` `/api/register` — 开放注册
  - `src/main.rs:443` `/api/sessions/{id}` GET、`src/main.rs:481` DELETE — 读写会话历史
- **影响**：任何能访问 `0.0.0.0:9753` 的主机可驱动 agent 执行工具。`agent.chat` 经 `boundary.check_tool`（`agent.rs:594`）放行 read/write 级工具 → `query_sql` 查内部固废库（system prompt 明文列出 `vehicle_entrance`/`experiment_data` 表结构，`agent.rs:1195-1207`）、`memory_remember`/`memory_observe` 写 Memoria、`a2a_send` 给其他 agent 发消息。**数据泄露 + 完整性破坏**。permissive CORS 使任意网页可跨域触发（CSRF 风格）。
- **修复**：① 给 `/api/chat`、`/api/chat/stream`、`/api/save-config`、`/api/sessions/{id}` DELETE、`/api/config`、`/api/register` 加统一 auth 中间件；② `host` 默认改 `127.0.0.1`（桌面 app WebView 本就本地）；③ CORS 收紧到 `http://127.0.0.1:9753`。

### P0-2 `/api/save-config` 未授权改写凭证/端点（接管）
- **位置**：`src/main.rs:333-353`。
- **事实**：直接 `cfg.api_key = req.api_key; cfg.agent_id = ...; save_config(&cfg)` 写 `agent.toml`，无鉴权。
- **影响**：任意人可覆盖 API Key、把 `server` 指向恶意 MCP、改 `agent_id` → **接管 agent、滥用 LLM 额度、重定向到攻击者后端**。
- **修复**：该路由必须鉴权；api_key 等敏感字段改写需二次确认/本地解锁。

---

## P1（本周修复）

- **P1-1 开放注册使 `/v1/chat` 鉴权形同虚设**（`main.rs:634-674`）：`/api/register` 无 admin 闸门，`auth_cache` 仅由 register 填充（main.rs:658）。攻击链：先 `register` 拿 `badge_token` → 直接调 `/v1/chat`（auth_cache 命中）。建议 register 加 admin gate 或移除开放注册。
- **P1-2 硬编码 dashboard 凭据**（`main.rs:216-217`）：`("admin","admin123")` 写死源码，调 `http://127.0.0.1:8000/api/login` 重启 agent worker。凭据入源码 + 复用 dashboard 默认弱密码（同源问题）。改为读 env/secret。
- **P1-3 permissive CORS + 0.0.0.0**（main.rs:248/139）：任意网页可跨域打未鉴权端点。
- **P1-4 边界工具分类/放行过宽**（`boundary.rs`）：
  - `DataExfiltrationGuard::check_export`（203）仅**精确匹配** `export_data/send_email/...`，新命名外发工具（如 `exfil`）漏过。
  - `register_from_tools`（541）新工具前缀不匹配 read/dangerous 时默认 `write` → 放行；`SupplyChainGuard` 无 whitelist 时 `source="local"` 恒过 → 不可信 `additional_mcp` 工具可被调用。
  - `query_sql` 归为 read 且 `ExecutionSandbox` 不拦（boundary.rs:151 只拦 `exec_*`/`run_script`）→ 内部 DB 任意 SELECT。
  - 参数级 SQL 注入检测（448-467）是子串黑名单（`' --`、`UNION` 等），可绕过（如 `/* */` 注释、无 `1=1` 的 `OR`）。

---

## P2（清理）

- **P2-1 硬编码绝对 Windows 路径**（`main.rs:314-315, 768-769`）：`C:\Users\user\dashboard\...` 写死在 logo/icon 加载，可移植性差 + 泄露 dashboard 位置。
- **P2-2 确认流可被 unauth 驱动**（`agent.rs:163-176`）：消息为确认词（"确认"等）且存在 pending_action 即执行工具；pending_action 由结果含"确认"/"require_confirm"设置（`agent.rs:694`）。`/api/chat` unauth 下攻击者可借"确认"词触发此前 LLM 置为待确认的写操作。
- **P2-3 `auth_cache` 密钥比较非恒定时间**（`main.rs:544`），TTL 1h 可接受，低风险。
- **P2-4 `agent.toml` 明文存 api_key**（`main.rs:129` save_config 写 toml），明文密钥落盘。
- **P2-5 红线为软阻断**：`delete_*`/`batch_*`/`shutdown_*` 仅归 dangerous→yellow→返回 `REQUIRES_REVIEW` 文本给 LLM（`agent.rs:641`），无 approver 时不真正阻止，依赖 LLM 服从而非硬阻断。
- **P2-6 `harness.db` 每请求 `rusqlite::Connection::open`**（`main.rs:413/454/488`），未设只读、并发多连接管理粗糙（参数化故无注入）。

---

## 已确认安全（给结论）

- **SQL 注入：干净。** `harness.rs`/`main.rs`/`session.rs` 全部参数化（`?1`/`params!`）；全 `src` 扫描无 `format!` 拼 SQL；静态 SQL 字符串无用户输入插值。
- **命令注入：干净。** 无 `subprocess`/`shell` 调用；工具经 MCP HTTP 转发，不直接执行命令。
- **路径穿越：干净。** `chat_history` 的 `session_id` 来自路径但走 `?1` 参数化查询；无用户提供的文件路径拼接。
- **边界真实生效：** `check_tool` 在 `llm_loop`/`execute_plan`/`try_harness_match` 三条执行路径均被调用（`agent.rs:594/454/1104`）——有防线，问题在**放行策略过宽 + 入口无鉴权**，而非完全缺失。boundary 已有较完整单测（boundary.rs:646+），质量基线好。

---

## 行动建议（优先级）

1. **今天**：P0-1（统一 auth 中间件覆盖上述路由 + host 默认 `127.0.0.1` + CORS 收紧）、P0-2（`/api/save-config` 鉴权）。
2. **本周**：P1-1（register 加 admin gate）、P1-2（dashboard 凭据移出源码）、P1-4（export 工具正则/前缀拦截、`query_sql` 强制 SELECT-only、默认开 supply-chain 白名单）、P1-3。
3. **待办**：P2 清理；确认 `additional_mcp` 来源可信；补充 `/api/chat` 的输入速率限制与最大工具轮次硬上限（当前 `max_tool_rounds=3` 仅软限，已在 agent.rs:566 生效，良好）。

> 系统性结论（与 dashboard/memoria 一致）：**默认全网卡绑定 + 入口缺统一鉴权中间件**是跨项目共病。建议在 axum 层用 `.layer(from_fn(auth_mw))` 统一收口，而非逐路由补丁；桌面 app 默认 `127.0.0.1` 即可消除绝大部分 LAN 暴露面。
