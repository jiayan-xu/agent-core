# Agent-Core

> Enterprise-grade AI agent engine. Lightweight, secure, MCP-native. Built in Rust.

## Why Agent-Core?

### The Enterprise Problem

Most AI agent frameworks try to do everything. They ship with built-in tools for web scraping, code execution, image generation — the kitchen sink. This is **dangerous** in an enterprise setting.

A finance person doesn't need web coding tools. An HR specialist shouldn't have database write access. An operator shouldn't be able to execute shell commands.

**All-in-one agents are a security liability, not a productivity boost.**

### Our Approach

Agent-Core takes the opposite approach — it provides **only the basic agent abilities**:

- Talk to LLMs
- Call MCP tools
- Enforce security boundaries
- Manage sessions and memory

Everything else comes from **skills**, distributed by administrators. The agent starts empty. It grows only the capabilities its user needs.

```
Company MCP (enterprise-wide skills: auth, HR policies, org data)
    └─ Department MCP (domain skills: finance, HR, operations)
        └─ Project MCP (project-specific tools)
            └─ User Role (assigned skills)
```

**Agent-Core's mission is not to replace humans. It's to be a true AI assistant — capable within its responsibility scope, and no more.**

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Desktop App │────▶│  Agent-Core  │────▶│   Memoria    │
│  (any MCP    │     │  (:9753)     │     │  (:9003)     │
│   client)    │     │              │     │              │
└──────────────┘     └──────┬───────┘     └──────────────┘
                             │
                     ┌───────▼───────┐
                     │   MCP Sources │
                     │  ┌─────────┐  │
                     │  │ Company  │  │  (enterprise-wide)
                     │  ├─────────┤  │
                     │  │Dept/HR   │  │  (department-level)
                     │  ├─────────┤  │
                     │  │ Project │  │  (project-specific)
                     │  └─────────┘  │
                     └───────────────┘
```

**Desktop App** 是桌面壳 **Jan / PFAiX**（官方壳，基于 Tauri）——只做壳，不直接连内网 Memoria，所有请求经 agent-core 转发。任何 MCP 兼容客户端亦可接入。壳与引擎的边界与序列图见 [`docs/SHELL_ENGINE_BOUNDARY.md`](docs/SHELL_ENGINE_BOUNDARY.md)。
**Agent-Core** handles reasoning, tool routing, safety, and skill management.
**Memoria** provides persistent memory and cross-agent knowledge sharing.
**MCP Sources** define what each user/role can do — no more, no less.

## Design Philosophy

### Minimal Core, Maximal Extension
Agent-Core ships with no domain-specific skills. It's a blank canvas. Skills are installed from the skill market or configured by administrators per role. This keeps the core small, secure, and auditable.

### Security by Default

**默认本机、默认鉴权、默认拒绝。**

- **仅本机监听**：默认 `127.0.0.1`，不暴露公网；公开部署请走反向代理 + TLS。
- **统一鉴权**：所有 API 需经 `auth_middleware`；桌面壳（Jan / PFAiX）通过 `x-user-tag` 自动注册身份并向 Memoria 反查命名空间授权。
- **危险工具硬闸门**：`delete_*` 等红线工具无审批人时直接硬拒绝，不进入 LLM 下一轮、不调用 MCP。
- **外发收敛**：`export_/send_/upload_/webhook_/exfil/share_` 等前缀动作走确认 / 审批。
- **Kill switch**：`POST /api/admin/killswitch` 可全局拒绝工具、仅留状态查询（受统一鉴权保护）。
- **降级收缩**：某 MCP 源连续失败 → 标记 unhealthy 剔除并审计；全部业务 MCP 不可用 → 仅 Memoria 只读 + 纯聊天；LLM 主备皆失败 → 返回可重试错误。状态见 `GET /api/admin/degrade`。

7 red lines enforced at runtime: permission decay, code isolation, governance immutability, data exfiltration prevention, kill switch, unique identity, and supply chain vetting. Every tool call is checked against all 7 lines.

### Three-Level MCP
- **Company MCP**: Enterprise-wide tools (auth, organizational data, compliance)
- **Department MCP**: Domain-specific tools (finance, HR, operations, R&D)
- **Project MCP**: Project-level tools (code repos, CI/CD, monitoring)

### Fail-Safe Degradation
When things go wrong, Agent-Core **shrinks permissions** instead of crashing: MCP down → only basic query tools available; LLM timeout → fallback provider; lock poisoned → graceful recovery.

### Skill Distillation (Harness)
The more you use it, the smarter it gets for your domain. Execution logs are distilled into reusable skill templates. Repeated tasks skip the LLM entirely — matched directly to known solutions.

## Features

- **LLM Integration** — Multi-provider with automatic failover
- **MCP Protocol** — Native client for Company/Department/Project MCP sources
- **Skill Market** — Install skills per user role, white-list controlled
- **7 Red Lines Safety** — Permission chain, sandbox, governance, exfiltration guard, kill switch, identity, supply chain
- **Task Confirmation Gate** — SAD-style rephrasing before dangerous actions
- **Skill Distillation** — Auto-learn from execution logs
- **Session Management** — LRU-based conversation history with namespace isolation
- **Audit Logging** — Structured audit trail with sensitive key masking
- **Embedded Web UI** — Built-in chat interface at `http://localhost:9753`

## Quick Start

### Build & Run

```bash
cargo build --release
cp agent.toml.example agent.toml
# 编辑 agent.toml；密钥请用环境变量注入（见下），不要写明文

# 默认即无窗服务（监听 127.0.0.1:9753）；勿裸启 GUI，「AI 助手」窗需显式 --gui
./target/release/agent-core
# 等价：./target/release/agent-core --service
# Windows: target\release\agent-core.exe
# 调试桌面窗（一般不要）：target\release\agent-core.exe --gui
```


### 密钥不落盘（P2-6）

`agent.toml` 中**不要写明文密钥**。两种注入方式：

1. 配置文件用 `${ENV_VAR}` 占位符，运行时展开：
   ```toml
   api_key = "${AGENT_API_KEY}"
   memoria_admin_key = "${MEMORIA_ADMIN_KEY}"
   [[mcp_source]]
   name = "finance-dept"
   token = "${FINANCE_MCP_TOKEN}"
   ```
2. 或直接在环境变量中提供 `AGENT_API_KEY` / `MEMORIA_ADMIN_KEY`（优先级最高，覆盖配置文件）。

> `agent.toml` 与 `.env` 已在 `.gitignore`，不会进入公开仓库。

### Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `agent_id` | `default` | Agent identifier |
| `api_key` | — | LLM API key |
| `server` | `http://127.0.0.1:9003` | Memoria server |
| `port` | `9753` | HTTP port |
| `memoria_admin_key` | — | Memoria admin key |
| `[[mcp_source]]` | — | MCP sources (company/dept/project) |

### Multi-Level MCP Example

```toml
# Company MCP
[[mcp_source]]
name = "company-hr"
url = "http://company-mcp.internal/hr"
token = "${COMPANY_MCP_TOKEN}"

# Department MCP
[[mcp_source]]
name = "finance"
url = "http://dept-mcp.internal/finance"
token = "${DEPT_MCP_TOKEN}"

# Project MCP
[[mcp_source]]
name = "project-data"
url = "http://localhost:8000/mcp"
```

## Project Structure

```
src/
├── main.rs       — HTTP server, routes, config, auth middleware
├── agent.rs      — Core agent loop, confirmation state machine, MCP routing
├── llm.rs        — LLM client with failover (chat + streaming)
├── mcp_client.rs — MCP protocol client (HTTP + stdio)
├── boundary.rs   — 7 red lines safety, namespace gating, exfiltration guard
├── checkpoint.rs — P1-1 Checkpoint 控制面（与数据面分离的续跑状态机）
├── degrade.rs    — P1-5 降级收缩状态机 (Normal/PartialDegraded/MemoriaReadonlyChat/KillSwitch)
├── composer.rs   — Multi-step task decomposition (HITL 预览)
├── approval.rs   — Human-in-the-loop approval
├── audit.rs      — Audit logging (敏感字段脱敏)
├── session.rs    — Session state and LRU history
├── namespace.rs  — Multi-tenant namespace isolation
├── harness.rs    — Skill distillation engine
└── chat.html     — Embedded web chat UI
```

## Comparison

| System | vs Agent-Core |
|--------|--------------|
| **All-in-one agents** | Ship with everything, hard to secure per role |
| **LangChain Agent** | Framework-locked, Python-only, no built-in safety |
| **AutoGPT** | No safety boundaries, no skill distillation |
| **Agent-Core** | **Minimal core + role-based skills, 7 safety lines, MCP-native** |

## AI Collaboration Note

> Agent-Core's code is approximately **99% AI-assisted** (Claude, DeepSeek, Doubao).
> Architecture design, safety strategy, and technology choices are human-led.

## Examples & Design Records

- **示例技能（空核心 + 赋权的活示范）**：[`examples/skills/`](./examples/skills) — 含 `echo` / `calculator` 两个零机密 stdio MCP 服务，可直接接线验证链路。
- **架构决策记录（ADR）**：[`docs/decisions/`](./docs/decisions)
  - ADR-002 组合式 Skill 路由
  - ADR-003 统一鉴权与本机默认（P0-1）
  - ADR-004 Checkpoint 控制面落盘（P1-1）
  - ADR-005 Tracing 可观测底盘（P0-3）
- **优化路线图**：[`docs/OPTIMIZATION_PLAN_2026-07-11.md`](./docs/OPTIMIZATION_PLAN_2026-07-11.md) — W1(P0 安全) / W2(P1 可运营) / W3(P2 可开源示范) 全量条目与进度。

## License

MIT

## Related

- [Memoria](https://github.com/jiayan-xu/memoria) — Persistent memory and knowledge sharing
