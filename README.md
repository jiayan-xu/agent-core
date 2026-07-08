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

**Desktop App** can be any MCP-compatible client (Jan, Claude Desktop, custom).
**Agent-Core** handles reasoning, tool routing, safety, and skill management.
**Memoria** provides persistent memory and cross-agent knowledge sharing.
**MCP Sources** define what each user/role can do — no more, no less.

## Design Philosophy

### Minimal Core, Maximal Extension
Agent-Core ships with no domain-specific skills. It's a blank canvas. Skills are installed from the skill market or configured by administrators per role. This keeps the core small, secure, and auditable.

### Security by Default
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
cp agent.example.toml agent.toml
# Edit agent.toml with your LLM API key

./target/release/agent-core
```

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
├── main.rs       — HTTP server, routes, config
├── agent.rs      — Core agent loop, confirmation state machine
├── llm.rs        — LLM client with failover (chat + streaming)
├── mcp_client.rs — MCP protocol client
├── boundary.rs   — 7 red lines safety
├── composer.rs   — Multi-step task decomposition
├── approval.rs   — Human-in-the-loop approval
├── audit.rs      — Audit logging
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

## License

MIT

## Related

- [Memoria](https://github.com/jiayan-xu/memoria) — Persistent memory and knowledge sharing
