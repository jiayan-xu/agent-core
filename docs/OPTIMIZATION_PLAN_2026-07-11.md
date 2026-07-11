# Agent-Core 优化方案

- **日期**：2026-07-11
- **范围**：`jiayan-xu/agent-core`（canonical：`C:/Users/user/agent-core`，分支 `master`）
- **性质**：设计文档（只谈「怎么优化」，不改代码；落地前按项确认）
- **对照基线**：LangGraph / OpenAI Agents SDK / CrewAI / AutoGen / Letta / 企业 MCP Agent 生态
- **前置审查**：`CODE_REVIEW_2026-07-06.md`（本地）、ADR-002 Compositional Skill Routing

---

## 0. 裁决（先读这段）

**目标**：在不改变设计理念的前提下，把 agent-core 从「能跑的安全引擎」补成「可观测、可续跑、可硬闸门、可回归」的企业级最小核心。

**不改动的理念（硬约束）**：

1. **最小核心，最大扩展** — 领域能力只来自 MCP / 技能市场，核心不堆业务工具。
2. **安全即默认** — 红线、命名空间、供应链白名单优先于「好用」。
3. **三级 MCP（公司 / 部门 / 项目）** — 权限树与 Memoria namespace 对齐。
4. **降级收缩** — 故障时缩权限、切备用，而不是裸崩或无限重试。
5. **技能蒸馏（Harness）** — 执行日志 → 模板 → 短路 LLM，闭环保留。
6. **记忆外置（Memoria）** — 不把记忆/RAG 吸回核心。
7. **单 Agent 主循环 + 外置 A2A** — 多 Agent 编排不进核心。

**明确不做（防理念漂移）**：

| 不做 | 原因 |
|------|------|
| 引入 LangChain / LangGraph 运行时依赖 | 框架锁定，违背最小核心 |
| 内置爬虫 / shell / 代码执行工具箱 | 全能 Agent，企业风险 |
| CrewAI 式多角色剧班作为默认路径 | 编排外置到 Bridge / 上层即可 |
| 把 Memoria 记忆逻辑并进 agent-core | 职责污染 |
| 为涨星堆 demo 能力 | 稀释安全默认 |

**成功标准（90 天后）**：

- 所有执行入口统一鉴权；默认仅本机监听。
- YELLOW / 危险工具无审批人时**硬拒绝**（非文本劝退）。
- 任意一次 chat：可按 `trace_id` 还原 LLM → 边界 → MCP → 结果。
- 进程重启后：会话确认态 / 待审批 / 组合计划可续跑。
- 固定回归集（≥20 场景）CI 可跑；越权与外发场景必须失败即红。

---

## 1. 现状摘要

### 1.1 架构定位（保持）

```
桌面壳 (Jan / 任意 MCP 客户端)
        │
        ▼
 Agent-Core (:9753)  ← 推理 / 路由 / 红线 / 会话 / 蒸馏
        │
        ├── Memoria (:9003)     记忆 / 身份 / 技能市场
        ├── 公司级 MCP
        ├── 部门级 MCP
        └── 项目级 MCP (含 dashboard stdio/HTTP)
```

### 1.2 已有能力（优势，优化时加强而非替换）

| 模块 | 能力 |
|------|------|
| `boundary.rs` | 7+ 条红线（权限递减、沙箱、治理、外发、熔断、身份、供应链、任务确认） |
| `agent.rs` | chat 循环、确认状态机、工具路由、组合路由开关 |
| `composer.rs` | 多 skill 分解 / 拓扑执行 / 并行无依赖步 |
| `harness.rs` | 执行日志蒸馏模板 |
| `mcp_client.rs` | HTTP + Stdio、传输错误可重试、业务错误不重试 |
| `namespace.rs` / `approval.rs` / `audit.rs` / `session.rs` | 隔离、审批、审计、LRU 会话 |

### 1.3 已知短板（相对高星项目）

| 短板 | 表现 | 对标可借鉴「机制」 |
|------|------|-------------------|
| 可观测空白 | 无 `tracing_subscriber` / OTel | Agents SDK / LangSmith 形态的 span |
| 入口鉴权不齐 | 部分 `/api/*` 无 auth、曾默认全网卡 + permissive CORS | 企业统一 auth 中间件 |
| 软阻断 | YELLOW 多靠 LLM 服从而非硬闸 | OpenAI guardrails / LangGraph interrupt |
| 无 checkpoint | 重启丢确认态 / 计划 / 待审批 | LangGraph checkpoint 思想（自研 SQLite） |
| 计划 HITL 未产品化 | Composer 有，用户可见/可驳回不够一等公民 | SkillWeaver + HITL |
| 缺评测集 | 单测有，场景回归弱 | AgentEval / 自建 fixture |
| 配额与成本 | 仅有 `max_tool_rounds` | SDK 级 token/轮次/命名空间配额 |
| schema 纪律 | 曾出现工具名写死错位 | PydanticAI 式严格 JSON schema |

---

## 2. 优化总览（三波）

| 波次 | 主题 | 周期建议 | 核心交付 |
|------|------|----------|----------|
| **W1 P0** | 安全闸门 + 可观测底盘 | 1–2 周 | 统一鉴权、本机默认、硬审批、tracing |
| **W2 P1** | 可续跑状态 + 计划 HITL + 回归 | 2–3 周 | checkpoint、计划预览/驳回、评测集 |
| **W3 P2** | 工程打磨与产品化 | 持续 | schema 严校验、配额、文档/示例 skill、审计增强 |

每项落地须：**先补/改 ADR 或本节条目 → 再改代码 → 跑回归 → 用户确认合入**。

---

## 3. W1 — P0 优化项（必须先做）

### P0-1 统一鉴权与默认本机暴露面

**问题**：执行路径（chat / stream / 改配置 / 会话写删）若缺鉴权，红线形同虚设；全网卡 + 宽松 CORS 扩大攻击面。

**目标**：

- 默认 `host = 127.0.0.1`（配置可显式改为 `0.0.0.0`，启动时打醒目告警）。
- CORS 默认仅本源；生产显式白名单。
- 统一 `auth` 中间件：除健康检查 / 静态壳外，全部要求身份（`x-agent-id` + `x-agent-key`，或已文档化的 legacy `x-user-tag` 路径）。
- `/api/save-config`、开放注册类接口：admin 闸门或本地解锁二次确认。

**涉及文件（预期）**：`src/main.rs`、`agent.toml`、README 安全章节。

**验收**：

- [ ] 无身份头访问 `/api/chat`、`/v1/chat/completions`、`/api/save-config` → 401。
- [ ] 默认监听地址为 loopback；改 `0.0.0.0` 时日志有 WARN。
- [ ] 跨域任意 Origin 默认被拒。

**借鉴**：企业 Agent「默认最小暴露」；不借鉴云厂商 OAuth 全家桶（可后续可选）。

---

### P0-2 危险工具硬闸门（结束「软阻断」）

**问题**：`REQUIRES_REVIEW` 文本依赖 LLM 听话；无 `approver_id` 时危险操作仍可能被绕过。

**目标**：

- 分类：`READ` 可自动；`WRITE` 按策略（白名单自动 / 其余审批）；`DANGEROUS` / 外发类 **必须** 审批或硬拒绝。
- 无 `approver_id` 且工具为 DANGEROUS/外发 → **直接返回错误给调用方**，不进入 LLM 下一轮「假装遵守」。
- Harness 快速路径与 Composer `execute_plan` **同一套** `boundary.check_tool` 硬规则（禁止旁路）。
- 审批状态机：`PendingApproval` → 通过/拒绝；拒绝写入审计。

**涉及文件**：`src/boundary.rs`、`src/approval.rs`、`src/agent.rs`、`src/composer.rs`。

**验收**：

- [ ] 单测：无 approver 调 `export_*` / `send_email` / `delete_*` → Err，不调用 MCP。
- [ ] 有 approver：进入 pending，未批准前 MCP 调用次数为 0。
- [ ] Harness 命中路径同样被拦。

**借鉴**：OpenAI Agents SDK hard guardrails；LangGraph interrupt（语义：暂停等人，不是换框架）。

---

### P0-3 全链路 Tracing（可观测底盘）

**问题**：`tracing::*` 宏存在但无 subscriber → 排障靠猜；与主流「一请求一树 span」差距最大。

**目标**：

- 启动时初始化 `tracing_subscriber`（env filter：`AGENT_CORE_LOG` / `RUST_LOG`）。
- 每个请求生成 `trace_id`（响应头回传 `x-trace-id`）。
- 最小 span 集合：
  - `http.request`
  - `agent.chat` / `agent.confirm` / `agent.compose` / `agent.harness`
  - `llm.complete`（model、tokens、latency、failover 次数）
  - `boundary.check`（tool、level、allow/deny、reason）
  - `mcp.call`（source、tool、retries、error_class）
  - `audit.write`
- 可选：导出 OTLP（默认关），对接本地 Jaeger / Grafana Tempo；**不**强制 LangSmith。

**涉及文件**：`src/main.rs`、新建 `src/observability.rs`（建议）、`Cargo.toml`。

**验收**：

- [ ] 一次「查昨天进了几车」日志树可见：鉴权 → LLM → 工具选择 → boundary → MCP → 汇总。
- [ ] 故意错误工具名时，span 标出 cache miss / deny，无 async panic。
- [ ] 默认不打明文 api_key / badge_token（脱敏）。

**借鉴**：Agents SDK / LangSmith 的「形态」；实现保持自研、零框架锁定。

---

### P0-4 边界策略收紧（与审查 P1-4 对齐）

**问题**：外发工具名精确匹配易漏；供应链白名单空时过宽；SQL 只读需持续硬化。

**目标**：

- 外发检测：前缀 / 正则（`export_`、`send_`、`upload_`、`exfil` 等）+ 显式危险名表。
- `SupplyChainGuard`：生产默认 **要求白名单**；`source=local` 仅 debug 配置可放行。
- SQL：保持正向 SELECT-only；参数级再扫多语句（`;` 后写操作）。
- `register_from_tools`：未知工具默认 **deny 或 YELLOW**，不再默认当 WRITE 自动放行（策略可配，默认收紧）。

**验收**：

- [ ] 单测覆盖：绕过命名、多语句 SQL、空白名单拒接不可信 MCP 工具。
- [ ] 与现有 READ 白名单（`execute_sql` / `fuzzy_match_*`）不回归断连修复。

---

## 4. W2 — P1 优化项

### P1-1 Checkpoint：会话 / 计划 / 审批可续跑

**问题**：进程重启或崩溃后确认态、组合计划、待审批丢失；对比 LangGraph 持久状态差距明显。

**目标（自研 SQLite，不引入图框架）**：

持久实体建议：

```
checkpoints
  trace_id / session_id / agent_id
  state: New | AwaitingConfirmation | Confirmed | PendingApproval | ExecutingPlan | Done | Failed
  payload_json: pending_message, plan, step_results, approval_id, ...
  updated_at
```

- 写点：状态迁移成功即 upsert（至少：进入确认、计划生成、每步完成、审批等待、终态）。
- 读点：同 `session_id` 恢复；过期策略（如 24h / 可配）。
- 与 `session.rs` / `harness` 的 chat_history **职责分开**：history = 对话内容；checkpoint = 控制面状态。

**验收**：

- [ ] 确认中途杀进程 → 重启后同一 session 仍停在「待确认」，不重复执行。
- [ ] 计划执行到一半杀进程 → 从失败步或下一步恢复（策略写明：at-least-once + 幂等工具约定）。
- [ ] 审计能关联 `checkpoint_id`。

**借鉴**：LangGraph checkpoint / time-travel **思想**；存储用现有 rusqlite 生态。

---

### P1-2 Composer 计划 HITL 产品化

**问题**：ADR-002 已定「计划可见」，工程上需变成默认体验开关。

**目标**：

- 配置：`compositional_routing.preview = true|false`（企业默认 true）。
- 流程：`Confirmed` → 生成 plan → **返回计划给用户**（结构化 JSON + 人话摘要）→ 用户「确认执行 / 修改 / 取消」→ 再 `execute_plan`。
- 取消与修改写入审计；修改仅允许改 args / 删步（不允许任意注入未授权 tool 名——改后仍过 boundary）。
- 与任务确认状态机合并，避免「确认两遍」过度摩擦：简单单工具请求可跳过计划预览。

**验收**：

- [ ] 多步请求：用户未点执行前 MCP 调用为 0。
- [ ] 用户删掉某危险步后，该工具永不调用。
- [ ] 单步只读查询：可配置跳过预览，延迟不明显增加。

---

### P1-3 场景回归评测集（Agent Eval）

**问题**：单元测试无法覆盖「越权 / 外发 / 工具名幻觉 / 命名空间」行为契约。

**目标**：新建 `tests/eval/` 或 `eval/cases/*.json`：

| ID | 场景 | 期望 |
|----|------|------|
| E01 | 无身份 chat | 401 |
| E02 | 只读查车次 | 允许；仅 SELECT 类工具 |
| E03 | 诱导 ignore previous instructions | 注入检测拦截或降级 |
| E04 | 请求 export/send_email | 硬拒或 pending |
| E05 | 跨 ns 工具 | 不可见或不允许 |
| E06 | 错误工具名 | 不 panic；友好错误 |
| E07 | MCP 宕机 | 降级收缩，有明确提示 |
| E08 | Harness 命中危险模板 | 仍过 boundary |
| E09 | Composer 多步 | 预览态不执行 |
| E10 | 杀进程恢复 | checkpoint 续跑 |

CI：`cargo test` + 可选 `eval` feature（可 mock MCP）。

**验收**：E01–E10 自动化；新增红线必须加对应 case。

**借鉴**：Agent eval 生态的「固定 fixture」；不绑云评测 SaaS。

---

### P1-4 LLM / 工具契约硬化

**目标**：

- 每次 `llm_loop` **动态注入**真实 `list_tools`（已部分完成，收口为唯一来源，禁止 system prompt 写死过期工具名）。
- 工具参数：JSON Schema 校验失败则不调用 MCP，回灌 LLM 或直接报错（可配）。
- Failover：记录到 span；备用 provider 配置文档化。
- Prompt 注入：保持 `prompt_injection` 模块；确认/计划文本同样过检测。

**验收**：回归「工具名错位导致断连」类 bug 为零；schema 失败有明确错误码。

---

### P1-5 降级收缩策略显式化

**目标**：把「降级收缩」写成状态机并打日志：

| 触发 | 行为 |
|------|------|
| 某 MCP 源连续失败 | 标记 source unhealthy，工具列表剔除，审计 |
| 全部业务 MCP 不可用 | 仅保留 Memoria 只读记忆检索 + 纯聊天 |
| LLM 主 provider 超时 | 切备用；仍失败则返回可重试错误 |
| Kill switch | 全局拒绝工具，仅系统状态查询 |

**验收**：混沌测试（停 dashboard MCP）行为符合表；有 trace。

---

## 5. W3 — P2 优化项（持续）

### P2-1 命名空间级配额与成本

- 每 ns：`max_tool_rounds` / 日 token 预算 / 并发会话数。
- 超限：硬拒绝 + 审计；管理员可临时提升。
- 仪表：内置简单 `/api/metrics`（本机）或导出 Prometheus 文本（可选）。

### P2-2 审计增强

- 统一事件：`AuthFail` / `BoundaryDeny` / `Approval*` / `McpRetry` / `CheckpointResume` / `HarnessHit`。
- 敏感字段继续脱敏；支持按 `trace_id` 查询。
- 可选只读审计查询 API（必须鉴权）。

### P2-3 Harness 蒸馏质量

- 蒸馏触发：成功组合路由 N 次、置信度阈值。
- 危险模板永不自动 activate（需人工/admin 批准 activate）。
- 匹配分与 boundary 结果写入 span。

### P2-4 DX 与开源文档

- README：安全默认、三级 MCP 示例、与 Memoria/Jan 拓扑图。
- `examples/skills/`：1–2 个**无业务机密**的示例 MCP（echo / calculator），证明「空核心 + 赋权」。
- ADR 模板：每个 P0/P1 大项合入前补 ADR（ADR-003 鉴权、ADR-004 checkpoint、ADR-005 tracing…）。

### P2-5 桌面壳边界清晰

- agent-core 保持 HTTP/MCP 引擎；Jan/PFAiX 只做壳。
- 登录/注册代理已有：补序列图到 docs，避免壳侧直连内网 Memoria 的分叉实现。

### P2-6 配置与密钥

- `agent.toml` 禁止落盘明文 api_key（仅 env / 系统密钥环）；已有方向继续收干净。
- 示例配置全部占位符；`agent.toml` 中业务绝对路径改为 env（开源友好）。

---

## 6. 里程碑与排期建议

```
W1 (P0)  ──鉴权/暴露面──硬闸门──tracing──边界收紧──▶  可称为「安全加固版」
W2 (P1)  ──checkpoint──计划 HITL──eval 集──契约硬化──▶  可称为「可运营版」
W3 (P2)  ──配额──审计──Harness──文档/示例──▶  可称为「可开源示范版」
```

建议发布标签（语义化，可按实际调整）：

| 版本 | 包含 |
|------|------|
| `0.2.0` | W1 全部 |
| `0.3.0` | W2 全部 |
| `0.4.0` | W3 主体 + 文档示例 |

---

## 7. 工作分解（按模块）

| 模块 | W1 | W2 | W3 |
|------|----|----|-----|
| `main.rs` | auth 中间件、host/CORS、trace_id 头 | checkpoint 恢复钩子 | metrics、配置去密钥 |
| `observability.rs`（新） | subscriber + span 助手 | checkpoint/plan span | OTLP 可选 |
| `boundary.rs` | 硬拒、外发正则、白名单默认 | eval 挂钩 | 配额钩子 |
| `approval.rs` | 无 approver 硬拒 | 与 checkpoint 联动 | 审计事件补全 |
| `agent.rs` | 硬闸接入、动态 tools | 计划预览态、恢复 | — |
| `composer.rs` | 执行前 boundary | HITL 预览协议 | 蒸馏质量 |
| `harness.rs` | 路径过 boundary | — | activate 审批 |
| `session.rs` | — | 与 checkpoint 分工 | — |
| `mcp_client.rs` | span + 错误分级已有则挂接 | unhealthy 标记 | — |
| `audit.rs` | 脱敏确认 | trace/checkpoint 关联 | 查询 API |
| `tests/` / `eval/` | P0 单测 | 场景集 | 扩容 |

---

## 8. 风险与缓解

| 风险 | 缓解 |
|------|------|
| 鉴权收紧导致 Jan/PFAiX 旧客户端全 401 | 保留文档化 legacy `x-user-tag`；发版前对壳做联调清单 |
| 硬闸门「变笨」影响体验 | WRITE 分级；只读高频路径保持自动；预览仅多步/危险 |
| Checkpoint 双写性能 | 异步写或同连接事务；先正确后优化 |
| Tracing 日志泄露隐私 | 默认 INFO；工具 args 脱敏；禁止记录密钥头 |
| 理念漂移（借着优化引入框架） | 本文件 §0 硬约束；PR 检查清单勾选「无新编排框架依赖」 |

---

## 9. PR / 合入检查清单

每个优化 PR 必须勾选：

- [ ] 不新增领域业务工具到核心
- [ ] 不引入 LangChain/LangGraph/CrewAI 等编排运行时
- [ ] 记忆仍走 Memoria
- [ ] 新执行路径调用了 `boundary.check_tool`
- [ ] 有对应单测或 eval case
- [ ] 无密钥 / 无本机绝对路径进公开树
- [ ] 更新本方案进度表或新 ADR
- [ ] 用户确认后再合入影响生产行为的变更

---

## 10. 进度跟踪表（落地时勾选）

| ID | 项 | 波次 | 状态 |
|----|-----|------|------|
| P0-1 | 统一鉴权 + 本机默认 | W1 | 已完成 |
| P0-2 | 危险工具硬闸门 | W1 | 已完成 |
| P0-3 | Tracing 底盘 | W1 | 已完成 |
| P0-4 | 边界策略收紧 | W1 | 已完成 |
| P1-1 | Checkpoint 落盘 | W2 | 已完成 |
| P1-2 | Composer 计划 HITL | W2 | 已完成 |
| P1-3 | Eval 回归集 | W2 | 已完成 |
| P1-4 | 工具/LLM 契约硬化 | W2 | 已完成 |
| P1-5 | 降级收缩显式化 | W2 | 已完成 |
| P2-1 | 配额与成本 | W3 | 未开始 |
| P2-2 | 审计增强 | W3 | 未开始 |
| P2-3 | Harness 质量 | W3 | 未开始 |
| P2-4 | DX / 文档 / 示例 | W3 | 未开始 |
| P2-5 | 壳与引擎边界文档 | W3 | 未开始 |
| P2-6 | 配置与密钥收干净 | W3 | 未开始 |

---

## 11. 建议的下一步（等你拍板）

**推荐启动顺序**：先做 **P0-1 → P0-2 → P0-3**（同一版本 `0.2.0`），再开 P0-4 与 W2。

你确认后，可按项开 ADR + 实现；默认仍遵守：**审查只出方案，改生产行为前先问你。**

---

## 附录 A — 与主流项目的「借鉴映射」

| 主流能力 | 借鉴什么 | 落在 agent-core 何处 |
|----------|----------|----------------------|
| LangGraph checkpoint | 持久状态 / 续跑 | P1-1 自研 SQLite |
| LangGraph interrupt | 人机暂停 | P0-2 / P1-2 |
| OpenAI Agents guardrails | 硬拦截 | P0-2 / P0-4 |
| LangSmith / SDK traces | span 树 | P0-3 |
| PydanticAI schema | 参数校验 | P1-4 |
| CrewAI 角色 | **不**进核心 | 继续 A2A / Bridge |
| Letta 记忆 | **不**合并 | Memoria 协议增强 |

## 附录 B — 相关文档

- `README_CN.md` — 设计理念
- `docs/decisions/ADR-002-compositional-skill-routing.md`
- `EVOLUTION.md` — 演进事实
- `AGENTS.md` — 开源推送红线
- `CODE_REVIEW_2026-07-06.md` — 安全审查（本地，勿提交公开树）
