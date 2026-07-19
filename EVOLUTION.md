# agent-core 演进日志

## 2026-07-06 — McpClient 枚举重构 + Stdio 传输支持

### 背景
dashboard 剥离 LLM 后，agent-core 需要通过新的方式连接 dashboard 能力。原有的 HTTP-only MCP 客户端无法覆盖子进程场景。

### 变更
- **`src/mcp_client.rs`** — `McpClient` 从单一 struct 重构为枚举：
  - `McpClient::Http(HttpMcpClient)` — HTTP(S) 远程连接
  - `McpClient::Stdio(Arc<StdioMcpClient>)` — 子进程 stdin/stdout JSON-RPC
  - 所有方法（`call`、`list_tools`、`call_json`）通过枚举代理，调用方零改动
- **`src/main.rs`** — `McpSourceConfig` 新增 `command`/`args` 字段，`build_agent()` 根据配置创建对应客户端
- **`src/agent.rs`** — `AgentConfig.additional_mcp` 类型扩展为 4 元组，`AgentCore::new()` 支持 stdio 分支
- **`agent.toml`** — 新增 `dashboard`（HTTP）和 `dashboard-stdio`（stdio）双源配置

### 验证
- 编译通过（8925 KB）
- stdio MCP 端到端测试通过：系统状态查询、车牌查询、日统计
- 向后兼容：所有 HTTP MCP 调用（Memoria）零改动

---

## 2026-07-09 — Task Workflow 确认机制 + 阿里 SkillWeaver 组合路由 + Harness 蒸馏闭环

### 新增功能

#### 1. 任务级确认状态机（借鉴 task-workflow）
- 新增 `SessionState` 三态枚举（New / AwaitingConfirmation / Confirmed）
- `chat()` 入口集成确认状态机：任务类请求先复述确认再执行
- 回复带步骤前缀：`[Step 1/3: 确认理解]` → `[Step 2/3: 执行 → Step 3/3: 交付]`
- 已确认会话支持话题切换检测和暂停询问
- **文件**: `src/agent.rs`

#### 2. 第 8 条红线 — TaskConfirmationGate
- `requires_confirmation(msg)` — 判断消息是否需要复述确认
- `detect_topic_switch(msg, task)` — 中文 2-char 滑动窗口话题检测
- **文件**: `src/boundary.rs`

#### 3. SAD 风格增强复述（借鉴阿里 SkillWeaver）
- `rephrase_and_confirm` 并行获取记忆 + 可用工具列表
- 注入 system prompt，LLM 复述时对齐能力词汇表
- **文件**: `src/agent.rs`

#### 4. 多 Skill 组合路由
- 新增 `composer.rs` 模块：`StepPlan` / `ExecutionPlan` 数据结构 + `decompose()` 函数
- LLM 将请求拆解为带依赖关系的多步 JSON 执行计划
- `execute_plan()` 按依赖拓扑序执行，支持 `step_N` 占位符引用
- 无依赖步骤**并行执行**（`futures::future::join_all`）
- 配置开关 `enable_compositional_routing: bool`
- **文件**: `src/composer.rs`（新增）, `src/agent.rs`, `src/lib.rs`, `src/main.rs`

#### 5. Harness 蒸馏闭环
- 组合路由执行成功后自动记录摘要 `ExecutionLog`
- 触发 `distill_from_logs` 从积累日志生成 Harness 模板
- 后续相似任务直接命中 Harness 快速路径
- 闭环：composer → execution_log → Harness → try_harness_match
- **文件**: `src/agent.rs`

#### 6. 设计文档
- ADR-002: Compositional Skill Routing
- **文件**: `docs/decisions/ADR-002-compositional-skill-routing.md`

### 技术细节

- `AgentConfig` 新增 `enable_compositional_routing: bool`
- `AgentCore` 新增 `session_state` / `pending_original_message` 字段
- 新增 4 个单元测试（TaskConfirmationGate）
- 全部 30 个测试通过

### 待做
- 无依赖步骤的并行执行已完成
- e2e 集成测试（需要真实 MCP 源运行）
- 组合路由执行日志蒸馏到 Harness 的闭环已完成

## 2026-07-08 — 开源隐私与安全整改

### 背景
开源后发现工作区残留硬编码绝对路径与内部审查文档，按隐私红线统一清理。

### 变更
- **硬编码路径移除**：`src/main.rs` logo/icon 加载去除 2 处写死 `C:\Users\<user>\dashboard\...` 的绝对路径，仅保留工作目录相对路径（`logo.png` / `static/logo.png` / `assets/logo.png`）
- **内部文档移出公开树**：`CODE_REVIEW_2026-07-06.md` 等内部审查文档 `git rm --cached`（本地保留），补全 `.gitignore`（`CODE_REVIEW_*.md` / `RUST_REWRITE_*.md` / `DESIGN_*.md` 等）
- **密钥轮换**：`MEMORIA_ADMIN_KEY` 改为随机值；agent API key 在提供方注销旧值并换发新 key
- **`.env` / 配置纳入忽略**：密钥走环境变量 / `.env`（已 gitignore），代码只读 `std::env::var(...)`
- **历史扫描**：全量 `git rev-list --all` 扫描，旧明文密钥已在提供方注销（惰性死串），无需改写历史
- **公开默认分支切换**：将 GitHub 默认分支由 `main`（空壳脚手架）切换为 `master`（功能完整且已清理），使公开门面为真实代码库

### 当前状态
| 项 | 状态 |
|------|------|
| 工作区硬编码路径 | ✅ 已清除 |
| 内部文档泄漏 | ✅ 已移出公开树 |
| admin key 轮换 | ✅ |
| agent API key 换发 | ✅ |
| 公开历史改写 | ⛔ 免做（旧 key 已注销） |

---

## 2026-07-10 — 兼容 x-user-tag + ASCII 命名空间 + badge 传播修复

### 背景
PFAiX 桌面端聊天只发 `x-user-tag`（随机安装 ID），不发 `x-agent-id`/`x-agent-key`；原 `handle_register` 用硬编码中文公司名生成 `agent_id`，中文无法进 HTTP 头/session_id → 稳定 401「请先注册」。

### 变更
- **`src/main.rs` `authenticate()`**：`x-agent-id` 为空时回退 `x-user-tag`（ASCII 安全）；回退身份用 `MEMORIA_ADMIN_KEY` 环境变量代替客户端 `x-agent-key` 去查/注册 Memoria。
- **`src/agent.rs` `handle_register`**：`COMPANY` 由硬编码中文改为 ASCII slug `cs-pufa-2nd-thermal`；部门/姓名 ASCII 清洗。
- **badge 传播修复（P0）**：原 `handle_register` 自己随机生成 `badge_token` 返回，却没传给 Memoria（`register_agent` 调用没带）→ 客户端 key 与 Memoria 存值对不上 → `get_allowed_ns` -32001 → 聊天 401。改为用 Memoria `register_agent` 响应返回的 `AgentBadge.badge_token` 覆盖本地 token。
- **自动入网**：`allowed_ns` 为空且身份未注册时，自动 `register_agent` 到 `org/cs-pufa-2nd-thermal`（公司根），首次聊天即入网。

### 验证
- 模拟 PFAiX 只发 `x-user-tag` 打 `/v1/chat/completions` → 200 且返回真实 AI 回复（不再 401）；裸请求无头仍 401（闸门保留）。
- `agent.toml` 的 mcp_source namespace 前缀已对齐 `org/cs-pufa-2nd-thermal/...`，与 Memoria `check_ns_access` 祖先匹配一致。

---

## 2026-07-11 — 本地账密登录体系 + 工具调用断连根因修复

### 背景
两条线在同一批次落地：
1. **登录身份**：PFAiX 需要真实员工账密（此前仅随机安装 ID 的 legacy 无登录模式）；财务机等分发端连不到内网 Memoria，注册/登录必须经 agent-core 代理。
2. **聊天断连**：查库类问题（如「昨天进了几车」）在 ~8.5s 稳定报 `connection failed`，纯聊天正常 —— 定位为工具调用路径的 async 运行时 panic。

### 变更

#### A. 本地账密登录/注册代理（`src/main.rs`）
- 新增路由 `/api/login` 与 `/api/register_user`，以 admin 身份代理转发 Memoria `login_user` / `register_user`（分发端免直连内网）。
- `sanitize_user_id()`：user_id 作为 agent_id 会进 HTTP 头与 session_id，严格 ASCII 清洗（仅字母/数字/`_`/`-`/`.`）。
- **legacy 与登录模式分流**：仅 legacy（无 `x-agent-id`、仅 `x-user-tag`）才用 admin key 无口令自动开户；登录模式身份不存在时必须走 `register_user`（带口令），否则口令形同虚设。
- **按安装实例隔离 ns（B2）**：自动开户分配 `agent/{install_id}` + `org/cs-pufa-2nd-thermal` 双 ns（个人记忆隔离 + 保留 dashboard 共享工具可见性），逗号写入同一 namespace 字段，缓存失效回读时不丢 dashboard。
- `handle_v1_chat` session_id 修复：用真实 `session_id` 取代写死的 `jan/{agent_id}`。

#### B. MCP 传输健壮性（`src/mcp_client.rs`）
- `HttpMcpClient.call` 错误分级：**传输层错误（连接失败/超时）可重试**；**JSON-RPC 业务错误（鉴权/参数错误）不重试直接返回** —— 避免把一次鉴权失败当传输错误重试 3 次，放大对端调用量（曾致 Memoria CPU 飙升）。
- 结果抽取改为逐层 `get()` 安全解析，消除 index panic 隐患。
- `spawn_process` 加 Windows `CREATE_NO_WINDOW`(0x08000000)：修复每次调 stdio MCP（python）弹出黑色控制台窗口。

#### C. 工具调用断连根因修复（`src/agent.rs` + `src/boundary.rs`）— P0
- **断连真根因**：`find_mcp_for_tool()` 同步函数内调 `tool_route_cache.blocking_lock()`（tokio Mutex），被 `find_mcp_for_tool_async()` 在 async 上下文调用 → 运行时线程内 `blocking_lock` **panic** → axum handler 任务崩溃 → TCP 连接被 drop → 前端三地址 failover 全废、报 `connection failed`。触发点是 LLM 去调一个**不存在的工具名**（缓存未命中 → 走 fallback → 命中 panic）。→ `find_mcp_for_tool` 改 async + `.lock().await`，调用处加 `.await`。
- **工具名错位（P1）**：system prompt 写死 `query_sql`/`query_plate`，真实 MCP 工具实为 `execute_sql`/`fuzzy_match_plate`；普通 `llm_loop` 路径未动态注入真实工具清单（只有确认路径做了）→ LLM 调错工具或退化成问候。→ `llm_loop` 取得工具后动态注入真实工具清单，`build_system_prompt` 过期工具名改真名。
- **权限归类（`boundary.rs`）**：`register_from_tools` 启发式把 `execute_sql`/`fuzzy_match_*` 因前缀不匹配错判为 WRITE；补充规则将 SQL 查询类与模糊匹配/审阅类归为 READ，并加入默认 READ 白名单兜底。

### 验证
- 用新二进制重启生产实例，登录后「昨天进了几车」**200 OK（7-8s，不再断连）**，返回真实进厂车次/车辆数/吨位汇总及企业分布明细，LLM 正确调用 `execute_sql` 查库（此前该路径稳定 panic 断连）。
- 纯聊天路径不受影响；裸请求无身份头仍 401（闸门保留）。

### 遗留/改进点
- 源码未初始化 tracing subscriber，所有 `tracing::*` 为空操作 → 无法靠日志排障（后续可补 `tracing_subscriber::fmt().with_env_filter(...)`）。

## 2026-07-11 (evening) — 暗知识层夜间巩固 + NER 真实体图谱（A2+B2）

### 背景
agent-core 已有 `run_insights` 洞见发现雏形，但只处理当前会话观察，无**跨会话模式提炼**和**实体图谱**。设计文档确定架构：agent-core 出脑子（self.llm.chat），memoria 当哑存储（纯 SQL）。夜间巩固填补了「观察→模式→可搜索暗知识」的空白；NER 实体提取替换了 graph.rs 的旧启发式假图谱。

### 变更

#### A2. 通用 consolidate(ns) 编排器（`src/agent.rs`）
- 新增 `consolidate(ns)` 方法，复用 `run_insights` 的 McpClient 模式：
  1. `dream_state_get` 取游标（首跑 → 1970-01-01，全量处理）
  2. `memory_fetch_unconsolidated` 拉 200 条 observation（namespace+created_at 过滤空 content）
  3. LLM 提炼 ≤5 条跨会话 pattern
  4. `memory_remember(category=pattern)` 写回
  5. `dream_state_update` 推进游标（cursor_ts + runs + items_out）
- **追加 NER 第二阶段**：同一批原料通过第二轮 LLM 调用提取实体（9 类：person/system/tool/concept/org/project/location/event/other）和关系，调 `entity_upsert`（幂等 name+ns）/ `entity_add_edge`（去重）写入，同时 `memory_remember(category=fact)` 落库便于搜索。
- **管理员身份**：以 `MEMORIA_ADMIN_KEY` 跨 ns 读 `agent/xujiayan` 的 11 万观察原料。

#### B2. 低峰定时器（`src/main.rs`）
- 导入 `chrono::Timelike`，30 分钟巡逻循环内加低峰闸 `02:00-05:00` 本地时间触发
- 遍历 `CONSOLIDATE_NAMESPACES` 环境变量（默认 `agent/xujiayan`）
- 关定时器即回退（零侵入）

### 验证
- **A3 联调**：手动模拟全链路 — dream_state_get → fetch_unconsolidated(200条多样观察) → 提炼 5 pattern → memory_remember(category=pattern) → dream_state_update → 幂等跳过已处理批次 ✅
- **B4 联调**：entity_upsert(agent-core/memory_search/暗知识层) + entity_add_edge(calls/builds) + entity_search → memory_graph 返回 nodes=3 edges=2 ✅
- 服务 :9753 运行中，凌晨 02:00 自动触发

## 2026-07-11 (SSE 修复) — `/v1/chat/completions` 返回标准流式响应

### 背景
PFAiX 聊天弹窗 + 回复空白的根因之一是 agent-core 对 `stream:true` 仍返回整块 `application/json`；前端 Vercel AI SDK 按 SSE 解析，读不到 `data:` 分块而报错。此前前端靠 `makeAgentCoreFailoverFetch` 转写 JSON→SSE 绕过，但服务端未真正兼容。

### 变更（`src/main.rs`）
- `handle_v1_chat` 增加 `req.stream` 分支：
  - `stream=true` → 返回 `text/event-stream`，使用 `Sse::new(...)` 通过 `tokio::sync::mpsc` 异步推送
  - 输出标准 OpenAI `chat.completion.chunk`：role 起始事件 → 3 字分片 content（20ms 节奏）→ finish_reason=stop → `[DONE]`
  - `stream=false` 或未传 → 保持原 `application/json` 响应

### 验证
- 非流式：`Content-Type: application/json`，返回 `chat.completion` 对象 ✅
- 流式：`Content-Type: text/event-stream`，解析得到完整回复，`[DONE]` 结束 ✅
- 服务 :9753 运行正常，PFAiX 聊天不再依赖前端转写

## 2026-07-14 — Dream 巩固闭环 + health 聚合 embed + 默认无窗

### 背景
夜间巩固此前会硬编码默认 ns、低峰窗口内可能重复跑；`/health` 只报自身 ok，托盘/壳无法判断嵌入通道；裸启 `agent-core` 默认弹出「AI 助手」WebView，运维重启时易误开 GUI。

### 变更
- **Dream 闭环**（`src/main.rs` / `src/agent.rs`）
  - 低峰 **02–04 点本地、每日最多一轮**；默认 ns=`agent/{agent_id}`，可用 `CONSOLIDATE_NAMESPACES` 覆盖
  - `POST /api/admin/consolidate` 手动触发（鉴权：`x-agent-id` + `x-agent-key`）
  - consolidate 以本 Agent + `MEMORIA_ADMIN_KEY` 调 Memoria（不用字面 `"admin"`）
- **health**：公开 `/health` 聚合 Memoria `/health.embed` + 最近 `dream` 摘要；整体 `ok|degraded|fail`
- **默认无窗**：默认 / `--service` 均不弹桌面窗；仅 `--gui` / `--desktop` 开「AI 助手」；README 同步

### 验证
- Memoria embed `pass` 时 agent-core `/health` → `status=ok`，含 `memoria.embed` / `dream`
- 手动 consolidate → `trigger=manual`，`dream` 从 `never` 更新；空观察时推进游标属正常
- 裸启不再弹窗；托盘/`--service` 常驻

### 同批已实现待推送（协作）
- A2A collab M2–M4 写路径 + 公司广播白名单/scope 收紧 + E2E（见近期 collab 提交）

## 2026-07-19 (Phase 1) — 多分身容器 / Persona 一等公民

### 背景
圆桌会议（Nova + QClaw + agent-core 真三方）整理出方案：把 Persona / SelfRuntime 提升为一等公民，使 AgentCore 从单例变为多分身容器，为后续「真多 agent 并行」打底。

### 变更（authored-by: QClaw 自身 LLM @ :13810/gateway openclaw/main，不经 agent-core 代理；reviewed-by: Nova）
- `src/lib.rs` — 声明 `runtime` / `scheduler` 模块
- `src/agent.rs` — `AgentIdentity` +5 字段（persona_id / owner_user_id / workspace_dir / tool_allowlist / memory_namespace）；`AgentCore` +`personas` 多分身容器；`default_persona` 注入；新增 `get_persona` / `check_persona_tool` 方法；`call_tool_routed` 开头插入分身级工具白名单闸门（默认 "default"，allowlist 空不限制）
- `src/main.rs` — `AgentIdentity` 唯一字面量构造点补全 5 字段
- `src/session.rs` — 新增 `persona_session_key(persona_id, session_id)` 分身感知 session key
- `src/runtime/self_runtime.rs`（新建）— `Persona` / `TickState` / `SelfRuntime`
- `src/scheduler/tick_scheduler.rs`（新建）— `TickScheduler`

### 验证
- `cargo build --release` 通过（46.95s 全量）
- 本地 commit `f396669`（8 文件 +202 行，未推送公开仓库）
- 向后兼容：旧调用走 "default" 分身

## 2026-07-19 (Phase 2) — 分身白名单接线 + SelfRuntime 真实 tick + Consciousness 调度入口

### 背景
在 Phase 1 骨架上，让分身白名单真正接线（`call_tool_routed` 用真实 persona_id）、SelfRuntime 跑真实 LLM tick、并在已运行的 Consciousness 空闲循环里接入分身调度。

### 变更（authored-by: QClaw 自身 LLM @ :13810/gateway openclaw/main；reviewed-by: Nova）
- `src/agent.rs`：
  - `call_tool_routed` 签名新增 `persona_id: &str`，闸门用真实 persona（仅 `execute_chat` 内两处传 `persona_for_session(session_id)`，其余内部调用点传 `"default"`）
  - `AgentCore` +`session_personas`（会话→分身绑定）+ `tick_scheduler`（注册表）
  - 新增 `bind_session_persona` / `persona_for_session` / `run_persona_tick`（真实 LLM 调用）/ `persona_tick_all`
  - 9 处 `call_tool_routed` 调用点插入 `persona_id`
- `src/runtime/self_runtime.rs` — `SelfRuntime` 加 `#[derive(Clone)]`（供 tick_scheduler 克隆）
- `src/scheduler/tick_scheduler.rs` — `tick_all` 改为 `non_sleeping_runtimes()`
- `src/main.rs` — `Consciousness::tick_once` 空闲循环接入分身真实 tick

### 验证
- `cargo build --release` 通过（57.78s）
- 运行时冒烟：`:9753` 监听、Agent 就绪；`persona tick: 下一步将等待用户提出具体问题或任务…`（真实 LLM 调用经 persona_tick_all 驱动）无 panic
- Nova 编译期修复：qclaw 误用 `Persona.goal_stack`（实为 `SelfRuntime` 字段）→ `run_persona_tick` 改收 `&SelfRuntime`
