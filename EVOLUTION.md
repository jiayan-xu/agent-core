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
