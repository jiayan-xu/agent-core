# 白龙马（BaiLongma）吸收分析 + 落地方案

> 调研对象：`github.com/xiaoyuanda666-ship-it/BaiLongma`（v2.1.515，518★，Electron + Node.js + better-sqlite3，持续运行式 Agent 框架）
> 评估目标：判断其「明星特性」能否吸收进 `agent-core`（Rust 运行时）+ `Memoria`（SQLite 记忆/身份总线），并给出「做一个类似东西」的落地路线。
> 调研方法：**clone 源码后由 Explore agent 精读实现**（区分代码事实与 README/理念文档宣传），非二手文章。

---

## 1. 边界与定位

| 维度 | 白龙马 | agent-core + Memoria |
|---|---|---|
| 形态 | 桌面 Electron 单体（JS/TS），自带 UI、语音、微信/飞书接入 | Rust 服务（`agent-core` 跑 :9753，脑子在 Rust；`Memoria` 跑 :9003 薄存储/身份总线，PFAiX 调用） |
| 持久化 | better-sqlite3 单文件 | `Memoria` SQLite 单文件（本地零运维） |
| 核心卖点 | ACI 预判注入 / TICK 意识循环 / Focus Stack 焦点栈 | 已具备 Harness（task_context 模糊匹配）、llm_loop、boundary 工具门控、Memoria 的 supersede 时序真值 + consolidation |
| 我们的约束 | — | 本地单节点、零运维、Rust 强类型、公开仓需过 GIT 安全扫描 |

**吸收原则**：吸收**机制与数据结构**，不吸收 Electron 单体 / 语音 / 社交接入壳。白龙马真正有价值的是三个**纯逻辑**子系统 + 一个 consolidation 循环。

---

## 2. 三大核心的代码事实（来自源码精读）

### 2.1 ACI 预判注入（Anticipatory Context Injection）
- **入口**：`src/memory/injector.js:74` `runInjector({message, state, hint, currentChannel})`
- **调用时机**：**每次 `runTurn` 之前同步调用**（在 `src/index.js` 组装 prompt 阶段），**不是**后台定时、不是并行预执行。
- **实际做了什么**（全部同步 await）：
  - 记忆语义召回 `searchRelevantMemories`（FTS5 + 向量融合，`injector-retrieval.js`）
  - 时间词轮廓 `gatherTemporalRecall`
  - UI 信号消费 `getUnconsumedUISignals`
  - **工具 schema 选择 `selectTools`**（`tool-router.js:305`）——**只决定暴露哪些工具 schema，不实际调用工具**
  - 读预热缓存 `getValidPrefetchCache`
- **塞进 System Prompt**：`src/index.js:1039` `formatPrefetchedItems` → `:1126` 拼进 `extraContext`。
- **资源感知**（`src/local-resources-scanner.js`、`desktop-scanner.js`）：启动扫描一次 `~/.ssh`、`~/.gitconfig`、**只读元数据不读私钥**，按消息正则命中上下文规则才注入（条件式，非恒在）。

### 2.2 TICK 意识主循环（心跳 / consciousness loop）
- **调度**：`src/runtime/consciousness-loop.js:1` `createConsciousnessLoop`，自调度 `setTimeout`（`scheduleNextTick :139-204`），尾递归式排下一轮，`processing` 锁防重入。
- **节奏决策**（`:156-179`）：有待处理用户消息→`0`；限流 429→10 分钟档；L2 自定义 `set_tick_interval`（0–36000s，ttl 用尽回默认）；唤醒期→10s；活跃任务→30s；**空闲默认 20 分钟**（`config.js:961`）。
- **消息抢占**：`triggerImmediateTick` + `setInterruptCallback`（`:208-247`），用 `AbortController.abort('higher-priority-message')` 打断正在进行的 LLM 流/工具调用。
- **空闲自主思考**：**无独立 daydream 函数**。由三部分拼成：① TICK 轮里模型自行决策（沉默/更新状态/调工具/推进任务，`tick-policy.js:8`）② **consolidation 循环**（`consolidation-loop.js:34`，`setInterval` 30 分钟 round-robin 实体提炼）③ 预热缓存（见 2.4，事实死代码）。
- **看门狗**：`runTurnWithWatchdog`（`:59-81`）= `Promise.race([runTurn, watchdog])`，超时 `RUN_TURN_WATCHDOG_MS = 600_000`（**10 分钟**，注意 `llm.js:18` 注释写 180s 是错的）。超时→`abort` + 清执行态 + `reject`，`onTick` 吞错并排下一轮。

### 2.3 Focus Stack 焦点栈记忆管理
- ⚠️ **两套实现**：旧 `src/memory/focus.js`（`focus_stack` 表，栈+push/pop，**只读遗留**）；新 `src/memory/threads.js`（**当前主线**，线索 Thread + 前台指针 + 承诺，无 pop）。
- **新模型数据结构**（`threads.js:180-191`）：`state.threadState = { threads: Thread[], foregroundId, commitments }`；`Thread` 字段含 `topic/signature/label/summary/conclusions[]/status/hitCount/lastSummaryAt`。
- **归属判定** `attributeUserMessage`（`:352-477`）：返回 `created/continued/resumed/ambiguous/noop`，切前台返回 `switchedFrom`。
- **切话题压缩挂回**（`focus-compress.js:139-251`）：pop 旧帧时 **调用 LLM**（`maxTokens=150, temp=0.2`）总结 → `conclusions.push`（上限 5）→ 写 `event_type='focus_conclusion'` 长期记忆 → 旧帧对话标 `focus_absorbed=1`（软隐藏，下轮注入默认隐藏）。
- **持久化**（`db/repositories/thread-state.js`）：旧 `focus_stack` 整栈原子替换；新 `threads/commitments/thread_state` 事务 upsert；`thread_state` 单行 KV 存 `foregroundId`。表定义在 `db/schema.js:410-458`。

### 2.4 consolidation（记忆提炼，跨核心可用）
- `src/memory/consolidation-loop.js:34` + `consolidator.js`，每 30 分钟 round-robin 选实体跑 `runConsolidator`，把多条记忆提炼为更少高层记忆。**正好对应 Memoria 的 consolidation 阶段**（Memoria 已有 `consolidate(ns)` + low-peak 02:00-05:00 触发）。

---

## 3. 宣传口径 vs 代码事实（吸收前必读）

| # | 宣传口径 | 代码事实 | 结论 |
|---|---|---|---|
| 1 | ACI「并行预执行只读工具」提前查好直接注入 | `runInjector` **只做 FTS 召回 + 工具 schema 选择，不调任何工具** | 预执行未实现，丢弃该设想 |
| 2 | ACI「1.5s 超时上限，慢了不等」 | `runInjector` 内无任一时钟/预算，同步 await | 不存在，勿照搬 |
| 3 | ACI「定时预热缓存（cron 确定性预判）」 | `runPrefetch()` 全仓库无自动定时调用；执行器只实现 list/add/remove，无「立即执行」分支 | 事实死代码，不吸收 |
| 4 | 本地资源感知「每次进 system prompt」 | 启动扫描只读元数据，仅消息命中规则才门控注入 | 部分属实，吸收其「条件式资源门控」思路 |
| 5 | 焦点栈 = 栈 + push/pop | 主线已重构为 threads（前台指针+承诺），无 pop | 看 `threads` 实现，忽略 `focus_stack` 遗留表 |
| 6 | 看门狗 180s | 实际 600_000ms（10 分钟） | 注释错，以代码为准 |

---

## 4. 与 agent-core / Memoria 当前架构对照

| 白龙马概念 | agent-core / Memoria 现状 | 差距 |
|---|---|---|
| ACI 请求前记忆召回 | `Memoria.memory_context` 已在 llm_loop 前富化（`profile.rs` 的 `enrich_ledger`） | 已有基础；缺「按 task_context 选工具子集」 |
| ACI 工具 schema 选择 | `Harness` 已有 `task_context` 模糊匹配（`harness.rs:188 compute_match_score`） | 可扩展为「进 LLM 前按 task_context 选暴露工具」 |
| TICK 心跳 / 后台自主思考 | agent-core 当前**纯请求驱动**，`main.rs` 仅有被动 `tokio::spawn`（websocket/转发） | 缺主动心跳 + 空闲 tick + 抢占 + watchdog |
| Focus Stack 线程栈 | `agent.rs` 用 `conversation_id` 平铺会话，无前台指针/承诺/压缩 | 缺线程模型 + 切话题压缩 + 软隐藏 |
| consolidation | `Memoria.consolidate(ns)` + low-peak 触发 | 已有；可接 BaiLongma 的 round-robin 实体策略 |

---

## 5. 吸收决策矩阵

| 条目 | 决策 | 理由 | 落地到 |
|---|---|---|---|
| **A1. 请求前上下文预取** | ✅ 吸收 | 纯函数式、低风险、直接复用 Memoria `memory_context`；扩展 Harness 做工具子集选择 | agent-core `agent.rs` 组装 messages 处 + `harness.rs` |
| **A2. TICK 心跳 + 抢占 + watchdog** | ✅ 吸收（核心） | 自调度循环 + `CancellationToken` 抢占 + `tokio::time::timeout` 看门狗，是干净模板，映射到 Rust 零摩擦 | agent-core 新增 `consciousness.rs` + `main.rs` `tokio::spawn` |
| **A3. Focus Stack → Thread 模型** | ✅ 部分吸收 | 用「线索+前台指针+承诺+软隐藏」取代栈，比 Memoria 当前平铺 `conversation_id` 更稳；压缩走 LLM 调用 | Memoria 新增 `episode` 表 + agent-core 切话题逻辑 |
| **A4. consolidation round-robin** | ✅ 吸收 | 直接对齐 Memoria 已有 consolidation，补「按实体调度」 | Memoria `consolidate(ns)` |
| **不吸收**：ACI 工具预执行 | ❌ | 白龙马自己都没实现（死代码） | — |
| **不吸收**：预热缓存 cron | ❌ | 死代码；若未来要「主动预取」应另设计 guarded 实验 | — |
| **不吸收**：Electron/语音/社交壳 | ❌ | 与 Rust 服务定位不符，运维负担 | — |
| **不吸收**：旧 `focus_stack` 表 | ❌ | 遗留只读，误导 | — |

---

## 6. 落地方案（对标 HMS 那轮的 Phase 节奏）

### Phase A（P1，核心机制，推荐先做）
> 目标：给 agent-core 装上「请求前预取 + 心跳 + 线程栈」骨架，全部向后兼容，不影响 PFAiX 线上。

**A1 — 请求前上下文预取（agent-core 侧）**
- `agent.rs` 组装 `messages` 前新增 `prefetch_context(session_id, task_context)`：调 `Memoria.memory_context`（已富化账本）+ 基于 `Harness` 的 `task_context` 模糊匹配选出**要暴露的工具子集**（等价 `selectTools`），其余工具从本轮 schema 隐藏（模型仍可经 `find_tool` 主动发现，复用现有机制）。
- 不引入「工具预执行」——只选 schema，符合白龙马代码事实。
- 验收：`/v1/chat` 请求日志显示「exposed_tools=N, recalled_memories=M」；PFAiX 功能不变。

**A2 — TICK 心跳 + 抢占 + watchdog（agent-core 侧，新增 `consciousness.rs`）**
- `tokio::spawn` 启动 `ConsciousnessLoop`：自调度 `tokio::time::interval`，节奏决策对齐白龙马（用户消息在途→立即；活跃任务→短；空闲→长，默认 20 分钟）。
- 抢占：用 `tokio_util::sync::CancellationToken` 充当 `AbortController`；用户消息到达时 `cancel()` 正在进行的 tick task，再 `trigger_immediate_tick`。
- 空闲 tick 语义：**silent**（不向用户回复），只做①更新内部状态 ②对 Memoria 发「建议 consolidation」信号 ③可选主动调用无害只读工具（guarded）。
- watchdog：用 `tokio::time::timeout(Duration::from_secs(600), run_turn)` 包裹，超时→取消 + 记 tracing span `watchdog_timeout`，排下一轮。
- 验收：模拟「空闲 20 分钟」日志出现 periodic tick；注入高优消息能打断在途 tick；run_turn 卡死 10 分钟被 watchdog 回收不崩溃。

**A3 — Focus Stack → Thread 模型（Memoria + agent-core 协同）**
- Memoria 新增 `episodes` 表（`id, agent_id, foreground_id, topic[], summary, conclusions[], status, created_at, last_event_at`）+ `conversations.episode_id` + `conversations.focus_absorbed` 软隐藏列（幂等迁移，对齐 `migrate_event_time` 写法）。
- agent-core `agent.rs`：用 `session_id` 解析出 `episode_id`；新话题→`created` 新 episode 并切前台；切回旧话题→`resumed`；切走旧话题→调 LLM 压缩旧 episode（`conclusions` + 写 `focus_conclusion` 记忆 + 旧对话标 `focus_absorbed=1`）。
- 验收：连续切 3 个话题再切回，回复能引用旧话题压缩结论而不重发全文；`memory_search_v2` 默认隐藏 `focus_absorbed` 对话。

### Phase B（P2，增强，待 A 稳定后）
- A4：Memoria `consolidate(ns)` 接入 round-robin 实体调度（对齐白龙马 `consolidation-loop`）。
- 可选「主动预取」实验：仅在低风险只读工具上，由 tick 触发、带预算超时（**不照搬白龙马死代码的 cron 预热**）。
- 多端唤醒：把心跳与 PFAiX 推送打通（白龙马的多平台接入思路，但只接已有 channel）。

### 不吸收清单（写入代码注释与 AGENTS.md，防后人误抄）
- ACI 工具预执行、cron 预热缓存（死代码）
- 旧 `focus_stack` 栈表
- Electron/语音/社交壳

---

## 7. 风险与运维铁律
- 改动只在 canonical `agent-core`（本仓库，GitHub 公开 `master`）进行；`gitee` 私有镜像**永不推开源内容**（pre-push hook 已拦截）。
- 推前过 GIT 安全扫描（无密钥/无 `C:\Users\user` 绝对路径）；`agent.toml` 的 key 走 env，不硬编码。
- 改 Rust 源后 `cargo build --release` 前停所有 `agent-core.exe`，防 os error 5。
- 生产 cutover 沿用双树纪律：新二进制经看门狗/launcher 接管 :9753；旧二进制留 `.bak-<ts>` 回滚。
- TICK 心跳新增后台负载，先在 staging 验证 CPU/配额（对齐白龙马 429 限流档）。

---

## 8. 实施状态
- [x] 研究完成（源码精读 + 本决策矩阵）— 2026-07-17
- [x] **Phase A 已全部落地（A1 + A2 + A3）— 2026-07-17**
  - **A1 请求前上下文预取**：`agent.rs` 新增 `select_exposed_tools`（Jaccard 词命中打分，top-12 暴露子集，仅选工具 schema 不调工具）；`execute_chat` 加 `recalled_memories` 计数，与 `exposed_tools` 配对观测。等价白龙马 `selectTools`，不引入「工具预执行」。
  - **A2 TICK 心跳 + 抢占 + watchdog**：`main.rs` 内联 `Consciousness`（**零新依赖**，`tokio::sync::Notify` 抢占 + `tokio::time::timeout(600s)` 看门狗；空闲默认 20min）；三处 chat handler 在取 agent 锁前 `interrupt()`；`run_idle_tick` silent 心跳（不回复用户）。
  - **A3 Focus Stack → Thread**：`agent.rs` 新增 `EpisodeArchive` 结构 + `episode_archive` 索引；`archive_current_episode`（LLM 压缩→写 Memoria `tags=["focus_conclusion","absorbed:<sid>"]` 软隐藏 + 本地 HashMap 索引）+ `recall_episode_for`（切回召回结论注入）；`handle_topic_switch` 接入「切走归档 / 切回召回」。
  - **两处对原方案的合理偏离（均为降生产风险）**：
    1. A2 原计划新增 `consciousness.rs` + 用 `tokio_util::CancellationToken`；因 cargo 依赖不含 `tokio-util`，改为 `main.rs` 内联 + `Notify` 实现，**零新依赖、零改动 Cargo.toml**。
    2. A3 原计划 Memoria 新增 `episodes` 表 + `conversations.focus_absorbed` 列；改为**纯 agent-core 实现**（复用 `memories.tags` 列软隐藏 + 本地 HashMap），**不动生产 Memoria schema 迁移**，与 A1/A2 同级、零迁移风险。
- [x] 编译通过（`cargo build --release`，master，无错误）
- [x] 冒烟通过：新 exe 绑定 `:9753`；`/health` 返回 `status:ok` 且 `memoria.reachable:true`；日志确认 `consciousness: TICK 循环启动` + 首跳 `consciousness_tick: 空闲心跳` 已执行；`Agent 已就绪（dashboard-agent@:9003）` 注册成功。
- [x] **Phase B 已全部落地（A4 + 主动预取 + 多端唤醒）— 2026-07-18**
  - **A4 TICK round-robin consolidation**：`Consciousness::tick_once` 每次空闲 tick 推进一个 namespace 的 `agent.consolidate(ns)`（游标 `consolidate_cursor` 内存态、不持久化，对齐白龙马 `consolidation-loop.js` 每 30min 一个实体）；内层 300s 预算超时，外层 TICK 已有 600s watchdog。ns 列表来自 `CONSOLIDATE_NAMESPACES`（默认单 agent ns）。
  - **多端唤醒（拉模型）**：`background_events` 队列 + `GET /api/agent/events?since=&limit=` 轮询端点（统一鉴权保护）；A4 consolidate / 主动预取产出事件入队，PFAiX 前端轮询即可"唤醒"，零改造 PFAiX。
  - **主动预取实验（guarded，默认关）**：`guarded_prefetch` 识别「只读 + 无必填参数」工具做 liveness probe；`AGENT_PRETEST=1` 开启候选识别，`AGENT_PRETEST_EXEC=1` 才实际 dummy 调用（默认关），带 60s 预算超时。对齐白龙马死代码 cron 预热的**反面**——只探测工具可用性，不预执行业务数据。
  - **两处对原方案的合理收敛（降风险/零改造）**：① A4 不照搬白龙马「实体级」调度（我方 consolidate 颗粒度为 ns，多 ns 由 `CONSOLIDATE_NAMESPACES` 覆盖）；② 多端唤醒用「拉模型事件端点」而非「推模型」（PFAiX 无接收推送端点，grep 证实），更稳且零改造。
- [x] 冒烟验证（Phase B）：新 exe 绑定 :9753；`/health` status:ok 且 memoria.reachable:true；日志确认 `A4: 空闲 tick 推进 consolidation round-robin ns=agent/dashboard-agent cursor=0` + `consolidate[...]: 无新观察` 实锤 A4 调通；`/api/agent/events` 返回 HTTP 401（路由已注册、受鉴权保护）。

---

## 9. 参考
- 仓库：`github.com/xiaoyuanda666-ship-it/BaiLongma`（clone 于 `<workspace>/bailongma-probe`，研究用，不提交）
- 关键文件：`src/memory/injector.js`、`src/runtime/consciousness-loop.js`、`src/memory/threads.js`、`src/memory/focus-compress.js`、`src/memory/consolidation-loop.js`、`src/harness.rs`（我方）
- 关联：`memoria-open/docs/OPTIMIZATION_HMS_ABSORPTION.md`（同一套路的上一次吸收）
