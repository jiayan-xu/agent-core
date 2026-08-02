# Agent-Core 系统 Palantir 对标优化方案

- **日期**：2026-08-02
- **范围**：agent-core（Rust, :9753）+ dashboard（Python, :8000）+ memoria（Rust, :9003）三件套
- **性质**：设计文档（只谈「怎么优化」，不改代码；落地前按项确认）
- **对照基线**：Palantir Foundry Ontology / AIP Chatbot Studio（原 Agent Studio）/ AI FDE
- **前置审查**：2026-07-31 Palantir Ontology 调研 + 七层全面对比（本会话产出）
- **状态**：待评审

---

## 0. 裁决（先读这段）

**目标**：把三件套从「业务流程 + AI 助手」升级为「决策中心的单厂数字孪生」——数据（名词）+ 逻辑（推理）+ 动作（动词）+ 安全（护栏）统一建模，人和 agent 共用同一操作层。**不引入 Palantir 式企业级基础设施，只吸收其决策架构思想，用 SQLite 级别的轻量手段落地。**

**不改动的理念（硬约束）**：

1. **最小核心，最大扩展** — 领域能力只来自 MCP / 技能市场，核心不堆业务工具（继承 ADR 系列）。
2. **安全即默认** — 红线、命名空间、供应链白名单优先于「好用」。
3. **记忆外置（Memoria）** — 不把记忆/RAG 吸回核心。
4. **降级收缩** — 故障时缩权限、切备用，而不是裸崩。
5. **单厂规模不装企业级** — 不引入分布式事务、跨组织 marking、全局分支。5-10 人协作场景用影子表 + 外键解决。

**明确不做（防理念漂移）**：

| 不做 | 原因 |
|------|------|
| 引入 Palantir 平台/OSDK 依赖 | 私有云 + 商业授权，与自研路线冲突 |
| 场景模拟做成独立服务 | 影子表 + 视图切换足够，别加进程 |
| 属性级权限全面落地 | 单厂规模 namespace 级已够，属性级只做高敏字段（车牌/企业）白名单 |
| 决策血缘做全局 lineage 图 | op_log 增强 + memoria 关联即可，别建图谱引擎 |

**成功标准（90 天后）**：

- 「如果白名单 +3 车 / 运力调整」可在影子表沙箱推演，无副作用提交
- 任意一次审批/受控写，可按 `op_id` 还原「谁、何时、为何、基于什么快照」决策链
- agent 回答业务问题时，可引用数据字典（字段含义/来源/口径），不再靠 prompt 硬编码
- 动作写回（通知/回调）走统一副作用层，可审计、可回滚、可重试
- ops_incidents（824 条历史）可被 agent 复盘时引用为「教训」，而非只躺在表里

---

## 1. 现状摘要

### 1.1 三件套架构

```
PFAiX 桌面壳 (Jan 魔改, LAN 分发)
   │  :9753 HTTP
   ▼
agent-core (Rust, 30.8k 行)
   ├─ 治理层: boundary(2023) / approval(1230) / namespace(576) / audit(657)
   ├─ 智能层: agent(7508) / llm(1865) / lats(335) / composer(356) / harness(925)
   ├─ 受控写: controlled_write(664) / repo_ws(474) / local_fs(461) / db_write / pref_write
   └─ 演化层: meta_evolve(1113) / code_evolve(486) / self_evolution / memory_extract(358)
   │  :9003 MCP
   ▼
memoria (Rust, 记忆系统)
   ├─ hybrid_search(向量+文本) / HNSW / QueryCache
   ├─ remember_with_dedup / memory_context / evolve_memory / consolidate / decay
   └─ embed: cloud_embed_proxy → siliconflow / embed_server(:8777)
   │  :8000
   ▼
dashboard (Python, 固废业务域)
   ├─ SQLite 34 表: vehicle_entrance(3978) / vehicle_whitelist(114) / manifest_records(23)
   ├─ 文件台账: pdf(2185) / photo(11606) / video(3958)
   ├─ 接入: SNMIS 下载器 / OCR(manifest_ocr) / RTSP 摄像头(camera_manager) / Excel 对账
   ├─ 运维: ops_incidents(824) / ops_patterns(5) / ops_knowledge(1) / ops_baselines(3)
   └─ 记忆桥: agent_memories(1215) / memoria_index(50) / event_bus(13203)
```

### 1.2 已有但未激活的能力（方案的地基）

| 能力 | 位置 | 现状 |
|------|------|------|
| 数据字典 API | `routers/admin.py:56 /api/db/data-dictionary` | 有雏形（表/字段枚举），缺业务口径 |
| 受控写双轨校验 | `controlled_write.rs` + `checkpoint_recovery.rs` | 已跑通（白名单/取样/联单） |
| 审批权威表 | `checkpoints.db` 同库异表（ADR-015） | P0-P3 全落地 |
| 事件总线 | `event_bus.db` 13,203 事件 | 有，缺订阅/重放治理 |
| ops 四表 | `ops_incidents/patterns/knowledge/baselines` | 在采集，未闭环进 agent 行为 |
| Harness 蒸馏 | `harness.rs distill_from_logs` | 已有，针对技能模板 |
| 记忆同步桥 | `memoria_index` 表 + `sync_to_memoria` | 已建，50 条同步记录 |

---

## 2. 差距矩阵（Palantir → 我们，七层）

| 层 | Palantir | 我们现状 | 差距等级 |
|----|----------|----------|----------|
| 数据 | Object/Property/Link 带元数据+派生属性 | 34 表无业务口径，关系隐式 | **P0**（字典+派生） |
| 接入 | 统一连接器框架，流式+批量 | SNMIS/OCR/RTSP 各写各的 | P1（收敛） |
| 逻辑 | Functions 带版本/发布/回滚 | skills 脚本级无版本 | P1 |
| 动作 | Action+副作用(webhook/通知)+回滚 | controlled_write 有校验无副作用层 | **P0**（副作用层） |
| 安全 | marking+属性级动态策略 | namespace+boundary 同构 | P2（高敏字段白名单） |
| 记忆 | Decision lineage→微调素材 | agent_memories 记结果不记因果 | **P0**（决策血缘） |
| 模拟 | Scenarios 沙箱+全局分支 | **无** | **P0**（影子表，灵魂） |

---

## 3. 优化项清单（按优先级，每项给出落点）

### P0-1 场景模拟沙箱（数字孪生灵魂）

**现状**：无任何 what-if 能力。白名单变更/运力调整只能靠人脑推演。
**Palantir 参照**：Ontology Scenarios —— 变更暂存沙箱子集，模拟后果后再提交；AI FDE 用其做供应链推演。
**方案**（SQLite 影子表 + 视图切换，不动业务代码）：
1. 新增 `scenario` 表 + `scenario_snapshot` 表（记录基线的 `rowid` 范围 + 变更 SQL 段）
2. 对关键读路径（`vehicle_whitelist` / `vehicle_entrance` / `manifest_records`）提供 `scenario_view(table, scenario_id)` 查询函数：基线上叠加影子行，`SELECT ... FROM whitelist_scenario(:sid)`
3. `dashboard` 新路由 `/api/scenarios/*`：创建/编辑/推演/提交/丢弃
4. agent 侧：`check_tool` 新增 `scenario.*` 工具组（只读沙箱，**永不直接写生产表**），允许 agent 推演「如果 +3 车」再给建议
5. 提交=事务内把影子行写回生产表 + `op_log` 记 `scenario_id` 关联

**落点**：`dashboard/db/scenario.py`（新）、`dashboard/routers/scenarios.py`（新）、`agent-core/src/boundary.rs`（工具注册）、`agent-core/src/dept_ops.rs`（黄线工具清单）
**工作量**：2-3 天 ｜ **风险**：低（只读路径，提交走事务）
**收益**：数字孪生最核心能力；对账/补录前可先推演影响面

### P0-2 决策血缘（为什么做这个决策）

**现状**：`op_log`（30 条）只记动作结果，不记「为何 + 基于什么快照」。agent 复盘只能看结果。
**Palantir 参照**：Decision lineage —— 数据/逻辑/动作全链捕获，作为模型微调与蒸馏素材。
**方案**：
1. `op_log` 加列：`reason`（自然语言决策依据）、`context_snapshot`（JSON：操作前关键行快照或 hash）、`scenario_id`（可选，关联沙箱）
2. `controlled_write` / `approval` 提交路径统一写入（受控写天然有 checkpoint，扩展即可）
3. memoria 侧：`agent_memories` 分类 `category='decision'` 存「事件 → 决策 → 结果」三元组；agent 复盘时 `memory_context(query='该决策的缘由')` 可召回
4. dashboard `/api/ops/incidents` 与 op_log 打通：824 条历史 incident 补 reason 字段（迁移脚本，缺失填 NULL）

**落点**：`dashboard/db/core.py`（op_log 迁移）、`agent-core/src/controlled_write.rs`、`agent-core/src/approval_store.rs`、`memoria`（复用现有 remember 通道）
**工作量**：1-2 天 ｜ **风险**：低（加列 + 写路径扩展）
**收益**：审计从「发生了什么」升级为「为什么发生」；为蒸馏/复盘提供因果链

### P0-3 数据字典升级（语义元数据层）

**现状**：`/api/db/data-dictionary` 返回表/字段枚举，无业务口径（如 `vehicle_entrance.waste_type` 的取值含义、`sample_weight` 单位、来源表）。
**Palantir 参照**：Object type 元数据（属性描述/格式化/校验规则）+ 派生属性。
**方案**：
1. `data_dictionary` 表新增：`business_name`（业务名）、`meaning`（口径说明）、`unit`（单位）、`source`（来源表/接口）、`derived_from`（派生表达式，NULL=原始）
2. `get_data_dictionary()` 改为三视图：表视图 / 字段视图 / **派生规则视图**（声明式，`indicators.py` 的 134 条指标迁移为规则行）
3. agent-core 侧：字典内容进 `resources.rs`（可检索资源），agent 回答业务口径问题时自动引用；prompt 不再硬编码口径
4. dashboard 大屏/报表生成器用同一字典渲染中文列名

**落点**：`dashboard/db/data_dict.py`（新表+迁移）、`routers/admin.py`（改）、`agent-core/src/resources.rs`（接入）
**工作量**：2 天 ｜ **风险**：低 ｜ **收益**：agent 回答可信度↑；报表口径统一；新同事上手快

### P0-4 动作副作用层（写回外部系统）

**现状**：`controlled_write` 校验完备，但动作执行后「通知/写回/触发」无统一机制（SNMIS 回写散在业务代码）。
**Palantir 参照**：Action side effects —— 通知/webhook/触发调度/上传附件，可审计可重试。
**方案**：
1. `side_effect` 表（dashboard）：`op_id` / `kind`(webhook|notification|snmis_writeback) / `target` / `payload` / `status`(pending|sent|failed|retried) / `attempts`
2. `controlled_write` 提交成功后，`post-commit` 钩子写 `side_effect` 行；后台 worker 消费重试（复用 event_bus）
3. 首批场景：白名单变更 → 通知负责人；联单归档 → webhook 到外部台账；SNMIS 补录 → 写回 SNMIS
4. 审计：`op_log` 与 `side_effect` 通过 `op_id` 关联，一次动作全链可查

**落点**：`dashboard/db/side_effect.py`（新）、`dashboard/services/side_effect_worker.py`（新）、`agent-core/src/controlled_write.rs`（钩子）
**工作量**：2-3 天 ｜ **风险**：中（写外部系统需幂等设计，`op_id` 天然幂等键）
**收益**：动作闭环；故障可重试不丢事件

### P1-1 接入层收敛（连接器框架）

**现状**：SNMIS 下载器 / OCR / RTSP / Excel 对账四条接入线，各写各的轮询与错误处理。
**Palantir 参照**：统一连接器，流式+批量管道，编排复用。
**方案**：
1. 定义 `connector` 抽象（dashboard）：`poll() -> Event[]` + `handle(Event)` + `health()`，事件进 event_bus
2. 现有四条线按抽象改造（先 OCR 与 Excel 对账，RTSP 最后——流式特殊）
3. event_bus 增加重放（`replay(from_ts)`）与死信队列

**落点**：`dashboard/services/connectors/`（新目录）
**工作量**：3-4 天 ｜ **风险**：中（改造存量逻辑，需回归对账技能）｜ **收益**：新增接入源（如地磅接口）一天搞定

### P1-2 技能版本化

**现状**：`skill_library.rs` 有 export/import/load_or_default，无版本/发布/回滚；技能市场（memoria skill_market_*）有版本字段但未用起来。
**Palantir 参照**：Functions 版本化 + 发布管理 + 回滚。
**方案**：
1. `Skill` 加 `version` + `published_at` + `deprecated`；`record_usage` 结果回写质量分
2. 发布流程：草稿 → 测试（harness 蒸馏跑一遍）→ 发布；`rollout_if_better`（meta_evolve 已有类似机制）做灰度
3. 回滚：`import_state` 已有，加历史快照（`skill_library.json` 轮转 5 份）

**落点**：`agent-core/src/skill_library.rs`、`harness.rs`
**工作量**：1-2 天 ｜ **风险**：低 ｜ **收益**：技能可灰度可回滚，5 人团队也值得

### P2-1 高敏字段属性级白名单

**现状**：namespace 级授权（`agent/{id}` vs `org/.../dept/...`），但同部门内人人可见全部字段（含车牌/企业简称）。
**Palantir 参照**：行级+列级动态策略。
**方案**：只做列级：`field_acl` 表（`table.field → min_ns`），`data-dictionary` 查询时过滤；首批仅 `vehicle_whitelist.plate`、`sample_records.supplier` 等 3-5 个高敏字段。
**工作量**：1 天 ｜ **风险**：低 ｜ **收益**：试用同事（只读）看不到高敏列

### P2-2 决策蒸馏闭环

**现状**：`ops_incidents` 824 条在采集，无消费。
**Palantir 参照**：决策血缘 → 蒸馏原则 → 注入 agent prompt（"部落知识显性化"）。
**方案**：
1. 夜间批处理：incidents → LLM 蒸馏为「教训条目」（规则形式，如「SNMIS 补录前必须比对 A/B 台账」）→ `ops_knowledge`
2. agent 执行相关任务时，`ops_knowledge` 注入 system prompt（`intake_filter.rs` 或 `resources.rs` 挂载）
3. 闭环：知识被引用时 `times_applied++`，未用过的定期重审

**落点**：`dashboard/scripts/distill_lessons.py`（新）、`agent-core/src/resources.rs`
**工作量**：1-2 天 ｜ **风险**：低（只读消费）｜ **收益**：824 条教训从死数据变活知识

### P2-3 场景模拟的 agent 入口 + Request clarification

**现状**：agent 无「暂停问人」能力（composer 有确认机制雏形）；沙箱推演依赖 dashboard 页面。
**Palantir 参照**：Request clarification 工具（暂停执行等用户输入）+ Chatbots as tools。
**方案**：
1. agent-core 工具 `request_clarification`（挂 approval 同款机制，轻量版：非危险操作也可暂停问一句）
2. 场景模拟工具组 `scenario.*` 接入 composer 的 `decompose` 计划流：计划里含「推演 → 汇报 → 等确认 → 提交」

**落点**：`agent-core/src/agent.rs`（工具注册）、`composer.rs`（计划流扩展）
**工作量**：2 天 ｜ **风险**：低 ｜ **收益**：agent 从「猜」升级为「问」

---

## 4. 实施路线（三批）

| 批次 | 项 | 验证门 |
|------|----|--------|
| **第一批（P0，2 周）** | P0-1 场景沙箱 → P0-2 决策血缘 → P0-3 数据字典 → P0-4 副作用层 | 沙箱推演 e2e + op_log 因果链可查 + 字典被 agent 引用 + 副作用重试不断 |
| **第二批（P1，1 周）** | P1-1 连接器收敛 → P1-2 技能版本化 | 对账/补录技能回归全过 + 技能可回滚 |
| **第三批（P2，1 周）** | P2-1 字段白名单 → P2-2 蒸馏闭环 → P2-3 澄清工具 | 高敏字段只读不可见 + 824 条教训可注入 + 澄清流 e2e |

每批完成：`cargo check`（agent-core）+ 前端/后端 smoke（dashboard）+ 技能回归（feishui 两技能）必须过。

---

## 5. 风险与回滚

| 风险 | 等级 | 缓解 |
|------|------|------|
| 影子表与生产读路径不一致 | 中 | 视图函数单点实现 + 全量基线一致性测试 |
| 副作用写外部系统重复投递 | 中 | `op_id` 幂等键 + worker 去重 |
| 存量接入线改造回归 | 中 | 第二批单独做，每线改造后跑既有对账技能 |
| 数据字典口径填错误导 agent | 低 | 字典行带 `owner` + 变更走审批 |
| op_log 加列影响旧查询 | 低 | SQLite 加列向后兼容，旧代码不读新列 |

**回滚原则**：全部为「加列/加表/加路由」式增量变更，无破坏性迁移；任一环节出问题，关路由/停 worker 即回退，不动存量数据。

---

## 6. 一句话

**Palantir 的 Ontology 教会我们：数字孪生的灵魂不是数据镜像，而是「模拟（Scenario）+ 血缘（Lineage）+ 动作闭环（Action）」三件事。我们已有数据镜像和动作审批，缺的是模拟与血缘——而这两个恰好能用 SQLite 影子表和 op_log 增强低成本补齐。**
