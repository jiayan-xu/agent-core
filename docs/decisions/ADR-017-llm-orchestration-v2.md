# ADR-017: LLM 编排层 v2 —— Flash 锚定引导 + Plan-Act-Reflect 状态机

## Status
Accepted（P1–P3 代码落地；全部开关默认 OFF，生产灰度验收前保持关闭）

## Date
2026-08-15

## Context

agent-core 的 LLM 调用设计目前是"单层 ReAct + 领域补丁"：

1. `llm_loop` 热路径只有一种姿势：`LLM → 有工具？执行回灌 : 直接答`，
   高级编排组件（`composer` / `skill_library` / `lats` / `multiagent` / `ttc`）
   全部 feature off，等于没有编排层。
2. 领域逻辑硬编码在循环体里：数据查询强制工具提示、证据门禁、JSON 泄漏重写、
   Easy 查询 3 轮封顶……每加一个领域就多一串 if，循环体不可扩展。
3. 小模型（deepseek-v4-flash）首轮表现差是已知痛点：代码注释承认 flash 对
   Easy 数据查询首轮常直接编答案，现有对策是"注入重试提示顶回去"，多耗
   1 轮 5–20s——这是**纠错式**强化，先让模型犯错再纠正。
4. dsh 侧 `win-flash-anchored` 预设（社区实测）给出了**锚定式**强化的证据：
   - 首轮只给 2 个工具（pwsh + str_replace_editor）：Windows 配方首行轨迹 5/5
     命中极简轨迹，pwsh+read 为 0/5；
   - 中性人设（无 "software engineer" 等 spec 句）：Flash 上带 spec 句反路由；
   - 首轮 `max_tokens=1024`：26/32 复现极简轨迹，默认 256000 为 0/5；
   - 剥离首轮自动注入（AGENTS.md 摘要 / 技能清单）：有技能清单时 0/9，
     无则约 81%；
   - `promoteOn: either`：首次 tool/call 或首次回复后自动展开完整目录与正常
     预算，session 事件持久化，resume 保留相位。
5. agent-core 的 `llm_loop` 首轮就把完整真实工具清单 + 规则注入 system prompt
   （`agent.rs` 6685–6736 行），恰是 dsh 实测中"注入越多锚定越差"的反模式。

目标：把 dsh 已验证的**锚定式**机制吸收进 agent-core（不复制 dsh 代码），并把
`llm_loop` 重构成可扩展的**Plan-Act-Reflect 状态机**，领域补丁抽成 guardrail hooks。

## Decision

1. **引入 session 级两阶段锚定引导**：`bootstrap → promoted`，仅对 easy/flash
   路由且未 promoted 的会话生效；首请求最小工具面 + 1024 输出预算 + 中性
   system prompt，promote 后展开完整目录与正常预算（Design §1）。
2. **引入 Plan-Act-Reflect 状态机**：Hard 任务先轻量 Plan（复用 composer），
   Act 沿用现有工具循环，终答前 Reflect（critic 检查目标达成，预算内 ≤2 次）
   （Design §2）。
3. **领域补丁全部抽成 guardrail hooks**：`on_pre_act / on_tool_result /
   on_final_answer` 等挂载点，核心循环不再 import 领域逻辑（Design §3）。
4. **启用已有半成品**：composer 计划预览（HITL）、skill_library 检索注入、
   TTC verifier 终答验证，作为编排层组件逐步放行，全部保持默认关 + G 门验收。
5. **工具结果超阈值改用 LLM 摘要**，替代暴力截断（Design §4）。
6. **同轮独立工具并行执行**：读类并发 + 每工具超时，写类串行（审批语义不变）
   （Design §4）。
7. **统一 TurnBudget**：轮次 / token / 墙钟 / 日预算合成一个控制器（Design §5）。
8. **工具失败三分类**：`retryable / recoverable / fatal`，取代散落的
   continue/break（Design §6）。

## Design

### §1 Flash 锚定引导（Anchored Bootstrap）

**触发条件**：`RoutedLlm` 本轮选中 easy/flash provider（沿用现有难度路由）且
该 session 未 promoted 且非写意图（`has_write_intent` 为假）。pro/主模型、
写意图、危险工具会话不启用 bootstrap。

**Bootstrap 请求（promoted 前的首个用户请求）**：

| 维度 | 现值 | Bootstrap 值 |
|---|---|---|
| 工具面 | 12（Easy）/ 30（Hard），完整清单注入 system prompt | 2–3 个：意图相关工具 + `request_clarification`；危险工具永不进入 |
| 输出预算 | `LlmConfig.max_tokens`（默认 8192） | 运行时覆盖 1024（clone 配置改字段，promote 后显式恢复，杜绝预算残留） |
| system prompt | 完整人设 + 真实工具清单 + 规则 | 中性模板（对齐 Flash 反路由实测），不注入完整工具清单 / 技能块 / AGENTS 摘要 |
| 意图适配 | — | `data_query` → `query_*` 类 + clarify；其他意图 → 2 个常驻只读工具 + clarify |

**Promote 信号**：首个非空 `tool_calls` **或**首个终答（`either` 语义，避免
"首轮无工具回复"把会话永久卡在 bootstrap）。promote 后：展开 12/30 工具面、
恢复默认 `max_tokens`、补回完整规则注入。

**持久化**：session 级 promote 状态落 `harness.db`（新表 `session_phase`
或等价结构），进程重启 / 会话恢复保留相位；promote 是 append-only，不退档。

**降级安全（对齐 dsh 设计）**：bootstrap 工具缺失 / flash 不可用 / 任何过滤
异常 → 直接走全量路径 + 一次 warn；故障方向永远向"可用"降级，绝不吃掉用户
上下文。

**回归线**：固废数据查询"首轮工具调用率"不得低于现状；Easy 查询端到端延迟
不得显著增加（bootstrap 目标是省掉重试轮，而不是增加轮次）。

### §2 Plan-Act-Reflect 状态机

```text
Bootstrap（flash 会话首请求，见 §1）
      │ promote
      ▼
Request ──Easy──▶ Act ──▶ Reflect(可选) ──▶ Answer
      │            ▲          │
      └─Hard─▶ Plan ─┘        └─(未达成, ≤2 次)─▶ 注入 re-plan 提示
```

- **Plan**：仅 Hard 任务触发，复用 `composer` 现有 decompose 逻辑与 HITL
  计划预览（`compositional_preview` 语义不变）；Easy 直接进 Act。
- **Act**：现 `llm_loop` 的核心（工具选择 → `call_tool_routed` → 回灌），
  执行层完全不动（边界/审批/配额/审计不变）。
- **Reflect**：终答前用 judge/easy provider 做一次 critic 调用，输入
  `(goal, 工具结果摘要)`，输出 `satisfied | not_satisfied + feedback`；
  未达成时注入 re-plan 提示重新 Act，预算内 ≤2 次；预算尽 → 诚实降级
  （保留现有"未查询到业务数据"式兜底语义）。
- 每次 Plan/Reflect 调用计入 TurnBudget 与审计。

### §3 Guardrail Hooks 拆分

现有硬编码补丁 → hook 映射：

| 现有补丁 | Hook |
|---|---|
| data_query 强制工具提示 | `on_pre_act`（注入一次，不重试式） |
| 证据门禁（`dept_ops`） | `on_pre_plan` + `on_final_answer` |
| reply_polish JSON 泄漏重写 | `on_final_answer` |
| honesty_guard_readonly_as_write | `on_final_answer` |
| 观察/偏好/分身记忆写入 | `on_session_end` |

接口骨架（Rust 草案）：

```rust
enum HookPoint { OnBootstrap, OnPromote, OnPrePlan, OnPlan,
                 OnPreAct, OnToolResult, OnFinalAnswer }

enum HookAction { Continue, Inject { messages: Vec<Message> },
                  Abort { reply: String } }

trait OrchestrationHook: Send + Sync {
    fn point(&self) -> HookPoint;
    fn run(&self, ctx: &OrchestrationCtx) -> HookAction; // 或 async
}
```

- 核心循环只遍历已注册 hook；领域模块（`dept_ops`、`reply_polish` 等）在
  启动时按配置注册，核心不 import 领域。
- 顺序敏感（如 Abort 优先级）由 `point + priority` 决定，单测覆盖。

### §4 工具结果摘要与并行执行

- **摘要**：单工具结果 > 8192 字符，或进入第 4 轮后，用 cheap/easy provider
  生成结构化摘要回灌（复用 `memory_extract` 的 LLM 压缩思路）；摘要失败
  回退现有 `squash_stale_tool_outputs` 截断。
- **并行**：同轮 `tool_calls` 按工具分类分组：read 组 `join_all` + 每工具
  timeout；write/dangerous 组保持串行（审批与写后回读语义不变）。工具级
  并发上限（默认 4），受配额并发会话维度约束。

### §5 统一 TurnBudget

把 `max_rounds`（Easy 3 / Hard 20）、token 估算（chars/4）、TTC/LATS 日预算、
`AutonomyBudget` 四预算合并为一个 `TurnBudget` 查询接口；循环中只有一处检查，
违约统一 `Abort(诚实降级文案) + 审计`。现有 `/api/admin/quota` 与配置格式不变。

### §6 工具失败分类

| 分类 | 判据 | 动作 |
|---|---|---|
| `retryable` | schema 校验失败（strict_schema 回灌）、超时（一次） | 回灌修正后重试（现有语义） |
| `recoverable` | 工具名近似匹配失败、源 unhealthy（降级状态机已知） | 换相近工具或降级路径 |
| `fatal` | 边界拒绝、审批拒绝、配额、killswitch、safe_mode | 立即 Abort 或诚实报错，审计 |

分类结果写审计事件，供运营观测"flash 主要死在哪个桶"。

### §7 与 ADR-016 的关系

- 本 ADR 是 **chat 路径的编排层增强**，ADR-016 是 **gateway 化**；两者正交：
  编排层 v2 让 legacy chat 在双引擎过渡期不退化，也让"agent-core 做宿主"
  的反向方案有了最小改造面。
- 若 ADR-016 落地，Plan/Reflect 的产物（计划、工具选择）最终由 dsh 承担；
  本 ADR 的 hooks / TurnBudget / 失败分类仍保留在 gateway 执行侧。

## Alternatives Considered

| 方案 | 结论 |
|---|---|
| A. 直接复制 dsh `win-flash-anchored` 预设 | 否决：agent-core 是 HTTP 企业 agent，工具面与 shell agent 不同，需按意图适配而非照搬 pwsh+editor |
| B. 保持现状（纠错式补丁继续堆 if） | 否决：flash 首轮问题持续，每领域继续加补丁 |
| C. 引入现成 agent 编排框架 | 否决：重依赖、与 7 红线/审批边界集成成本高 |
| D. 锚定引导 + 状态机 + hooks（本 ADR） | **采纳** |

## Consequences

- **正面**：flash 首轮轨迹锚定（省掉重试轮）；编排层可扩展，领域逻辑出循环体；
  工具结果可摘要、读工具可并行、预算统一、失败可观测。
- **代价**：llm_loop 重构有回归风险；bootstrap 让"首问复杂任务"理论上多一个
  promote 请求（`either` 信号 + 写意图豁免 + 指标监控兜底）。
- **风险**：
  1. 固废生产补丁在 hook 化时行为漂移 → 先写"补丁→hook 等价性"单测再切。
  2. 1024 预算对非 flash 模型误伤 → 仅 easy 路由启用，pro 模型不触发。
  3. 摘要 LLM 引入额外成本/延迟 → 默认关，阈值可配，失败回退截断。
  4. 并行读工具改变时序 → 仅 read 级并发，写类串行不变。

## 分期与验收

### P0 — 设计冻结
- [x] 本 ADR 评审通过；hook 拆分清单与等价性测试用例冻结

### P1 — Flash 锚定引导（代码已落地）
- [x] `[orchestration] bootstrap` 开关（默认 off）；`orchestration_phase` 表（harness.db）；
      `max_tokens` 运行时覆盖（`LlmClient::chat_with_max_tokens` / `RoutedLlm::chat_budgeted`）；
      首轮工具面 ≤3 且写/危险工具硬排除；完整清单/技能块/LATS 首轮剥离；promote 信号与持久化
- [x] 单测：promote 幂等持久化、工具面选择/硬排除、预算默认值、降级路径
- [ ] 生产灰度指标：Easy 查询首轮工具调用率 ↑、平均轮次/延迟 ↓（需带流量验证）
- [x] 写意图（`has_write_intent`）与危险工具不触发 bootstrap（接线条件保证）

### P2 — Plan-Act-Reflect + hooks（代码已落地）
- [x] 状态机骨架：bootstrap 相位 + Plan-Reflect 终答评审（opt-in，评审失败视为达成、不阻断）
- [x] guardrail hooks 迁移：`data_query` 强制工具 → `OnPreAct`；`reply_polish` 重试 →
      `OnFinalAnswer`（文本与条件逐字等价，等价性单测已覆盖）；HookRegistry 支持
      priority 排序 / Inject / Retry / Abort 合并裁决
- [ ] `e2e_controlled_write.py` 与审批/边界回归（需 live 环境，合入 PR 前必跑）

### P3 — 摘要 + TurnBudget + 并行（代码已落地）
- [x] 工具结果 LLM 摘要：`maybe_summarize_tool_outputs`（阈值/起始轮可配，失败保留原文）
- [x] TurnBudget 统一：轮次上限 + 日 token 预算收口到 `orchestration::TurnBudget`
      （同一 quota 调用，行为等价）
- [x] read 并行：`execute_tool_calls_parallel`（仅同轮全 read + 边界/schema 预检全绿；
      任一异常自动回退顺序路径；写/dangerous 永远串行）
- [x] composer / skill_library / TTC verifier 组件放行：**保持 off**（按本 ADR 决策 4，
      等待各自 G 门验收，不随本次变更开启）

## Non-Goals（明确不做）

1. 不引入新编排框架 / 重依赖。
2. 不改边界、审批、配额、审计等执行层语义。
3. 不默认开启任何新增 LLM 调用路径（全部 opt-in + G 门）。
4. 不复制 dsh 代码，只吸收已验证的机制与参数。
5. 不改变 `/api/chat`、`/v1/chat` 对外契约与既有配置格式。
6. bootstrap 不适用于写意图、危险工具、pro 模型会话。

## Rollback

- P1：`[orchestration] bootstrap=false` 即完全回现状（代码路径零改动）。
- P2/P3：状态机与 hooks 各自独立开关；任一阶段回归红线不绿则暂停推进。

## Implementation Notes（2026-08-15 已落地）

代码锚点与行为保证：

- `src/orchestration.rs`（新增）：`OrchestrationConfig` / `BootstrapConfig` /
  `PlanReflectConfig` / `ToolSummaryConfig` / `ReadParallelConfig`（全部默认 OFF）、
  `SessionPhaseStore`（`orchestration_phase` 表挂 harness.db，append-only）、
  `OrchestrationController`、`HookRegistry` + 内置 `DataQueryForceToolHook` /
  `ReplyPolishRetryHook`、`FailureClass::classify_tool_failure`、
  `TurnBudget`（轮次 + 日 token 预算统一查询）。
- `src/llm.rs`：`LlmClient::chat_with_max_tokens`（clone 覆盖预算，不污染原配置）、
  `RoutedLlm::chat_budgeted`（bootstrap 专用，不进 Best-of-N）。
- `src/agent.rs::llm_loop`：bootstrap 触发条件（enabled + easy + 非写意图 + 未
  promoted）→ 最小工具面；首轮剥离完整清单/技能块/LATS 注入；首轮预算化调用；
  首个响应即 promote（either 语义）；OnPreAct / OnFinalAnswer hook 挂载；
  Plan-Reflect 终答评审（opt-in）；工具结果摘要（opt-in）；TurnBudget 收口。
- `src/agent.rs::execute_tool_calls`：拆为调度器 + `execute_tool_calls_sequential`
  （原逻辑逐字保留）+ `execute_tool_calls_parallel`（仅同轮全 read + 预检全绿；
  任一异常自动回退顺序路径）。
- `src/config.rs` / `src/handlers/identity.rs`：`[orchestration]` 配置装配。
- `agent.toml.example`：新增 `[orchestration]` 全量注释示例。

回归基线：`cargo check` 通过；`cargo test` 通过（lib 405 单测全绿，含 7 个
orchestration 单测；集成测试全绿，需外部环境的用例维持 ignored）。
flag-off 等价性由「全部新分支以 `enabled=false` 短路、顺序路径逐字保留」保证。

## References

- ADR-016（agent-core 收敛为 Tool Gateway，推理主循环移交 dsh）
- ADR-008（危险工具硬闸门）、ADR-015（审批单一真相源）
- 实现锚点：`src/agent.rs::llm_loop`、`src/llm.rs::RoutedLlm`、
  `src/composer.rs`、`src/skill_library.rs`
- 机制来源：dsh `win-flash-anchored` 预设（社区实测，锚定式小模型强化）
