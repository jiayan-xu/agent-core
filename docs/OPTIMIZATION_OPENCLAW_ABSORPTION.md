# OpenClaw v2026.7.1 — 吸收分析（运行侧 / agent-core）

> 只读研究产物。源码克隆于 `openclaw-probe/`（tag `v2026.7.1`，仅研究，永不提交/推送）。
> 对照目标栈：`agent-core`（Rust 运行时 :9753）+ `Memoria`（SQLite 记忆/身份总线 :9003）。
> 存储侧（备份契约 / 向量现状 / per-agent 隔离）见 `memoria-open/docs/OPTIMIZATION_OPENCLAW_ABSORPTION.md`。
>
> **修订（2026-07-18）**：补上控制流 checkpoint / 沙箱现状；修正 Crestodian 笔误；与 Grok/HMS/白龙马划界。供 hy3 执行前以本文为准。

## 0. 与既有吸收研究的关系

| 研究 | 落点 | 与本文关系 |
|---|---|---|
| HMS 吸收 | Memoria ledger / text_signals / Dream | 存储侧已完成；本文不碰 |
| Grok Build | **执行沙箱**（`sandbox.rs` Job Object）+ 文件级 checkpoint（内容快照） | **已部分落地沙箱**；本文 A1/A2 **不重复造沙箱**，只补 boot-lifecycle / 审批三门 / 审计元数据 |
| 白龙马 | 意识循环 / 预取 / Focus Stack | 算法层；与本文安全/生命周期正交 |
| **OpenClaw（本文）** | boot safe_mode + Crestodian 三门 + 审计元数据 | 控制面健壮性 |

## 1. 边界与定位对照

| 维度 | OpenClaw 7.1 | agent-core（现状，2026-07） | 重叠度 |
|---|---|---|---|
| 语言/运行时 | TypeScript + Node（pnpm monorepo） | Rust（cargo，:9753） | 低（理念可借鉴） |
| 进程模型 | 单 Gateway + CLI + 多 channel/provider | 单 agent-core + MCP 子进程 | 中 |
| 会话 / 控制流 | 会话注册表 = **纯内存 Map**，重启丢 | **已有**控制流 `checkpoint.rs`（会话/计划/审批状态机，SQLite，崩溃可续跑）；**无**独立「对话消息」会话库 | 中（勿写成「完全无恢复」） |
| 执行隔离 | 见其自身策略 | **已有** `sandbox.rs`（Windows Job Object 等，Grok Phase A1） | — |
| 权限模型 | tool allow/deny + Crestodian 三门 + 操作符作用域 | 两层门控（`fetch_tools_filtered` + `call_tool_routed`）+ `ToolClassifier` 红线/黄线 + `allowed_ns` | 高（理念同构；三门更严） |
| 崩溃恢复 | SQLite 记启动 + 阈值 + channel 抑制；退避委托 OS | 控制流靠 checkpoint；**缺** boot-lifecycle / safe_mode 抑制危险工具自动执行；看门狗 launcher 兜底进程 | 中（可吸收 boot 思路） |
| 模型路由 | ClawRouter（**非成本路由**） | 无路由层 | 低 |
| 技能体系 | Skill Workshop | 宿主 WorkBuddy 侧 | 低 |

## 2. 核心子系统代码事实（file:line）

> file:line 锚定 OpenClaw `v2026.7.1` 探针。

### 2.1 Gateway 启动 / 生命周期
- 服务器主入口：`src/gateway/server.impl.ts:524` `startGatewayServer`；`src/cli/gateway-cli/run-loop.ts` 的 `startLoop→start`。
- HTTP / WS / 端口绑定重试见原探针路径（`server-http.ts`、`server-runtime-state.ts`、`http-listen.ts`）。
- 协议：`packages/gateway-protocol` TypeBox schema。

### 2.2 会话管理（对话层缺口）
- 会话存储 = 纯内存：`packages/acp-core/src/session.ts:35` `createInMemorySessionStore` → `Map`。**无 DB 后端**，重启即丢。
- **注意**：这不等于 agent-core「完全无恢复」——agent-core 的 `checkpoint.rs` 管的是**控制面状态**，不是 ACP 会话 Map。

### 2.3 崩溃循环恢复 / 控制面安全模式
- 启动结果落 SQLite：`src/infra/gateway-boot-lifecycle.ts`，阈值 `GATEWAY_BOOT_LOOP_UNCLEAN_THRESHOLD=3`、窗口 `5*60_000ms`。
- `inspectGatewayCrashLoopBreaker`：窗口内不干净启动 ≥3 → `tripped`。
- 「安全模式」真相：仅抑制 channel/provider **自动**启动（`server-channels.ts:460-474`），HTTP/WS 控制面照常；**无**独立 `safeMode` 布尔。
- `EX_CONFIG=78` **仅配置错误**；崩溃循环路径本身不退出 78。
- 应用层**无**指数退避，委托 systemd/launchd。

### 2.4 安全作用域 / Crestodian 接入
- Capability profile：`resolveConversationCapabilityProfile` —— 文件头明言只是既有工具策略聚合，**非新公共边界子系统**。
- Exact-operation 审批：`hashCrestodianOperation`；三道门：模型断言 `approved` **且** host `approvalArmed` **且** `proposalRef===operationHash`；哈希不匹配立即作废（防模型自我批准）。
- Crestodian 真 agent-loop + 确定性回退三级链（agent → planner → deterministic）。
- 审计：`audit_events` **仅元数据**；`tool_call_id` sha256。
- MCP：工具 allow/deny，**无**来源/namespace 逐调用鉴权（弱于 agent-core `allowed_ns`）。

### 2.5 ClawRouter（成本路由？—— 不是）
- `buildRoutedModel`：能力→传输 API 映射，**非**按价格/延迟选路；`modelCost` 仅展示。
- 可用性故障转移 fallback 链真实存在，与「成本路由」无关。

### 2.6 Skill Workshop
- 状态机 `pending|applied|rejected|quarantined|stale`；apply 前强制安全扫描，非 clean → quarantine。
- 「history-review 扫旧工作」夸大：默认仅当前轮次信号哈希。

## 3. 宣传 vs 代码事实（运行侧）

| 宣传主张 | 代码判定 | 证据要点 |
|---|---|---|
| 崩溃循环进入「控制面安全模式」 | **部分**：仅抑制 channel 自动启动 | `run.ts` / `server-channels.ts` |
| 反复不干净启动停止抖动 | **委托 OS** | boot-lifecycle + systemd |
| 崩溃循环返回 EX_CONFIG(78) | **否** | 78 仅配置错误 |
| ClawRouter 成本路由 | **否（夸大）** | provider-catalog |
| 会话注册表持久化 | **否**（纯内存） | acp-core session |
| Capability profiles 是新边界层 | **否** | 聚合器 |
| Crestodian 三门 + 确定性回退 | **是** | crestodian-tool / agent-turn / chat-engine |
| Skill Workshop 默认无提示 apply | **与代码相反**（默认需审批） | policy / prompt |

## 4. 与 agent-core 当前架构对照（修订后）

- **权限**：两层门控 + `allowed_ns` **优于** OpenClaw 无来源鉴权；应吸收的是 Crestodian **三门操作指纹**，不是 Capability profile 聚合器。
- **崩溃恢复**：已有 **控制流 checkpoint**；缺 **boot-lifecycle + safe_mode（抑制危险/外发工具自动执行）**。OpenClaw 的 SQLite 记启动 + 阈值思路可移植；**退避必须自研**（不能假设 systemd）。
- **沙箱**：Grok A1 已有 `sandbox.rs`——OpenClaw 本文 **不重开沙箱工程**。
- **会话持久化**：对话消息层仍可后续落 Memoria；**勿**吸收 OpenClaw 纯内存 Map。
- **路由**：勿被 ClawRouter 命名误导；成本路由若要做则自研。

## 5. 吸收决策矩阵（运行侧）

| 项 | 判定 | 理由 | 落地点 |
|---|---|---|---|
| 崩溃循环 boot-lifecycle（记启动 + 阈值 + 抑制） | 🟡部分 | 思路清晰；退避自研；抑制对象改为 ToolClassifier 红线/黄线/外发 | `bootstrap` / 新建 `boot_lifecycle`（或旁路小表） |
| **Crestodian 三门审批**（operation_hash + armed + proposalRef） | ✅吸收 | 防 LLM 自我批准；比单门严 | 审批路径（如 `boundary` / checkpoint 审批态）引入指纹校验 |
| 审计仅元数据 + tool_call_id 哈希 | ✅吸收 | 隐私友好 | tracing + 可选 `audit_events` 元数据表 |
| Capability profile 聚合器 | ❌不吸收 | `allowed_ns` 更优 | — |
| ClawRouter 成本路由 | ❌不吸收 | 名不副实 | — |
| Skill Workshop 状态机 | 🟡可选 | 若引入技能再做 apply 前扫描 | 非 Phase A |
| 会话纯内存 Map | ❌不吸收 | 落后 | 对话层另案落 Memoria |
| 重做执行沙箱 | ❌不吸收 | Grok/`sandbox.rs` 已覆盖 | — |

## 6. 落地方案（供 hy3 执行）

### Phase A（最小可用，1–2 周）— **必做**

> **禁止**：重写 `sandbox.rs`；重做控制流 `checkpoint.rs` 状态机；引入 ClawRouter 式「成本路由」。

- **A1：boot-lifecycle + safe_mode**  
  - 记录每次启动 `startup_at` / `completed_at` / `failed`（本地 SQLite 小表即可，不必进 Memoria 热路径）。  
  - 窗口内不干净启动 ≥3 → `safe_mode=true`：  
    - **抑制**危险/外发工具自动执行（复用 `ToolClassifier` 红线/黄线 + 既有边界策略）；  
    - **保留** `/health`、运维/诊断 RPC、人工审批路径。  
  - 对齐 OpenClaw「抑制自动 channel」思路，映射到 agent-core 工具面。  
  - 退避：应用层指数 backoff + jitter（不依赖 systemd）；达上限后停在 safe_mode 等人工。

- **A2：审批三门（Crestodian 不变量）**  
  - 规范化工具调用 JSON → `operation_hash`；  
  - 执行前必须：`approved` ∧ `armed` ∧ `proposal_ref == operation_hash`；  
  - 哈希不匹配 → 作废提案、拒绝执行（防模型自我批准）。  
  - 与现有 checkpoint 审批态衔接，勿另起平行状态机。

- **A3：审计元数据表（可选但推荐同迭代）**  
  - `audit_events`：仅元数据；`tool_call_id` 存 sha256；保留/上限策略可后调。  
  - 与现有 tracing `x-trace-id` 关联，不存工具全文密钥。

### Phase B（健壮性，2–4 周）— **非阻塞**

- **B1**：safe_mode 运维出口（显式 clear / 诊断包）。  
- **B2**：会话消息元数据落 Memoria（与存储侧文档协同；非 OpenClaw Map）。  
- **B3**：若引入技能包，apply 前安全扫描卡口（复用 A2 门）。

**验收（Phase A）**  
1. 注入 3 次不干净启动 → 进入 safe_mode；外发/红线工具自动执行被拒；health 仍通。  
2. 红队：LLM 试图偷换已 armed 操作参数 → `operation_hash` 不一致 → 拒绝。  
3. `cargo build --release` 前停尽 `agent-core.exe`（防 os error 5）；cutover 经看门狗；旧二进制 `.bak-<ts>`。

**运维铁律**  
- 仅改 canonical `agent-core`；gitee 私有镜像不推开源探针内容。  
- 推前 GIT 安全扫描（无密钥、无本机绝对路径）。  
- 生产 cutover 经既有 launcher；与 Memoria 存储侧 Phase A **可并行**，无阻塞依赖。

## 7. 不吸收清单

1. **ClawRouter「成本路由」** —— 目录+配额展示。  
2. **Capability profiles 当新边界层** —— 仅聚合器。  
3. **会话纯内存 Map** —— 重启丢失。  
4. **崩溃退避委托 OS** —— 必须自实现。  
5. **Skill Workshop「默认无提示 apply」** —— 代码默认需审批。  
6. **用本文重做 Grok 沙箱** —— `sandbox.rs` 已存在。

## 8. 实施状态

- [x] 研究完成（v2026.7.1 源码深读 + 宣传对照）
- [x] 方案修订（2026-07-18：checkpoint/沙箱现状 + Crestodian 笔误 + 划界）
- [x] **Phase A 已落地（2026-07-18）**：A1 `boot_lifecycle.rs` + boundary `safe_mode` 闩锁（崩溃循环抑制危险/未分类/外发工具自动执行）；A2 approval `operation_hash` 三门（`compute_operation_hash` + `build_a2a_request` 带 hash + `record_response` 经 `get_pending` 回填，防 LLM 自批）；A3 `audit_events` SQLite 元数据表（`attach_db` 建表 + `record_event` INSERT `tool_call_id=sha256` + `recent_from_db` 读回 + `from_str` 反查）。`cargo check` 全绿，approval/audit 单测通过。
- [ ] Phase B 待开工（按 §6 路线）
- 探针目录 `openclaw-probe/` 为只读研究副本，可随时删除。
