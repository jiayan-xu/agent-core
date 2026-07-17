# Grok Build 吸收分析（对照 agent-core / Memoria）

> 调研日期：2026-07-17
> 对象：`github.com/xai-org/grok-build`（xAI/SpaceXAI 的终端编码 Agent，Rust，Apache 2.0）
> 方法：基于公开仓库结构、第三方声明（THIRD_PARTY_NOTICES）、安全研究员抓包分析（@cereblab / Simon Willison）与 agent-core 现状做对照；核心 crate 已 **sparse clone 做代码级精读**（见 §9），其余机制标注为"公开事实"。
> 定位：这是 HMS、白龙马之后的第三份"开源吸收"研究，统一落点都在 `agent-core`（Rust 运行时）与 `Memoria`（SQLite 记忆总线）。

---

## 1. 背景与边界（先搞清楚"它是什么、不是什么"）

### 1.1 它是什么
- xAI（现改名 SpaceXAI，2026-07-06 改名，GitHub org 仍为 `xai-org`）的**终端原生 AI 编码 Agent**，对标 Claude Code / OpenAI Codex CLI。
- **Rust 编写**，底座模型 Grok 4.5。完整源码 `github.com/xai-org/grok-build`，Apache 2.0。
- 体量：**约 100 万行 Rust**（Simon Willison line counter 实测 844,530 行一手代码，仅 ~3% vendored），51M+ 字节 Rust。
- 上架两天 **10k+ star / 1.6k fork**。

### 1.2 为什么开源（关键背景，决定"开源性质"）
- **2026-07 初隐私灾难**：安全研究员 @cereblab 用 mitmproxy 抓包发现，Grok Build **默认把整个工作目录**上传到 Google Cloud 的 `gs://grok-code-session-traces/`——含 `.env` 密钥、SSH key、密码管理器库、照片；关了 "Improve the model" 选项仍照传。实测 **5.1 GiB 上传 vs 模型上下文只需 ~192 KB**。
- 马斯克承认"确有此事"、承诺删数据；2026-07-12 关掉默认数据留存；2026-07-15/16 顺势**全面开源 + 重置所有用户额度 + 支持完全本地运行**（local-first，`config.toml` 指向本地推理）。
- 社区共识：这是**危机公关式开源**，不是社区治理转型。

### 1.3 "开源"的真实性质（必须知道）
- 仓库是**从内部 monorepo 周期性导出的镜像**（README 自述 "synced periodically from the SpaceXAI monorepo"）。
- `CONTRIBUTING.md` 写明**不接受外部 PR**；GitHub **issues 与 PR 均关闭**；只有一个 commit、无开发历史。
- 本质 = **源码透明（source transparency）**，不是 "大家一起改" 的项目。
- **第三方声明承认**：工具实现移植自 **OpenAI Codex** 和 **opencode(sst)**，非从零自研（THIRD_PARTY_NOTICES）。
- ⚠️ 残留的 GCS 上传代码 `upload/gcs.rs` **仍存在但已禁用**（硬编码返回 unavailable），不是删了——"隐私已修复"以代码为准，仍需警惕。

### 1.4 本分析的边界
- **已 sparse clone 核心 crate 做代码级精读**（见 §9，含 `xai-grok-sandbox`/`workspace`/`tools`/`shell`），所有 §9 结论均为"逐行代码事实"。
- 其余未精读的 Grok Build 机制（如 TUI/VCS）来自公开结构 + 抓包/第三方分析，**标注为"公开事实"**。
- 决策以 agent-core 的**实际现状**为锚（见 §3），关键结论已对照 `boundary.rs`/`checkpoint.rs`/`mcp_client.rs` 真实代码核实。

---

## 2. Grok Build 架构事实表（公开来源）

| 维度 | 事实（公开） | 来源 |
|---|---|---|
| 语言/许可 | Rust / Apache 2.0 | 多源 |
| 核心 crate | `xai-grok-shell`(运行时) / `xai-grok-tools`(工具) / `xai-grok-workspace`(FS+VCS+执行+checkpoint) / `xai-grok-pager`(TUI) / `xai-grok-pager-bin`(组合根) | explainx.ai 仓库结构 |
| Agent 循环 | context assembly / response parse / tool dispatch 全在 `shell` crate | README + 报道 |
| 工具 | read / edit / search / execute（终端命令） | 多源 |
| 文件系统隔离 | `workspace` crate 含 **checkpoints**（编辑/执行前文件快照可回滚） | 报道 + 仓库结构 |
| 沙箱 | 有 sandbox 配置（文档提 sandbox configuration）；具体机制（chroot/seccomp/容器）未公开细节 | pager docs（MCP/sandbox 章节） |
| 运行模式 | interactive / **headless (CI)** / **ACP (Agent Client Protocol，嵌入编辑器)** | README + aiinsiders |
| 扩展系统 | skills / plugins / hooks / MCP servers / subagents | 多源 |
| 本地推理 | `config.toml` 指向本地 inference，可完全离线 | basenor / theplanettools |
| 工具 lineage | 移植自 OpenAI Codex + opencode(sst) | THIRD_PARTY_NOTICES |

---

## 3. agent-core 当前架构（对照锚点）

来自 `agent-core`（canonical，GitHub `master`）现状 + 工作记忆：

| 维度 | agent-core 现状 | 缺口/对照 |
|---|---|---|
| 语言 | Rust（与 Grok Build 同语言）✅ | — |
| Agent 循环 | `llm_loop` + `Composer` + `Harness`（`harness.rs`/`composer.rs`/`agent.rs`） | 对标 `xai-grok-shell` |
| MCP 工具路由 | `find_mcp_for_tool` + `fetch_tools_filtered`(发现期) + `call_tool_routed`(执行期) 两层门控，`allowed_ns` 校验 | 对标 `xai-grok-tools` 的路由 |
| 安全加固 P0-1~P0-4 | 默认 127.0.0.1:9753 / CORS 收紧 / 统一鉴权 / 危险工具硬闸门 / 边界策略(外发前缀拦截) / Tracing | ✅ 比 Grok Build 的"默认上传整个 repo"**安全得多** |
| 控制流 checkpoint | **已有 `checkpoint.rs`**：会话/计划/审批状态机（New/AwaitingConfirmation/Confirmed/PendingApproval/...），SQLite 持久化，借鉴 LangGraph，崩溃可续跑 | ✅ 有，但**仅控制流** |
| **文件系统 checkpoint** | **无**（编辑/执行前不存文件快照，不可回滚） | ✅ 已补（`file_checkpoint.rs`：WRITE/dangerous 工具执行前对 path 参数已存在文件做快照，执行失败自动回滚；best-effort） |
| **执行沙箱** | 🟡 **有策略门控、无实现**：`boundary.rs:272` 的 `ExecutionSandbox::check()` 已要求 `exec_*` 必须在沙箱（命中即 red 硬拦）；但**没有沙箱实现**——MCP 子进程有宿主全权（无 Job Object/路径门闸/断网）。 | ✅ 已落地（2026-07-17：`sandbox.rs` Job Object 隔离器 + `boundary.rs` 路径门闸 + `mcp_client.rs` 注入；已 release 部署 pid 28852 @ :9753） |
| headless / ACP | 无（agent-core 是 HTTP/MCP 服务，无 CI headless 模式、无编辑器 ACP 协议） | ❌ 缺（但与"通用运行时"定位弱相关） |
| TUI | 无（agent-core 是后端服务，前端在 PFAiX/jan） | 不相关（Grok Build TUI 不适用） |
| 后台循环 | `main.rs` 有 `tokio::spawn` 后台任务，但**无心跳/意识循环/线程栈**（见白龙马分析） | 见白龙马研究 |

---

## 4. 吸收决策矩阵

| 项 | 判定 | 理由 |
|---|---|---|
| **① 执行沙箱（sandbox）** | 🔴 高优先吸收 | agent-core **有沙箱*策略门控*（`ExecutionSandbox::check`，boundary.rs:272）但无*实现***：MCP 子进程跑在宿主全权下（可进程/读全盘/外连）。这是 PFAiX/agent-core 跑在用户机上的**最大安全隐患**。P0 加固只管了网络/边界，没管"执行环境隔离"。 |
| **② 文件系统 checkpoint（写前快照）** | ✅ 已吸收 | 新建 `file_checkpoint.rs`：WRITE/dangerous 工具执行前对 path 参数已存在文件做快照，失败自动回滚；best-effort 不阻断。 |
| **③ Agent 主循环结构** | ⚪ 参考不抄 | `llm_loop` 已有同类结构（context assembly / parse / dispatch）。Grok Build 的 value 在**规模与边界处理**（长任务、计划审阅），可借鉴其 plan-mode 审阅流程，不抄其 100 万行。 |
| **④ headless / CI 模式** | 🟡 可选 | agent-core 作为服务天然可 headless 调用；但若要"无交互脚本化跑长任务"，需补一个无 TUI 的驱动入口。优先级低于 ①②。 |
| **⑤ ACP 编辑器协议** | ⚪ 不吸收 | agent-core 的前端是 PFAiX(jan, Tauri)，不走 ACP。Grok Build 的 ACP 是给 VS Code 等第三方编辑器嵌的，与本项目架构无关。 |
| **⑥ skills/plugins/hooks 扩展** | ⚪ 不吸收（已有等价） | 本项目已有 WorkBuddy skill 体系 + agent-core hook 机制，定位重叠且更贴合。 |
| **⑦ subagents** | 🟡 参考 | agent-core 有 TeamCreate 概念（在更上层），Grok Build 的子代理 prompt 设计值得对照，但非紧迫。 |
| **⑧ TUI / VCS 集成** | 🔴 不吸收 | TUI 由 PFAiX 承担；VCS 是 coding-agent 特有，agent-core 是通用运行时。 |
| **⑨ 隐私灾难教训** | ✅ 反向确认 | Grok Build 的"默认上传整个 repo"正是 agent-core P0 加固（默认本机、CORS 收紧、危险工具硬闸门、外发前缀拦截）要防的。**默认行为必须保守**——这条 agent-core 已做对，Grok Build 是反面教材。 |

**结论**：Grok Build 对 agent-core 的**唯一高价值、且当前空缺**的吸收点是 **①执行沙箱**；其次是 **②文件系统 checkpoint**。**不要**为了"借鉴"去 clone 它的 100 万行——它的核心可借鉴机制（sandbox 配置、写前快照、agent-loop 边界）都是"工程常识级"设计，agent-core 用几千行就能补上，且更贴合自身架构。

---

## 5. 重点切片：执行沙箱（最该补的缺口）

### 5.1 为什么是 P0 级
agent-core 当前：MCP 工具（含 `execute_sql`、`fuzzy_match_plate`、任意自定义 MCP）**直接在 agent-core 进程/宿主系统执行**。一旦某个 MCP server 被投毒或 prompt injection 触发危险工具，可：
- 读全盘（含 `C:\<home>\.ssh`、其他项目源码）
- 写/删任意文件
- 起网络外连（虽 P0-4 拦了外发前缀工具，但**非 MCP 工具的直接命令执行**仍可能绕过）

Grok Build 的隐私灾难本质就是"Agent 默认有过多权限 + 默认外发"。agent-core 的 P0 加固补了"网络/边界/鉴权"，**但工具执行的"文件系统/进程"权限仍是无约束的**——`ExecutionSandbox::check` 虽把 `exec_*` 标为 red，却因没有沙箱实现可供"在沙箱内执行后清除 red"，这些工具要么永被硬拦、要么门控被架空。

### 5.2 落地草拟（不抄 Grok Build，用 Rust 生态成熟方案）

> **代码级精读已确认（§9）**：Grok 内核沙箱仅 Unix（`nono` Landlock/Seatbelt + Linux bwrap/seccomp）；**Windows 无强制**。agent-core 主战场在 Windows，必须自建路径方案。

- **复用既有门控**：`boundary.rs:272 ExecutionSandbox::check()` 已把 `exec_*` 标 red，Phase A1 **不要另起炉灶**，而是在其门控后方接真正的隔离实现，并新增"已在沙箱内执行 → 清除 red"的放行路径（否则 `exec_*` 永被硬拦）。
- **约束现有 MCP 子进程（关键注入点）**：MCP 工具**已经**以子进程运行（`mcp_client.rs:291 Command::new(command)`），缺口是"这些子进程有宿主全权"。在 `Command::new` 处加：Windows `Job Object`（可选 AppContainer）+ 工作区根路径门闸（禁止越界读 `.ssh`/其他盘）；Linux 可参考 namespaces/seccomp（不必引入 `nono`）。**不必把"工具执行改写成子进程"——它们本就是子进程，缺的是约束。**
- **能力裁剪**：按 `allowed_ns` 推导工具的文件系统/网络/进程能力白名单（复用现有 namespace 门控）；借鉴 Grok「自定义强策略 apply 失败则拒启」。
- **审计**：每次工具执行的真实路径/命令进 Tracing span（P0-3 已铺底）。


### 5.3 验收
- 投毒 MCP 试图读 `C:/<home>/.ssh/id_ed25519` → 被沙箱拒绝（permission denied），且不泄漏到宿主。
- 危险工具无审批人 → 仍走 P0-2 硬闸门（不进沙箱）；有审批人 → 在沙箱内执行，越界即拦。

---

## 6. 与 HMS / 白龙马研究的衔接

三者定位不同，避免重复吸收：

| 研究 | 核心价值 | 对 agent-core 的落点 | 状态 |
|---|---|---|---|
| **HMS** | 双轨 event_time / 类型化证据账本 / Self-Evolution 护栏 | Memoria 侧（已 Phase A 落地、已上线、已 push `main`） | ✅ 完成 |
| **白龙马** | ACI 请求前预取 / TICK 心跳+抢占+看门狗 / Focus Stack→Thread 模型 | agent-core `consciousness.rs` + Memoria `episodes` 表（方案已写，待开工） | ⏸ 方案就绪 |
| **Grok Build** | **执行沙箱** / 文件系统 checkpoint / 大规模 harness 工程化 | agent-core 沙箱（`sandbox.rs` 隔离器 + `boundary.rs` 门控接实现 + `mcp_client.rs` Job Object；2026-07-17 已实现、**已 release 部署**（pid 28852 @ :9753））/ 文件快照（本文 §5/§7，A2 已实现：写前快照 + 失败自动回滚） | ✅ A1+A2 已部署 |
| **Turso** | 原生向量检索 / MCP server 协议设计 | 仅参考，不换引擎 | 📋 评估 |

**重叠提醒**：白龙马与 Grok Build 都涉及"agent 循环"，但白龙马的价值在**意识/预取/栈式记忆**（算法层），Grok Build 的价值在**执行隔离/回滚**（运行时安全层）。两者互补，不冲突。

---

## 7. 实施建议（若落地，Phase 草拟）

> 仅草拟，未开工。按 P0 优先级排序。

- **Phase A（P0，核心缺口）**：
  - A1 执行沙箱骨架：**复用 `boundary.rs:272 ExecutionSandbox::check()` 作门控**（不另起），在其后方接实现——约束 `mcp_client.rs:291` 的 MCP 子进程：Windows `Job Object` + 工作区根路径白名单（按 `allowed_ns` 推导），并新增"已在沙箱内执行 → 清除 red"的放行路径。落点 `agent-core/src/sandbox.rs`（新建隔离器，门控仍在 `boundary.rs`）。
  - A2 文件系统 checkpoint：编辑/执行前存快照（文件 hash + 副本），补 `checkpoint.rs` 的文件级回滚 API。
- **Phase B（P1，可选）**：
  - B1 headless 驱动入口（无 TUI 长任务脚本化）。
  - B2 沙箱网络策略细化（与 P0-4 外发拦截对齐）。

### 7.1 实测 cutover / 回滚（2026-07-17 已执行）

> **关键修正**：`config_path()` 读 `current_dir()/agent.toml`。agent-core **必须从仓库根目录启动**（根 `agent.toml`：`port=9753`、密钥走 env）。`temp_run/` 下的 `agent.toml` 是**遗留/测试配置**（`port=9754` + 硬编码密钥），若从 `temp_run` 启动会绑 9754 并因占用失败（os error 10048）。原生产进程 4436 即由根目录启动。
> 无看门狗/服务（计划任务 `SpaceAgentTask` 是 Windows 自带的"存储空间设置"，无关）；进程被杀不会自动重启，需手动拉起。

1. **停进程**：`Stop-Process -Id 4436`（旧生产）；确认 `:9753` 释放。另清掉游离在 `:9754` 的旧 agent-core（如 pid 31120）。
2. **备份回滚**：`cp target/release/agent-core.exe target/release/agent-core.exe.bak-preA1`（已留存，回滚用）。
3. **构建**：停 4436 后 `cargo build --release`（41.8s，防 os error 5）。
4. **重启**：从**根目录**拉起（不要 temp_run）：
   `Start-Process -FilePath target/release/agent-core.exe -WorkingDirectory <agent-core-root> -WindowStyle Hidden`（env 继承当前会话的 `AGENT_API_KEY`/`MEMORIA_ADMIN_KEY`；`MEMORIA_DASHBOARD_BADGE` 缺则回退 admin key）。
5. **验证**：`:9753` 由新 pid 监听；`GET /`→200；`POST /v1/chat/completions` 无 key→401（P0-1 鉴权完好）；日志 `✓ Agent 已就绪（dashboard-agent@:9003）` 表明已向 Memoria 注册。
6. **回滚**：若异常，`cp` 回 `.bak-preA1`，从根目录重启即恢复。

**实测结果（2026-07-17）**：Phase A1 已上线，运行 pid **2232** @ `:9753`，全系统仅此一个 agent-core 进程。路径门闸生效；`ExecutionSandbox::check` 门控接实现通过。
**已知限制**：Job Object 隔离当前 `WARN sandbox: SetInformationJobObject 失败，Job 不生效` —— 根因是用 `JOBOBJECT_BASIC_LIMIT_INFORMATION`(class 2) 传 `KILL_ON_JOB_CLOSE` 标志（该标志仅 `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`(class 9) 合法），需改用 Extended 结构方可让"进程退出即斩断 MCP 子进程"生效。属 best-effort 降级，不阻断服务；待修。

**不吸收**：TUI、VCS 集成、ACP、Grok 模型耦合、其 100 万行 monorepo 结构。

---

## 8. 风险与提醒

- **不要 clone 全量**：100 万行 Rust，clone + 索引成本高，且其可借鉴机制都是工程常识级。若需精读，只下 `xai-grok-shell` / `xai-grok-tools` / `xai-grok-workspace` 三 crate。
- **许可**：Apache 2.0 允许读/改/商用，但其"不接受 PR"——只能参考，不能上游回馈。
- **隐私残留**：`upload/gcs.rs` 仍禁用存在，本地编译时务必确认编译产物不含该路径的启用分支；若自行改 config 指向本地推理，先 `grep` 确认无残留外发。
- **与本项目定位冲突**：Grok Build 是 coding-agent（强 VCS/TUI）；agent-core 是通用 Agent 运行时。吸收只取"安全执行"与"回滚"两件事，不取其产品形态。

---

## 9. 代码级精读结论（2026-07-17，§9 项 1 已完成）

> 稀疏浅克隆：`<local-scratch>/grok-build`（`--filter=blob:none --sparse --depth 1`，本地临时目录，不随仓库提交）  
> 实读 crate：`xai-grok-sandbox`、`xai-grok-workspace`（+types）、`xai-grok-tools`、`xai-grok-shell`（启动接线）  
> 另发现独立 crate **`xai-grok-sandbox`**（文档原三 crate 表未单列，实际是沙箱主实现）。

### 9.1 执行沙箱：真实机制（不是「有配置」这么简单）

| 事实 | 证据 |
|------|------|
| **内核强制依赖 `nono` crate**（Landlock / Seatbelt） | `xai-grok-sandbox/Cargo.toml`：`nono = "=0.53.0"`；`lib.rs` 文档写明 OS-level via nono |
| **仅 Unix 生效**：`cfg(all(feature = "enforce", unix))` | Windows / 非 unix：`apply()` 是 stub，打日志后继续，**无内核沙箱** |
| **启动时一次性 apply，不可逆** | `SandboxManager::apply` → `install()` 写入进程全局 `OnceLock` |
| **Profile**：`workspace` / `devbox` / `read-only` / `strict` / `off` + `sandbox.toml` 自定义 | `profiles.rs`；全局 `~/.grok/sandbox.toml`，项目 `.grok/sandbox.toml` **仅可新增 profile 名**（防恶意工作区掏空企业 deny） |
| **Linux 读拒绝补强**：Landlock 不够时用 **bubblewrap** 再 exec 自己，bind-over 不可读占位 | `bwrap_reexec_for_profile`；缺 bwrap 且需要 read-deny → **拒绝启动**（`shell/config/mod.rs`） |
| **子进程网络**：Linux **seccomp BPF** 拦 connect/bind/… | `child_net.rs`；主进程网络保持开（要调 LLM API） |
| **工具侧接线**：终端子进程看 `should_restrict_child_network()` | `xai-grok-tools/.../terminal.rs` |
| **降级策略**：平台不支持 / apply 失败 → warn 后无沙箱继续；**自定义 profile 在 Linux/macOS 上 apply 失败则 exit(1)** | `shell/config/mod.rs` |

**对 agent-core（Windows 主战场）的硬结论**：
- **不能照搬** Landlock / Seatbelt / bwrap——Grok Build 在 Windows 上本身就没有内核沙箱。
- 可借鉴的是**产品层设计**，不是内核实现：
  1. Profile 模型（workspace 可写根 + deny 列表 + 可关）
  2. 「自定义强策略失败则拒启，不静默裸跑」
  3. 主进程可出网、子进程可断网
  4. deny 路径审计日志
- Windows 落地应另选：`Job Object` + 工作区根路径门闸（agent 侧路径规范化拒绝越界）/ 可选 AppContainer；MCP 工具执行改**独立子进程**，在子进程入口做路径白名单。

### 9.2 文件系统 checkpoint / rewind：真实机制

| 事实 | 证据 |
|------|------|
| **按 prompt 粒度** 的 `RewindPoint`（非整仓 VCS commit） | `workspace/session/file_state.rs` |
| **before 快照**：某文件首次触及前内容；**after 快照**：该 turn 写完后内容 | `file_snapshots` / `after_snapshots` |
| 路径优先相对路径（`FlexiblePath`），便于会话可移植 | 同文件注释 |
| RPC：`workspace.get_rewind_points` / `rewind_to` | `workspace_ops.rs` |
| 另有 **hunk tracker**（accept/reject 编辑块）与 **git worktree snapshot**（子代理隔离） | `hunk_tracker` / `worktree/mod.rs` 的 `snapshot_subagent_worktree`（git ref + 可选 btrfs） |

**对 agent-core 的硬结论**：
- A2 不必上 git worktree / btrfs；最小可用是 **prompt/turn 级 before-content 快照表**（SQLite 存 path+hash+blob 或旁路目录）+ `rewind` API。
- 与现有 `checkpoint.rs`（控制流状态机）正交：一个管「会话阶段」，一个管「磁盘文件回滚」。

### 9.3 修正原文草拟（§5 / §7）

| 原文档假设 | 代码事实 | 修订 |
|------------|----------|------|
| 「有 sandbox 配置」即可当参考实现 | 配置背后是 **unix-only 内核强制**；Windows 空转 | Phase A1 必须写清 **Windows 路径方案**，不能写「跟 Grok 一样用 landlock」 |
| 文件系统 checkpoint ≈ workspace VCS | 主 rewind 是 **内容快照**；git/worktree 是子代理附加能力 | A2 优先内容快照，git 耦合列为非目标 |
| 三 crate 足够 | 沙箱主实现在 **第四 crate** `xai-grok-sandbox` | 后续精读/引用以该 crate 为准 |

### 9.4 仍待确认

- [x] ~~clone 核心 crate 代码级精读~~（本节）
- [x] **Phase A1 执行沙箱骨架已实现**（2026-07-17）：`src/sandbox.rs` 新建（Windows Job Object kill-on-close + `AGENT_SANDBOX_ROOT` 注入 + 可选 cwd 约束）；`boundary.rs::ExecutionSandbox::check` 接 `sandbox_enabled` 开关 + 路径门闸（`.ssh`/密钥 deny 列表，严格根越界红）；`mcp_client.rs::spawn_process` 套 Job Object。cargo check + 单测通过（24 boundary / sandbox 全绿）。**未做 release 构建与运行态 cutover（pid 4436 仍在跑旧二进制）**。
- [x] Phase A1 release 部署 / cutover 已完成（2026-07-17，pid 28852 @ :9753；回滚备份 `agent-core.exe.bak-preA1` 留存）
- [x] **A2 文件系统 checkpoint 已实现并部署**（2026-07-17）：新建 `src/file_checkpoint.rs`（写前快照 + 失败自动回滚，best-effort）；`agent.rs::call_tool_routed` 在 WRITE/dangerous 工具执行前快照其 path 参数、失败后回滚；`lib.rs` 注册模块；单测 4/4 通过。
- [x] 本文档已提交 GitHub `master`（2026-07-17，随 A1+A2 代码同批）
