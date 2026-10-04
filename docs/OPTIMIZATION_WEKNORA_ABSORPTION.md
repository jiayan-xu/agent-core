# WeKnora 吸收分析（代码级）

>研究基线：`Tencent/WeKnora` @ `VERSION=0.8.2`（2026-09-24），全量源码静态阅读 + 调用方反向索引
> 研究日期：2026-10-04
> 许可证：MIT 主体 + MPL-2.0（go-sql-driver/mysql、go-m1cpu）+ Apache-2.0（OpenCC 词典数据），**可商用、可借鉴**
> 仓库实时数据：31,857 star / 4,252 fork / 650 open issues
> 目标栈：agent-core（Rust 运行时，:9753）+ memoria（Rust 记忆系统，:9003）

---

## 0. 一句话结论

**WeKnora 是一个「单主体、flat、≤2000 条、面向 RAG 产品个性化」的知识框架。它的记忆系统不是 agent 记忆系统。**

对agent-core / memoria 的净增益集中在三处：

1. **RAG 检索的工程细节**（RRF 归一化、父子分块、rerank 降级契约）—— 价值高，难度低
2. **中文文本处理的坑位记录**（双归一化器、bigram 加权）—— 纯增量
3. **RAG 个性化钩子**（记忆影响检索而非只影响回答）—— memoria 完全空白

**它的记忆架构（无命名空间、无图、无跨agent、≤2000 条）不具备替代 memoria 的可能。**

---

## 1. 宣传口径 vs 代码事实（必读，防误吸收）

| 宣传 | 代码事实 | 证据 |
|---|---|---|
| "**GraphRAG**" | **不是 GraphRAG**。图谱仅做「实体名子串匹配 → chunk ID 一跳反查」，把 chunk 当普通候选塞进 rerank 池。**无路径遍历、无社区摘要、无实体 embedding** | `internal/application/repository/neo4j/repository.go:271-294`（Cypher 只有一跳 `MATCH (n)-[r]-(m)`） |
| "KB retrieval **fan-out across vector stores**" | **不是跨引擎 fan-out**。是按 `(VectorStoreID, TenantID)` 分组——同一引擎类型的多个*绑定 store 实例* | `internal/application/service/knowledgebase_search_storegroup.go:94-106` |
| "知识图谱算法"（PMI 加权、二跳扩散） | **`internal/application/service/graph.go` 全部 1039 行是死代码**。grep 全项目：只有接口定义 + 自身定义 + 内部自调用，**零外部调用方**；`container.go:177` 只 `Provide` 了 neo4j **repository**，从未 `Provide` `types.GraphBuilder` | 已实证：`grep -rn "GraphBuilder\|BuildGraph(\|GetRelationChunks"` 非测试调用方 = 0 |
| "adaptive 3-tier chunking" | ✅ 真实且接线 | `internal/application/service/chunker/strategy.go:34-58` |
| "parent-child chunking" | ✅ 真实且接线 | `internal/application/service/knowledge_process.go:518-548, 581-584` |
| HyDE / multi-query | ❌ **不存在**。query 扩展是纯规则（停用词/引号/分隔符/疑问词剥离），且**明确 `DisableVectorMatch: true` 只走 keyword** | `internal/application/service/chat_pipeline/query_expansion.go:22-32, 82` |
| RRF | ✅ 真实且**正确**（含关键的归一化步骤，见§3.1） | `internal/application/service/knowledgebase_search_fusion.go:170-234` |
| 长期记忆 "auto-extracted" | ✅ 真实。但**默认模式是 `explicit_only`**，开箱即用时记忆近乎不工作 | `internal/types/memory.go:59-66`, `Normalize()` `:453-455` |

---

## 2. 与 memoria 记忆系统的正面对比

### 2.1 WeKnora 明确「没有」的能力（已实证）

| 能力 | WeKnora | 证据 |
|---|---|---|
| **命名空间** | ❌ 只有 `(TenantID, SubjectID)` 二元 scope | `internal/types/interfaces/memory.go:14-17`；grep `namespace` 在 memory 相关文件 → **0 命中** |
| **图记忆** | ❌ 5 个 kind 全是 flat 字符串枚举（profile/preference/fact/task/interest） | `internal/types/memory.go:24-35` |
| **A2A 跨 agent 记忆共享** | ❌ grep `a2a` / `cross.agent` 全仓 → **0 命中** | 实证通过 |
| **事件溯源** | ❌ 无。但有弱化替代：`SourceSessionID`+`SourceMessageID` 溯源到具体消息 | `internal/types/memory.go:308-309` |
| **11 万条规模** | ❌ 设计上限 **2000 条/人**（`memory.go:461-463`），且 `memory_items` 表**零索引**，全靠 `(tenant_id, subject_id)` 前缀扫描 | `internal/types/memory.go:288-326`（struct tag 无任何 index） |

### 2.2 WeKnora 有、memoria 需对照核实的

| 能力 | WeKnora 实现 | 与memoria 关系 |
|---|---|---|
| **memory decay / 衰减** | ❌ **刻意不做**，代码明确论证（见 §3.4） | memoria **有** `memory_decay` 工具 → 这是**替代方案对照**，不是重复 |
| 中文 topic 双归一化器 | ✅ 见 §3.2 | 需核实memoria 实体归一化是否处理中文 |
| 混合检索 RRF（k=60） | ✅ `fuseRankings` | 需核实memoria 是否已 RRF，还是FTS5 + ChromaDB 分别top-k 后拼接 |
| alias 只进向量不进 prompt | ✅ `vector.go:130-135` | 需核实 |
| 记忆影响检索（3 条路径） | ✅ 见 §3.3 | memoria 大概率空白 → **纯增量** |
| 写时敏感信息脱敏（14 条正则） | ✅ 写在 `writeReplacing` 第一道 | **需核实；若 memoria 无，这是真实缺口** |
| Tombstone 双键（fingerprint + source_message_id） | ✅ `memory.go:806-833` | 需核实 |
| 确认状态机（pending → active/reject） | ✅ 完整（prompt 标记 → 状态 → 不进 prompt → API 确认/拒绝） | 需核实 |
| Rerank 降级契约（9 种Outcome 枚举） | ✅ 见 §3.1 | 纯增量 |

---

## 3. 吸收决策矩阵

### ⭐⭐⭐ P0 — 强烈建议吸收（高价值 / 低难度）

#### 3.1 RRF 归一化到 [0,1] + rerank 降级契约

**代码事实**（`knowledgebase_search_fusion.go:175, 203`）：
```go
maxRRF := (vectorWeight + keywordWeight) / float64(rrfK+1)
...
info.Score = rrfScore / maxRRF     // 归一化到 [0,1]
```
已实证存在。作者注释直接写出后果：原始 RRF 顶到 **0.016**，混合命中会输给任何单路结果，导致 rerank 的 `baseScore` 项和 MMR 的 `relevance` 项**无输入可用**。

配套三件套：

| 设计 | 位置 | 要点 |
|---|---|---|
| `bestRanks` 逐list 独立排名 | `fusion.go:224-234` | 跨多召回 list 取每个 chunk 的**最佳位次**，而非拼接后取 rank。拼接排名会让第二个 list 的最佳命中排在第一个 list 的所有命中之后 —— 语义正确性 bug，极易漏 |
| `rescaleUnboundedScores` | `fusion.go:114-154` | BM25 分数无上界（常 >10），会把复合分数 clamp 到 1.0 使所有候选同分，**MMR 退化为纯多样性排序**。这个陷阱极隐蔽 |
| `clamp01` 显式处理 NaN/±Inf | `internal/application/repository/retriever/normalizer.go:84-95` | NaN 破坏 `sort_by` 全序关系，Rust 里表现为排序不确定而非 panic，极难debug |
| **9 种 Rerank Outcome 枚举** | `internal/types/rerank.go:47-72` | `threshold_degraded` / `fallback_top1` / `all_below_threshold` / `model_unavailable` … 每个降级路径独立 outcome 且透传到 API 响应。**把"为什么结果是空的"做成可观测契约，而不是静默降级** |
| `FallbackMinScore(explicitScope)` | `reranking/rerank.go:47-52` | 用户显式指定文档范围时返回 `-Inf` —— **不让全局阈值抹掉用户的权威范围**。这个思路极对 |

**落地点**：memoria `memory_recall` 路径。若当前是 FTS5 召回 + ChromaDB 召回分别 top-k 后拼接 → 改 RRF；若已是 RRF → 只补归一化 + `clamp01` + Outcome 枚举。

**验收**：构造一个词法命中但向量不中的 case，确认 RRF 归一化后其分数不再被单路结果压制；NaN 分数输入时排序稳定。

**Rust 难度**：低（纯函数，合计约 150 行）

---

#### 3.2 中文双归一化器（WeKnora 踩坑后的产物）

**代码事实**（`internal/types/memory.go:1217-1255`）：

两个归一化器**故意不同**：
- `NormalizeTopicKey`（保序）：去噪字 `'的''了''地'` + 去尾缀 `"相关问题"/"问题"/"方面"`
- `NormalizeMemoryKey`（排序+去重字符集，词序无关）：用于 item 冲突检测

作者注释明确论证了为什么不能共用：
> "it treats '门店排班管理' and '门店的排班管理' as different subjects because of one extra character, and it would treat two anagrams as the same one."

配套：`TopicSimilarity`（Dice 系数 bigram，`:1263-1275`）+ 低熵门控 `TopicIsSpecificEnoughToMatchLoosely`（要求 ≥4 字符，`:1299-1301`）。

**为什么值得抄**：这是中文文本处理的真难点。**通用价值远超记忆系统本身** —— 任何中文实体归一化都要先决定"词序是否影响身份"。

**落地点**：memoria 中文实体的 topic 身份判定。**Rust 难度**：低（纯函数约 80 行）

---

#### 3.3 记忆影响检索（而不是只影响回答）

**这是 WeKnora 记忆系统唯一真正的架构增量。** 三条独立路径：

| 路径 | 位置 | 机制 |
|---|---|---|
| ① Query rewriter 背景注入 | `chat_pipeline/query_understand.go:340-377` | `<asker_background note="...">` + 长期关注 + 常查资料 |
| ② Affinity rerank 加权 | `chat_pipeline/memory_affinity.go:100` | `Score *= affinityFactor(hits)` |
| ③ 兴趣词表 | 同 ① | — |

**关键设计（可直接搬的三点）**：

1. **Affinity 是对数饱和 + 硬上限 1.15**（`memory_affinity.go:119-128`）：
   ```go
   ratio := math.Log1p(hits) / math.Log1p(8)
   return 1 + 0.15 * min(ratio, 1)
   ```
   注释："the tenth reuse of a document counts for far less than the second: familiarity should be a nudge that compounds slowly, not a feedback loop that locks a person into the first document they ever opened."
   上限 1.15 远低于 wiki boost 的理由也写清了：**文档出现在历史回答里只说明检索器老选它，不代表用户觉得有用**。

2. **Advisory 而非 filter**（`query_understand.go:334-336`）：
   > "Memory narrows nothing and excludes no knowledge base: a stale note about last quarter's project must not be able to make this quarter's documents unreachable."

3. **注释解释了"记忆为什么该在这一层生效"**（`query_understand.go:330-338`）：
   > "This is the point where long-term memory stops being a paragraph appended to the answer prompt and starts changing what gets retrieved."

**落地点**：memoria 若已有知识检索环节 → 新增 retrieval conditioning；若纯记忆无检索 → 记为 Phase B。**Rust 难度**：中（三条路径都要接管线，但每条独立可增量）

---

#### 3.4 退役工具三件套（零迁移重命名）

**代码事实**（`internal/agent/tools/definitions.go:136-229`）。v0.8.2 把 5 个检索工具收敛成 3 个，**零数据迁移**：

1. 保留退役常量（解历史）—— `LegacyToolKnowledgeSearch` 等
2. 映射表 + `NormalizeAllowedTools` 运行时改写 allowlist
3. **`RetiredToolReplacement` 给模型的精确替代文案**（最值钱）：
   ```
   "grep_chunks is no longer available; use search_knowledge(query=..., mode=\"keyword\")
    for exact terms, or read_document(id=dN, query=...) to search inside one document"
   ```
   **不是告诉模型"这个工具没了"，而是给出精确替代 —— 模型能自我纠正，而不是反复撞墙。**

配套：`CanRunConcurrently` 显式 allowlist（默认 deny，`tools/execution_policy.go:3-20`）；能力门控时"故意不在 allowlist 里"写进代码注释防后人加回（`definitions.go:36-43`）。

**与你的 `mcp-tool-routing-guard` 技能直接同构。** 这是该技能在真实百万级项目里的验证样本。

**Rust 难度**：低（两张 HashMap + 三个函数）

---

### ⭐⭐ P1 — 建议吸收

#### 3.5 `NormalizedKey` 字符串冲突消解（无 LLM 的矛盾解决）

**代码事实**（`internal/types/memory.go:300-304, 554-559`）：
```go
// NormalizedKey identifies the topic this item is about. A new item with
// the same key supersedes the older one.
NormalizedKey string `gorm:"column:normalized_key;type:varchar(255);not null;default:''"`
```

`"生产库用 MySQL"` vs `"生产库已迁到 PostgreSQL"` → 同 key →后者自动 supersede 前者。**读路径零模型调用。**

**与 memoria 的关系**：需核实 `memory_merge` 实现。如果已有基于 embedding 相似度的合并，**这个 key 是补充而非替代**——key 抓"同一主题不同值"（向量相似度反而低），embedding 抓"同一句话不同措辞"（key 抓不到）。**两者互补，建议都要。**

#### 3.6 父子分块 + 结构面包屑（`EmbeddingContent`）

**代码事实**：
- parent 存 DB **不入索引**，child 入索引，检索命中 child 后回填 parent（`knowledge_process.go:518-548, 581-584`）
- `mergeBreadcrumbs`（`chunker/strategy.go:245-267`）：parent/child 各自跑 heading 检测，去重后合成 `A > B > C` 面包屑
- **`EmbeddingContent()` 把面包屑 prepended 到待 embedding 正文**（`chunker/../chunk.go:214-223`）—— 零成本的上下文增强
- `ContextHeader` **持久化而非每次重建**（`chunk.go:183-185` 注释："persisted so a later content edit can rebuild the same index input"）—— 否则内容改动后新旧向量语义漂移

**与 memoria 的关系**：**给 memory item 附加 category / source path 是完全同一手法**。`ContextHeader` 持久化这条尤其重要 —— memoria 的记忆内容如果会被编辑（merge/decay），必须能重建完全相同的 embedding 输入。

**Rust 难度**：中（父子模型）

#### 3.7 写时敏感信息脱敏

**代码事实**：`RedactSensitive`（`memory.go:659-665`）14 条正则，写在 `writeReplacing` **第一道**（`service/memory/service.go:325-332`）。含 provider token 前缀、密钥赋值、中文密码/口令/密钥（注释：`memory.go:640` —— "Go's word boundary is ASCII-only, so it never matches before a CJK character"）、身份证（带出生日期锚定避免误伤长订单号）、银行卡、手机号、40+ 高熵串。`IsMostlyRedacted` 丢弃被脱敏到不足 6 字符的。

**为什么重要**：记忆会被**每轮重发到模型**（system prompt），泄露面比普通存储大得多。注释记录了上一版教训（`memory.go:619-621`）："matched loosely and mangled ordinary long order numbers while still leaving the tail of an ID card in place"。

**落地点**：**先核实 memoria 记忆写入路径是否有这层。若无 → 这是 P0 缺口。** Rust 难度：低（regex crate，注意 `\b` 对 CJK 的语义差异）

#### 3.8 「检索面宽于注入面」—— alias 只进向量

**代码事实**（`internal/application/service/memory/vector.go:130-135`）：
> "aliases are the other wordings this person has used for the same subject. They widen what a question can match without widening what the model is told: **they exist only in the vector, never in the injected block.**"

解决真实两难：召回需要宽，注入需要窄。**Rust 难度**：低（20 行）

#### 3.9 上下文压缩：Checkpoint 落在 turn 边界 + 降级而非失败

**代码事实**（`internal/agent/compaction/compactor.go`）：
- `Checkpoint{TurnID, Summary, Degraded}` 持久化到具体 turn（`:67-78`）→ 下一轮**就地加载摘要而非重复摘要同一段历史**
- `Degraded bool`：摘要器失败也返回结果，只是降级为原文归档 —— "The context still shrank; its memory is just coarser."（`:52-57`）
- `New` 返回 nil 表示功能关闭（`:93-100`）—— 避免第二个 flag 的干净做法
- `ErrNothingToCompact` 作为**停止信号**而非错误（`:37-41`）

⚠️ 缺陷：`Degraded` 摘要被当合法 checkpoint 持久化，下一轮 fold 后**细节不可逆丢失且无用户可见标记**。抄的时候要补这个标记。

#### 3.10 Sandbox 相关：Docker 层链推理 + ForkSnapshotLease

| 设计 | 位置 | 要点 |
|---|---|---|
| **Docker 快照层链推理** | `internal/sandbox/docker_snapshot.go:106-117` | 理解到"Untagging N 在 N+1 存在时不释放任何东西"，用 `PruneChildren` 解决，并论证 refcount 保证不误删活跃镜像。**这是本次分析里最精彩的工程推理** |
| **快照 = 镜像 tag，`Create` 接受它作 `TemplateID`** | 同上 | skill install 路径不需要任何 Docker 特定分支 |
| **命名空间隔离 skill / fork 两类镜像** | `docker_snapshot.go:57-59, 140-191` | 避免 reaper 互相扫对方 |
| `ForkSnapshotLease` 独立表 | `internal/types/session_fork.go:81-96` | 处理"快照已创建但 session 行创建失败/进程崩溃"的窗口。"a rolled-back CreateForked must not erase the only copy of the snapshot ID" |
| `SandboxCheckpoint` 存 `SandboxID` | `types/session_fork.go:10-24` | commit SHA 只在一个沙箱的 git 仓库里有意义；沙箱回收后历史归零。**存 SandboxID 纯 DB 判断可达性，不探测沙箱** |

**落地点**：agent-core 若有会话回滚 / 外部资源双写，`ForkSnapshotLease` 与 `SandboxCheckpoint` 两条模式直接适用。**Rust 难度**：低

---

### 🟡 P2 — 有条件吸收

| 设计 | 位置 | 条件 |
|---|---|---|
| 退役工具 + `CanRunConcurrently` 默认 deny | `tools/execution_policy.go` | agent-core 工具面扩张时 |
| 图检索双层 LIMIT + 同排序键贯穿 | `neo4j/repository.go:271-294` | 注释记录了不这么做的实测后果（1309 nodes / 1917 relations 单次查询）。仅在真用图检索时 |
| CJK bigram + contentless FTS5 | `sqlite/repository.go:696-720, 99-127` | ⚠️ **必须修它的 `bm25()` 列权重 bug**（6 列等权，content 只占 1/6） |
| 能力接口切片（窄接口） | `internal/sandbox/capabilities.go:118-120` | ⚠️ **Go 的 getter-returns-nil 在 Rust 里不该照搬**（应改 `enum Backend` 或 trait object 组合）。Rust 1.86+ 有 trait upcasting 反而更安全 |
| 「验证发现分级」而非全或无 | `tenant_skill_verify.go:69-77` | 思维模式，非代码 |
| 适配阈值降级 fallback 语义 | `chat_pipeline/rerank.go:115-129` | rerank 是可选增强层，模型挂了不该让每轮对话失败 |
| 确定性多级排序（5 级 tie-breaker） | `filter_top_k.go:76-96` | 任何用 map 分组后排序的地方都需要 |
| merge 阶段 8 步流水线 | `chat_pipeline/merge.go:34-43` | ⭐ 第 7.5 步「扩展后再合并一次」是很多人漏掉的 |

---

## 4. 不吸收清单（写进代码注释，防后人误抄）

### 🔴 P0 安全 — 全部进 `agent-core/AGENTS.md` 硬红线

| # | 位置 | 问题 |
|---|---|---|
| **N1** | `internal/sandbox/remote_client.go:358` | `const DefaultSandboxExecUser = "root"` —— **LLM 控制的 shell 默认 root**。无 uid 降权、无 seccomp、无只读 rootfs、无 user namespace remap。已实证 |
| **N2** | `internal/sandbox/session_manager.go:736` | 代码注释自认：`AllowSkillsRoot` "**is not a filesystem boundary** for commands running as root"。**名字像安全边界，实际不是** |
| **N3** | `internal/sandbox/session_manager.go:860` | `if opts.AsRoot { user = "root" }` —— **dead branch**（`DefaultSandboxExecUser` 已是 root）。误导读者以为存在非 root 路径 |
| **N4** | `internal/agent/tools/shell_exec.go:94-97` | 黑名单自称 "**not a security perimeter**"，但实际是 root shell 唯一防线 |
| **N5** | `internal/agent/tools/shell_exec.go:108-110` | `rm -rf /workspace/foo` **故意不拦**（root 下可命中容器任意路径） |
| **N6** | `internal/agent/approval/gate.go:1` | 人工审批**只覆盖 MCP 工具**。`shell_exec` / 文件写 / skill 文件写**零审批** |
| **N7** | `internal/sandbox/session_manager.go:729-730` | `work_dir` allowlist 是**纯词法**（代码注释原话 "lexical only"） |
| **N8** | `internal/types/memory.go:946-970` | `WrapMemoryForPrompt` 用 `html.EscapeString` 防 prompt 注入 —— **防标记注入，不防语义注入**。代码自认 "it does not enforce tool permissions"。一句合法中文的恶意指令可完整通过 |
| **N9** | 全仓（`gpg`/`pgp`/`cosign` 零命中） | **Skill 无签名校验**。SHA256 只防传输损坏，**不防恶意 registry 或被接管的 GitHub 账号** |

### 🟡 P1 架构债

| # | 位置 | 问题 |
|---|---|---|
| N10 | `internal/types/memory.go:288-326` | **`memory_items` 表零索引**。200 条/人可忍，11 万条 O(n) 前缀扫描不可行 |
| N11 | `internal/types/memory.go:68-101` | 预算用 **rune 而非 token**。900 runes 在中文 ≈ 900-1800 token，英文 ≈ 225 token，**实际成本差 4 倍**。且三个预算是硬编码常量，不随模型 context window 变化 |
| N12 | `internal/types/memory.go:59-66` | `explicit_only` 是默认模式 → **开箱即用记忆近乎不工作**，与 README 印象不符 |
| N13 | `internal/types/interfaces/memory.go:44-216` | 单一 `MemoryService` 接口 **50 个方法**，混合 5 个不同消费者。**Rust 必须拆成 5 个 trait** |
| N14 | `internal/agent/compaction/compactor.go:73-77` | `Degraded` 摘要当合法 checkpoint 持久化，fold 后细节不可逆丢失且无用户标记 |
| N15 | `internal/application/service/agent_service.go:1323` | 工具名一致性只有 `logger.Warnf`，**不阻断** |
| N16 | `internal/application/service/tenant_skill_verify.go:64-68` | 明确放弃 import 解析，**安全属性依赖"installer agent 持有 root shell 实跑一遍"** —— 确定性检查被替换为 agent 判断 |
| N17 | `internal/types/retriever.go:10-11` + `normalizer.go:48-53` | `infinity` / `elasticfaiss` 是**死枚举**（无 driver 实现），`Normalize` 是恒等函数 `clamp01` 但配了 30 行注释 + 9 引擎硬编码列表 + `isKnownEngineType` 的 WARN 去重。**净收益接近零** |
| N18 | `internal/application/repository/elasticsearch/v8/repository.go:415` | ES v8 用 `cosineSimilarity` **script_score 而非 kNN** → 放弃 ES 的 HNSW，O(N) 全扫 |
| N19 | `internal/application/repository/neo4j/repository.go:41-53` | 用 **label 做 namespace**（每 KB 一套、每文档再一套）→ 10 万文档 = 20 万 label。Neo4j 社区最佳实践是用关系属性而非 label |
| N20 | `internal/application/repository/neo4j/repository.go:57-60` | `driver == nil` 时全部方法**静默返回 nil**（只 Warn）—— "图谱没配置"和"图谱为空"无法区分 |
| N21 | `internal/application/service/knowledgebase_search_fanout.go:24, 83-85` | `g.SetLimit(4)` + 注释自认 "does NOT set MaxOpenConns on the shared gorm pool" → 4 并发 × 无限连接池 = 可打爆 PG `max_connections`。且 **all-or-nothing 失败策略**（一个 store 挂全盘失败） |
| N22 | `internal/application/service/knowledgebase_search_fusion.go:87-94` | `sortByScoreDesc` **非稳定排序** + 输入 map 迭代随机 → **同分结果顺序不可复现**。而 `filter_top_k.go` 用的是 5 级 tie-break，两套策略不一致 |
| N23 | `internal/application/repository/retriever/postgres/structs.go:74-79` | embedding map 取不到时**静默写入零向量**（`Dimension=0`）不报错。**写入侧全程零维度校验** |
| N24 | `internal/models/embedding/protocol.go:63-69` + `knowledgebase_search.go:66` | `GetDimensions()` 是纯配置回显。若 DB 里 `Dimension=0` → `expected <= 0` 直接 return nil，**维度校验被完全绕过** |
| N25 | `internal/application/repository/sqlite/repository.go:546` | 每次检索都 `logger.Infof` 打印命中内容前 60 字符 —— **日志泄漏 + 性能问题**。postgres 做了 `maxVectorResultLog=8` 截断，sqlite 没做 |
| N26 | `internal/application/repository/sqlite/repository.go:121-126` | FTS 初始填充是 **N 次单行 `db.Exec`**，无事务无批量。10 万 chunk = 10 万次往返 |
| N27 | `internal/types/evaluation.go:13` | 包级 `var Jieba = newJieba()` —— init 阶段读 env + 加载词典（~10MB+），**纯向量部署也付内存** |
| N28 | `internal/application/service/search.go:648-664` | web 搜索 RAG 压缩（`CompressWithRAG` + Redis 状态）是**注释掉的死代码** |
| N29 | `internal/sandbox/manager.go:13-217` | `DefaultManager` + `disabledSandbox` + 顶层 `Sandbox`/`Manager` 接口 —— **两套并行沙箱抽象，其中一套生产未使用**（实际走 `SessionBoundManager` + `RemoteSandboxClient`） |
| N30 | `internal/application/service/memory/service.go:1085` | `ObserveQuestionTopics` 在接口上导出但**只有测试调用** —— 整个主题晋升能力的公共入口从未被使用 |
| N31 | `internal/types/memory.go:209-216` | `ExtractCursor` / `PendingSessions` 代码自认 "never advanced by new workers" —— **legacy 双写字段未清理**，且高并发 enqueue 靠行锁串行化是热点 |

### 🟢 P2 代码质量

- `internal/textconv/simplified.go` —— 纯 Go OpenCC 替代实现（含 Apache-2.0 词典 embed），但**只服务 FAQ 归一化**（唯一调用方 `types/faq.go:740`），**不参与检索链路**。繁简查询命中不了简体索引（功能缺口）
- SQLite `bm25()` 不带列权重（6 列等权）—— 见 §3.2 P2 条件
- `internal/application/service/graph.go` 全 1039 行死代码 —— **建议整体删除**
- `postgres/repository.go:440-446` 注释与实现不符（注释说 "non-fatal"，代码 `return err`）
- `internal/types/extract_graph.go:25-26` 注释说 `Source`/`Target` 是 "ID of the entity"，实现存的是 **Title 字符串**
- `internal/application/service/chunker/validator.go:73` `_ = avg` —— 局部死代码，暗示曾有"平均长度偏离"规则后被删
- `chunker/strategy.go:356-363` 用包级 `var` + `init()` 覆盖模拟编译期多态，可读性差
- 五种中文分词器并存（Doris chinese / Milvus chinese / SQLite bigram / ES 插件 / tencentvectordb SDK）—— **同一 query 在不同 backend 的关键词召回结果不可比**

---

## 5. 落地方案

### Phase A — 检索质量（memoria，1 个切口）

**目标**：把 memoria 记忆召回从"两路 top-k 拼接"升级为"RRF + 归一化 + 可观测降级"。

1. `memory_recall` 加 RRF（k=60）+ `maxRRF` 归一化 + `clamp01`（防 NaN 破坏排序）
2. 引入 `RecallOutcome` 枚举（对齐 §3.1 的 9 种），每次召回上报 outcome
3. 中文实体归一化接入双归一化器（§3.2）

**前置核实**（**动手前必做**）：
- memoria 当前是否已 RRF？→ 决定是新增还是补归一化
- memoria 记忆写入路径是否有敏感信息脱敏？（§3.7）→ 若无，**升为 P0 立即做**
- memoria 是否有 alias / 检索面-注入面分离？（§3.8）

**验收**：混合 case 回归 + NaN 注入测试 + 中文实体归一化单测。
**运维铁律**：改 Rust 后停进程 → `cargo build --release` → detached 重启 → `:9003/health` 探活。

### Phase B — 记忆影响检索（agent-core + memoria 协作）

给 agent-core 的检索环节接三条 conditioning 路径（§3.3）。每条独立可增量，先做 ① query rewriter 背景注入（价值最高、耦合最低），② affinity rerank 加权需要检索分数暴露，③ 兴趣词表最后。

### Phase C — 工具面治理（agent-core）

退役工具三件套 + `CanRunConcurrently` 默认 deny（§3.4）。**与既有 `mcp-tool-routing-guard` 技能同构，直接复用其验收流程。**

---

## 6. 实施状态

|阶段 | 状态 |
|---|---|
| 许可证红线检查 | ✅ 完成（MIT + MPL-2.0 + Apache-2.0，可商用可借鉴） |
| 全量源码获取 | ✅ 完成（112MB / 5081 文件，隔离目录未入库） |
| 检索链路精读 | ✅ 完成（分块 / 混合检索 / rerank / 8 个向量 driver / 图谱 / 中文分词） |
| 记忆 + 沙箱 + Agent 精读 | ✅ 完成 |
| 关键声明实证校验 | ✅ 完成（graph 死代码 / root 默认 / memory 无索引 / RRF 归一化 / 无 decay / 无 a2a&namespace） |
| 决策文档 | ✅ 本文档 |
| **Phase A 实施** | ⏸待开工（**需先完成三项前置核实**） |
| Phase B / C | ⏸待排期 |

**研究副本**：隔离目录 `<PROBE_DIR>/WeKnora-main`（未纳入版本控制，不提交不推送）
