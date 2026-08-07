# 会议功能设计（圆桌 → 部门会议 → 公司会议）

- **状态**：Draft（待评审）
- **日期**：2026-08-07
- **作者**：Nova（经用户确认方向）
- **范围**：PFAiX / agent-core 圆桌功能升级为「部门会议」，支持拉同部门真人实例 + AI 分身参会；**预留公司会议升级通道**
- **关联**：`docs/decisions/`、`src/main.rs`（roundtable/persona/meetings）、`web-app/src/routes/roundtable.tsx`、`web-app/src/services/roundtable.ts`

---

## 1. 背景与目标

### 1.1 现状
`POST /api/roundtable` 实现「AI 圆桌」：主席 + N 个本机注册的 AI 分身（Persona）逐个调 LLM 发言 → 主席汇总共识 → 写 Memoria(category=decision)。参与者**仅限本机 AI 分身**。

### 1.2 目标
把圆桌升级为「层级会议」：
- **P0**：部门会议——按部门维度拉参会者（同部门 AI 分身一键参会）
- **P1**：真人协作者（同部门其他 PFAiX 实例）以 A2A 消息参会
- **P2**（暂缓）：实时多人同步讨论
- **升级通道**：`scope` 参数化，`dept:<id>` → `org:<公司>` 天然升级为公司会议（ns 权限沿层级向下继承，公司级自动覆盖所有部门）

### 1.3 核心概念对齐
| 概念 | 现在（圆桌） | 目标（会议） |
|---|---|---|
| 参会者 | 本机 Persona（AI 分身） | 同层级真人实例 + AI 分身 |
| 发言方式 | 进程内调 LLM | 真人：A2A 消息；分身：LLM |
| 主席 | LLM 总结 | 发起人（真人）主持 + LLM 汇总 |
| 归属 | private/public | 层级维度（`scope`：dept 或 org，public within scope） |

### 1.4 层级模型（升级通道架构基础）
```text
org/<公司>                          ← 公司级（会议 scope=org:cs-pufa-2nd-thermal）
└── dept/<部门代号>                 ← 部门级（会议 scope=dept:engineering；代号 ASCII）
    └── proj/<项目>                 ← 项目级（会议 scope=proj:gufei）
```
- **ns 命名规范（2026-08-07 实施）**：技术段必须 ASCII，中文仅作 display。
  - 公司 `cs-pufa-2nd-thermal` → 展示「常熟浦发第二热电能源有限公司」
  - 部门 `engineering` → 展示「工程部」（历史 `dept/engineering/proj/gufei` 是把项目名误放部门位，已规范）
  - 项目 `gufei` → 展示「固废运营」
  - 完整固废 ns：`org/cs-pufa-2nd-thermal/dept/engineering/proj/gufei`
- ns 体系权限**沿层级向下继承**（`namespace.rs` 设计注释：Dept > Project > User，权限继承）
- 公司级 scope 自动覆盖其下所有部门成员，**无需新增权限逻辑**，只提升 scope 维度
- Memoria ns 格式 `org/<org_company>/dept/<dept>/...` 已支持该层级

---

## 2. 权限模型

### 2.1 角色
| 角色 | 判定 | 权限 |
|---|---|---|
| **发起人（owner）** | 会议创建者（authenticate 身份） | 发起 / 结束 / 删除 / 修改 |
| **层级成员** | agent_id ns 前缀匹配会议 `scope`（`dept:engineering` → 前缀含 `dept/engineering/proj/gufei`；`org:cs-pufa-2nd-thermal` → 前缀含该 org，自动覆盖所有部门） | 发起 scope 内会议 / 查看 scope 内会议 / 参会发言 |
| **admin** | `x-agent-key` == `memoria_admin_key` | 全部 + 跨 scope + 强制结束 |
| **AI 分身** | Persona | 自动发言（无决策权） |

### 2.2 动作权限矩阵
| 动作 | 发起人 | 层级成员 | admin | AI 分身 |
|---|---|---|---|---|
| 发起 scope 会议 | ✅ | ✅（限本 scope） | ✅（任意 scope） | ❌ |
| 查看 scope 会议 | ✅ | ✅ | ✅ | ❌ |
| 在会议中发言 | ✅ | ✅（A2A 收件箱） | ✅ | ✅（自动） |
| 结束会议 | ✅ | ❌ | ✅ | ❌（分身发言完自动 done） |
| 删除会议 | ✅ | ❌ | ✅ | ❌ |

### 2.3 可见性
- 会议默认 **public within scope**：scope 内所有实例可见（部门会议=本部门，公司会议=全公司）
- 实现：`list_meetings` 过滤条件扩展为 `!m.is_private || is_admin || m.owner == caller || scope_matches(m.scope, caller_ns)`；`scope_matches` 按 ns 前缀匹配（公司 scope 匹配所有部门子前缀）
- 跨 scope 不可见（ns 前缀校验）

---

## 3. 接口变更

### 3.1 `GET /api/persona` — 增加 scope 过滤
```http
GET /api/persona?scope=dept:engineering
GET /api/persona?scope=org:cs-pufa-2nd-thermal     # 公司级（未来）
```
返回：仅 `owner_user_id` ns 前缀匹配 scope 的 Persona。
- 后端：`list_personas()` 增加 `scope` 过滤参数（默认不传=全部，兼容旧客户端）
- 前端：发起会议界面用 scope 选择（部门/公司）替代"全部分身"

### 3.2 `POST /api/roundtable` — 增加 scope / participants 扩展
```json
{
  "topic": "7月固废入厂异常分析",
  "scope": "dept:engineering",                    // 或 "org:cs-pufa-2nd-thermal"（公司会议）
  "chair": "xujiayan",
  "personas": ["analyst", "ops"],           // 可选：显式选分身（缺省=scope 内全部分身）
  "participants": ["agent/cs-pufa-2nd-thermal_gufei_u801993"],  // P1：真人实例
  "visibility": "public",
  "session_id": "jan/xujiayan/default/default"
}
```
- `scope` 存在时：参与者 = scope 内所有分身（或 `personas` 指定子集）+ `participants` 列出的真人实例
- 兼容：`scope` 缺省 → 走现有逻辑（全部/显式分身）
- **升级通道**：`dept:engineering` → `org:cs-pufa-2nd-thermal` 即公司会议，无需改接口签名

### 3.3 `GET /api/meetings` — 返回 scope 信息 + 真人参会者
响应 Meeting 增加字段：
```json
{
  "id": "mtg_1785...",
  "topic": "...",
  "owner_user_id": "...",
  "scope": "dept:engineering",
  "participant_personas": ["analyst", "ops"],
  "participant_agents": ["agent/cs-pufa-2nd-thermal_gufei_u801993"],
  "status": "running",
  "consensus": null
}
```

### 3.4 `POST /api/meetings/{id}/message` —（P1）真人发言
```json
{
  "from": "agent/cs-pufa-2nd-thermal_gufei_u801993",
  "content": "我同意分析的结论，补充：7/23 那车异常单需复核"
}
```
- 校验 `from` 在 `participant_agents` 中（或同部门）
- 内容入会议记录 + 触发一轮新的分身补充/主席更新（可选）

### 3.5 `POST /api/meetings/{id}/end` —（P1）结束会议
```json
{ "requested_by": "agent/cs-pufa-2nd-thermal_gufei_xujiayan" }
```
- 权限：owner / admin
- 效果：status running → done，触发主席最终共识汇总

### 3.6 `DELETE /api/meetings/{id}` — 沿用现有（owner/admin）

---

## 4. 数据模型变更（agent.rs）

```rust
pub struct Meeting {
    pub id: String,
    pub topic: String,
    pub owner_user_id: String,
    pub scope: Option<String>,                     // NEW: "dept:engineering" | "org:cs-pufa-2nd-thermal"
    pub participant_personas: Vec<String>,         // 现有：AI 分身
    pub participant_agents: Vec<String>,           // NEW: 真人实例 agent_id
    pub messages: Vec<MeetingMessage>,             // NEW: 会议发言记录
    pub is_private: bool,
    pub created_at: String,
    pub status: String,                            // "running" | "done"
    pub consensus: Option<String>,
}

pub struct MeetingMessage {
    pub from: String,        // persona_id 或 agent_id
    pub kind: String,        // "ai" | "human"
    pub content: String,
    pub at: String,          // RFC3339
}
```

持久化：`save_meetings()` 已落盘 `meetings.json`，新字段序列化兼容（serde `#[serde(default)]`）。

---

## 5. 数据流

### 5.1 P0：scope AI 圆桌（改动最小）
```
发起人(scope 内成员) → POST /api/roundtable {topic, scope}
  → 后端按 scope 枚举匹配 Persona（dept:engineering → 该部门；org:... → 全公司）
  → 逐分身 persona_stance (LLM) → SSE stance 事件
  → chair_consensus (LLM) → SSE consensus 事件
  → finish_meeting (status=done, consensus) → 写 Memoria(decision)
```

### 5.2 P1：真人 A2A 参会
```
发起人 → POST /api/roundtable {topic, scope, participants:[真人实例]}
  → 建会 (status=running)
  → AI 分身自动发言（SSE 推给发起人）
  → 会议内容经 a2a_send 投递到每位真人实例收件箱 (agent/<id>)
  → 真人实例在自己的 PFAiX 看到会议通知 → 回复
  → POST /api/meetings/{id}/message → 会议记录追加
  → (可选) 触发分身补充轮 / 主席更新
  → 发起人或 admin 调 end → 主席汇总共识 → done
```

A2A 复用现有机制（`agent.rs:2091` `a2a_send`，`main.rs:5184` 30s 缓存拉取收件箱），不新建传输层。

### 5.3 公司会议升级路径（架构已就绪，改动仅 scope 传值）
```
部门会议：POST /api/roundtable {scope: "dept:engineering"}
公司会议：POST /api/roundtable {scope: "org:cs-pufa-2nd-thermal"}   ← 同一接口
```
- ns 前缀匹配天然支持：`org:cs-pufa-2nd-thermal` 匹配所有 `org/cs-pufa-2nd-thermal/dept/*` 成员
- 权限继承：公司级会议自动覆盖所有部门成员，无需新增角色或规则
- 未来项目级：`proj:<id>` 同理扩展（ns 体系已定义 Project 层）

---

## 6. 前端变更（web-app）

| 文件 | 变更 |
|---|---|
| `routes/roundtable.tsx` | 发起界面加"部门"下拉（替换/补充全部分身）；会议列表显示 dept/真人参会者 |
| `services/roundtable.ts` | `StartRoundtableArgs` 加 `dept`/`participants`；`getMeetings` 解析新字段；新增 `sendMeetingMessage`/`endMeeting` |
| `services/personas.ts` | `getPersonas(dept?)` 支持部门过滤 |
| `routes.ts` / `NavMain.tsx` | 可选：圆桌入口改名"部门会议" |

---

## 7. 改动文件清单

### 后端（agent-core）
| 文件 | 改动 |
|---|---|
| `src/agent.rs` | Meeting 结构扩展（scope/participant_agents/messages）；list_personas scope 过滤；create/finish/list/remove 会议扩展；meeting 消息/结束方法 |
| `src/main.rs` | roundtable handler 解析 scope/participants；meetings 列表返回新字段；新增 `/api/meetings/{id}/message`、`/api/meetings/{id}/end`；persona 列表 scope 过滤 |

### 前端（jan/web-app）
| 文件 | 改动 |
|---|---|
| `src/routes/roundtable.tsx` | 部门选择 + 真人参会者展示 + 会议中发言输入 |
| `src/services/roundtable.ts` | API 封装扩展 |
| `src/services/personas.ts` | dept 过滤 |

### 文档
- 本设计文档 → 实施后更新为 Final + ADR

---

## 8. 实施计划（分步）

### Step 1（P0，1-2 天）
- 后端：Meeting 加 scope 字段 + list_personas scope 过滤 + roundtable 接受 scope
- 前端：scope 选择（部门/公司下拉）+ 会议列表显示 scope
- 验收：发起"固废部门圆桌"→ scope 内全部分身参会发言 → 共识落库；改 `scope=org:...` 即公司会议

### Step 2（P1，2-3 天）
- 后端：participant_agents + messages 存储 + `/message` `/end` 接口 + A2A 通知真人实例
- 前端：真人参会者展示 + 会议中发言框
- 验收：发起部门会议 → 同事实例收件箱收到 → 回复 → 会议记录更新 → owner 结束出共识

### Step 3（P2，暂缓）
- 实时同步讨论（会议状态机 + 心跳 + 消息推送）

### 升级通道（公司会议触发条件）
- 前端 scope 下拉出现"公司"选项（admin 或 org 级成员可见）
- 后端 scope 解析增加 `org:` 前缀分支（复用 `dept:` 同一套 ns 前缀匹配逻辑）
- 无需改 Meeting 结构、接口签名、权限模型——全部已参数化

---

## 9. 风险与兼容

| 风险 | 缓解 |
|---|---|
| 旧客户端不传 scope | 全部兼容：scope 缺省走现有逻辑 |
| meetings.json 旧数据 | serde `#[serde(default)]` 兼容 |
| A2A 是异步收件箱，非实时 | 文档明确 P1 为"异步参会"，实时为 P2 |
| 真人实例离线 | A2A 消息入收件箱，上线轮询收到（现有 30s 缓存机制） |
| 跨 scope 越权 | ns 前缀匹配（dept/org 层级继承），admin 兜底 |
| 公司会议误开放 | 公司级 scope 需谨慎：默认仅 admin / org 级成员可发起，纳入 Step 3 前评审 |
