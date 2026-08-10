# 演进日志 / CHANGELOG

## 2026-08-10

### 版本管理补齐（发版纪律落地）
- **改动**：新增 `docs/RELEASING.md` 发版纪律，明确「bump 版本号 + 打 tag + 写 CHANGELOG」三步绑定同一合并。
- **动机**：`v0.4.0`（2026-07-12）后版本号近一个月零 bump（360+ commit），CHANGELOG 停在 07-15，无可回溯稳定点。
- **说明**：本条目合入时**不 bump 版本**——`0.4.0 -> 0.5.0` 留给 office 迁移（源改名 `fsutil` + officecli 接入）作安全边界发版锚点，避免撞车。

### 会议实时同步（meeting-realtime-sync，PR #16）
- **改动**：会议 Step3 实时同步链路，多轮（round-21~26）修复 ocr-review 发现的 data 静态性 / 伪事件 / 格式问题。
- **关键修复**：修复 SSE 空 `data` 伪事件致步骤 4 误报 FAIL（bug·high）；`ocr-review` 门禁共修复 30+ findings。
- **效果**：会议记录实时同步到目标端，门禁全绿合入。

### 会议域范围收敛（meeting-scope-step1，PR #12）
- **改动**：会议功能 Step1 作用域收敛，明确会议仅限授权范围，避免越权。

### 门禁 / CI 基础设施（PR #5~#13 系列）
- **改动**：ocr 门禁迁移火山方舟 AgentPlan + 显式 legacy commit status（与标准看齐）；`ci-gate-doc` / `ci-status-doc` / `ci-statuses` 补齐门禁与状态文档；`eval-fix` 修复评估链路。
- **效果**：PR 门禁（ocr-review / gitleaks / 构建）全链路可观测、可审计。

### 审批与回复体验（2026-07-31 ~ 08-02 批）
- **改动**：审批历史 API + 控制台历史 tab（audit trail）；审批提示展示 args 摘要（车牌/公司/固废种类/动作）；审批历史 auth 绑定注册 agent（badge）而非 admin key；回复风格改为纯中文、结论前置、不吐原始 JSON/代码块。
- **效果**：非技术用户可直接点按提问（quick-action cards，后 Revert 保留为待定）；审批链路可回溯。

### PFAiX 局域网更新服务（2026-07-31）
- **改动**：新增 `/updates/pfaix` 局域网更新服务 + agent 修复与显示名注册。

### 领域能力吸收（2026-07-18 白龙马 Batch）
- **改动**：白龙马吸收 Phase A（A1 请求前预取 / A2 TICK 心跳+抢占+watchdog / A3 Focus Stack→Thread）与 Phase C（条件式本地资源门控，只读元数据 + 消息命中才注入）。
- **效果**：本地资源按需注入，命中才加载，降低常驻开销。

### 兼容性与工具可见性（2026-07-26 ~ 07-28 批）
- **改动**：跨 agent 偏好/决策落盘 + Memoria 工具分级（隔离提交）；private personas + owner-visible 圆桌会议 + auth guard；`/v1/chat/completions` 兼容 OpenAI 多段 content 数组；工具名纠错中间件 + 工具可见性全量暴露；audit logger 用 admin 身份 + 收紧 is_test_namespace。

---

## 2026-07-15

### agent-core（PFAiX 后端）安全与健壮性修复

#### 1. 只读咨询不再弹审批闸
- **改动**：`src/boundary.rs` 新增 `is_read_only_tool(name)` —— 基于工具名前缀（`query_`/`search_`/`get_`/`check_`/`read_`/`list_`/`explain_`/`validate_`/`fuzzy_match_`/`*_sql` 等）判定纯只读，写/危险前缀（`delete_`/`update_`/`insert_`/`create_`/`shutdown_`）一律非只读；配套单元测试锁定行为。
- **改动**：`src/agent.rs` 新增 `plan_requires_confirmation(plan)`，将 `compositional_preview` 的「执行 / 取消」确认闸由「多步即弹」改为「**多步且含写/危险步骤才弹**」。
- **效果**：如 `query_system_status` / `query_today` / `query_yesterday` / `explain_anomaly` 这类全只读多步计划**直接执行并返回结论**，不再回「回复执行开始」；含写/删步骤的多步计划仍保留审批闸（安全不降级）。
- **动机**：此前对「这两天 DB 有没有问题」类只读提问也弹确认，属过度摩擦，消耗用户信任。

#### 2. 修复 inbox 中文消息字符边界 panic（P0）
- **根因**：`src/agent.rs:580` 拼接「其他 Agent 转发消息」前缀时按**字节**切片 `&content[..content.len().min(200)]`，遇 Memoria inbox 中一条中文长消息（>200 字节）切在字符中间 → panic，tokio worker 挂死，agent-core 不再接受连接，PFAiX 报 `Couldn't reach the provider`。
- **修复**：改为 `content.chars().take(200).collect()` 安全字符切片（同文件仅此一处字节切片）。
- **验证**：以真实 PFAIX 身份 `cs-pufa-2nd-thermal_gufei_pfaixfix` 发「你是谁」→ HTTP 200，日志无 panic，返回正常身份应答。

### 关联组件（dashboard，gitee 私有仓，本次未推 GitHub）
- `skills/media_check_skill.py`：照片按日期排序的 lambda 对匹配不到 `X月X日` 的文件（`未知` 桶）未保护 `.group()` 崩溃 → 改为保护函数，`未知` 沉到末尾。
- `services/固废日志填写系统_v6.py:2251`：链式 `re.search(r'(\d+)月$', ...).group(1)` 未判空 → 加 `if _dir_month_m:` 保护，解析失败保守不跳过填写。
- 说明：此前「commander.py / executor.py / diagnose_skill.py:55 / snmis_db_monitor.py:431 / nl_query.py 存在未保护 `.group()` 雷」为误报——经全量核查，这些文件的 `.group()` 调用**均已用 `if m:` 判空**，或来自 `re.sub` 回调（保证非 None），无未保护风险。
