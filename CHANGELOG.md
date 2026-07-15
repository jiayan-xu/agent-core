# 演进日志 / CHANGELOG

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
