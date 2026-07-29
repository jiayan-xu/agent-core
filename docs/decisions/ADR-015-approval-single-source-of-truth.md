# ADR-015: 审批单一真相源（TASK-652）

## Status
Accepted（P0–P3 已落地）

## Date
2026-07-29

## ID
TASK-652

## Context

受控写铁轨（白名单 / 异常同步 / 取样 / local_fs / edit_code）已把「危险写」压到 **L2 人工审批** 上。急性症状（假成功、孤儿审批死循环、幽灵重执行）已用补丁压住：

| 补丁 | 作用 |
|------|------|
| 孤儿自愈 | checkpoint 有 `approval_id`，但权威表无该项 → 清 checkpoint，提示重述 |
| 执行后 `remove` | 防 `list_approved_ready` 全局扫描幽灵重跑 |
| `list_approved_ready` | 修复「批准后 list_pending 看不到」死路 |
| `confirmed` / `dry_run` 注入 | 批准=充分授权 |

但根因仍在：**两套持久化各写一半真相**（历史态：`checkpoints.db` ↔ `approvals.json`）。

### 已知不一致模式（立项时）

1. **重启丢一边**：JSON 写失败 / 被清，checkpoint 仍 `PendingApproval` → 用户反复「确认」空转。
2. **响应在 JSON、意图在 SQLite**：批准与执行弱关联 → 错会话抢跑风险。
3. **消费路径分叉**：有的 `remove`，有的只改 checkpoint 终态。
4. **ADR-004 未覆盖审批台**：控制面与审批生命周期权威分裂。

## Decision（目标态 / 已实现）

**审批生命周期以 SQLite 为唯一持久化权威；`approvals.json` 仅启动只读回填，运行时不再写入。**

> **方案 A：** `approvals` 表挂 `checkpoints.db` 同库异表；checkpoint 的 `PendingApproval` 只保留 `approval_id` FK。

## Design

### 权威模型

```text
ApprovalRecord {
  approval_id      PK
  session_id       NOT NULL
  agent_id
  tool_name
  arguments_json
  description
  operation_hash
  approver_id
  requester_id
  status           Pending | Approved | Denied | Consumed
  created_at / decided_at / consumed_at
  decision_reason
}
```

- **创建**：写 `ApprovalRecord(Pending)` + checkpoint → `{approval_id}`。
- **执行**：`execute_approved_request(session_id)` 只取本 session 且 `Approved`；成功 → `Consumed`。
- **恢复**：`restore_checkpoint` join 权威表；缺失 → Failed（孤儿自愈）。
- **迁移残留**：启动若存在 `approvals.json` → 只读导入内存并 upsert SQLite；**不写回 JSON**。

### 特性开关

| 变量 | 含义 |
|------|------|
| `APPROVAL_SQLITE=0` | 关闭 SQLite 权威（仅内存；生产勿关） |
| `APPROVAL_DUAL_WRITE` | **P3 已退役**；设 `=1` 仅打 warn，不再写 JSON |

## Alternatives Considered

| 方案 | 结论 |
|------|------|
| A. 审批进 SQLite，checkpoint 只留 FK | **已采纳并落地** |
| B. 审批只活在 checkpoint payload | 否决 |
| C. JSON 为唯一权威 | 否决 |
| D. 保持双写 + 补丁 | 否决（立项前状态） |

## Consequences

- **正面**：重启/批准/确认/消费同一条记录；幽灵与孤儿从结构上收敛。
- **代价**：迁移窗口已过；遗留 `approvals.json` 可保留作冷备份，勿手工当主库改。
- **运维**：审批权威在 `checkpoints.db` 表 `approvals`；勿再依赖 JSON 作为运行时 SoT。

## 分期与验收

### P0 — 设计冻结
- [x] 方案 A 裁决（同库异表）

### P1 — 存储与双写
- [x] `ApprovalStore` + 单测
- [x] `ApprovalManager` 切 store；双写开关（已退役）
- [x] 启动回填 JSON → SQLite；`create_request_for_session`

### P2 — 切主与瘦 checkpoint
- [x] checkpoint payload 仅 `approval_id`
- [x] `execute_approved_request` 按 `session_id`
- [x] JSON 双写默认关
- [x] `e2e_controlled_write.py --live` / `--full` 绿

### P3 — 退役
- [x] 移除 JSON **写入**路径；保留启动只读导入
- [x] 更新 ADR-004 Future / 立项书
- [x] 本 ADR → **Accepted**

### 回归红线
- 未批准不得写；`confirmed`/`dry_run` 注入保留。
- 只推 GitHub `origin/master`。

## References

- ADR-004 Checkpoint 控制面
- ADR-008 危险工具硬闸
- 回归：`scripts/e2e_controlled_write.py`
- 提交族：`c4f6721` / `f4ca61f` / `04ded0e` / P3 本提交
