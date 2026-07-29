# ADR-015: 审批单一真相源（TASK-652）

## Status
Proposed（已立项，未开工实现）

## Date
2026-07-29

## ID
TASK-652

## Context

受控写铁轨（白名单 / 异常同步 / 取样 / local_fs / edit_code）已把「危险写」压到 **L2 人工审批** 上。急性症状（假成功、孤儿审批死循环、幽灵重执行）已用补丁压住：

| 补丁 | 作用 |
|------|------|
| 孤儿自愈 | checkpoint 有 `approval_id`，但 `approvals.json` 无该项 → 清 checkpoint，提示重述 |
| 执行后 `remove` | 防 `list_approved_ready` 全局扫描幽灵重跑 |
| `list_approved_ready` | 修复「批准后 list_pending 看不到」死路 |
| `confirmed` / `dry_run` 注入 | 批准=充分授权 |

但根因仍在：**两套持久化各写一半真相**。

```
┌─────────────────────┐     ┌──────────────────────┐
│  checkpoints.db     │     │  approvals.json      │
│  (SQLite / ADR-004) │     │  (ApprovalManager)   │
├─────────────────────┤     ├──────────────────────┤
│ PendingApproval 态  │◄─?─►│ outgoing + responses │
│ payload:            │     │ operation_hash       │
│  approval_id        │     │ TTL memory（不落盘）  │
│  pending_action     │     │                      │
│ （无响应、无 hash） │     │                      │
└─────────────────────┘     └──────────────────────┘
         ▲                            ▲
         │ 按 session 恢复            │ 全局扫描就绪项
         │ restore_checkpoint         │ execute_approved_request
```

### 已知不一致模式

1. **重启丢一边**：JSON 写失败 / 被清，checkpoint 仍 `PendingApproval` → 用户反复「确认」空转（已有孤儿补丁，但是兜底不是根治）。
2. **响应在 JSON、意图在 SQLite**：批准写入 `responses`，执行靠全局 `list_approved_ready`，与「当前 session 的 checkpoint」弱关联 → 错会话抢跑风险（hash 校验降低但未消灭）。
3. **消费路径分叉**：有的路径 `remove(approval_id)`，有的只改 checkpoint 终态 → 残留。
4. **ADR-004 未覆盖审批台**：checkpoint 自称控制面权威，但审批生命周期权威实际在 JSON。

急性可运营；继续堆受控写会放大双 SoT 债。故立项统一。

## Decision（目标态）

**审批生命周期（创建 / 待批 / 批准|拒绝 / 已执行|已消费）以单一持久化权威为准；另一存储降级为投影或废弃。**

选定方案（见下节权衡）：

> **方案 A（推荐）：`approvals` 迁入 SQLite（可与 `checkpoints.db` 同库异表，或独立 `approvals.db`），JSON 仅作迁移期只读回退；checkpoint 的 `PendingApproval` 只保留 `approval_id` 外键，不再复制工具参数。**

不选「把审批整段塞进 checkpoint payload」作为长期态（方案 B），以免按 session 主键无法支撑「审批台跨会话列表 / 全局就绪扫描」。

## Design

### 权威模型

```text
ApprovalRecord {
  approval_id      PK
  session_id       NOT NULL   -- 绑定会话，消灭全局错配
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

- **创建**：写 `ApprovalRecord(Pending)` + checkpoint → `PendingApproval{approval_id}`（payload 极简）。
- **审批台 API**：只读写 `ApprovalRecord`（不再是 JSON 主路径）。
- **执行**：`execute_approved_request(session_id)` **只取本 session** 且 `status=Approved` 的记录；执行成功 → `Consumed`；失败可留 `Approved` 供重试策略（另定）。
- **恢复**：`restore_checkpoint` 见 `PendingApproval` → 用 `approval_id` join 权威表；若记录不存在 → Failed（等同今日孤儿自愈，但是主键路径）。
- **TTL**：Pending 24h / Approved 未消费 1h / Denied 短 TTL → 表字段或定时 `purge`，替代进程内 `memory` HashMap 的「半持久」。

### API / 模块边界

| 模块 | 职责 |
|------|------|
| `approval` | 唯一 CRUD + hash 校验 + 列表（pending / ready-by-session） |
| `checkpoint` | 会话控制面状态机；审批细节不进 payload |
| `agent` | 创建/执行时只调 `approval`；禁止直接拼 JSON 文件 |
| HTTP `/api/approval/*` | 适配层，背后换存储对调用方透明 |

### 迁移

1. **双写一期**：写 SQLite + 写 JSON；读优先 SQLite，miss 回退 JSON。
2. **回填**：启动时若 JSON 有、SQLite 无 → 导入并标 `session_id`（未知则 `session_id="legacy"`，仅支持全局扫描兼容一轮）。
3. **切主**：读只走 SQLite；JSON 写开关默认关。
4. **退役**：删除 JSON 持久化代码路径；保留导入工具一段时间。

### 非目标（本立项不做）

- 不把审批搬进 Memoria / 跨进程分布式锁。
- 不改 dashboard 审批台 UX（API 契约保持：`approval_id` + `operation_hash`）。
- 不放开受控写权限面。

## Alternatives Considered

| 方案 | 收益 | 损失 | 结论 |
|------|------|------|------|
| **A. 审批进 SQLite，checkpoint 只留 FK** | 单一权威；按 session 隔离；与 ADR-004 同栈 | 迁移 JSON；改 ApprovalManager 存储 | **采纳** |
| **B. 审批只活在 checkpoint payload** | 少一个文件 | 审批台难做全局列表；多 session 扫描丑 | 否决 |
| **C. JSON 为唯一权威，砍掉 checkpoint 审批态** | 改动面小 | 与 ADR-004「控制面可恢复」冲突；session 续跑变弱 | 否决 |
| **D. 保持双写 + 更多对账补丁** | 零大改 | 债利滚利；每加受控写多一类孤儿 | 否决（正是今日状态） |

## Consequences

- **正面**：重启/批准/确认/消费同一条记录；幽灵重跑与孤儿确认从结构上消失；受控写可继续扩注册表。
- **代价**：一到两周量级存储迁移 + 回归（含 `--full` 与审批台手工路径）；需处理 `legacy` session 回填。
- **风险**：迁移窗口双写不一致 → 以 SQLite 为准并打迁移审计日志；失败可回滚到 JSON 主读（特性开关）。

## 分期与验收

### P0 — 设计冻结（本 ADR）
- [x] 方案 A 裁决
- [ ] 实现前再确认：同库异表 vs `approvals.db`（默认建议 **同库异表**，少一个文件句柄）

### P1 — 存储与双写
- [ ] `ApprovalStore`（rusqlite）+ 单测
- [ ] `ApprovalManager` 背后切 store；JSON 双写开关 `APPROVAL_DUAL_WRITE=1`（迁移默认开）
- [ ] 启动回填 JSON → SQLite
- [ ] 验收：杀进程重启后 pending 仍在；批准后仅本 session「确认」可执行

### P2 — 切主与瘦 checkpoint
- [ ] checkpoint `PendingApproval` payload 仅 `approval_id`
- [ ] `execute_approved_request` 按 `session_id` 取 ready
- [ ] 关闭 JSON 主读；e2e：孤儿/幽灵用例改为「权威表状态机」断言
- [ ] 验收：`e2e_controlled_write.py --live` / `--full` 全绿；人为删 JSON 不影响已迁移项

### P3 — 退役
- [ ] 移除 JSON 持久化（或只读导入 CLI）
- [ ] 文档：更新 ADR-004 Future / AGENTS 运维说明
- [ ] 标记本 ADR → Accepted

### 回归红线（全程）
- 权限生存线不变：未批准不得写；`confirmed`/`dry_run` 注入保留。
- 不推 gitee；只推 GitHub `origin/master`。

## 工时粗估

| 阶段 | 估时 |
|------|------|
| P1 | 1–2 天 |
| P2 | 1 天 |
| P3 | 0.5 天 |
| 合计 | **约 3 天**（含回归，不含 dashboard 大改） |

## References

- ADR-004 Checkpoint 控制面
- ADR-008 危险工具硬闸
- 补丁提交族：`e1d4900` / `e1dc23b` / `41fcd26` / 受控写系列 `0eee0ac`–`e33fd8d`
- 回归入口：`scripts/e2e_controlled_write.py`
