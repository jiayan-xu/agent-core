# TASK-652：审批单一真相源（立项书）

| 字段 | 内容 |
|------|------|
| 状态 | **Accepted / P0–P3 已落地** |
| ADR | [ADR-015](../decisions/ADR-015-approval-single-source-of-truth.md) |
| 库形态 | **同库异表**（`checkpoints.db` → 表 `approvals`） |
| 优先级 | 已完成；后续只做运维与回归 |

## 一句话

把 `checkpoints.db` 与 `approvals.json` 的双真相源收成 **SQLite 审批权威表**；checkpoint 只挂 `approval_id`。`approvals.json` 仅启动只读回填，运行时不再写入。

## 为何立项（已兑现）

急性假成功 / 孤儿 / 幽灵已补丁化；结构债用方案 A 收口，避免每加一条受控写再碰双 SoT。

## 不做（边界仍有效）

- 不改审批台产品交互
- 不放开写权限
- 不进 Memoria 分布式

## 分期

见 ADR-015「分期与验收」—— **P1 / P2 / P3 均已勾选**。

## 验收总门

```bash
python scripts/e2e_controlled_write.py --live
E2E_ALLOW_WRITE=1 python scripts/e2e_controlled_write.py --full
# 另：杀进程重启后，已 pending 的审批台项仍可见且可批准执行（权威在 SQLite）
```
