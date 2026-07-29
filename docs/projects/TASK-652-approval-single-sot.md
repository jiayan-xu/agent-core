# TASK-652：审批单一真相源（立项书）

| 字段 | 内容 |
|------|------|
| 状态 | **已立项 / 设计冻结中**（Proposed） |
| ADR | [ADR-015](../decisions/ADR-015-approval-single-source-of-truth.md) |
| 优先级 | P1（不挡当前受控写运营；继续扩写工具前建议完成 P1–P2） |
| 建议开工条件 | 受控写总闸连续绿；业务无紧急写需求窗口 |

## 一句话

把 `checkpoints.db` 与 `approvals.json` 的双真相源收成 **SQLite 审批权威表**；checkpoint 只挂 `approval_id`。

## 为何现在立项

急性假成功 / 孤儿 / 幽灵已补丁化，但每加一条受控写都会再碰「两边不一致」。结构债该立项，而不是再堆 if。

## 不做

- 不改审批台产品交互
- 不放开写权限
- 不进 Memoria 分布式

## 分期

见 ADR-015「分期与验收」。默认实现顺序 **P1 → P2 → P3**；开工前口头确认「同库异表」。

## 验收总门

```bash
python scripts/e2e_controlled_write.py --live
E2E_ALLOW_WRITE=1 python scripts/e2e_controlled_write.py --full
# 另：杀进程重启后，已 pending 的审批台项仍可见且可批准执行
```
