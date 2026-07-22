# HY3 G 门复验证据（docs/evidence/）

> **诚实声明**：本文件是「复验命令 + 输出」留档，**不等同于运行时铁证**。
> 标注规则：`[已复验]` = 本会话实跑命令并取得输出；`[prior 记录]` = 依赖操作者此前记录；`[未重跑]` = 本会话未重新执行（环境/时间未满足）。
> G 门「宣称全绿」= prior 操作者记录 + 源码证据，**运行时独立复验日志尚未入仓**，只能信操作者。

状态时间：2026-07-22 深夜（P0 复盘同期）。

---

## G1 二进制对齐

- `[prior 记录]` agent-core HEAD 可复现；memoria redeploy 已对齐 canonical（含 `1fdd4a5` 修复）。
- `[已复验]` 本会话实跑：
  ```
  $ cd agent-core && git log --oneline -1
  e67bad5 docs(hy3-1.3): MultiAgent 开闸落档——三大项全部开闸完成

  $ cd .qclaw/workspace/memoria-open && git log --oneline -1
  1fdd4a5 fix(mcp): add namespace param to evolution_rollback/evolution_log_query schemas
  ```
- 注：agent-core 当前工作树含**未提交修正**（本回合 P0-1/P0-2 三处 `.rs` 改动 + roadmap），属「修正进行中」正常态；G1 以 `HEAD` 可复现为准。

---

## G2 evolution_log ≥ 1

- `[prior 记录]` 探针 `memory_evolve` 返回 `log_id=ev-1784714355431676800`（2026-07-22 末）。
- `[未重跑]` 本会话探针（curl `:9003/api/system_status`，带 admin key）返回**空体**——本地 memoria 实例不可达或未返回，未重验运行时。
- 澄清：`db_stats.decisions` 计的是 `category=decision` 记忆数，**≠** evolution_log 数；二者不混。

---

## G3 rollback 负样本

- `[已复验]` 源码证据（`1fdd4a5`，memoria-open `src/mcp_server.rs`）：
  ```diff
  @@ -621,7 +621,8 @@ pub fn tools_list() -> Vec<serde_json::Value> {
           "（PR4）按 evolution_log.id 回滚某次演化，恢复 old_value...",
           serde_json::json!({
               "log_id": {"type": "string", "description": "evolution_log 行 id（必填）"},
  -            "admin_key": {"type": "string", "description": "Admin Key"}
  +            "admin_key": {"type": "string", "description": "Admin Key"},
  +            "namespace": {"type": "string", "description": "记忆所属命名空间（NamespaceArg 必填）；不传将被拒绝（Namespace argument required）"}
           }),
  ```
  `evolution_log_query` 同样补 `namespace`。根因：`NsPolicy::NamespaceArg` 强制要 `namespace`，但两 schema 漏声明 → 经 MCP 必死锁；补 `namespace` 后编译通过、解除了调用死锁。
- `[prior 记录]` 运行时 redeploy 后验证：`evolution_rollback` 返 `status:rolled_back`、schema 已声明 `namespace`，负样本闭环 live。
- `[未重跑]` 本会话未重新 redeploy / 重跑运行时验证。

---

## G4 registry 清理

- `[已复验]` 同 `1fdd4a5` 源码（见 G3 diff）——`evolution_log_query` schema 补 `namespace`，使 G4 查询路径可经 MCP 调用。
- `[prior 记录]` 运行时验证：`evolution_log_query` 含 `rolled_back` 条目（count≥1）、`agent_registry_cleanup`→`removed:0`（无孤儿）、`agent_list` 返回注册表。
- `[未重跑]` 本会话未重新运行时验证。

---

## BoN 观测门

- `[prior 记录]` 第三轮 live 真数（2026-07-22）：`Δpp = 0.0`、`win=0 tie=5 loss=0`、`mean_single=10.00 / mean_bon=10.00`。
  - BoN-A 修复（相对排序 + 逐候选 `SCORE:` + 劣则回退基线）生效，消灭「8 压过 10」selection bug，BoN 不再劣于单次（不回归）。
  - 5/5 仍双双 10/10 = 天花板效应（deepseek-chat 生成满分 + judge 饱和），`+10pp` 仍不可证（非修复问题）。
  - 观测门判据 `selector 修复后 Δpp≥0 且不回归` → **通过**；`+10pp` 硬门已于拍板废除，非三大项阻塞。
- `[未重跑]` 本会话未重跑 BoN harness（需 live LLM + judge key，且属观测 track，不阻塞本回合修正）。

---

## 结论（诚实版）

- G1：源码/HEAD 可复现 ✅（已复验 git）。
- G2：prior 探针有 log_id，本会话未重跑 ⚠️。
- G3/G4：源码死锁已修（`1fdd4a5`，已复验 diff）；运行时 redo 为 prior 记录、本会话未重跑 ⚠️。
- BoN：-观测门 prior 记录过线，本会话未重跑 ⚠️。
- **G 门「全绿」= prior 操作者记录 + 源码证据；运行时独立复验日志未入仓，只能信操作者**——不写成「已铁证」。
