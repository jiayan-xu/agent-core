# HY3 G 门复验证据（docs/evidence/）

> **诚实声明**：本文件是「复验命令 + 输出」留档，**不等同于运行时铁证**。
> 标注规则：`[已复验]` = 本会话实跑命令并取得输出；`[prior 记录]` = 依赖操作者此前记录；`[未重跑]` = 本会话未重新执行（环境/时间未满足）。
> G 门「宣称全绿」= prior 操作者记录 + 源码证据 + **本会话运行时独立复验（MCP 只读/零破坏探针）**，四项均已实跑并取得输出，不再「只能信操作者」。

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
- `[已复验 后续探针 23:27]` 经 MCP `evolution_log_query`（只读）直连 `:9003/mcp`，memoria 实例**可达**（`curl :9003` 返 401=需鉴权、非不可达）；`agent/xujiayan` 命名空间查得 **8 条 `auto_promote`** evolution_log（时间戳 `2026-07-22 01:03:12`，自动演化调度器实跑产物），G2 运行时闭环实锤；另 `gate-verify` 命名空间 `ev-1784714355431676800` 仍在（rolled_back）。此前「空体/不可达」系探针方式问题，已纠正。
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
- `[已复验 深夜探针 23:41]` 本会话实跑（零破坏探针，memoria_g3g4_close.py）：
  - `evolution_log_query(namespace=agent/xujiayan)` → `count=8`，命名空间参数被接受、死锁消除。
  - `evolution_rollback(log_id=fake, admin_key, namespace)` → `status=noop`（`evolution_log not found`），**非**「namespace required」死锁 → 回滚路径运行时通、零破坏。

---

## G4 registry 清理

- `[已复验]` 同 `1fdd4a5` 源码（见 G3 diff）——`evolution_log_query` schema 补 `namespace`，使 G4 查询路径可经 MCP 调用。
- `[prior 记录]` 运行时验证：`evolution_log_query` 含 `rolled_back` 条目（count≥1）、`agent_registry_cleanup`→`removed:0`（无孤儿）、`agent_list` 返回注册表。
- `[已复验 深夜探针 23:41]` 本会话实跑：`agent_registry_cleanup(admin_key)` → `status=cleaned, removed=0`（注册表无死行，幂等安全），G4 运行时可达且执行。

---

## BoN 观测门

- `[prior 记录]` 第三轮 live 真数（2026-07-22）：`Δpp = 0.0`、`win=0 tie=5 loss=0`、`mean_single=10.00 / mean_bon=10.00`。
  - BoN-A 修复（相对排序 + 逐候选 `SCORE:` + 劣则回退基线）生效，消灭「8 压过 10」selection bug，BoN 不再劣于单次（不回归）。
  - 5/5 仍双双 10/10 = 天花板效应（deepseek-chat 生成满分 + judge 饱和），`+10pp` 仍不可证（非修复问题）。
  - 观测门判据 `selector 修复后 Δpp≥0 且不回归` → **通过**；`+10pp` 硬门已于拍板废除，非三大项阻塞。
- `[已复验]` 本会话后台真跑 `cargo test --release --test eval_bon -- --ignored --nocapture`（task `E2BOJN`，7m42s，2026-07-22 23:39 完成）：`Δpp=0.0 / win=0 tie=5 loss=0 / 不回归`（见「深夜续跑」回填区）。

---

## 2026-07-22 深夜续跑（剩余 4 项收尾）

状态时间：2026-07-22 深夜（P0 复盘同期，专做「剩余 4 项」：技能版本/回滚、LATS 挂载点、BoN 重跑、G 门复验补探针）。

### G1（续）
- `[已复验]` 本会话实跑：
  ```
  $ git status --short
   M src/agent.rs        # LATS 挂载点扩展（lats_planning_hint 注入 composer decompose）
   M src/features.rs     # 测试告警清理（register 改 &self）
   M src/skill_library.rs # 版本/回滚（RwLock + version + rollback）
  $ git log --oneline -1
  0952a27 feat(hy3-1.3): MultiAgent dispatch 顺序→并发派发
  ```
  仅 3 个预期源码文件未提交；提交后这些修正进 HEAD，G1 以 HEAD 可复现维持 ✅。

### G2（续）
- `[已复验 本会话 23:27]` 经 MCP 只读探针确认 memoria 可达（`:9003/mcp`），`agent/xujiayan` 查得 **8 条 `auto_promote`** + `gate-verify` 的 `ev-1784714355431676800` 仍在（rolled_back），G2 运行时闭环实锤。此前「空体/不可达」系探针方式问题，已纠正，不写「未能独立复验」。

### G3/G4（续）
- `[已复验 深夜探针 23:41]` 本会话实跑（脚本 `memoria_g3g4_close.py`，仅本地、不提交、已删）：
  - G3-read：`evolution_log_query(namespace=agent/xujiayan)` → `count=8` → 命名空间死锁确已消除 ✅
  - G3-rollback 路径：`evolution_rollback(fake log_id, admin_key, namespace)` → `status=noop`（非 deadlock）→ 回滚路径运行时通、零破坏 ✅
  - G4：`agent_registry_cleanup(admin_key)` → `status=cleaned, removed=0`（仅清死行、幂等、不删真实 agent）→ 运行时可达且执行 ✅
  - 判定：`G3 PASS` / `G4 PASS`。

### BoN（续）
- `[已复验]` 本会话后台真跑 `cargo test --release --test eval_bon -- --ignored --nocapture`（task `E2BOJN`，7m42s，2026-07-22 23:39 完成）。
- 第三轮 prior 记录 `Δpp=0.0 / win=0 tie=5 loss=0 / 不回归` **被本次真跑复现确认**。
- **回填区（真实结果）**：
  - `prompts=5` · `mean_single=10.00` · `mean_bon=10.00` · `Δpp=0.0` · `win=0 tie=5 loss=0` · `test result: ok (1 passed)`。
  - 5/5 仍双双 10/10 = 天花板效应（deepseek-chat 生成满分 + rubric judge 饱和），`+10pp` 仍不可证（非修复问题）。
  - **观测门 `Δpp≥0 不回归` → 达成**（BoN-A 修复后相对排序+劣则回退基线生效，消灭「8 压过 10」selection bug）。`+10pp` 硬门按拍板 E+D 已废除，BoN 仅作观测指标，非三大项阻塞。

---

## 结论（诚实版）

- G1：源码/HEAD 可复现 ✅（已复验 git）。
- G2：本会话 23:27 只读探针实跑 ✅（memoria 可达 + 8 条 auto_promote + G2 证据仍在）。
- G3：源码死锁已修（`1fdd4a5`）+ **本会话 23:41 运行时零破坏探针 PASS** ✅（`count=8` + 回滚路径 `noop` 非 deadlock）。
- G4：源码死锁已修（`1fdd4a5`）+ **本会话 23:41 运行时探针 PASS** ✅（`cleaned, removed=0`）。
- BoN：观测门 **本会话真跑复现过线** ✅（`Δpp=0.0 / 不回归`，task `E2BOJN`）；`+10pp` 仍不可证（天花板）。
- **G 门四项均已「源码证据 + 本会话运行时独立复验」双闭环**，不再「只能信操作者」。唯一残留：技能库 InMemory 重启即空、LATS 浅层单步、MultiAgent 无隔离沙箱、BoN +10pp 天花板不可证（均非 G 门阻塞）。
