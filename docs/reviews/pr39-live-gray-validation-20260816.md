# PR #39 — live e2e 与生产灰度验收记录（2026-08-16）

结论：**通过**。PR #39 已按合入前待办完成 live 回归与 bootstrap 生产灰度 A/B 验收，
生产实例在 clean 构建（commit `5f83644`）上运行，验收后 `[orchestration] bootstrap`
保持开启进入持续灰度观察。

## 1. 离线回归

- `cargo test --lib`：412 passed / 0 failed
- `scripts/e2e_controlled_write.py --unit-only`：受控写相关 7 组过滤全绿
  （dsml / whitelist_preroute / v1_compat / controlled_write /
  approval_gated / approval_store / sqlite_authority）

## 2. live e2e（clean 构建，bootstrap 开启）

`python scripts/e2e_controlled_write.py --live` → `LIVE OK`

- update_company / add / update_waste_type / remove：全部 `AWAITING_APPROVAL`，
  未写库
- exception_sync → `sync_exception_correction`，`AWAITING_APPROVAL`
- sample_sync → `manage_samples`，`AWAITING_APPROVAL`
- short_confirm：从上文还原后正确进入 `sync_whitelist_plates` 审批，无假成功
- 纯查询不回写、不进审批
- 测试产生的 pending 审批已全部由管理员拒绝清理（`/api/approval/pending` 归零）

## 3. 生产灰度 A/B（bootstrap ON vs OFF）

同一批 8 条 Easy 查询 + 2 条写意图对照，各跑一轮、每次全新 session；
在 clean 构建上依次切换配置并重启实例完成对照。

| 指标 | OFF | ON |
|---|---|---|
| bootstrap_promotes | 0 | 5 |
| llm_calls（8 条 Easy） | 6 | 7 |
| 进入 llm_loop 的 Easy 请求数 | 5 | 5 |
| bootstrap 首轮工具调用 | - | 1/5（20%） |
| 写意图触发 bootstrap | - | 0/2（正确豁免） |
| Easy 平均时延 | 8.57s | 9.93s |

单条时延高方差（如「系统状态」OFF 16.9s / ON 22.6s；「今天称重」OFF 22.0s /
ON 34.4s），样本量小，整体未观察到明显恶化或改善；fast-path 查询（3 条）不受
bootstrap 影响。结论：机制与安全门控符合 ADR-017，时延影响需多日生产流量继续观察。

## 4. 最终状态

- 生产实例：clean PR 构建 `agent-core.exe`（`target/release`），`--service` 运行
- 配置：`agent.toml` 追加 `[orchestration]`，仅 `bootstrap.enabled = true`；
  `plan_reflect` / `tool_summary` / `read_parallel` 维持关闭
- 终态 smoke：新 session Easy 查询 `bootstrap_promotes +1`、`llm_calls +1`、
  时延 3.72s，健康检查 OK
- 回滚：将 `[orchestration.bootstrap] enabled` 改为 `false` 并重启即可
