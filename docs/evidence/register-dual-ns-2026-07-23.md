# P0 留痕：`/api/register` 双 ns 漂移修复（2026-07-23）

> **给后续助手**：同事 / PFAiX Onboarding 注册身份时，若只见 `org/.../dept/...`、没有 `agent/{id}`，或误以为「一人一私人 ns」未拍板——先读本文件与 `EVOLUTION.md` 本节，**不要再全库考古半天**。

## 已定共识（不是新需求）

| 层 | 命名空间 | 作用 |
|---|---|---|
| 私人 | `agent/{id}` | 个人记忆隔离 |
| 共享 | `org/cs-pufa-2nd-thermal[/dept/...]` | 部门/公司工具与共享 |

拍板出处：`EVOLUTION.md` → **2026-07-11 B2**（legacy 自动开户 / `register_user` 已对齐）。

范本身份：`xujiayan` → `agent/xujiayan,org/cs-pufa-2nd-thermal`。

## 缺口（已修）

| 路径 | 修复前 | 修复后 |
|---|---|---|
| PFAiX Onboarding → `POST /api/register` | 仅 `org/.../dept/...` | `agent/{agent_id},org/.../dept/...` |
| `/api/register_user` | 已双 ns | 不变 |
| legacy `x-user-tag` 自动开户 | 已双 ns | 不变 |

代码：`src/main.rs` → `handle_register`（变量 `org_ns` + `namespace = format!("agent/{},{}", agent_id, org_ns)`）。

## 运维注意

1. **改源码后必须** `cargo build --release` 并重启本机 `agent-core.exe --service`（二进制：`agent-core/target/release/agent-core.exe`，端口 `9753`）。
2. **旧注册身份不会自动回填**私人 ns；需重走 Onboarding / 重调 `/api/register`，或手工改 Memoria `agent_registry.namespace`。
3. Agent Key = 注册返回的 `badge_token`，**勿填** `MEMORIA_ADMIN_KEY`。
4. 徐佳琰主记忆身份是预置的 `xujiayan`，与某次安装产生的 `cs-pufa-2nd-thermal_gufei_*` **不是同一个 agent_id**。

## 部署陷阱（必读，曾踩坑）

本机 shell 常残留：

`CARGO_TARGET_DIR=<memoria-repo>/memoria-core/target`

会导致 `cargo build --release` **编到 Memoria 的 target**，而实际拉起的是  
`agent-core/target/release/agent-core.exe`（旧二进制）→ 改了源码、冒烟仍见单 ns。

**正确编法：**

```powershell
Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
$env:CARGO_TARGET_DIR = 'agent-core/target'
cd C:\Users\user\agent-core
cargo build --release --bin agent-core
# 确认 LastWriteTime 为刚才；再停旧进程、起新 exe --service
```

## 验证清单（2026-07-23 已勾）

- [x] `cargo build --release --bin agent-core`（强制 `CARGO_TARGET_DIR=…\agent-core\target`）
- [x] `:9753/health` → 200
- [x] 冒烟 `POST /api/register` →  
  `namespace=agent/cs-pufa-2nd-thermal_gufei_dual093407,org/cs-pufa-2nd-thermal/dept/gufei`（`DUAL_NS_OK`）
- [x] 进程：`agent-core.exe --service`（部署当日重启）
