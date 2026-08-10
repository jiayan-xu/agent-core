# 发版纪律（RELEASING）

> agent-core 的版本管理规范。目标：让每个版本都可复现、可回溯、可审计。
> 原则一句话：**「bump 版本号 + 打 tag + 写 CHANGELOG」三步必须绑定同一次合并**，
> 缺一不可。

## 为什么要有这个文件

历史教训（2026-08-10 审计）：
- 版本号曾从 `v0.4.0`（2026-07-12）之后**近一个月零 bump**，期间合入 360+ commit，
  却没有任何一个 tag 能指回某个可复现的稳定点。
- CHANGELOG 停在 2026-07-15，之后空白。
- 副作用：排障时「哪个版本有这个能力」只能靠 `git log` 考古。

## 版本号规则（SemVer）

- 格式 `X.Y.Z`：
  - **X（major）**：破坏性 / 不兼容改动（如 boundary 安全边界重构、协议不兼容）。
  - **Y（minor）**：新增功能（新 MCP 源、新能力）。
  - **Z（patch）**：bug 修复、小改动。
- 当前基线：`0.4.0`。字段在 `Cargo.toml` 的 `[package] version`。

## 发版三步（每次合并前完成）

1. **bump 版本号**：改 `Cargo.toml` 的 `version`，提交信息用
   `chore(release): bump agent-core X.Y.Z -> X.Y.Z+1`。
2. **打 tag**：`git tag vX.Y.Z`（annotated tag，附发版说明），push 时 `--tags`。
3. **写 CHANGELOG**：在 `CHANGELOG.md` 顶部新增 `## YYYY-MM-DD` 条目，
   按主题压缩本版本关键变更（参考既有格式：改动/效果/动机 + 关联组件）。

> ⚠️ 三步必须落在**同一个 feature 分支**上一起合入，禁止散落在不同 commit。

## 发版触发时机

- **必须发版**：非补丁级功能（新 MCP 源 / 新能力 / 安全边界改动）合入时。
- **建议发版**：累积 ≥ 20 个 commit 或跨一个自然周时。
- **延迟发版**：纯内部重构、无行为变化时，可攒到下一个功能版一起 bump。

## git 安全纪律（本仓库硬约束）

- 本仓库为**公开 GitHub 仓库**（`jiayan-xu/agent-core`，默认分支 `master`）。
- **禁止**在 commit 中带入密钥 / 隐私 / 绝对路径（`C:\Users\user\...`）。
- 发版 commit 只含 `Cargo.toml` / `CHANGELOG.md` / `docs/*` 等元数据文件，
  **不得**混入业务代码改动。
- tag 是**不可变**锚点：打错 tag 只能删除重建，禁止 `--force` 覆盖已有 tag。

## tag 推送策略（2026-08-10 起生效）

- `.githooks/pre-push` 已放开 **annotated 语义化版本 tag（`refs/tags/v*`）** 推送，
  作为发版锚点；**其余 tag 仍拦截**（防 lightweight tag 滥用）。
- tag 必须用 annotated 创建：`git tag -a vX.Y.Z -m "说明"`。
- 推送：`git push origin refs/tags/vX.Y.Z`（或 `git push --tags` 一并推送）。

## 与 office 迁移（P2）的协调

- office 迁移（本地源改名 `fsutil` + officecli 接入）涉及 `agent.toml` / `boundary.rs` /
  `office-tools`，**属于安全边界改动**，应作为 `0.4.0 -> 0.5.0` 的 minor 发版锚点。
- 在 office 迁移合入前，`Cargo.toml` 版本保持 `0.4.0` 不动，避免与迁移 bump 冲突。
- 本文件（发版纪律）先于迁移合入，作为发版规范基线。