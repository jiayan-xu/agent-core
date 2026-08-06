# agent-core CI 门禁通过操作手册

> 给 reasonix（或任何操作 agent-core 的 agent/同事）的实操说明。
> 适用仓库：GitHub `jiayan-xu/agent-core`（本地工作副本见 AGENTS.md 的 canonical 目录说明）
> 更新日期：2026-08-06

---

## 0. 门禁是什么（30 秒理解）

**push 到 master 自动触发两个 GitHub Actions 检查，两个都绿才算通过：**

| 检查 | 干什么 | 失败后果 |
|---|---|---|
| **ocr-review** | AI 代码审查**最近一次 commit 的 diff**（HEAD~1..HEAD），发现 bug/安全/性能/可维护性问题就报评论 | exit 1 拦截合并 |
| **gitleaks** | 用 `.gitleaks.toml` 扫密钥/敏感信息（api_key、token、secret、密码等） | 拦截合并 |

**关键认知：**
- push 本身不会被拒绝，但 CI 红 = 代码没过审，等于"提交了但没通过"。
- ocr 审查的是 **HEAD~1..HEAD 这一个 commit**，不是整个分支。一次只推一个 commit 最清晰。
- ocr 意见按严重度分级：`[bug·high]` / `[bug·medium]` / `[performance]` / `[maintainability]` / `[other]` / `[test]`。**大部分是真问题，不要直接忽略**——实战中它抓到过：并发数据竞争、字符串截断 bug、NaN 序列化绕过防护、O(n²) 性能陷阱。

---

## P0 提交前必做（每次 commit 之前）

```bash
cd <仓库根目录>

# 1. 编译 + 单测（必须全绿）
cargo check
cargo test --lib          # 当前 313+ 测试，0 failed 才算过

# 2. 密钥/隐私扫描（提交内容中不应出现以下模式）
git diff | grep -E "(api_key|admin_key|token|secret|password)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']|C:\\\\Users|/home/user|/Users/[a-z]|ff11b8"
# 无输出 = 干净；有输出 = 先清理再提交

# 3. 提交信息规范（中文，描述改了什么 + 为什么）
# 格式：fix(模块): 一句话 + 要点列表
git commit -m "fix(context): 修复 XXX" -m "- 具体改动点1"
```

---

## P1 推送与 CI 查看

```bash
# 推送
git push origin master

# 查最新一次 ocr-review run 的 id（⚠️ 可能同时有并发会话的 run，取最新一条）
gh run list --repo jiayan-xu/agent-core --limit 1 --workflow ocr-review.yml

# 等待结果（--exit-status：CI 失败时命令返回非 0）
gh run watch <run-id> --repo jiayan-xu/agent-core --exit-status
```

**怎么判断过没过：**
- watch 输出末尾是 `✓ Complete job` + 没有 `X Process completed with exit code 1` = **通过** ✅
- 出现 `X OpenCodeReview 发现 N 条评论，门禁拦截合并` = **被拦截** ❌，需要处理
- `ANNOTATIONS` 里的 `! Node.js 20 is deprecated` 是 GitHub 的提示，**不是错误，忽略**。

---

## P2 处理 ocr 意见（循环闭环流程）

被拦截后按这个循环走，直到绿：

```bash
# 1. 提取意见内容（--log-failed 只输出失败日志；sed 去掉 ANSI 颜色码）
gh run view <run-id> --repo jiayan-xu/agent-core --log-failed \
  | grep -A 4 -E "───" | sed 's/\x1b\[[0-9;]*m//g'

# 2. 逐条看：每条含「文件名:行号」+ 严重度 + 问题描述
#    ─── src/agent.rs:3524-3532 ───
#    [bug·high] 描述...

# 3. 修复 → 本地验证 → 提交 → 推送 → 再看 CI
cargo check && cargo test --lib
git add -p src/xxx.rs        # 只 stage 自己的改动（见 P3-3）
git commit -m "fix(xxx): 按 ocr 门禁意见修——问题一句话"
git push origin master
gh run watch <新run-id> --repo jiayan-xu/agent-core --exit-status
```

**实战经验：**
- **一轮意见修完，下一轮可能带出新问题**（同一函数被 ocr 反复深挖）。出现过 9 轮的案例（parse 函数从 4 行走到 90 行）。不要以为"修完就结束了"，推到绿为止。
- 意见明确是真 bug（high/medium）必须修；纯风格类（low）也可修，修了更快过。
- 修完的 commit 信息里**引用意见主题**（如"修复外部历史替换场景返回过期摘要"），方便追溯。

---

## P3 常见坑（全部实战踩过）

### P3-1 拿错 run
`gh run watch $(gh run list --limit 1 ...)` 可能拿到**并发会话的旧 run**（另一 agent 刚推过）。
**推送后必须重新 `gh run list` 取最新 id**，再 watch。

### P3-2 watch 输出"Run has already completed with 'failure'"
说明 `--json databaseId --jq '.[0].databaseId'` 拿到的还是上一个 run。
重跑 `gh run list --limit 1` 确认你要 watch 的是自己 commit 对应的 run。

### P3-3 并发会话干扰（最重要）
**另一 agent 可能同时在改 agent-core**（提交 commit、或留下未提交改动与你交错）。识别与隔离：

```bash
# 每次操作前检查是否有并发痕迹
git log --oneline -3            # 出现你没提交过的 commit = 并发
git status -s                   # 出现你没碰过的文件 M = 并发

# commit 前核对 hunk 分布（分清哪些是自己的）
git diff src/agent.rs | grep -E "^@@"

# 只 stage 自己的 hunk（y=自己的，n=别人的），按顺序回答
printf 'y\nn\ny\nn\n...\n' | GIT_PAGER=cat git add -p src/agent.rs

# stage 后泄漏检查：确认只含自己的 hunk、不含对方标记
git diff --cached src/agent.rs | grep -E "^@@"
git diff --cached src/agent.rs | grep -E "^\+" | grep -vE "^\+{3}" | grep -E "对方标记" && echo LEAK || echo clean
```

**硬规则：**
- ⚠️ **stage 后禁止再 `git add <文件>`**——会把未 stage 的对方改动全量卷进 index，污染你的 commit（实战踩过 2 次）。
- 误卷入了且**未推送**：`git reset HEAD~1` 撤销 commit（工作区保留），重新 `add -p` 精准选。
- 对方可能在**多个文件**有改动（如 `src/llm.rs`），`git status -s` 全看，`add -p` 只处理目标文件，别的文件绝不 `git add`。
- 提交信息里注明「工作区另含并行会话改动，已用 add -p 排除」，让后续协作者知道工作树不干净是对方造成的。

### P3-4 临时文件污染
- 提交信息文件（`_commit_msg_*.txt`）、ocr 日志等临时文件**不要 git add**，提交后清理。

---

## 快速核对清单（推送前最后过一遍）

```
[ ] cargo check 无 error
[ ] cargo test --lib 全绿（313+ 测试 0 failed）
[ ] git diff 无密钥 / 无 C:\Users 绝对路径
[ ] 并发场景：git diff --cached 只含自己的 hunk（add -p 已排除对方改动）
[ ] 提交信息中文规范（fix(模块): 一句话 + 要点）
[ ] 推送后 gh run list 取最新 id → watch 到双绿：ocr-review ✅ + gitleaks ✅
```

---

## 常用命令速查

| 目的 | 命令 |
|---|---|
| 查最新 ocr run | `gh run list --repo jiayan-xu/agent-core --limit 1 --workflow ocr-review.yml` |
| 等结果 | `gh run watch <id> --repo jiayan-xu/agent-core --exit-status` |
| 提取意见 | `gh run view <id> --repo jiayan-xu/agent-core --log-failed \| grep -A 4 -E "───" \| sed 's/\x1b\[[0-9;]*m//g'` |
| 密钥扫描 | `git diff \| grep -E "api_key\|token\|secret\|password\|C:\\\\Users"` |
| 精准 stage | `printf 'y\nn\ny\n...' \| git add -p src/xxx.rs` |
| 污染拆开 | `git reset HEAD~1`（未推送时） |
