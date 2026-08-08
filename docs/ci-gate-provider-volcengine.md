# agent-core CI 门禁 LLM Provider 配置（火山方舟 AgentPlan）

> ⚠️ **给所有操作 agent-core 的 AI 助手 / 同事的强制交接说明**。
> 本文件解释仓库 GitHub 门禁（ocr-review）当前用的 LLM provider 是什么、**为什么必须这么配**、改错会怎样。
> 适用仓库：GitHub `jiayan-xu/agent-core`（canonical 本地目录见 `AGENTS.md`）。
> 更新日期：2026-08-08（PR #7 合并后）

---

## 0. 一句话结论

**当前门禁 ocr-review 的 LLM 用的是火山方舟 AgentPlan，模型 `ark-code-latest`，API Key 从 GitHub Secret `ARK_API_KEY` 读取。**

- 配置位于：`.github/workflows/ocr-review.yml` 的 `Configure LLM` step
- 已合并：PR #7（merge commit `b65e9d2`，2026-08-08）
- 验证：master 合并后 push 触发的 `ocr-review` run `31260741341` = **success（14 秒）**，火山链路正常

---

## 1. 当前配置（master 生效值）

```yaml
# .github/workflows/ocr-review.yml  Configure LLM step
ocr config set provider volcengine-ark-plan
ocr config set custom_providers.volcengine-ark-plan.url \
    https://ark.cn-beijing.volces.com/api/plan/v3
ocr config set custom_providers.volcengine-ark-plan.protocol openai-responses
ocr config set custom_providers.volcengine-ark-plan.model "ark-code-latest"
ocr config set custom_providers.volcengine-ark-plan.api_key "$ARK_API_KEY"
```

| 项 | 值 | 说明 |
|---|---|---|
| provider | `volcengine-ark-plan` | **自定义** provider 名（非内置） |
| url | `https://ark.cn-beijing.volces.com/api/plan/v3` | 火山 AgentPlan 端点 |
| protocol | `openai-responses` | **关键**，见 §3 |
| model | `ark-code-latest` | 火山方舟模型 ID |
| api_key | `$ARK_API_KEY` | 从 GitHub Secret 读取，**不硬编码** |

---

## 2. 之前的配置（为什么换了）

迁移前（2026-08-08 之前）用的是 **DeepSeek**：

| 项 | 旧值（DeepSeek） | 新值（火山 AgentPlan） |
|---|---|---|
| provider | 内置 `deepseek` | 自定义 `volcengine-ark-plan` |
| Secret | `DEEPSEEK_API_KEY` | `ARK_API_KEY` |
| 模型 | `deepseek-v4-flash` | `ark-code-latest` |
| 端点 | DeepSeek 官方 | `https://ark.cn-beijing.volces.com/api/plan/v3` |
| 协议 | OpenAI chat completions | **OpenAI Responses API** |

---

## 3. ⚠️ 最容易搞错的核心坑（务必读）

### 3.1 为什么不能用内置 `volcengine` provider？

open-code-review 确实**内置** `volcengine` provider，但它指向的是：

```
https://ark.cn-beijing.volces.com/api/v3   ← chat completions 协议
```

而火山方舟 **AgentPlan** 端点是：

```
https://ark.cn-beijing.volces.com/api/plan/v3   ← OpenAI Responses API 协议
```

**两者协议不同**（chat completions vs Responses API）。如果直接用内置 `volcengine`，会把请求发到 `/api/v3`、按 chat completions 协议发——**与 AgentPlan 手昀不匹配，请求会失败**。

**正确做法（当前生效）**：用自定义 provider + 显式声明 `protocol=openai-responses`，指向 `/api/plan/v3`。

### 3.2 模型 ID 必须加引号

```yaml
# ✅ 正确：双引号字符串
ocr config set custom_providers.volcengine-ark-plan.model "ark-code-latest"

# ❌ 错误：无引号时，若值是 <ARK_MODEL_ID> 这类尖括号占位符，
#    会被 shell 当成重定向，CI 直接挂
```

### 3.3 Secret 走 GitHub 加密存储，不写进仓库

- GitHub Secret 名：`ARK_API_KEY`（在 Settings → Secrets and variables → Actions）
- 用 `gh secret set` 写入，**绝不把真实 key 写进任何 .yml / .md / 提交历史**
- Key 样例 `ark-xxxx-...` 是火山方舟的 API Key 格式，属敏感凭据

---

## 4. 改 provider 的操作流程（如果以后还要换）

1. 改 `.github/workflows/ocr-review.yml` 的 `Configure LLM` step
2. 本地验证：`cargo check`（workflow 本身不编译，但确保 yml 语法正确）
3. 建分支 → 推送 → 开 PR → 等 `ocr-review` + `gitleaks` 双绿
4. 合并（见 §5 的合并坑）→ 确认 master 上 merge push 触发的 `ocr-review` success

---

## 5. ✅ 本仓库合并 PR 的 BLOCKED 坑（已根治，2026-08-08 PR #9）

**曾经的症状**：PR 的 `ocr-review` / `gitleaks` check-run 全部 `success`，但
`gh pr merge` 报 `not mergeable: the base branch policy prohibits the merge`，
`mergeStateStatus = BLOCKED`。

**曾经的根因**：master 分支保护 `required_status_checks` 要求 legacy commit status
context `ocr-review` / `gitleaks`，但这些 context 由 GitHub Actions **check-run** 产生
（`github-actions` app 触发），**从不自动生成 legacy commit status** —— 查
`GET /commits/{sha}/status` 恒为 `state=pending` + `statuses=[]` 空数组。GitHub 因此
认为"要求的 status context 缺失"，永远 BLOCKED。

**✅ 根治方案（PR #9 已合并，master 220264d）**：
在两个 workflow 末尾各加一步，用 `GITHUB_TOKEN`（`permissions: statuses: write`）
显式 `POST /statuses/{sha}` 把 check-run 结果同步成 legacy commit status：

```yaml
permissions:
  contents: read
  statuses: write   # 关键：写入 legacy status 需要此权限

# 每个 job 末尾（if: always()）
- name: Sync check result to commit status
  if: always()
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    if [ "${{ job.status }}" = "success" ]; then
      STATE="success"; DESC="ocr-review passed"   # 或 gitleaks passed
    else
      STATE="failure"; DESC="ocr-review failed"
    fi
    SHA="${{ github.event.pull_request.head.sha || github.sha }}"
    curl -sS -X POST \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${{ github.repository }}/statuses/$SHA" \
      -d "{\"state\":\"$STATE\",\"context\":\"ocr-review\",\"description\":\"$DESC\"}"
```

**关键点**：
- context 名必须与分支保护完全一致：`ocr-review` / `gitleaks`
  （⚠️ gitleaks 的 context 是 `gitleaks`，**不是 job 名** `gitleaks secret scan`）
- 两个 workflow 都要加（否则另一个 context 仍缺失，仍 BLOCKED）
- `if: always()`：无论前步成败都同步（失败时写 failure，门禁照样拦）

**效果验证**：PR #9 的 head commit 的 `GET /commits/{sha}/status` 返回
`state=success` + `statuses=[ocr-review:success, gitleaks:success]`，
`mergeStateStatus = CLEAN` → **普通 `gh pr merge` 即可合并，无需 --admin**。

**历史背景**：PR #5 / #6 / #7 是在根治前合并的，当时用 `--admin` 绕过。

---

## 6. 快速核对清单（改完配置后）

```
[ ] provider = 自定义名（如 volcengine-ark-plan），不是内置 volcengine
[ ] url 指向 /api/plan/v3（AgentPlan 端点）
[ ] protocol = openai-responses（不是默认 chat completions）
[ ] model 用双引号字符串（如 "ark-code-latest"）
[ ] api_key 读自 $ARK_API_KEY（Secret），无硬编码
[ ] GitHub Secret 里 ARK_API_KEY 已配置
[ ] 推送后 ocr-review + gitleaks 双绿（含 legacy commit status 同步）
[ ] 合并：普通 gh pr merge（已根治，无需 --admin）
```

---

## 7. 相关文件

- `.github/workflows/ocr-review.yml` — 门禁 workflow（provider 配置在这里）
- `scripts/ocr-review.sh` — 门禁运行器（CI 与本地 hook 共用）
- `docs/ci-gate-guide.md` — 门禁通过操作手册（怎么处理 ocr 意见、P0-P3 流程）