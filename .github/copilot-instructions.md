# Copilot Instructions — jiayan-xu/agent-core

This is a **public open-source** repo. Before any `git` command, follow the policy in `AGENTS.md`
(at repo root). Critical points:

- **Canonical local checkout:** `C:/Users/user/agent-core`. **Default branch: `master`** (only branch).
- **DO NOT push from** `C:/Users/user/.qclaw/workspace/agent-core-open` — stale copy marked `.NO_PUSH`.
- **DO NOT push to the `gitee` remote** — it is the closed-source private mirror.
- Before any `git push`: confirm `git remote -v` is the GitHub URL and the target branch is `master`.
- Never commit secrets or `C:/Users/<name>/...` absolute paths. Keep `.env` gitignored; use env vars.
- A `pre-push` hook (`.githooks/pre-push`) blocks wrong-branch / wrong-remote / deletion pushes.
  Activate with `git config core.hooksPath .githooks` after cloning.
