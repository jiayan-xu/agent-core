# AGENTS.md — Operational Rules for AI Assistants (and humans)

This repository is **publicly open-sourced on GitHub**. Read this file **before running any `git`
command**. Violating these rules can leak private data or push to the wrong place — both have
happened here before and are now structurally prevented.

## Canonical source of truth
- **GitHub repo:** `jiayan-xu/agent-core` (default branch: **`master`** — the ONLY branch)
- **Canonical local checkout (edit & push from HERE):** `C:/Users/user/agent-core`
- **Remote `origin` (public):** `https://ghfast.top/https://github.com/jiayan-xu/agent-core.git`
  - The `ghfast.top/https://` prefix is a GitHub mirror proxy. Treat it as `github.com/jiayan-xu/agent-core`.
- **Remote `gitee` (CLOSED-SOURCE private mirror):** `gitee.com/xujiayn/agent-base`. This is a
  private mirror — **never push open-source content there, and never open-source it**. The `pre-push`
  hook blocks any push to `gitee` by design.

## DO NOT push from the other local copy
There is a SECOND, stale local working copy at `C:/Users/user/.qclaw/workspace/agent-core-open`
(it previously held a `main` branch; the GitHub `main` was intentionally removed). It is marked with
a `.NO_PUSH` file and its `pre-push` hook blocks all pushes. Do not edit or push from there. The
public branch is `master` only.

## Hard rules (P0)
1. **Before ANY `git push`:** confirm (a) `git remote -v` shows the canonical GitHub URL (not gitee),
   and (b) the target branch is `master`. If unsure, STOP and ask the user.
2. **Never push to a branch other than `master`.** A `pre-push` hook enforces this mechanically.
3. **Never push to the `gitee` remote** — it is the closed-source mirror. The hook blocks it.
4. **Never push secrets or private data.** No hardcoded API keys, tokens, passwords, or
   `C:/Users/<name>/...` absolute paths. Keep `.env` gitignored; read keys from env vars only.
5. **Rotate, don't commit.** If a secret must change, write it to `.env` (gitignored) or env vars —
   never into tracked files or commit messages.
6. A safety `pre-push` hook ships in `.githooks/pre-push`. After cloning, run
   `git config core.hooksPath .githooks` to activate it. It blocks wrong-branch, wrong-remote,
   branch-deletion, and `.NO_PUSH` checkouts.

## Privacy history
On 2026-07-08 the repo was scrubbed: admin key rotated, agent API key rotated, hardcoded
`C:/Users/user/...` paths removed, internal review docs removed from the public tree. Historical
commits may still contain inert (revoked) secret strings — do not reintroduce live ones.
