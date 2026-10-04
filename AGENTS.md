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
1. **ALL changes go through Pull Requests.** Direct push to `master` is BLOCKED by the `pre-push`
   hook (see `docs/PR_PROCESS.md` for the full workflow). Push to a `feat/*` branch and open a PR.
2. **Before ANY `git push`:** confirm (a) `git remote -v` shows the canonical GitHub URL (not gitee).
   If unsure, STOP and ask the user.
3. **Never push to the `gitee` remote** — it is the closed-source mirror. The hook blocks it.
4. **Never push secrets or private data.** No hardcoded API keys, tokens, passwords, or
   `C:/Users/<name>/...` absolute paths. Keep `.env` gitignored; read keys from env vars only.
5. **Rotate, don't commit.** If a secret must change, write it to `.env` (gitignored) or env vars —
   never into tracked files or commit messages.
6. A safety `pre-push` hook ships in `.githooks/pre-push`. After cloning, run
   `git config core.hooksPath .githooks` to activate it. It blocks direct-to-master, wrong-remote,
   branch-deletion, and `.NO_PUSH` checkouts; on feature branches it also runs ocr-review
   (OCR_GATE=1 blocks on findings).
7. **After opening a PR, poll CI in the foreground** (`gh pr checks --watch`). Do not end the
   turn and leave "waiting for CI" to the user. Report immediately when green; if red, enter the
   fix loop at once. See `docs/PR_PROCESS.md` §2 item 5 / §3.4.

## Privacy history
On 2026-07-08 the repo was scrubbed: admin key rotated, agent API key rotated, hardcoded
`C:/Users/user/...` paths removed, internal review docs removed from the public tree. Historical
commits may still contain inert (revoked) secret strings — do not reintroduce live ones.

## Hard red lines: patterns NEVER to absorb from WeKnora (2026-10-04)
Source: `docs/OPTIMIZATION_WEKNORA_ABSORPTION.md` §4 (evidence: file:line in WeKnora v0.8.2).
If a future change reintroduces any of these, it is a security regression, not a style choice.

1. **Never default sandbox exec to root.** WeKnora `DefaultSandboxExecUser = "root"` with no uid
   drop / seccomp / read-only rootfs. Any exec-user config must default to an unprivileged user.
2. **A name that sounds like a boundary must be a boundary.** WeKnora's `AllowSkillsRoot` was
   documented as "not a filesystem boundary" while being the only thing standing in front of a
   root shell. If it is not enforced in code, do not name it like it is.
3. **No dead "non-root paths".** An `if opts.AsRoot { user = "root" }` branch that can never fire
   (because root is already the default) misleads every reader and every auditor.
4. **A deny-list is not a perimeter when it is the only defense** for a root shell. Escape the
   trap by not having the root shell, not by extending the list.
5. **Approval gates must cover every execution surface**, not just MCP tools. WeKnora's gate
   covered MCP while `shell_exec` / file writes / skill installs ran unapproved.
6. **Lexical allow-lists (`work_dir` "lexical only") are not path safety.** Resolve and canonicalize.
7. **HTML-escaping memory blocks blocks markup injection, not semantic prompt injection.** A
   well-formed sentence carrying hostile instructions passes intact; never present escaping as
   an injection defense.
8. **Skill packages need signature verification** (gpg/cosign). SHA256 only detects transport
   corruption, not a malicious registry or a compromised publisher account.
9. **Never silently persist degraded summaries as if they were full checkpoints** without a
   user-visible marker — the loss becomes irreversible and invisible (context compaction).
