//! 进化引擎 handler（从 src/main.rs 拆出，P4 重构）。
//!
//! 承载：`/api/evolve`（代码自我进化 SSE）、`/api/meta-evolution/run`、`/api/meta-evolution/status`。
//! 四预算自治封套（AutonomyBudget/BudgetTracker，见 `agent-core四预算自治封套落地方案.md`）
//! 的注入点即本文件 `handle_code_evolve` 的 `for gen` 循环。
//! 纯搬移 + `pub(crate)`，零行为变更；既有安全门禁（x-evolve-key / resolve_isolated_target /
//! dry_run+allow_commit / circuit_failures）原样保留。

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::response::sse::{Event as SseEvent, Sse};
use axum::response::IntoResponse;
use axum::Json;
use tokio_stream::wrappers::UnboundedReceiverStream;

use agent_core::code_evolve::{
    apply_patch, eval_crate, find_up, git_commit, git_diff, git_revert, propose_fn, EvalResult,
};
use agent_core::llm::LlmClient;

use crate::state::AppState;

/// Phase 7：进化任务并发守卫（Drop 时复位，确保任何退出路径都释放锁）
pub(crate) struct EvolveGuard<'a> {
    flag: &'a AtomicBool,
}
impl<'a> Drop for EvolveGuard<'a> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

/// Phase 7：代码自我进化引擎（POST /api/evolve，SSE 流式）
///
/// 安全模型（对齐圆桌共识 + 人类否决闸门 + P0 加固）：
/// - 必须由 `[code_evolution] enabled = true` 开启，否则 403。
/// - 必须由 `[code_evolution] evolve_key` 配置密钥，且请求携带匹配的 `x-evolve-key`（P0-1）；
///   否则 401 / fail-closed。全局 auth_middleware 的自动开户不足以触发进化。
/// - 目标路径经 `resolve_isolated_target` 规范化校验：拒 symlink、拒落入 agent-core / memoria
///   源码树（含改名克隆、memoria-open）（P0-2）。
/// - 真签名冻结：apply_patch 归一化比对签名，仅替换函数体（P0-3）。
/// - 默认 dry_run 由 `dry_run_default` 决定（默认 true）：只产 diff（veto 事件），不落盘；
///   须显式 `apply=true` 且配置 `allow_commit=true` 才 git commit（人类否决闸门）。
/// - 熔断：连续失败/无进展达 `circuit_failures` 代立即停。
pub(crate) async fn handle_code_evolve(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    // 取 code_evolution 配置
    let ce = { let c = st.config.lock().await; c.code_evolution.clone() };
    let ce = match ce {
        Some(c) if c.enabled => c,
        _ => return (axum::http::StatusCode::FORBIDDEN, "code evolution disabled").into_response(),
    };
    // P0-1：专用进化密钥闸门（fail-closed）。即便已通过全局 auth_middleware 的自动开户，
    // 触发进化仍必须携带与配置匹配的 `x-evolve-key`，否则 401。避免「端口可达 + 自动开户 = 即可触发进化」。
    let cfg_evolve_key = ce.evolve_key.clone().unwrap_or_default();
    if cfg_evolve_key.is_empty() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "evolution key not configured (fail-closed)",
        )
            .into_response();
    }
    let supplied_key = headers
        .get("x-evolve-key")
        .and_then(|x| x.to_str().ok())
        .unwrap_or("")
        .to_string();
    if supplied_key != cfg_evolve_key {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "missing/invalid x-evolve-key",
        )
            .into_response();
    }
    // 解析参数
    let target = v
        .get("target_path")
        .and_then(|x| x.as_str())
        .map(String::from)
        .or(ce.target_path.clone());
    let target = match target {
        Some(t) => t,
        None => return (axum::http::StatusCode::BAD_REQUEST, "target_path required").into_response(),
    };
    // P0-2：路径隔离强化 —— 规范化 + 拒 symlink + 拒落入 agent-core/memoria 源码树（含改名克隆、memoria-open）
    let target_p = match agent_core::code_evolve::resolve_isolated_target(&target) {
        Ok(p) => p,
        Err(e) => return (axum::http::StatusCode::FORBIDDEN, e).into_response(),
    };
    let fn_name = v
        .get("fn_name")
        .and_then(|x| x.as_str())
        .map(String::from)
        .unwrap_or_else(|| ce.fn_name.clone());
    let generations = v
        .get("generations")
        .and_then(|x| x.as_u64())
        .map(|n| n as usize)
        .unwrap_or(ce.generations);
    let circuit = ce.circuit_failures.max(1);
    // P1：apply 默认值由配置 dry_run_default 决定（默认 true → 默认 dry_run）。
    // 此前该字段是死字段（handler 未读），现已接线生效。
    let apply_param = v
        .get("apply")
        .and_then(|x| x.as_bool())
        .unwrap_or(!ce.dry_run_default);
    let effective_apply = apply_param && ce.allow_commit;
    let goal = v.get("goal").and_then(|x| x.as_str()).map(String::from).unwrap_or_else(|| {
        "在保持正确性、签名与 `pub fn fib` 不变、且不改动 #[cfg(test)] 测试模块的前提下，优化实现使其运行更快；禁止使用 unsafe、外部 IO 或新增依赖。".to_string()
    });

    // 并发守卫：同一时刻只允许一个进化任务（防止多请求并发覆盖隔离仓库）
    if st.evolve_running.swap(true, Ordering::SeqCst) {
        return (
            axum::http::StatusCode::CONFLICT,
            "evolution already running",
        )
            .into_response();
    }

    // agent 就绪 + 选取提议用 LLM（专属 model 或全局主 client）
    let g = st.agent.lock().await;
    if g.is_none() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "agent 尚未就绪",
        )
            .into_response();
    }
    let proposer = match &ce.model {
        Some(m) => LlmClient::new(m.clone()),
        None => g.as_ref().unwrap().llm.clone(),
    };
    drop(g);

    let (tx, rx): (
        tokio::sync::mpsc::UnboundedSender<Result<SseEvent, Infallible>>,
        tokio::sync::mpsc::UnboundedReceiver<Result<SseEvent, Infallible>>,
    ) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        // 任务结束（含任意 early break）自动复位并发守卫
        let _guard = EvolveGuard {
            flag: &st.evolve_running,
        };
        let send = |ev: &str, data: serde_json::Value| {
            let _ = tx.send(Ok(SseEvent::default().event(ev).data(data.to_string())));
        };
        // 派生隔离仓库的 manifest 与 git 根
        let manifest = find_up(&target_p, "Cargo.toml").unwrap_or_else(|| target_p.clone());
        let repo = match find_up(&target_p, ".git") {
            Some(gd) => gd
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or(gd),
            None => target_p.parent().unwrap_or(&target_p).to_path_buf(),
        };

        // 种子最优：以当前已提交状态为基线
        let mut best: Option<f64> = {
            let m = manifest.clone();
            let e = tokio::task::spawn_blocking(move || eval_crate(&m))
                .await
                .unwrap_or(EvalResult {
                    passed: false,
                    bench_ms: None,
                    log: "eval 失败".into(),
                });
            if e.passed {
                e.bench_ms
            } else {
                None
            }
        };
        send(
            "info",
            serde_json::json!({
                "repo": repo.to_string_lossy(),
                "manifest": manifest.to_string_lossy(),
                "apply": effective_apply,
                "best_seed_ms": best,
                "goal": goal,
            }),
        );

        let mut consecutive = 0usize;
        let mut gens_run = 0usize;
        // P0 四预算自治封套（借鉴 Prime Agent，方案 §2 注入点 A）：
        // turns / tokens / wall-clock + 可选 gate_command；违约 → budget_break SSE +
        // git_revert 干净基线（下方现有回退点已覆盖），绝不绕过隔离/鉴权/dry_run 双闸门。
        let mut tracker = agent_core::autonomy_budget::BudgetTracker::new(ce.budget.clone());
        for gen in 1..=generations {
            gens_run += 1;
            // ① 纯墙钟检查（每代顶部，不消耗 turn）
            if let Err(b) = tracker.check_wall_clock() {
                send(
                    "budget_break",
                    serde_json::json!({
                        "reason": format!("{:?}", b),
                        "gens_run": gens_run,
                        "elapsed_secs": tracker.elapsed_secs(),
                        "max_wall_clock_secs": ce.budget.max_wall_clock_secs,
                    }),
                );
                break;
            }
            let current = match std::fs::read_to_string(&target_p) {
                Ok(c) => c,
                Err(e) => {
                    send("error", serde_json::json!({"gen": gen, "msg": format!("读目标文件失败: {}", e)}));
                    break;
                }
            };
            send("gen_start", serde_json::json!({"gen": gen, "best_ms": best}));

            // 1) LLM 提议
            let new_fn = match propose_fn(&proposer, &fn_name, &current, &goal).await {
                Ok(f) => f,
                Err(e) => {
                    send("proposal_error", serde_json::json!({"gen": gen, "msg": e}));
                    consecutive += 1;
                    if consecutive >= circuit {
                        send("circuit_break", serde_json::json!({"reason": format!("连续 {} 代提议失败/超时", consecutive)}));
                        break;
                    }
                    continue;
                }
            };
            send("proposal", serde_json::json!({"gen": gen, "code": new_fn}));
            // ② 记一轮 + token 记账（过渡期 chars/4 估算，方案 §6）；违约立即停 + 回退
            if let Err(b) = tracker.record_turn(
                agent_core::autonomy_budget::estimate_tokens(&new_fn),
            ) {
                let _ = git_revert(&repo, &target_p); // 硬红线：回到干净基线
                send(
                    "budget_break",
                    serde_json::json!({
                        "reason": format!("{:?}", b),
                        "gens_run": gens_run,
                        "turns": tracker.turns_used(),
                        "tokens": tracker.tokens_used(),
                        "elapsed_secs": tracker.elapsed_secs(),
                    }),
                );
                break;
            }

            // 2) 外科替换
            let new_src = match apply_patch(&current, &fn_name, &new_fn) {
                Ok(s) => s,
                Err(e) => {
                    send("rejected", serde_json::json!({"gen": gen, "reason": e}));
                    consecutive += 1;
                    if consecutive >= circuit {
                        send("circuit_break", serde_json::json!({"reason": "连续被拒达上限"}));
                        break;
                    }
                    continue;
                }
            };
            if std::fs::write(&target_p, &new_src).is_err() {
                send("rejected", serde_json::json!({"gen": gen, "reason": "写目标文件失败"}));
                consecutive += 1;
                if consecutive >= circuit {
                    send("circuit_break", serde_json::json!({"reason": "连续失败达上限"}));
                    break;
                }
                continue;
            }

            // 3) 评估（在阻塞线程跑 cargo，避免占用 async 工作线程）
            let m = manifest.clone();
            let ev = tokio::task::spawn_blocking(move || eval_crate(&m))
                .await
                .unwrap_or(EvalResult {
                    passed: false,
                    bench_ms: None,
                    log: "eval 失败".into(),
                });

            if !ev.passed {
                let _ = git_revert(&repo, &target_p);
                send("reverted", serde_json::json!({"gen": gen, "reason": "测试/编译失败", "log": ev.log}));
                consecutive += 1;
                if consecutive >= circuit {
                    send("circuit_break", serde_json::json!({"reason": "连续失败达上限"}));
                    break;
                }
                continue;
            }

            // 4) 判定是否优于当前最优
            let improved = match best {
                None => true,
                Some(b) => ev.bench_ms.map_or(false, |m| m < b - 1e-9),
            };
            if improved {
                best = ev.bench_ms;
                consecutive = 0;
                if effective_apply {
                    match git_commit(&repo, &target_p, &format!("代码进化(gen {}): 优化 {}", gen, fn_name)) {
                        Ok(h) => send(
                            "committed",
                            serde_json::json!({"gen": gen, "commit": h, "bench_ms": ev.bench_ms, "log": ev.log}),
                        ),
                        Err(e) => {
                            let _ = git_revert(&repo, &target_p);
                            send("rejected", serde_json::json!({"gen": gen, "reason": format!("commit 失败: {}", e)}));
                        }
                    }
                } else {
                    let diff = git_diff(&repo, &target_p);
                    send("veto", serde_json::json!({"gen": gen, "bench_ms": ev.bench_ms, "diff": diff, "log": ev.log}));
                    let _ = git_revert(&repo, &target_p); // 不落盘，等待人工批准
                }
            } else {
                let _ = git_revert(&repo, &target_p);
                send("reverted", serde_json::json!({"gen": gen, "reason": "未优于当前最优", "bench_ms": ev.bench_ms}));
                consecutive += 1;
                if consecutive >= circuit {
                    send("circuit_break", serde_json::json!({"reason": "连续无进展达上限"}));
                    break;
                }
            }
        }
        // ③ 循环结束后可选 pass/fail gate（Prime Agent 同款，方案 §2）
        if let Some(cmd) = &ce.budget.gate_command {
            if !cmd.trim().is_empty() {
                let gate = tokio::process::Command::new("sh")
                    .args(["-c", cmd])
                    .current_dir(&repo)
                    .output()
                    .await;
                let ok = gate.map(|o| o.status.success()).unwrap_or(false);
                if !ok {
                    let _ = git_revert(&repo, &target_p);
                    // Gate 违约类型统一由 BudgetTracker 构造（ocr 2026-08-12 bug·high）
                    let _breach = agent_core::autonomy_budget::BudgetTracker::gate_failed();
                    send(
                        "gate_failed",
                        serde_json::json!({"command": cmd, "reason": "pass/fail gate 未通过，整体否决"}),
                    );
                }
            }
        }
        send(
            "done",
            serde_json::json!({"gens_run": gens_run, "best_ms": best, "applied": effective_apply}),
        );
    });

    Sse::new(UnboundedReceiverStream::new(rx)).into_response()
}

/// PR5：触发一轮元进化（POST /api/meta-evolution/run）
pub(crate) async fn handle_meta_evolution_run(
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let agent_guard = st.agent.lock().await;
    let Some(ref agent) = *agent_guard else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    let default_ns = format!("agent/{}", agent.config.identity.agent_id);
    let ns = body
        .as_ref()
        .and_then(|Json(v)| v.get("namespace").and_then(|x| x.as_str()).map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or(default_ns);
    // ns 校验（ocr 2026-08-12 第十一轮 security·medium）：ns 是用户可控输入，且是
    // evo_continuations map 的键——超长/畸形字符串会撑大 map（配合键数上限仍应
    // 限制单键大小）并污染日志。允许字符集：字母数字 _ / : - . + @ 与空格。
    let ns_valid = ns.len() <= 128
        && ns
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-/:.+@ ".contains(c));
    if !ns_valid {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "namespace 非法：长度须 ≤128 且仅含字母数字 _ - / : . + @ 空格"
            })),
        )
            .into_response();
    }
    let res = agent.run_meta_evolution(&ns).await;
    drop(agent_guard);
    Json(res).into_response()
}

/// PR5：元进化状态（GET /api/meta-evolution/status）
pub(crate) async fn handle_meta_evolution_status(
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let agent_guard = st.agent.lock().await;
    let Some(ref agent) = *agent_guard else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    let res = agent.meta_evolution_status().await;
    drop(agent_guard);
    Json(res).into_response()
}
