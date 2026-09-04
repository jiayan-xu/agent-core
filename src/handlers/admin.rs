//! admin handler（从 src/main.rs 拆出，P6 重构）。
//!
//! 承载：consolidate、persona CRUD、degrade/killswitch、quota、audit、harness 激活。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use serde::Deserialize;
use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use agent_core::llm::LlmConfig;

use crate::auth::authenticate;
use crate::handlers::approval::is_admin;
use crate::state::{record_dream_health, AppState};

/// P2-2：consolidate 固定评估（POST /api/admin/consolidate_eval）——《程序化汇合改造方案》§8 P2。
///
/// 在固定题集（10 例：6 正例 + 4 prompt 禁区负例）上真实调用一次提炼 LLM 并程序判分，
/// 北极星指标 = `positive_hit_rate`；报告落盘 `data/consolidate_eval/` 供跨次比较，
/// 为 P3 的 prompt 离线进化提供可比基线。消耗一次 LLM 调用，仅限 admin 手动触发。
pub(crate) async fn handle_admin_consolidate_eval(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    // 解串行：克隆 Arc 后释放全局锁（评估含 LLM 调用，可能耗时数十秒）
    let agent = {
        let g = st.agent.lock().await;
        g.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    let ns = format!("agent/{}", agent.config.identity.agent_id);
    match agent_core::consolidate_eval::run_consolidate_eval(&agent, &ns).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

pub(crate) async fn handle_admin_consolidate(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    // 解串行：克隆 Arc 后释放全局锁，consolidate() 循环在锁外执行
    let agent = {
        let g = st.agent.lock().await;
        g.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    let default_ns = format!("agent/{}", agent.config.identity.agent_id);
    let ns_list: Vec<String> = body
        .as_ref()
        .and_then(|Json(v)| v.get("namespaces").and_then(|a| a.as_array()).cloned())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| {
            std::env::var("CONSOLIDATE_NAMESPACES")
                .unwrap_or(default_ns.clone())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        });
    let mut results = Vec::new();
    for ns in &ns_list {
        let res = agent.consolidate(ns).await;
        results.push(serde_json::json!({"ns": ns, "result": res.detail, "patterns_added": res.patterns_added, "observations": res.observations}));
    }
    // PR5 自驱：手动 consolidate 后可选元进化（追平时默认关，防拖垮）
    let skip_meta = std::env::var("CONSOLIDATE_SKIP_META")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);
    if !skip_meta {
        let me_val = agent.run_meta_evolution(&default_ns).await;
        tracing::info!(target: "consciousness", "meta_evolution(manual): {}", me_val);
        results.push(serde_json::json!({"ns": default_ns, "meta_evolution": me_val}));
    } else {
        results.push(serde_json::json!({"ns": default_ns, "meta_evolution": "skipped"}));
    }
    record_dream_health(&st, "manual", results.clone(), true).await;
    let summary = st.consolidate_last.lock().await.clone();
    Json(summary).into_response()
}

/// Phase 3：运行时创建分身
pub(crate) async fn handle_persona_create(
    headers: axum::http::HeaderMap,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let persona_id = match v.get("persona_id").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST, "persona_id required").into_response(),
    };
    let display_name = v.get("display_name").and_then(|x| x.as_str()).unwrap_or(&persona_id).to_string();
    // owner 一律由鉴权身份推导，不信任请求体（防越权声明他人身份）
    let owner_user_id = caller.clone();
    let is_private = v.get("is_private").and_then(|x| x.as_bool()).unwrap_or(false);
    let tool_allowlist: Vec<String> = v
        .get("tool_allowlist")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let memory_namespace = v.get("memory_namespace").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let llm: Option<LlmConfig> = v
        .get("llm")
        .and_then(|x| serde_json::from_value(x.clone()).ok());
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    match agent.create_persona(&persona_id, &display_name, &owner_user_id, tool_allowlist, memory_namespace, llm, is_private) {
        Ok(()) => {
            agent.save_personas();
            Json(serde_json::json!({"ok": true, "persona_id": persona_id, "owner_user_id": owner_user_id, "is_private": is_private})).into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Phase 3：列出分身（仅返回调用者可见的：公开 / 拥有者 / admin）
pub(crate) async fn handle_persona_list(
    headers: axum::http::HeaderMap,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    let list: Vec<serde_json::Value> = agent
        .list_personas()
        .iter()
        .filter(|p| !p.is_private || admin || p.owner_user_id == caller)
        .map(|p| {
            serde_json::json!({
                "persona_id": p.persona_id,
                "display_name": p.display_name,
                "owner_user_id": p.owner_user_id,
                "tool_allowlist": p.tool_allowlist,
                "memory_namespace": p.memory_namespace,
                "is_private": p.is_private,
            })
        })
        .collect();
    Json(serde_json::json!({"personas": list})).into_response()
}

/// Phase 3：删除分身（私有分身仅拥有者 / admin 可删）
pub(crate) async fn handle_persona_delete(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    // 私有分身：非拥有者 / 非 admin 一律隐藏（404 不泄露存在）
    if let Some(p) = agent.persona_by_id(&id) {
        if p.is_private && !admin && p.owner_user_id != caller {
            return (axum::http::StatusCode::NOT_FOUND, "persona not found").into_response();
        }
    }
    match agent.remove_persona(&id) {
        Ok(()) => {
            agent.save_personas();
            Json(serde_json::json!({"ok": true, "removed": id})).into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Phase 3：把会话绑定到某分身
pub(crate) async fn handle_session_persona_bind(
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let session_id = match v.get("session_id").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST, "session_id required").into_response(),
    };
    let persona_id = match v.get("persona_id").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST, "persona_id required").into_response(),
    };
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    agent.bind_session_persona(&session_id, &persona_id);
    Json(serde_json::json!({"ok": true, "session_id": session_id, "persona_id": persona_id})).into_response()
}

/// Phase 4：给分身压入目标，驱动真实 tick
pub(crate) async fn handle_persona_goal_push(
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let goal = match body.and_then(|Json(v)| v.get("goal").and_then(|x| x.as_str().map(|s| s.to_string()))) {
        Some(s) if !s.is_empty() => s,
        _ => return (axum::http::StatusCode::BAD_REQUEST, "goal required").into_response(),
    };
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    match agent.push_persona_goal(&id, &goal) {
        Ok(()) => Json(serde_json::json!({"ok": true, "persona_id": id, "goal": goal})).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Phase 4：查询单分身详情（含目标栈；私有分身仅拥有者 / admin 可见）
pub(crate) async fn handle_persona_get(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    let p = match agent.persona_by_id(&id) {
        Some(p) => p,
        None => return (axum::http::StatusCode::NOT_FOUND, "persona not found").into_response(),
    };
    if p.is_private && !admin && p.owner_user_id != caller {
        return (axum::http::StatusCode::NOT_FOUND, "persona not found").into_response();
    }
    let goals = agent.get_persona_goals(&id);
    Json(serde_json::json!({
        "persona_id": p.persona_id,
        "display_name": p.display_name,
        "owner_user_id": p.owner_user_id,
        "tool_allowlist": p.tool_allowlist,
        "memory_namespace": p.memory_namespace,
        "is_private": p.is_private,
        "goals": goals,
    })).into_response()
}

/// Phase 6：圆桌（native，自动分配 LLM，不依赖 qclaw）—— SSE 流式
///
/// 多分身就同一议题发表立场 → 主席（默认 default）收敛共识；
/// 每个分身立场完成即推 `stance` 事件，主席收敛推 `consensus`，最后推 `done`。
/// 结论最佳努力写入 Memoria（调用者自身 ns）。LLM 分配由 `AgentCore::persona_stance`
/// 完成：配置/圆桌池自动轮询到多个 provider，做到真多 LLM。
pub(crate) async fn handle_admin_degrade(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        Json(agent.degrade_status()).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P1-5：运行时切换 Kill switch（全局禁用/恢复工具调用）
#[derive(Deserialize)]
pub(crate) struct KillSwitchRequest {
    enabled: bool,
}

pub(crate) async fn handle_admin_killswitch(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<KillSwitchRequest>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        agent.set_kill_switch(req.enabled);
        Json(agent.degrade_status()).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-1：本机运行指标（命名空间配额用量 + 降级状态）
pub(crate) async fn handle_admin_quota_get(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        Json(agent.quota_status()).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-1：临时调整某命名空间配额策略（管理员）
#[derive(Deserialize)]
pub(crate) struct QuotaPolicyUpdate {
    namespace: String,
    #[serde(default)]
    max_tool_rounds: Option<u32>,
    #[serde(default)]
    daily_token_budget: Option<u64>,
    #[serde(default)]
    max_concurrent_sessions: Option<u32>,
}

pub(crate) async fn handle_admin_quota_put(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<QuotaPolicyUpdate>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let mut policy = {
            let s = agent.quota.lock().unwrap_or_else(|p| p.into_inner());
            s.get_policy(&req.namespace)
        };
        if let Some(v) = req.max_tool_rounds {
            policy.max_tool_rounds_per_day = v;
        }
        if let Some(v) = req.daily_token_budget {
            policy.daily_token_budget = v;
        }
        if let Some(v) = req.max_concurrent_sessions {
            policy.max_concurrent_sessions = v;
        }
        agent.set_ns_quota(&req.namespace, policy.clone());
        Json(serde_json::json!({
            "ok": true,
            "namespace": req.namespace,
            "policy": {
                "max_tool_rounds": policy.max_tool_rounds_per_day,
                "daily_token_budget": policy.daily_token_budget,
                "max_concurrent_sessions": policy.max_concurrent_sessions,
            }
        }))
        .into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-2：审计事件只读查询（本地有界环形缓冲即时返回，支持 trace_id / event_type 过滤）
#[derive(serde::Deserialize)]
pub(crate) struct AuditQuery {
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

pub(crate) async fn handle_admin_audit(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let limit = q.limit.unwrap_or(50).min(500);
        let events =
            agent
                .audit_logger
                .recent_events(q.trace_id.as_deref(), q.event.as_deref(), limit);
        Json(serde_json::json!({
            "count": events.len(),
            "events": events,
        }))
        .into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-3：批准并激活待审批的 Harness 模板（含危险工具的蒸馏模板须经此人工 / admin 批准）
#[derive(serde::Deserialize)]
pub(crate) struct HarnessActivate {
    id: i64,
}

pub(crate) async fn handle_admin_harness_activate(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<HarnessActivate>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let ok = agent.harness.lock().await.activate(req.id);
        Json(serde_json::json!({
            "ok": ok,
            "id": req.id,
            "is_active": ok,
        }))
        .into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}