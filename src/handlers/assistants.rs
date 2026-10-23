//! Personal Assistant Platform handlers（Phase 0）。
//!
//! 受保护路由：用户管理自己的 assistant binding。
//! 公开路由：本地助手持 opaque scoped token 访问平台资源（binding/heartbeat/memory/A2A）。
//! 本模块不做本地智能体管控，只做平台身份、资源代理、协作与审计。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use chrono::Local;
use serde::Deserialize;

use agent_core::audit::{new_trace_id, AuditEvent, AuditEventType};

use crate::assistant_platform::{NewBinding, TokenAuth};
use crate::auth::AuthContext;
use crate::state::AppState;

fn err(status: axum::http::StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"error": code, "message": message})),
    )
        .into_response()
}

fn bearer_token(headers: &HeaderMap) -> String {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth.len() >= 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
        return auth[7..].trim().to_string();
    }
    headers
        .get("x-assistant-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string()
}

async fn assistant_auth(
    st: &Arc<AppState>,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<TokenAuth, Response> {
    let token = bearer_token(headers);
    match st.assistant_platform.validate_token(&token, required_scope) {
        Ok(auth) => Ok(auth),
        Err(message) => {
            let _ = st.assistant_platform.record_event(
                "policy.denied",
                "",
                None,
                &format!("scope={required_scope} reason={message}"),
            );
            Err(err(
                axum::http::StatusCode::UNAUTHORIZED,
                "assistant_unauthorized",
                &message,
            ))
        }
    }
}

async fn audit_platform(
    st: &Arc<AppState>,
    event_type: &str,
    user_id: &str,
    binding_id: Option<&str>,
    detail: &str,
) {
    let trace_id = st
        .assistant_platform
        .record_event(event_type, user_id, binding_id, detail)
        .unwrap_or_else(|_| new_trace_id());
    let agent = {
        let guard = st.agent.lock().await;
        guard.as_ref().map(|a| a.clone())
    };
    if let Some(agent) = agent {
        agent
            .audit_logger
            .record_event(AuditEvent {
                ts: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                trace_id,
                agent_id: user_id.to_string(),
                session_id: binding_id.map(|s| s.to_string()),
                event_type: AuditEventType::Custom(event_type.to_string()),
                detail: detail.to_string(),
            })
            .await;
    }
}

async fn audit_agent_only(
    st: &Arc<AppState>,
    event_type: &str,
    user_id: &str,
    binding_id: Option<&str>,
    detail: &str,
    trace_id: &str,
) {
    let agent = {
        let guard = st.agent.lock().await;
        guard.as_ref().map(|a| a.clone())
    };
    if let Some(agent) = agent {
        agent
            .audit_logger
            .record_event(AuditEvent {
                ts: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                trace_id: trace_id.to_string(),
                agent_id: user_id.to_string(),
                session_id: binding_id.map(|s| s.to_string()),
                event_type: AuditEventType::Custom(event_type.to_string()),
                detail: detail.to_string(),
            })
            .await;
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateBindingRequest {
    assistant_type: String,
    #[serde(default)]
    assistant_name: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    public_key: String,
}

pub(crate) async fn handle_assistant_binding_create(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<CreateBindingRequest>,
) -> Response {
    let new = NewBinding {
        user_id: ctx.agent_id.clone(),
        assistant_type: req.assistant_type.clone(),
        assistant_name: req.assistant_name.clone(),
        device_id: req.device_id.clone(),
        capabilities: req.capabilities.clone(),
        scopes: req.scopes.clone(),
        public_key: req.public_key.clone(),
    };
    match st.assistant_platform.create_binding(new) {
        Ok(binding) => {
            let (token, _) = match st.assistant_platform.issue_token(&binding.binding_id, 24) {
                Ok(v) => v,
                Err(message) => {
                    return err(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "token_issue_failed",
                        &message,
                    )
                }
            };
            audit_platform(
                &st,
                "assistant.binding.created",
                &ctx.agent_id,
                Some(&binding.binding_id),
                &format!(
                    "assistant_type={} device={}",
                    binding.assistant_type, binding.device_id
                ),
            )
            .await;
            (
                axum::http::StatusCode::CREATED,
                Json(serde_json::json!({
                    "binding": binding,
                    "token": {
                        "access_token": token.access_token,
                        "refresh_token": token.refresh_token,
                        "token_id": token.token_id,
                        "expires_at": token.expires_at,
                        "scopes": token.scopes,
                    }
                })),
            )
                .into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "binding_create_failed",
            &message,
        ),
    }
}

pub(crate) async fn handle_assistant_binding_list(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    match st.assistant_platform.list_bindings(&ctx.agent_id) {
        Ok(items) => Json(serde_json::json!({"bindings": items})).into_response(),
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "binding_list_failed",
            &message,
        ),
    }
}

pub(crate) async fn handle_assistant_binding_revoke(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Path(binding_id): Path<String>,
) -> Response {
    match st
        .assistant_platform
        .revoke_binding(&binding_id, &ctx.agent_id)
    {
        Ok(Some(binding)) => {
            audit_platform(
                &st,
                "assistant.binding.revoked",
                &ctx.agent_id,
                Some(&binding.binding_id),
                "revoked by owner/admin",
            )
            .await;
            Json(serde_json::json!({"binding": binding})).into_response()
        }
        Ok(None) => err(
            axum::http::StatusCode::NOT_FOUND,
            "binding_not_found",
            "binding 不存在",
        ),
        Err(message) => err(
            axum::http::StatusCode::FORBIDDEN,
            "binding_revoke_forbidden",
            &message,
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct IssueTokenRequest {
    #[serde(default = "default_hours")]
    hours: i64,
}
fn default_hours() -> i64 {
    24
}

pub(crate) async fn handle_assistant_token_issue(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Path(binding_id): Path<String>,
    Json(req): Json<IssueTokenRequest>,
) -> Response {
    let binding = match st.assistant_platform.get_binding(&binding_id) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return err(
                axum::http::StatusCode::NOT_FOUND,
                "binding_not_found",
                "binding 不存在",
            )
        }
        Err(message) => {
            return err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "binding_read_failed",
                &message,
            )
        }
    };
    if binding.user_id != ctx.agent_id && ctx.agent_id != "admin" {
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "not_binding_owner",
            "只能为自己的 binding 签发 token",
        );
    }
    let hours = req.hours.clamp(1, 24 * 30);
    match st.assistant_platform.issue_token(&binding_id, hours) {
        Ok((token, _)) => {
            audit_platform(
                &st,
                "assistant.token.issued",
                &ctx.agent_id,
                Some(&binding_id),
                &format!("hours={hours}"),
            )
            .await;
            Json(serde_json::json!({
                "access_token": token.access_token,
                "refresh_token": token.refresh_token,
                "token_id": token.token_id,
                "expires_at": token.expires_at,
                "scopes": token.scopes
            }))
            .into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "token_issue_failed",
            &message,
        ),
    }
}

pub(crate) async fn handle_assistant_events(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    match st.assistant_platform.recent_events_for_user(&ctx.agent_id, 100) {
        Ok(events) => Json(serde_json::json!({"events": events})).into_response(),
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "event_query_failed",
            &message,
        ),
    }
}

pub(crate) async fn handle_assistant_heartbeat(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "assistant:heartbeat").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if let Err(message) = st.assistant_platform.heartbeat(&auth.binding_id) {
        return err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "heartbeat_failed",
            &message,
        );
    }
    Json(serde_json::json!({
        "status": "ok",
        "binding_id": auth.binding_id,
        "user_id": auth.user_id,
        "scopes": auth.scopes
    }))
    .into_response()
}

pub(crate) async fn handle_assistant_me(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "assistant:heartbeat").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let binding = st.assistant_platform.get_binding(&auth.binding_id);
    match binding {
        Ok(Some(v)) => {
            Json(serde_json::json!({"binding": v, "scopes": auth.scopes})).into_response()
        }
        Ok(None) => err(
            axum::http::StatusCode::NOT_FOUND,
            "binding_not_found",
            "binding 不存在",
        ),
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "binding_read_failed",
            &message,
        ),
    }
}

pub(crate) async fn handle_assistant_token_revoke(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "assistant:heartbeat").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let token = bearer_token(&headers);
    match st.assistant_platform.revoke_token(&token) {
        Ok(()) => {
            audit_platform(
                &st,
                "assistant.token.revoked",
                &auth.user_id,
                Some(&auth.binding_id),
                "revoked by assistant token",
            )
            .await;
            Json(serde_json::json!({"status": "revoked"})).into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "token_revoke_failed",
            &message,
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct AssistantMemoryWriteRequest {
    content: String,
    #[serde(default = "default_memory_type")]
    memory_type: String,
    #[serde(default = "default_category")]
    category: String,
    #[serde(default = "default_importance")]
    importance: i64,
    #[serde(default)]
    tags: Vec<String>,
}
fn default_memory_type() -> String {
    "declarative".to_string()
}
fn default_category() -> String {
    "assistant_observation".to_string()
}
fn default_importance() -> i64 {
    3
}

pub(crate) async fn handle_assistant_memory_write(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AssistantMemoryWriteRequest>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "memory:write:self").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if req.content.trim().is_empty() {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "empty_content",
            "content 不能为空",
        );
    }
    let namespace = format!("agent/{}", auth.user_id);
    let mut tags = vec![
        format!("assistant:{}", auth.assistant_type),
        format!("binding:{}", auth.binding_id),
    ];
    tags.extend(
        req.tags
            .iter()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .take(8)
            .map(|x| x.to_string()),
    );
    let args = serde_json::json!({
        "namespace": namespace,
        "content": req.content,
        "memory_type": req.memory_type,
        "category": req.category,
        "importance": req.importance.clamp(1, 5),
        "source": auth.assistant_type,
        "tags": tags,
    });
    let agent = {
        let guard = st.agent.lock().await;
        guard.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
        return err(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            "agent-core 尚未就绪",
        );
    };
    match agent.mcp.call_json("memory_remember", &args).await {
        Ok(result) => {
            audit_platform(
                &st,
                "memory.write",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("ns={namespace} bytes={}", req.content.len()),
            )
            .await;
            Json(serde_json::json!({
                "status": "ok",
                "namespace": namespace,
                "source": auth.assistant_type,
                "memoria": result
            }))
            .into_response()
        }
        Err(message) => {
            audit_platform(
                &st,
                "memory.write.failed",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("ns={namespace} error={message}"),
            )
            .await;
            err(
                axum::http::StatusCode::BAD_GATEWAY,
                "memory_write_failed",
                &message,
            )
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct AssistantContextQuery {
    q: String,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    5
}

pub(crate) async fn handle_assistant_context(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AssistantContextQuery>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "memory:read:self").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if query.q.trim().is_empty() {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "empty_query",
            "q 不能为空",
        );
    }
    let namespace = format!("agent/{}", auth.user_id);
    let args = serde_json::json!({
        "namespace": namespace,
        "query": query.q,
        "max_results": query.limit.clamp(1, 20)
    });
    let agent = {
        let guard = st.agent.lock().await;
        guard.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
        return err(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            "agent-core 尚未就绪",
        );
    };
    match agent.mcp.call_json("memory_search_v2", &args).await {
        Ok(result) => {
            audit_platform(
                &st,
                "memory.read",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("ns={namespace} query_bytes={}", query.q.len()),
            )
            .await;
            Json(serde_json::json!({
                "status": "ok",
                "namespace": namespace,
                "result": result
            }))
            .into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_GATEWAY,
            "memory_read_failed",
            &message,
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct A2aTaskCreateRequest {
    target_binding: String,
    #[serde(default = "default_task_type")]
    task_type: String,
    subject: String,
    body: String,
    #[serde(default)]
    meeting_id: Option<String>,
}
fn default_task_type() -> String {
    "generic".to_string()
}

pub(crate) async fn handle_a2a_task_create(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<A2aTaskCreateRequest>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:send").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // P2-1（D10c）：带 meeting_id 的任务必须双方均为该会有效成员
    if let Err(resp) =
        a2a_meeting_check(&st, &auth.binding_id, &req.target_binding, req.meeting_id.as_deref()).await
    {
        return resp;
    }
    let task = st.assistant_platform.create_task(
        &auth,
        &req.target_binding,
        req.meeting_id.clone(),
        &req.task_type,
        &req.subject,
        &req.body,
    );
    match task {
        Ok(task) => {
            // 任务同帧投递目标 inbox；Phase 0 无推送连接，目标用 inbox 拉取。
            let _ = st.assistant_platform.create_message(
                &auth,
                &req.target_binding,
                req.meeting_id.clone(),
                Some(task.task_id.clone()),
                "task",
                &format!("{}\n\n{}", req.subject, req.body),
            );
            // create_task/create_message 已各自持久化 assistant_events；
            // AuditLogger 使用 task.trace_id 再落治理审计，保证 /api/admin/audit 可追踪。
            audit_agent_only(
                &st,
                "a2a.task.created",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("task={} target={}", task.task_id, task.to_binding),
                &task.trace_id,
            )
            .await;
            (
                axum::http::StatusCode::CREATED,
                Json(serde_json::json!({"task": task})),
            )
                .into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "task_create_failed",
            &message,
        ),
    }
}

pub(crate) async fn handle_a2a_task_get(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:receive").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match st.assistant_platform.get_task(&task_id) {
        Ok(Some(task))
            if task.from_binding == auth.binding_id || task.to_binding == auth.binding_id =>
        {
            Json(serde_json::json!({"task": task})).into_response()
        }
        Ok(Some(_)) => err(
            axum::http::StatusCode::FORBIDDEN,
            "task_forbidden",
            "无权读取该 task",
        ),
        Ok(None) => err(
            axum::http::StatusCode::NOT_FOUND,
            "task_not_found",
            "task 不存在",
        ),
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "task_read_failed",
            &message,
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct A2aTaskUpdateRequest {
    status: String,
    #[serde(default)]
    result: Option<String>,
}

pub(crate) async fn handle_a2a_task_update(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    Json(req): Json<A2aTaskUpdateRequest>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:receive").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match st.assistant_platform.update_task(
        &task_id,
        &auth.binding_id,
        &req.status,
        req.result.clone(),
    ) {
        Ok(task) => {
            audit_platform(
                &st,
                "a2a.task.status_changed",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("task={} status={}", task.task_id, task.status),
            )
            .await;
            Json(serde_json::json!({"task": task})).into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "task_update_failed",
            &message,
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct A2aMessageCreateRequest {
    target_binding: String,
    body: String,
    #[serde(default = "default_message_type")]
    message_type: String,
    #[serde(default)]
    meeting_id: Option<String>,
    #[serde(default)]
    task_id: Option<String>,
}
fn default_message_type() -> String {
    "text".to_string()
}

pub(crate) async fn handle_a2a_message_create(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<A2aMessageCreateRequest>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:send").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // P2-1（D10c）：带 meeting_id 的消息必须双方均为该会有效成员
    if let Err(resp) =
        a2a_meeting_check(&st, &auth.binding_id, &req.target_binding, req.meeting_id.as_deref()).await
    {
        return resp;
    }
    match st.assistant_platform.create_message(
        &auth,
        &req.target_binding,
        req.meeting_id,
        req.task_id,
        &req.message_type,
        &req.body,
    ) {
        Ok(message) => {
            audit_platform(
                &st,
                "a2a.message.sent",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("message={} target={}", message.message_id, message.to_binding),
            )
            .await;
            (
                axum::http::StatusCode::CREATED,
                Json(serde_json::json!({"message": message})),
            )
                .into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "message_create_failed",
            &message,
        ),
    }
}

pub(crate) async fn handle_a2a_inbox(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:receive").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match st.assistant_platform.list_inbox(&auth.binding_id) {
        Ok(messages) => Json(serde_json::json!({"messages": messages})).into_response(),
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "inbox_read_failed",
            &message,
        ),
    }
}

// ── Phase 1：refresh token 轮换（公开路由，prt_ 即凭证） ──────────────────

#[derive(Deserialize)]
pub(crate) struct TokenRefreshRequest {
    refresh_token: String,
}

pub(crate) async fn handle_assistant_token_refresh(
    State(st): State<Arc<AppState>>,
    Json(req): Json<TokenRefreshRequest>,
) -> Response {
    match st.assistant_platform.refresh_access(&req.refresh_token, 24) {
        Ok((token, binding)) => {
            audit_platform(
                &st,
                "assistant.token.refreshed",
                &binding.user_id,
                Some(&binding.binding_id),
                &format!("token rotated, binding={}", binding.binding_id),
            )
            .await;
            Json(serde_json::json!({"token": token})).into_response()
        }
        Err(message) => {
            // 轮换失败也留痕（无效/重放 refresh token 是安全信号）
            audit_platform(&st, "assistant.token.refresh_failed", "", None, &message).await;
            err(
                axum::http::StatusCode::UNAUTHORIZED,
                "token_refresh_failed",
                &message,
            )
        }
    }
}

// ── Phase 1：可见性策略（受保护，本人） ────────────────────────────────────

pub(crate) async fn handle_assistant_visibility_get(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    match st.assistant_platform.get_visibility(&ctx.agent_id) {
        Ok(level) => Json(serde_json::json!({"level": level})).into_response(),
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "visibility_read_failed",
            &message,
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct VisibilitySetRequest {
    level: String,
}

pub(crate) async fn handle_assistant_visibility_set(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<VisibilitySetRequest>,
) -> Response {
    match st.assistant_platform.set_visibility(&ctx.agent_id, &req.level) {
        Ok(level) => {
            audit_platform(
                &st,
                "assistant.visibility.changed",
                &ctx.agent_id,
                None,
                &format!("level={level}"),
            )
            .await;
            Json(serde_json::json!({"level": level})).into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "visibility_set_failed",
            &message,
        ),
    }
}

// ── Phase 1：通讯录助手摘要目录（受保护，按可见性过滤） ────────────────────
//
// 规则（方案 §6.3）：
//   本人             → 自己全部 active binding
//   level=off        → 他人不可见（本人仍可见）
//   level=company    → 全员可见能力摘要
//   level=dept（缺省）→ 仅同部门可见能力摘要
// 部门关系经 dept_registry（memoria 注册表 ns 的 dept/<slug> 段，TTL 300s）；
// 无部门信息的双方视为跨部门（默认不可见，宁缺勿漏）。

pub(crate) async fn handle_assistant_directory(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let requester = ctx.agent_id.clone();
    let summaries = match st.assistant_platform.active_summaries() {
        Ok(v) => v,
        Err(message) => {
            return err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "directory_read_failed",
                &message,
            )
        }
    };
    let visibility = st.assistant_platform.visibility_map().unwrap_or_default();
    let requester_depts = crate::auth::member_depts(&st, &requester).await;

    // agent_id → display_name：通讯录按显示名匹配。同一员工可能有两条身份
    // （正式注册 + office_proxy 复合身份内嵌 _u_ 安装标签，后者被通讯录噪音
    // 过滤排除），binding 挂复合身份而通讯录显示正式身份——display_name 合一。
    let mut display_names: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    {
        let (server, cfg_admin) = {
            let cfg = st.config.lock().await;
            (cfg.server.clone(), cfg.memoria_admin_key.clone())
        };
        let client = crate::config::memoria_proxy_client(&server, &cfg_admin);
        if let Ok(v) = client.call_json("agent_list", &serde_json::json!({})).await {
            if let Some(agents) = v.get("agents").and_then(|a| a.as_array()) {
                for a in agents {
                    let aid = a.get("agent_id").and_then(|x| x.as_str()).unwrap_or("");
                    let dn = a.get("display_name").and_then(|x| x.as_str()).unwrap_or("");
                    if !aid.is_empty() && !dn.is_empty() {
                        display_names.entry(dn.to_string()).or_insert_with(|| aid.to_string());
                        display_names.insert(aid.to_string(), dn.to_string());
                    }
                }
            }
        }
    }

    // 按 user 聚合
    use std::collections::BTreeMap;
    let mut by_user: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    for (user_id, assistant_type, assistant_name, capabilities, last_seen) in summaries {
        by_user.entry(user_id).or_default().push(serde_json::json!({
            "assistant_type": assistant_type,
            "assistant_name": assistant_name,
            "capabilities": capabilities,
            "last_seen_at": last_seen,
        }));
    }

    let mut out = Vec::new();
    for (user_id, assistants) in by_user {
        let is_self = user_id == requester;
        if !is_self {
            let level = visibility.get(&user_id).map(|s| s.as_str()).unwrap_or("dept");
            let visible = match level {
                "off" => false,
                "company" => true,
                _ => {
                    let owner_depts = crate::auth::member_depts(&st, &user_id).await;
                    !owner_depts.is_disjoint(&requester_depts)
                }
            };
            if !visible {
                continue;
            }
        }
        out.push(serde_json::json!({
            "user_id": user_id,
            "display_name": display_names.get(&user_id).cloned().unwrap_or_default(),
            "is_self": is_self,
            "assistants": assistants,
        }));
    }
    Json(serde_json::json!({
        "requester": requester,
        "requester_level": visibility
            .get(&requester)
            .cloned()
            .unwrap_or_else(|| "dept".to_string()),
        "users": out,
    }))
    .into_response()
}

// ── Phase 1：换助手交接 brief（受保护，本人） ──────────────────────────────
//
// 汇总 bindings 历史 + 近期平台事件 + 个人 NS 代表性记忆 → 生成结构化 brief，
// 写回本人 NS（category=handover, tag=handover-brief），
// 新助手经 /api/agent/context 检索 handover-brief 即可读到。

pub(crate) async fn handle_assistant_handover_brief(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let user_id = ctx.agent_id.clone();
    let bindings = st
        .assistant_platform
        .list_bindings(&user_id)
        .unwrap_or_default();
    let events = st
        .assistant_platform
        .recent_events_for_user(&user_id, 40)
        .unwrap_or_default();

    let namespace = format!("agent/{user_id}");
    let mut memories: Vec<serde_json::Value> = Vec::new();
    {
        let agent = {
            let guard = st.agent.lock().await;
            guard.as_ref().map(|a| a.clone())
        };
        if let Some(agent) = agent {
            let args = serde_json::json!({
                "namespace": namespace,
                "query": "工作偏好 决策 结论 教训 项目",
                "limit": 10,
            });
            if let Ok(result) = agent.mcp.call_json("memory_search_v2", &args).await {
                if let Some(items) = result.get("results").and_then(|v| v.as_array()) {
                    memories = items.clone();
                }
            }
        }
    }

    // ── 组装 brief 文本 ──
    let mut brief = String::new();
    brief.push_str("# 助手交接 Brief\n\n");
    brief.push_str(&format!(
        "用户：{user_id}\n生成时间：{}\n\n",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    ));

    brief.push_str("## 助手绑定历史\n\n");
    if bindings.is_empty() {
        brief.push_str("（无绑定记录）\n");
    }
    for b in &bindings {
        let caps = b.capabilities.join(" / ");
        brief.push_str(&format!(
            "- [{}] {}（{}）设备：{} · 能力：{} · 创建 {} · 最后活跃 {}\n",
            b.status,
            b.assistant_name,
            b.assistant_type,
            if b.device_id.is_empty() { "—" } else { &b.device_id },
            if caps.is_empty() { "—" } else { &caps },
            b.created_at,
            b.last_seen_at.as_deref().unwrap_or("从未活跃"),
        ));
    }

    brief.push_str("\n## 近期平台事件（最新 40 条）\n\n");
    if events.is_empty() {
        brief.push_str("（无事件）\n");
    }
    for e in events.iter().rev() {
        let ts = e.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let et = e.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
        let d = e.get("detail").and_then(|v| v.as_str()).unwrap_or("");
        brief.push_str(&format!("- {ts} [{et}] {d}\n"));
    }

    brief.push_str("\n## 个人记忆要点（换助手延续的上下文）\n\n");
    if memories.is_empty() {
        brief.push_str("（个人 NS 暂无可检索记忆）\n");
    }
    for m in &memories {
        let text = m
            .get("content")
            .or_else(|| m.get("text"))
            .or_else(|| m.get("memory"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if text.is_empty() {
            continue;
        }
        let snippet: String = text.chars().take(200).collect();
        brief.push_str(&format!("- {snippet}\n"));
    }

    brief.push_str("\n## 新助手开工指引\n\n");
    brief.push_str("1. 优先延续上方「个人记忆要点」中的偏好与结论；\n");
    brief.push_str("2. 历史助手的能力范围见绑定历史，接手时以用户最新授权为准；\n");
    brief.push_str("3. 本 brief 由 agent-core 生成并写入个人 NS，可随时请求用户重新生成。\n");

    // ── 写回个人 NS ──
    let mut stored = false;
    {
        let agent = {
            let guard = st.agent.lock().await;
            guard.as_ref().map(|a| a.clone())
        };
        if let Some(agent) = agent {
            let args = serde_json::json!({
                "namespace": namespace,
                "content": brief,
                "memory_type": "document",
                "category": "handover",
                "importance": 5,
                "source": "agent-core",
                "tags": ["handover-brief", "assistant:platform"],
            });
            match agent.mcp.call_json("memory_remember", &args).await {
                Ok(_) => stored = true,
                Err(message) => {
                    return err(
                        axum::http::StatusCode::BAD_GATEWAY,
                        "brief_store_failed",
                        &format!("写入 memoria 失败：{message}"),
                    )
                }
            }
        }
    }
    audit_platform(
        &st,
        "assistant.handover_brief.created",
        &user_id,
        None,
        &format!(
            "bindings={} events={} memories={} stored={stored}",
            bindings.len(),
            events.len(),
            memories.len()
        ),
    )
    .await;
    Json(serde_json::json!({
        "stored": stored,
        "namespace": namespace,
        "brief": brief,
    }))
    .into_response()
}

// ── Phase 2 P2-1：会议成员（助手 binding 入会 / 临时 scope） ───────────────
//
// D10a：仅会议 owner / 平台 admin 可邀请/移除助手（会议可见 ≠ 可管理）。
// D10b：临时 scope 独立存 meeting_members（不进持久 token scopes），会 end 批量失效。
// D10c：a2a task/message 带 meeting_id 时必须双方均为该会有效成员（见下方校验钩子）。

/// 邀请助手入会：POST /api/meetings/{id}/assistants  {binding_id}
/// 权限：badge 身份 = 会议 owner 或平台 admin；binding 必须 active。
pub(crate) async fn handle_meeting_assistant_invite(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Path(meeting_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let binding_id = req
        .get("binding_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if binding_id.is_empty() {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "binding_id_required",
            "缺少 binding_id",
        );
    }
    // 会议存在性 + owner 判定（agent 锁短作用域）
    let owner_ok = {
        let guard = st.agent.lock().await;
        match guard.as_ref() {
            None => {
                return err(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "agent_not_ready",
                    "服务尚未就绪",
                )
            }
            Some(agent) => match agent.get_meeting(&meeting_id) {
                None => {
                    return err(
                        axum::http::StatusCode::NOT_FOUND,
                        "meeting_not_found",
                        "会议不存在",
                    )
                }
                // 已结束的会议不可再邀请（临时 scope 生命周期与会议一致）
                Some(m) if m.status == "ended" || m.status == "done" => {
                    return err(
                        axum::http::StatusCode::BAD_REQUEST,
                        "meeting_ended",
                        "会议已结束，临时授权已失效",
                    )
                }
                Some(m) => m.owner_user_id == ctx.agent_id,
            },
        }
    };
    // D10a：owner 或平台 admin（admin 判定走 is_admin 需 headers，这里以 caller==owner
    // 为准；平台 admin 场景可用 admin 头直调同端点——is_admin 在此不可用因未传 headers，
    // 简化：owner-only。会议 scope 经理暂不开邀请权，Phase 2 试用后再议）
    if !owner_ok {
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "not_meeting_owner",
            "仅会议发起人可邀请助手",
        );
    }
    let binding = match st.assistant_platform.get_binding(&binding_id) {
        Ok(Some(b)) if b.status == "active" => b,
        Ok(Some(b)) => {
            return err(
                axum::http::StatusCode::BAD_REQUEST,
                "binding_not_active",
                &format!("binding 状态不可用: {}", b.status),
            )
        }
        Ok(None) => {
            return err(
                axum::http::StatusCode::NOT_FOUND,
                "binding_not_found",
                "binding 不存在",
            )
        }
        Err(message) => {
            return err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "binding_read_failed",
                &message,
            )
        }
    };
    if let Err(message) = st
        .assistant_platform
        .meeting_invite(&meeting_id, &binding, &ctx.agent_id)
    {
        return err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "meeting_invite_failed",
            &message,
        );
    }
    audit_platform(
        &st,
        "assistant.meeting.invited",
        &ctx.agent_id,
        Some(&binding.binding_id),
        &format!("meeting={meeting_id} binding={} type={}", binding.binding_id, binding.assistant_type),
    )
    .await;
    Json(serde_json::json!({
        "meeting_id": meeting_id,
        "binding_id": binding.binding_id,
        "scopes": crate::assistant_platform::AssistantPlatformStore::meeting_scopes(),
    }))
    .into_response()
}

/// 移除助手出会：DELETE 语义经 POST /api/meetings/{id}/assistants/remove {binding_id}
pub(crate) async fn handle_meeting_assistant_remove(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Path(meeting_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let binding_id = req
        .get("binding_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if binding_id.is_empty() {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "binding_id_required",
            "缺少 binding_id",
        );
    }
    let owner_ok = {
        let guard = st.agent.lock().await;
        match guard.as_ref() {
            None => {
                return err(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "agent_not_ready",
                    "服务尚未就绪",
                )
            }
            Some(agent) => agent
                .get_meeting(&meeting_id)
                .map(|m| m.owner_user_id == ctx.agent_id)
                .unwrap_or(false),
        }
    };
    if !owner_ok {
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "not_meeting_owner",
            "仅会议发起人可移除助手",
        );
    }
    match st
        .assistant_platform
        .meeting_remove(&meeting_id, &binding_id)
    {
        Ok(true) => {
            audit_platform(
                &st,
                "assistant.meeting.removed",
                &ctx.agent_id,
                Some(&binding_id),
                &format!("meeting={meeting_id} binding={binding_id}"),
            )
            .await;
            Json(serde_json::json!({"removed": true})).into_response()
        }
        Ok(false) => {
            return err(
                axum::http::StatusCode::NOT_FOUND,
                "member_not_found",
                "该助手不在此会议中",
            )
        }
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "meeting_remove_failed",
            &message,
        ),
    }
}

/// 会议助手成员列表：GET /api/meetings/{id}/assistants
/// 权限：会议可见者（owner/admin/scope 成员/公开）——复用 meeting_visible 判定。
#[derive(Deserialize)]
pub(crate) struct MeetingMembersQuery {
    #[serde(default)]
    pub(crate) token: Option<String>,
}

pub(crate) async fn handle_meeting_assistants_list(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Path(meeting_id): Path<String>,
) -> Response {
    // meeting_visible 返回 Option（None=agent 未就绪）；与会议模块同判：None→503
    let visible = {
        let guard = st.agent.lock().await;
        match guard.as_ref() {
            None => {
                return err(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "agent_not_ready",
                    "服务尚未就绪",
                )
            }
            Some(agent) => {
                agent.meeting_visible(&meeting_id, &ctx.agent_id, &ctx.allowed_ns, false)
            }
        }
    };
    if visible != Some(true) {
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "meeting_forbidden",
            "无权访问该会议",
        );
    }
    match st.assistant_platform.meeting_members(&meeting_id) {
        Ok(members) => {
            let list: Vec<serde_json::Value> = members
                .into_iter()
                .map(|(binding_id, user_id, invited_by, granted_at)| {
                    serde_json::json!({
                        "binding_id": binding_id,
                        "user_id": user_id,
                        "invited_by": invited_by,
                        "granted_at": granted_at,
                    })
                })
                .collect();
            Json(serde_json::json!({"meeting_id": meeting_id, "members": list})).into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "members_read_failed",
            &message,
        ),
    }
}

/// P2-1 校验钩子（D10c）：a2a task/message 带 meeting_id 时校验发送方与目标
/// 双方均为该会有效成员。无 meeting_id 维持 Phase 0 全局 a2a 语义。
/// 返回 Err(响应) = 校验失败；Ok(()) = 放行。
pub(crate) async fn a2a_meeting_check(
    st: &Arc<AppState>,
    from_binding: &str,
    to_binding: &str,
    meeting_id: Option<&str>,
) -> Result<(), Response> {
    let Some(meeting_id) = meeting_id else { return Ok(()) };
    // 会议必须存在且未结束（结束的会不允许再发）
    let meeting_alive = {
        let guard = st.agent.lock().await;
        match guard.as_ref() {
            None => false,
            Some(agent) => match agent.get_meeting(meeting_id) {
                None => false,
                Some(m) => m.status != "ended" && m.status != "done",
            },
        }
    };
    if !meeting_alive {
        return Err(err(
            axum::http::StatusCode::FORBIDDEN,
            "meeting_not_active",
            "会议不存在或已结束",
        ));
    }
    for b in [from_binding, to_binding] {
        match st.assistant_platform.meeting_is_member(meeting_id, b) {
            Ok(true) => {}
            Ok(false) => {
                return Err(err(
                    axum::http::StatusCode::FORBIDDEN,
                    "not_meeting_member",
                    &format!("binding 未获该会议授权: {b}"),
                ))
            }
            Err(message) => {
                return Err(err(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "member_check_failed",
                    &message,
                ))
            }
        }
    }
    Ok(())
}
