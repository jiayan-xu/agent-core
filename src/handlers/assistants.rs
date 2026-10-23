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
                event_type: AuditEventType::ToolInvocation,
                detail: format!("event={event_type} | {detail}"),
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
                event_type: AuditEventType::ToolInvocation,
                detail: format!("event={event_type} | {detail}"),
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
