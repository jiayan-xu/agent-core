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
            // P2-2：会议域任务的动作摘要注入会议消息流（kind=ai 系统行，不推进 phase）。
            // 注入失败不回滚任务（任务已持久化）——仅告警；广播与落盘复用会议模块模式。
            if let Some(meeting_id) = req.meeting_id.clone() {
                let summary = format!(
                    "🤖 [{}] 发起任务（{}）：{}",
                    auth.assistant_type, task.task_type, task.subject
                );
                let injected = {
                    let guard = st.agent.lock().await;
                    match guard.as_ref() {
                        Some(agent) => {
                            let agent_arc = agent.clone();
                            agent_arc
                                .add_meeting_system_line(
                                    &meeting_id,
                                    &format!("assistant:{}", auth.assistant_type),
                                    &summary,
                                )
                                .map(|msg| (agent_arc, msg))
                        }
                        None => Err("agent 未就绪".to_string()),
                    }
                };
                match injected {
                    Ok((agent_arc, msg)) => {
                        crate::handlers::meetings::broadcast_meeting_event(
                            &st,
                            &meeting_id,
                            agent_core::agent::EventKind::Message,
                            serde_json::json!({ "message": msg }),
                        )
                        .await;
                        tokio::spawn(async move {
                            crate::handlers::meetings::persist_meetings_for(&agent_arc, |e| {
                                tracing::error!(error = %e, meeting = %meeting_id, "P2-2: 助手动作行落盘失败");
                            })
                            .await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(meeting = %meeting_id, error = %e, "P2-2: 助手任务摘要注入会议流失败（任务本身不受影响）");
                    }
                }
            }
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
            // P2-2：会议域任务的终态（completed/failed/canceled）摘要注入会议流
            if matches!(task.status.as_str(), "completed" | "failed" | "canceled") {
                if let Some(meeting_id) = task.meeting_id.clone() {
                    let summary = format!(
                        "🤖 [{}] 任务 {} → {}{}",
                        auth.assistant_type,
                        task.task_id,
                        task.status,
                        task.result
                            .as_deref()
                            .map(|r| format!("：{}", r.chars().take(120).collect::<String>()))
                            .unwrap_or_default()
                    );
                    let injected = {
                        let guard = st.agent.lock().await;
                        match guard.as_ref() {
                            Some(agent) => {
                                let agent_arc = agent.clone();
                                agent_arc
                                    .add_meeting_system_line(
                                        &meeting_id,
                                        &format!("assistant:{}", auth.assistant_type),
                                        &summary,
                                    )
                                    .map(|msg| (agent_arc, msg))
                            }
                            None => Err("agent 未就绪".to_string()),
                        }
                    };
                    if let Ok((agent_arc, msg)) = injected {
                        crate::handlers::meetings::broadcast_meeting_event(
                            &st,
                            &meeting_id,
                            agent_core::agent::EventKind::Message,
                            serde_json::json!({ "message": msg }),
                        )
                        .await;
                        tokio::spawn(async move {
                            crate::handlers::meetings::persist_meetings_for(&agent_arc, |e| {
                                tracing::error!(error = %e, meeting = %meeting_id, "P2-2: 助手终态行落盘失败");
                            })
                            .await;
                        });
                    }
                }
            }
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

/// PUT /api/assistants/bindings/{id}/scopes（受保护，binding 属主本人）——
/// 升级/收紧 binding scopes（白名单内；含 tools:call:read/write 等 P4 scope）。
pub(crate) async fn handle_assistant_binding_scopes(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Path(binding_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let Some(scopes): Option<Vec<String>> = req
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
    else {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "scopes_required",
            "缺少 scopes 数组",
        );
    };
    // 属主校验：binding.user_id 必须 == caller
    match st.assistant_platform.get_binding(&binding_id) {
        Ok(Some(b)) if b.user_id == ctx.agent_id => {}
        Ok(Some(_)) => {
            return err(
                axum::http::StatusCode::FORBIDDEN,
                "not_owner",
                "仅 binding 属主可修改 scopes",
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
    }
    match st
        .assistant_platform
        .update_binding_scopes(&binding_id, &scopes)
    {
        Ok(binding) => {
            audit_platform(
                &st,
                "assistant.binding.scopes_changed",
                &ctx.agent_id,
                Some(&binding_id),
                &format!("scopes={}", binding.scopes.join(",")),
            )
            .await;
            Json(serde_json::json!({"binding": binding})).into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "scopes_update_failed",
            &message,
        ),
    }
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

// ── Phase 2 P2-2：会前 brief（方案 §7.3） ──────────────────────────────────
//
// 参会人 + 主题 + 授权 → 会议简报：项目 NS 共享上下文 + 参会人偏好摘要，
// 写入组织 NS（tag=meeting-brief:<id>），入会助手经 Memory Proxy 的 context
// 语义可检索（简报在 org NS，Phase 0 context 只读个人 NS——故同时给 owner
// 个人 NS 落一份摘要副本，简报正文以 org 为准）。
// 边界（§7.3）：不暴露个人隐私记忆（偏好检索只取 preference 类），不暴露
// 未授权项目数据（项目上下文仅检索 org ns 已有内容）。

pub(crate) async fn handle_meeting_brief(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Path(meeting_id): Path<String>,
) -> Response {
    // 权限：会议可见者可生成（owner/admin/scope 成员/公开——与成员列表同判定）
    let (visible, meeting_info) = {
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
                let v = agent.meeting_visible(&meeting_id, &ctx.agent_id, &ctx.allowed_ns, false);
                let info = agent.get_meeting(&meeting_id).map(|m| {
                    (m.topic.clone(), m.owner_user_id.clone())
                });
                (v, info)
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
    let Some((topic, owner)) = meeting_info else {
        return err(
            axum::http::StatusCode::NOT_FOUND,
            "meeting_not_found",
            "会议不存在",
        );
    };

    // 入会助手（含其主人 user_id 去重）
    let members = st
        .assistant_platform
        .meeting_members(&meeting_id)
        .unwrap_or_default();
    let mut member_users: Vec<String> = members
        .iter()
        .map(|(_, user, _, _)| user.clone())
        .collect();
    member_users.push(owner.clone());
    member_users.sort();
    member_users.dedup();

    let agent = {
        let guard = st.agent.lock().await;
        guard.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
        return err(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            "服务尚未就绪",
        );
    };

    // 项目共享上下文：固废项目 org ns（Phase 2 单项目试点；多项目授权待 Phase 4）
    let org_ns = "org/cs-pufa-2nd-thermal/proj/gufei";
    let mut project_ctx: Vec<String> = Vec::new();
    if let Ok(v) = agent
        .mcp
        .call_json(
            "memory_search_v2",
            &serde_json::json!({"namespace": org_ns, "query": &topic, "limit": 8}),
        )
        .await
    {
        if let Some(items) = v.get("results").and_then(|r| r.as_array()) {
            for it in items {
                let t = it
                    .get("content")
                    .or_else(|| it.get("text"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                if !t.is_empty() {
                    project_ctx.push(t.chars().take(160).collect());
                }
            }
        }
    }

    // 参会人偏好摘要：每人个人 NS，只取 preference/偏好类（§7.3 边界）
    let mut prefs: Vec<String> = Vec::new();
    for u in &member_users {
        if let Ok(v) = agent
            .mcp
            .call_json(
                "memory_search_v2",
                &serde_json::json!({
                    "namespace": format!("agent/{u}"),
                    "query": "工作偏好 呈现方式 关注点",
                    "limit": 3,
                }),
            )
            .await
        {
            if let Some(items) = v.get("results").and_then(|r| r.as_array()) {
                for it in items {
                    let t = it
                        .get("content")
                        .or_else(|| it.get("text"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    if !t.is_empty() {
                        prefs.push(format!("- {u}：{}", t.chars().take(120).collect::<String>()));
                    }
                }
            }
        }
    }

    // 组装 brief
    let mut brief = String::new();
    brief.push_str("# 会前 Brief\n\n");
    brief.push_str(&format!(
        "会议：{topic}\n会议 ID：{meeting_id}\n生成时间：{}\n参会助手主人：{}\n\n",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        member_users.join("、")
    ));
    brief.push_str("## 项目共享上下文\n\n");
    if project_ctx.is_empty() {
        brief.push_str("（项目 NS 暂无相关上下文）\n");
    } else {
        for c in &project_ctx {
            brief.push_str(&format!("- {c}\n"));
        }
    }
    brief.push_str("\n## 参会人偏好摘要\n\n");
    if prefs.is_empty() {
        brief.push_str("（暂无偏好记录）\n");
    } else {
        for p in &prefs {
            brief.push_str(&format!("{p}\n"));
        }
    }
    brief.push_str("\n## 边界\n- 本 brief 仅含项目共享上下文与偏好级摘要，不含个人隐私记忆；\n- 未授权项目数据不在范围内。\n");

    // 写入 org NS（权威）+ owner 个人 NS（摘要副本，入会助手 context 可检索）
    let mut stored_org = false;
    let org_args = serde_json::json!({
        "namespace": org_ns,
        "content": &brief,
        "memory_type": "document",
        "category": "meeting-brief",
        "importance": 4,
        "source": "agent-core",
        "tags": [format!("meeting-brief:{meeting_id}"), "assistant:platform"],
    });
    if agent.mcp.call_json("memory_remember", &org_args).await.is_ok() {
        stored_org = true;
    }
    let owner_copy = format!("# 会前 Brief（副本，正文以项目 NS 为准）\n\n{}", brief);
    let owner_args = serde_json::json!({
        "namespace": format!("agent/{owner}"),
        "content": owner_copy,
        "memory_type": "document",
        "category": "meeting-brief",
        "importance": 3,
        "source": "agent-core",
        "tags": [format!("meeting-brief:{meeting_id}")],
    });
    let mut stored_owner = false;
    if agent.mcp.call_json("memory_remember", &owner_args).await.is_ok() {
        stored_owner = true;
    }

    audit_platform(
        &st,
        "assistant.meeting_brief.created",
        &ctx.agent_id,
        None,
        &format!(
            "meeting={meeting_id} members={} project_ctx={} prefs={} org_stored={stored_org}",
            member_users.len(),
            project_ctx.len(),
            prefs.len()
        ),
    )
    .await;
    Json(serde_json::json!({
        "meeting_id": meeting_id,
        "org_namespace": org_ns,
        "stored": stored_org,
        "owner_copy_stored": stored_owner,
        "brief": brief,
    }))
    .into_response()
}

// ── Phase 2 P2-3：inbox SSE 推送 ───────────────────────────────────────────
//
// GET /api/a2a/inbox/stream?since_id=N（assistant token 鉴权，a2a:receive）。
// 服务发送事件：event=message data={...含 last_id}；30s 心跳 comment 保活；
// 连接保持直至客户端断开或 token 失效（每轮推送前静默校验，失效即关流——
// 撤销/binding 吊销即时生效）。实现取简：DB 增量轮询（2s）而非常驻通道——
// Phase 0/2 消息量级（单机百级）下轮询足够，避免为 inbox 再建一套 broadcast
// 注册表。升级路径：消息量起来后换成 meeting_tx 同款 per-binding channel。

#[derive(Deserialize)]
pub(crate) struct InboxStreamQuery {
    #[serde(default)]
    pub(crate) since_id: Option<i64>,
}

pub(crate) async fn handle_a2a_inbox_stream(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<InboxStreamQuery>,
) -> Response {
    // 鉴权：assistant token（同 inbox 拉取）——token 原文在流期间不重验签名
    // （hash 查表即验），但每轮推送前复核有效性（撤销即时断流）。
    let token = bearer_token(&headers);
    let auth = match st
        .assistant_platform
        .validate_token(&token, "a2a:receive")
    {
        Ok(v) => v,
        Err(message) => {
            return err(
                axum::http::StatusCode::UNAUTHORIZED,
                "assistant_unauthorized",
                &message,
            )
        }
    };
    let mut last_id = q.since_id.unwrap_or(0);
    // 未指定 since_id：从当前最大 id 起推（只推新消息，历史走 /api/a2a/inbox 拉取）
    if q.since_id.is_none() {
        if let Ok(items) = st.assistant_platform.inbox_since(&auth.binding_id, i64::MAX - 1) {
            if let Some((max, _)) = items.last() {
                last_id = *max;
            }
        }
    }

    use axum::response::sse::{Event, KeepAlive, Sse};
    use std::convert::Infallible;
    use tokio_stream::wrappers::ReceiverStream;

    let st2 = st.clone();
    let binding_id = auth.binding_id.clone();
    let token_for_recheck = token.clone();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(32);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = keepalive.tick() => {
                    // SSE comment 保活（不产生客户端事件）
                    if tx.send(Ok(Event::default().comment("keepalive"))).await.is_err() {
                        break;
                    }
                    // 保活时顺带复核 token 有效性（撤销即时断流）
                    if st2
                        .assistant_platform
                        .validate_token(&token_for_recheck, "a2a:receive")
                        .is_err()
                    {
                        let _ = tx.send(Ok(Event::default().event("revoked").data("token revoked"))).await;
                        break;
                    }
                }
                _ = tick.tick() => {
                    match st2.assistant_platform.inbox_since(&binding_id, last_id) {
                        Ok(items) => {
                            for (id, msg) in items {
                                last_id = last_id.max(id);
                                let payload = serde_json::json!({"last_id": id, "message": msg});
                                let evt = Event::default().event("message").data(payload.to_string());
                                if tx.send(Ok(evt)).await.is_err() {
                                    return; // 客户端断开
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(binding = %binding_id, error = %e, "P2-3 inbox stream 增量查询失败");
                        }
                    }
                }
            }
        }
    });

    Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── Phase 3：artifact（方案 §8.3 / D8=本地受控目录+元数据+hash） ────────────
//
// POST /api/a2a/artifacts?task_id=&type=&title=  body=原始字节（a2a:send）
//   会议域（带 meeting_id 的 task）自动校验发送方为任务方+会议成员；
//   大小上限 50MB；返回 artifact 引用（消息里传引用不传本体）。
// GET  /api/a2a/artifacts/{id}          元数据（from/to 双方可见）
// GET  /api/a2a/artifacts/{id}/content  内容下载（读取时复核 sha256）
// GET  /api/a2a/artifacts?task_id=      任务 artifact 列表（任务方可见）

#[derive(Deserialize)]
pub(crate) struct ArtifactUploadQuery {
    #[serde(default)]
    pub(crate) task_id: Option<String>,
    #[serde(default)]
    pub(crate) art_type: Option<String>,
    #[serde(default)]
    pub(crate) title: Option<String>,
    #[serde(default)]
    pub(crate) meeting_id: Option<String>,
}

pub(crate) async fn handle_artifact_upload(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ArtifactUploadQuery>,
    body: axum::body::Bytes,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:send").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // 关联 task 时：task 必须存在且发送方是任务一方；task 的对方即 artifact 接收方
    let mut to_binding = String::new();
    let mut meeting_id = q.meeting_id.clone();
    let mut task_id = q.task_id.clone();
    if let Some(tid) = task_id.clone() {
        match st.assistant_platform.get_task(&tid) {
            Ok(Some(task))
                if task.from_binding == auth.binding_id
                    || task.to_binding == auth.binding_id =>
            {
                to_binding = if task.from_binding == auth.binding_id {
                    task.to_binding.clone()
                } else {
                    task.from_binding.clone()
                };
                meeting_id = meeting_id.or_else(|| task.meeting_id.clone());
            }
            Ok(Some(_)) => {
                return err(
                    axum::http::StatusCode::FORBIDDEN,
                    "task_forbidden",
                    "无权为该任务上传 artifact",
                )
            }
            Ok(None) => {
                return err(
                    axum::http::StatusCode::NOT_FOUND,
                    "task_not_found",
                    "task 不存在",
                )
            }
            Err(message) => {
                return err(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "task_read_failed",
                    &message,
                )
            }
        }
    } else if meeting_id.is_none() {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "task_or_meeting_required",
            "artifact 须关联 task_id 或 meeting_id",
        );
    }
    // 会议域校验（D10c 同源逻辑）：带 meeting_id 时发送方须为会议成员
    if let Some(mid) = meeting_id.as_deref() {
        match st
            .assistant_platform
            .meeting_is_member(mid, &auth.binding_id)
        {
            Ok(true) => {}
            Ok(false) => {
                return err(
                    axum::http::StatusCode::FORBIDDEN,
                    "not_meeting_member",
                    "binding 未获该会议授权",
                )
            }
            Err(message) => {
                return err(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "member_check_failed",
                    &message,
                )
            }
        }
    }
    // 无 task 时接收方须显式给出（query to_binding）
    if to_binding.is_empty() {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "target_required",
            "关联 task 或显式提供接收方",
        );
    }
    let art_type = q.art_type.clone().unwrap_or_else(|| "bin".to_string());
    let title = q
        .title
        .clone()
        .unwrap_or_else(|| format!("artifact-{}", Local::now().format("%Y%m%d%H%M%S")));
    match st.assistant_platform.save_artifact(
        &auth.binding_id,
        &to_binding,
        meeting_id.as_deref(),
        task_id.as_deref(),
        &art_type,
        &title,
        &body,
    ) {
        Ok((artifact_id, sha, size)) => {
            audit_platform(
                &st,
                "a2a.artifact.created",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!(
                    "artifact={artifact_id} task={:?} meeting={:?} type={art_type} size={size} sha256={}",
                    task_id.as_deref().unwrap_or("-"),
                    meeting_id.as_deref().unwrap_or("-"),
                    &sha[..16]
                ),
            )
            .await;
            // §8.3 引用形态返回：消息里只传这个，不传本体
            (
                axum::http::StatusCode::CREATED,
                Json(serde_json::json!({
                    "artifact": {
                        "artifact_id": artifact_id,
                        "type": art_type,
                        "title": title,
                        "sha256": sha,
                        "size": size,
                        "uri": format!("artifact://{artifact_id}"),
                    }
                })),
            )
                .into_response()
        }
        Err(message) => err(
            axum::http::StatusCode::BAD_REQUEST,
            "artifact_save_failed",
            &message,
        ),
    }
}

fn artifact_access_allowed(
    st: &Arc<AppState>,
    artifact: &crate::assistant_platform::Artifact,
    binding_id: &str,
) -> bool {
    artifact.from_binding == binding_id || artifact.to_binding == binding_id
    // 生命周期随 task/binding 撤销即不可再访问新上传；已存 artifact 保留（审计不删）
}

pub(crate) async fn handle_artifact_get(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(artifact_id): Path<String>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:receive").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match st.assistant_platform.get_artifact(&artifact_id) {
        Ok(Some(art)) if artifact_access_allowed(&st, &art, &auth.binding_id) => {
            Json(serde_json::json!({"artifact": art})).into_response()
        }
        Ok(Some(_)) => err(
            axum::http::StatusCode::FORBIDDEN,
            "artifact_forbidden",
            "无权读取该 artifact",
        ),
        Ok(None) => err(
            axum::http::StatusCode::NOT_FOUND,
            "artifact_not_found",
            "artifact 不存在",
        ),
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "artifact_read_failed",
            &message,
        ),
    }
}

pub(crate) async fn handle_artifact_content(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(artifact_id): Path<String>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:receive").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let art = match st.assistant_platform.get_artifact(&artifact_id) {
        Ok(Some(a)) => a,
        Ok(None) => {
            return err(
                axum::http::StatusCode::NOT_FOUND,
                "artifact_not_found",
                "artifact 不存在",
            )
        }
        Err(message) => {
            return err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "artifact_read_failed",
                &message,
            )
        }
    };
    if !artifact_access_allowed(&st, &art, &auth.binding_id) {
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "artifact_forbidden",
            "无权读取该 artifact",
        );
    }
    match st.assistant_platform.read_artifact_content(&artifact_id) {
        Ok(Some(data)) => {
            audit_platform(
                &st,
                "a2a.artifact.downloaded",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("artifact={artifact_id} bytes={}", data.len()),
            )
            .await;
            (
                [
                    (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        Box::leak(format!("attachment; filename=\"{artifact_id}.{}\"",
                            if art.art_type.is_empty() { "bin" } else { &art.art_type }).into_boxed_str()) as &str,
                    ),
                ],
                data,
            )
                .into_response()
        }
        Ok(None) => err(
            axum::http::StatusCode::NOT_FOUND,
            "artifact_not_found",
            "artifact 不存在",
        ),
        Err(message) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "artifact_content_failed",
            &message,
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct ArtifactListQuery {
    #[serde(default)]
    pub(crate) task_id: Option<String>,
}

// ── Phase 4：MCP 工具代理（方案 §9.3 Resource Gateway） ────────────────────
//
// POST /api/agent/tools/call  {tool, arguments}（scope tools:call:read）
// 六步链（§9.3）：scope 校验 → 工具分级 → （P4-2 审批位）→ MCP 调用 →
// 审计 → 返回。第一版防线：
//   ① 白名单：仅平台只读数据工具（数据管道状态/覆盖/新鲜度等）；
//   ② is_read_only_tool 复核（boundary 权威分级，白名单与分级双保险）；
//   写/未知工具一律 403+审计（危险工具审批管线属 P4-2）。
// 限流：每 binding 每日 500 次（内存计数，重启清零——超额审计已有持久记录）。

/// 助手可调的白名单工具（只读、平台数据类；逐个开放而非全量放行）。
const ASSISTANT_TOOLS_READONLY: &[&str] = &[
    // 数据管道（hhv-model pipeline MCP）
    "pipeline_status",
    "coverage_query",
    // memoria 只读健康/统计（不涉个人内容检索——那是 memory:read:self 的边界）
    "memory_health",
    "system_status",
];

/// P4-2：写工具白名单（经审批管线执行，approver=助手主人；逐个开放）。
const ASSISTANT_TOOLS_WRITABLE: &[&str] = &[
    // officecli 文档创建（PPT/文档生成场景）
    "officecli_create",
];

/// P4 限流：binding → (日期, 次数)。进程内计数（重启清零可接受：超额走审计追责）。
async fn tool_quota_take(st: &Arc<AppState>, binding_id: &str) -> Result<(), usize> {
    const DAILY_LIMIT: usize = 500;
    let today = Local::now().format("%Y-%m-%d").to_string();
    let mut map = st.assistant_tool_quota.lock().await;
    let entry = map.entry(binding_id.to_string()).or_insert((today.clone(), 0usize));
    if entry.0 != today {
        *entry = (today.clone(), 0);
    }
    if entry.1 >= DAILY_LIMIT {
        return Err(entry.1);
    }
    entry.1 += 1;
    Ok(())
}

#[derive(Deserialize)]
pub(crate) struct ToolCallRequest {
    tool: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

pub(crate) async fn handle_agent_tools_call(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ToolCallRequest>,
) -> Response {
    // P4-2 路由：按工具白名单决定读/写路径（写路径校验 tools:call:write）
    let tool_pre = req.tool.trim().to_lowercase();
    if ASSISTANT_TOOLS_WRITABLE.contains(&tool_pre.as_str()) {
        return handle_agent_tools_call_write(st, headers, req).await;
    }
    let auth = match assistant_auth(&st, &headers, "tools:call:read").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let tool = req.tool.trim().to_lowercase();
    // 防线①：白名单
    if !ASSISTANT_TOOLS_READONLY.contains(&tool.as_str()) {
        audit_platform(
            &st,
            "agent.tool.denied",
            &auth.user_id,
            Some(&auth.binding_id),
            &format!("tool={tool} reason=not_in_whitelist"),
        )
        .await;
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "tool_not_allowed",
            &format!("工具不在助手白名单: {tool}"),
        );
    }
    // 防线②：boundary 分级复核（白名单工具也必须是只读类）
    if !agent_core::boundary::is_read_only_tool(&tool) {
        audit_platform(
            &st,
            "agent.tool.denied",
            &auth.user_id,
            Some(&auth.binding_id),
            &format!("tool={tool} reason=not_read_only_class"),
        )
        .await;
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "tool_not_allowed",
            &format!("工具未通过只读分级: {tool}"),
        );
    }
    // 限流（P4 任务 3）
    if let Err(used) = tool_quota_take(&st, &auth.binding_id).await {
        audit_platform(
            &st,
            "agent.tool.rate_limited",
            &auth.user_id,
            Some(&auth.binding_id),
            &format!("tool={tool} used={used}"),
        )
        .await;
        return err(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "quota_exceeded",
            "每日工具调用配额已用尽",
        );
    }
    let agent = {
        let guard = st.agent.lock().await;
        guard.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
        return err(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            "服务尚未就绪",
        );
    };
    let args_obj = if req.arguments.is_null() {
        serde_json::json!({})
    } else {
        req.arguments.clone()
    };
    // 多源路由（按 tools/list 定位工具所在 source）——不能直打 agent.mcp：
    // 那是 memoria 专用客户端，平台工具（pipeline 等）会被送进 memoria 报
    // "Unknown tool"（2026-10-25 演示实测发现的 P4-1 路由 bug）
    let client = agent.find_mcp_for_tool_async(&tool).await;
    match client.call_json(&tool, &args_obj).await {
        Ok(result) => {
            audit_platform(
                &st,
                "agent.tool.called",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("tool={tool}"),
            )
            .await;
            Json(serde_json::json!({"tool": tool, "result": result})).into_response()
        }
        Err(message) => {
            audit_platform(
                &st,
                "agent.tool.failed",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("tool={tool} error={message}"),
            )
            .await;
            err(
                axum::http::StatusCode::BAD_GATEWAY,
                "tool_call_failed",
                &message,
            )
        }
    }
}

/// 助手可用工具清单（发现端点，配 tools/call 用）。
pub(crate) async fn handle_agent_tools_list(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = assistant_auth(&st, &headers, "tools:call:read").await {
        return resp;
    }
    Json(serde_json::json!({
        "tools": ASSISTANT_TOOLS_READONLY,
        "writable_tools": ASSISTANT_TOOLS_WRITABLE,
        "daily_quota": 500,
    }))
    .into_response()
}

// ── P4-2：写工具审批流（方案 §9.3 步骤 3「必要时审批」） ──────────────────
//
// POST /api/agent/tools/call（写白名单工具 + tools:call:write scope）：
//   不直接执行——建审批单（approver=助手主人 user_id，requester=binding_id，
//   operation_hash 防偷换），202 返回 approval_id/operation_hash；
//   主人经审批台（现有 /api/approval/* 链路）批准或拒绝。
// GET /api/agent/tools/approvals/{id}：助手轮询——
//   pending → 202；denied → 403；approved → 校验防重放后执行工具并返回结果。
// 防重放：执行成功即写 assistant_events（agent.tool.executed approval_id=…），
//   后续同 approval_id 的执行请求查到该事件即 409 拒绝。

pub(crate) async fn handle_agent_tools_call_write(
    st: Arc<AppState>,
    headers: HeaderMap,
    req: ToolCallRequest,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "tools:call:write").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let tool = req.tool.trim().to_lowercase();
    if !ASSISTANT_TOOLS_WRITABLE.contains(&tool.as_str()) {
        audit_platform(
            &st,
            "agent.tool.denied",
            &auth.user_id,
            Some(&auth.binding_id),
            &format!("tool={tool} reason=not_in_write_whitelist"),
        )
        .await;
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "tool_not_allowed",
            &format!("工具不在助手写白名单: {tool}"),
        );
    }
    if agent_core::boundary::is_read_only_tool(&tool) {
        // 写白名单与分级矛盾——防御性拒绝（白名单配置错误时兜底）
        audit_platform(
            &st,
            "agent.tool.denied",
            &auth.user_id,
            Some(&auth.binding_id),
            &format!("tool={tool} reason=write_tool_classified_read"),
        )
        .await;
        return err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "whitelist_conflict",
            "写白名单与工具分级冲突（配置错误）",
        );
    }
    // 限流同读路径
    if let Err(used) = tool_quota_take(&st, &auth.binding_id).await {
        audit_platform(
            &st,
            "agent.tool.rate_limited",
            &auth.user_id,
            Some(&auth.binding_id),
            &format!("tool={tool} used={used}"),
        )
        .await;
        return err(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "quota_exceeded",
            "每日工具调用配额已用尽",
        );
    }
    let agent = {
        let guard = st.agent.lock().await;
        guard.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
        return err(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            "服务尚未就绪",
        );
    };
    let args_obj = if req.arguments.is_null() {
        serde_json::json!({})
    } else {
        req.arguments.clone()
    };
    let desc = format!(
        "助手 {}（{}）请求写工具 {}",
        auth.assistant_type, auth.user_id, tool
    );
    // 审批单：approver=主人（admin 审批台/dashboard-admin 可响应）；session=binding
    let approval_id = agent
        .approval_manager
        .create_request_for_session(
            &tool,
            &args_obj,
            &desc,
            &auth.user_id,
            &auth.binding_id,
            &auth.binding_id,
            None,
            None,
        )
        .await;
    // 回传 operation_hash 供审批台回显（防偷换），助手侧不需要
    let op_hash = agent
        .approval_manager
        .get_pending(&approval_id)
        .await
        .map(|p| p.operation_hash)
        .unwrap_or_default();
    audit_platform(
        &st,
        "agent.tool.approval_requested",
        &auth.user_id,
        Some(&auth.binding_id),
        &format!("tool={tool} approval={approval_id}"),
    )
    .await;
    (
        axum::http::StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "approval_pending",
            "approval_id": approval_id,
            "operation_hash": op_hash,
            "poll": format!("/api/agent/tools/approvals/{approval_id}"),
        })),
    )
        .into_response()
}

pub(crate) async fn handle_agent_tool_approval_poll(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(approval_id): Path<String>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "tools:call:write").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let agent = {
        let guard = st.agent.lock().await;
        guard.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
        return err(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            "服务尚未就绪",
        );
    };
    // 单属校验：审批单 requester 必须是本 binding
    let pending = agent.approval_manager.get_pending(&approval_id).await;
    let Some(p) = pending else {
        return err(
            axum::http::StatusCode::NOT_FOUND,
            "approval_not_found",
            "审批单不存在或已终结",
        );
    };
    if p.requester_id != auth.binding_id {
        return err(
            axum::http::StatusCode::FORBIDDEN,
            "approval_forbidden",
            "无权访问该审批单",
        );
    }
    match agent.approval_manager.is_approved(&approval_id).await {
        None => (
            axum::http::StatusCode::ACCEPTED,
            Json(serde_json::json!({"status": "pending"})),
        )
            .into_response(),
        Some(false) => {
            audit_platform(
                &st,
                "agent.tool.approval_denied",
                &auth.user_id,
                Some(&auth.binding_id),
                &format!("approval={approval_id} tool={}", p.tool_name),
            )
            .await;
            err(
                axum::http::StatusCode::FORBIDDEN,
                "approval_denied",
                "审批已拒绝",
            )
        }
        Some(true) => {
            // 防重放：同 approval_id 已执行过 → 409
            let executed_marker = format!("approval_id={approval_id}");
            let already = st
                .assistant_platform
                .recent_events_for_user(&auth.user_id, 100)
                .unwrap_or_default()
                .into_iter()
                .any(|e| {
                    e.get("event_type").and_then(|v| v.as_str()) == Some("agent.tool.executed")
                        && str::contains(
                            &e.get("detail").and_then(|v| v.as_str()).unwrap_or(""),
                            &executed_marker,
                        )
                });
            if already {
                return err(
                    axum::http::StatusCode::CONFLICT,
                    "already_executed",
                    "该审批已执行过（单次有效）",
                );
            }
            // 执行工具（多源路由，同 tools/call 读路径——见该处注释）
            let client = agent.find_mcp_for_tool_async(&p.tool_name).await;
            match client.call_json(&p.tool_name, &p.arguments).await {
                Ok(result) => {
                    audit_platform(
                        &st,
                        "agent.tool.executed",
                        &auth.user_id,
                        Some(&auth.binding_id),
                        &format!("tool={} approval_id={approval_id}", p.tool_name),
                    )
                    .await;
                    Json(serde_json::json!({
                        "status": "executed",
                        "tool": p.tool_name,
                        "result": result,
                    }))
                    .into_response()
                }
                Err(message) => {
                    audit_platform(
                        &st,
                        "agent.tool.failed",
                        &auth.user_id,
                        Some(&auth.binding_id),
                        &format!("tool={} approval_id={approval_id} error={message}", p.tool_name),
                    )
                    .await;
                    err(
                        axum::http::StatusCode::BAD_GATEWAY,
                        "tool_call_failed",
                        &message,
                    )
                }
            }
        }
    }
}

pub(crate) async fn handle_artifact_list(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ArtifactListQuery>,
) -> Response {
    let auth = match assistant_auth(&st, &headers, "a2a:receive").await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let Some(task_id) = q.task_id else {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "task_id_required",
            "须按 task_id 查询",
        );
    };
    // 权限：请求方须为任务一方
    match st.assistant_platform.get_task(&task_id) {
        Ok(Some(task))
            if task.from_binding == auth.binding_id || task.to_binding == auth.binding_id =>
        {
            match st.assistant_platform.artifacts_for_task(&task_id) {
                Ok(list) => Json(serde_json::json!({"artifacts": list})).into_response(),
                Err(message) => err(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "artifacts_read_failed",
                    &message,
                ),
            }
        }
        Ok(Some(_)) => err(
            axum::http::StatusCode::FORBIDDEN,
            "task_forbidden",
            "无权读取该任务的 artifacts",
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
