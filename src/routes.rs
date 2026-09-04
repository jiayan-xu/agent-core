//! 路由装配（从 src/main.rs 拆出，P7 重构）。
//!
//! `build_router` 聚合全部 HTTP 路由：公开（豁免鉴权）+ 受保护（auth_middleware）+
//! CORS + trace 中间件。纯搬移 + `pub(crate)`，零行为变更（路由表与 handler 一一对应）。

use std::sync::Arc;

use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::cors::CorsLayer;

use crate::auth::auth_middleware;
use crate::bootstrap::trace_middleware;
use crate::handlers::admin::*;
use crate::handlers::gateway::{handle_auto_write_undo, handle_auto_writes_list, handle_tool_execute, handle_tool_execute_get};
use crate::handlers::approval::*;
use crate::handlers::chat::*;
use crate::handlers::collab::*;
use crate::handlers::evolve::*;
use crate::handlers::identity::*;
use crate::handlers::meetings::*;
use crate::handlers::system::*;
use crate::state::AppState;

/// 组装完整应用路由（公开 + 受保护 + CORS + trace）。
/// `state` 在最后 `.with_state` 被消费；auth_middleware 在组装前 clone。
pub(crate) fn build_router(state: Arc<AppState>, cors: CorsLayer) -> Router {
    let public = Router::new()
        .route("/", get(handle_index))
        .route("/logo.png", get(handle_logo))
        .route("/health", get(handle_health))
        .route("/api/config", get(handle_config))
        .route("/api/register", post(handle_register))
        .route("/api/register_user", post(handle_register_user))
        .route("/api/login", post(handle_login))
        .route("/api/approval/pending", get(handle_approval_pending))
        .route("/api/approval/history", get(handle_approval_history))
        .route("/api/approval/{id}/respond", post(handle_approval_respond))
        .route("/approval-console", get(handle_approval_console))
        .route("/api/ops/briefing", get(handle_ops_briefing))
        .route("/updates/pfaix/latest.json", get(handle_updates_latest))
        .route("/updates/pfaix/{file}", get(handle_updates_static))
        // /v1 别名：PFAiX 的 getAgentCoreBaseUrl() 返回带 /v1 的 base，
        // lanManifestUrl 直接拼接导致请求 /v1/updates/...——旧版客户端无法改，
        // 服务端同时挂别名兼容（review/修复：检查更新 401 根因）
        .route("/v1/updates/pfaix/latest.json", get(handle_updates_latest))
        .route("/v1/updates/pfaix/{file}", get(handle_updates_static));

    let protected = Router::new()
        .route("/api/chat", post(handle_chat))
        .route("/api/chat/stream", get(handle_chat_stream))
        .nest(
            "/api/sessions",
            Router::new()
                .route("/", get(handle_sessions))
                .route("/{id}", get(handle_session_load).delete(handle_session_delete)),
        )
        .route("/api/admin/degrade", get(handle_admin_degrade))
        .route("/api/admin/killswitch", post(handle_admin_killswitch))
        .route("/api/metrics", get(handle_metrics))
        .route(
            "/api/admin/quota",
            get(handle_admin_quota_get).put(handle_admin_quota_put),
        )
        .route("/api/admin/audit", get(handle_admin_audit))
        .route(
            "/api/admin/harness/activate",
            post(handle_admin_harness_activate),
        )
        .route("/api/admin/consolidate", post(handle_admin_consolidate))
        .route("/api/admin/consolidate_eval", post(handle_admin_consolidate_eval))
        .route("/api/admin/agent/repair", post(handle_agent_repair))
        .route("/api/agent/events", axum::routing::get(handle_agent_events))
        .route("/api/save-config", post(handle_save_config))
        .route("/api/collab/inbox", get(handle_collab_inbox))
        .route("/api/collab/send", post(handle_collab_send))
        .route("/api/collab/approval", post(handle_collab_approval))
        .route("/api/collab/delete", post(handle_collab_delete))
        .route("/api/collab/peers", get(handle_collab_peers))
        .route("/api/collab/profile", get(handle_collab_profile))
        .route("/api/memory/feedback", post(handle_memory_feedback))
        .route("/api/tool/execute", post(handle_tool_execute))
        .route("/api/tool/execute/{id}", get(handle_tool_execute_get))
        .route("/api/tool/auto-writes", get(handle_auto_writes_list))
        .route("/api/tool/auto-writes/{id}/undo", post(handle_auto_write_undo))
        .route("/v1/chat/completions", post(handle_v1_chat))
        .route("/api/persona", post(handle_persona_create).get(handle_persona_list))
        .route("/api/persona/{id}", delete(handle_persona_delete).get(handle_persona_get))
        .route("/api/persona/{id}/goal", post(handle_persona_goal_push))
        .route("/api/session/persona", post(handle_session_persona_bind))
        .route("/api/documents/archive", post(handle_documents_archive))
        .route("/api/roundtable", post(handle_panel_discuss))
        .route("/api/meetings", get(handle_meetings_list))
        .route("/api/meetings/{id}", delete(handle_meeting_delete))
        .route("/api/meetings/{id}/stream", get(handle_meeting_stream))
        .route("/api/meetings/{id}/heartbeat", post(handle_meeting_heartbeat))
        .route("/api/meetings/{id}/message", post(handle_meeting_message))
        .route("/api/meetings/{id}/end", post(handle_meeting_end))
        .route("/api/evolve", post(handle_code_evolve))
        .route("/api/meta-evolution/run", post(handle_meta_evolution_run))
        .route("/api/meta-evolution/status", get(handle_meta_evolution_status))
        .layer(from_fn_with_state(state.clone(), auth_middleware));

    public
        .merge(protected)
        .layer(cors)
        .layer(axum::middleware::from_fn(trace_middleware))
        .with_state(state)
}
