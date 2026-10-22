//! 服务编排 handler（P2，2026-10-22）。
//!
//! 端点：
//! - `GET  /api/services`         **公开**，精简状态（key/name/port/running/uptime）。
//!   托盘/看板必须能无凭据读取——这正是「托盘退化为纯面板」的前提；
//!   故只暴露端口与存活，不含 pid / last_error / fail_count（那些走 detail）。
//! - `GET  /api/services/detail`  受保护，完整状态（含 pid/错误/失败次数）。
//! - `POST /api/services/{key}/start|stop|restart`  受保护（能启停本机服务，高危）。
//! - `POST /api/services/tick`    受保护，手动跑一轮保活（运维/自检）。
//!
//! `enabled=false` 表示 `agent.toml` 没配 `[[services]]`，编排未启用；
//! 此时托盘仍是唯一管理者，行为与 P2 之前完全一致。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

/// 公开精简状态：只给「叫什么、在哪个端口、活着没、跑了多久」。
pub(crate) async fn handle_services_public(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let items: Vec<serde_json::Value> = state
        .services
        .status()
        .await
        .into_iter()
        .map(|s| {
            json!({
                "key": s.key,
                "name": s.name,
                "port": s.port,
                "running": s.running,
                "uptime_sec": s.uptime_sec,
                "restart": s.restart,
            })
        })
        .collect();
    Json(json!({
        "enabled": !state.services.is_empty(),
        "count": items.len(),
        "services": items,
    }))
}

/// 受保护完整状态：含 pid / managed_alive / last_error / fail_count。
pub(crate) async fn handle_services_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let items = state.services.status().await;
    Json(json!({
        "enabled": !state.services.is_empty(),
        "count": items.len(),
        "services": items,
    }))
}

pub(crate) async fn handle_service_start(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    match state.services.start(&key).await {
        Ok(m) => Json(json!({ "ok": true, "key": key, "message": m })),
        Err(e) => Json(json!({ "ok": false, "key": key, "message": e })),
    }
}

pub(crate) async fn handle_service_stop(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    match state.services.stop(&key).await {
        Ok(m) => Json(json!({ "ok": true, "key": key, "message": m })),
        Err(e) => Json(json!({ "ok": false, "key": key, "message": e })),
    }
}

pub(crate) async fn handle_service_restart(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    match state.services.restart(&key).await {
        Ok(m) => Json(json!({ "ok": true, "key": key, "message": m })),
        Err(e) => Json(json!({ "ok": false, "key": key, "message": e })),
    }
}

pub(crate) async fn handle_services_tick(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let actions = state.services.tick().await;
    Json(json!({ "ok": true, "actions": actions }))
}
