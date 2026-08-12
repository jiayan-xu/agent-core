//! 系统 handler（从 src/main.rs 拆出，P6 重构）。
//!
//! 承载：静态壳 index/logo/updates、health、agent 事件、config 读写、metrics。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;


use crate::auth::{authenticate, unauthorized};
use crate::handlers::identity::build_agent;
use crate::config::{resolve_config_for_runtime, save_config};
use crate::handlers::chat::{SetupRequest, SetupResponse};
use crate::state::{AppState, BackgroundEvent};

pub(crate) async fn handle_index() -> impl axum::response::IntoResponse {
    axum::response::Html(include_str!("../chat.html"))
}

pub(crate) async fn handle_logo() -> impl axum::response::IntoResponse {
    // 仅用相对/工作目录解析，避免硬编码绝对路径（P2-1 修复）
    let cwd = std::env::current_dir().unwrap_or_default();
    for path in &[
        cwd.join("logo.png"),
        cwd.join("static").join("logo.png"),
        cwd.join("assets").join("logo.png"),
    ] {
        if let Ok(data) = tokio::fs::read(path).await {
            return ([(axum::http::header::CONTENT_TYPE, "image/png")], data);
        }
    }
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        "logo not found".into(),
    )
}

/// PFAiX 局域网升级：静态目录根，默认在 agent-core.exe 同目录下 `updates/pfaix/`。
/// 允许通过 PFAIX_UPDATES_DIR 环境变量覆盖。
pub(crate) fn pfaix_updates_dir() -> std::path::PathBuf {
    std::env::var("PFAIX_UPDATES_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("updates")
                .join("pfaix")
        })
}

/// 返回当前最新版本的 manifest；若目录下没有放置 latest.json 则返回 404。
pub(crate) async fn handle_updates_latest() -> impl axum::response::IntoResponse {
    let path = pfaix_updates_dir().join("latest.json");
    match tokio::fs::read(&path).await {
        Ok(data) => (
            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
            data,
        )
            .into_response(),
        Err(_) => (axum::http::StatusCode::NOT_FOUND, "no update manifest").into_response(),
    }
}

/// 下载安装包等静态文件，做路径穿越防御 + 简单 MIME 推断。
pub(crate) async fn handle_updates_static(
    axum::extract::Path(file): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    let root = pfaix_updates_dir();
    let candidate = root.join(file.replace('\\', "/"));
    // 路径穿越防御：必须在 root 下
    let (Ok(root_canon), Ok(cand_canon)) = (
        std::fs::canonicalize(&root),
        std::fs::canonicalize(&candidate),
    ) else {
        return (axum::http::StatusCode::NOT_FOUND, "not found").into_response();
    };
    if !cand_canon.starts_with(&root_canon) || !cand_canon.is_file() {
        return (axum::http::StatusCode::NOT_FOUND, "not found").into_response();
    }
    let data = match tokio::fs::read(&cand_canon).await {
        Ok(d) => d,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let ct = match cand_canon
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "exe" => "application/octet-stream",
        "json" => "application/json; charset=utf-8",
        "txt" | "md" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    };
    ([(axum::http::header::CONTENT_TYPE, ct)], data).into_response()
}

/// 公开健康检查（无鉴权）。供 PFAiX 状态条 / 诊断包探测。
/// 附带 Memoria 公开 /health 的 embed 摘要 + 最近 Dream 巩固状态。
pub(crate) async fn handle_health(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let memoria_url = {
        let cfg = st.config.lock().await;
        cfg.server.clone()
    };
    let memoria_health = reqwest::Client::new()
        .get(format!("{}/health", memoria_url.trim_end_matches('/')))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok();
    let (memoria_ok, embed) = if let Some(resp) = memoria_health {
        let status = resp.status().is_success();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        (status, body.get("embed").cloned().unwrap_or(serde_json::Value::Null))
    } else {
        (false, serde_json::json!({"status":"fail","message":"memoria /health 不可达"}))
    };
    let dream = st.consolidate_last.lock().await.clone();
    let overall = if memoria_ok
        && embed
            .get("status")
            .and_then(|s| s.as_str())
            .map(|s| s == "pass")
            .unwrap_or(false)
    {
        "ok"
    } else if memoria_ok {
        "degraded"
    } else {
        "fail"
    };
    Json(serde_json::json!({
        "service": "agent-core",
        "status": overall,
        "version": env!("CARGO_PKG_VERSION"),
        "memoria": { "reachable": memoria_ok, "embed": embed },
        "dream": dream,
    }))
}

/// 手动触发 Dream 巩固（鉴权路由）。body 可选 `{ "namespaces": ["agent/xxx"] }`。
pub(crate) async fn handle_agent_events(
    State(st): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> axum::response::Response {
    let since: u64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let limit: usize = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let (events, cursor) = {
        let qd = st.background_events.lock().await;
        let events: Vec<BackgroundEvent> = qd
            .iter()
            .filter(|e| e.id > since)
            .take(limit)
            .cloned()
            .collect();
        let cursor = *st.consolidate_cursor.lock().await;
        (events, cursor)
    };
    let next_since = events.last().map(|e| e.id).unwrap_or(since);
    Json(serde_json::json!({
        "events": events,
        "cursor": cursor,
        "next_since": next_since,
    }))
    .into_response()
}

pub(crate) async fn handle_config(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let cfg = st.config.lock().await;
    Json(serde_json::json!({
        "configured": cfg.configured(),
        "agent_id": cfg.agent_id,
        "server": cfg.server,
    }))
}

pub(crate) async fn handle_save_config(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SetupRequest>,
) -> axum::response::Response {
    // P0-2 修复：已配置后重新保存（改写 api_key/server）必须鉴权，
    // 仅首次引导（尚未配置）允许无凭据，避免 LAN 攻击者覆写指向恶意 MCP。
    let configured = st.config.lock().await.configured();
    if configured {
        if authenticate(&headers, &st).await.is_err() {
            return unauthorized("保存配置需要身份认证");
        }
    }
    let mut cfg = st.config.lock().await;
    cfg.agent_id = req.agent_id;
    cfg.api_key = req.api_key;
    if !req.server.is_empty() {
        cfg.server = req.server;
    }
    save_config(&cfg);
    drop(cfg);
    let cfg = st.config.lock().await.clone();
    match build_agent(&resolve_config_for_runtime(&cfg), st.local_resources.clone(), st.metrics.clone()).await {
        Ok(agent) => {
            *st.agent.lock().await = Some(Arc::new(agent));
            Json(SetupResponse {
                ok: true,
                error: None,
            })
            .into_response()
        }
        Err(e) => Json(SetupResponse {
            ok: false,
            error: Some(e),
        })
        .into_response(),
    }
}

pub(crate) async fn handle_metrics(State(st): State<Arc<AppState>>) -> axum::response::Response {
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        // 战略罗盘「可观测」：特性门状态 + 运行计数器/时延/持久执行 gauge 全量快照
        let features = agent.feature_gates();
        let quota = agent.quota_status();
        Json(st.metrics.snapshot(features, quota)).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}