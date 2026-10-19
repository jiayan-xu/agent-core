//! 平台治理 handler（P3 解耦，2026-10-19）。
//!
//! 承载：统一注册表读端点 + AgentCard 沙箱策略。
//! 从 dashboard `routers/apps.py` + `routers/platform.py` 迁出，
//! agent-core 为平台唯一网关（10-10 规范 §3）。
//!
//! Phase 1（本轮）：只读端点（GET registry / GET agent-card），
//! 不修改 dashboard——灰度共存，验证后再切。

use std::path::PathBuf;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::Value;

// ── 注册表文件定位 ──
fn registry_path() -> PathBuf {
    if let Ok(p) = std::env::var("PFAIX_REGISTRY_FILE") {
        return PathBuf::from(p);
    }
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join("pfaix-platform").join("apps.json")
}

fn read_registry() -> Result<Vec<Value>, String> {
    let path = registry_path();
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("registry file {}: {e}", path.display()))?;
    let data: Value = serde_json::from_str(&content)
        .map_err(|e| format!("parse: {e}"))?;
    // 兼容 v1 entries / 旧版 apps
    let entries = data.get("entries")
        .or_else(|| data.get("apps"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(entries)
}

// ── 沙箱策略（对齐 dashboard pfaix_platform/agent_card.py）──
const READ_ONLY_TOOLS: &[&str] = &[
    "hhv_health", "hhv_list_configs", "hhv_list_jobs", "hhv_job_status", "hhv_get_result",
    "ops_signals", "ops_efficiency", "ops_heatvalue", "ops_runparams",
];
const WRITE_TOOLS: &[&str] = &["hhv_run", "ops_pipeline", "ops_playbook"];

fn sandbox_tools(level: i64) -> Vec<&'static str> {
    match level {
        0 => vec![],
        1 => READ_ONLY_TOOLS.to_vec(),
        _ => {
            let mut v = READ_ONLY_TOOLS.to_vec();
            v.extend_from_slice(WRITE_TOOLS);
            v
        }
    }
}

fn sandbox_network(level: i64) -> &'static str {
    match level {
        0 => "none",
        1 => "loopback",
        2 => "lan",
        _ => "full",
    }
}

fn sandbox_desc(level: i64) -> &'static str {
    match level {
        0 => "观察（仅探活）",
        1 => "试用（只读 MCP + 回环）",
        2 => "受信（白名单工具 + 局域网）",
        _ => "生产（全量 + 审计）",
    }
}

// ═══ HTTP handlers ═══

/// GET /api/registry — 统一注册表（v1 entries 兼容旧 apps）
pub(crate) async fn handle_registry_list() -> impl IntoResponse {
    match read_registry() {
        Ok(entries) => Json(serde_json::json!({"entries": entries})).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// GET /api/registry/{id} — 单条目
pub(crate) async fn handle_registry_entry(Path(id): Path<String>) -> impl IntoResponse {
    match read_registry() {
        Ok(entries) => {
            let entry = entries.iter().find(|e| {
                e.get("id").and_then(|v| v.as_str()) == Some(id.as_str())
            });
            match entry {
                Some(e) => Json(e.clone()).into_response(),
                None => (StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "entry not found", "id": id}))).into_response(),
            }
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// GET /api/platform/agent-card/{id} — AgentCard + 签名状态 + 沙箱策略摘要
pub(crate) async fn handle_agent_card(Path(id): Path<String>) -> impl IntoResponse {
    match read_registry() {
        Ok(entries) => {
            let entry = entries.iter().find(|e| {
                e.get("id").and_then(|v| v.as_str()) == Some(id.as_str())
            });
            let Some(entry) = entry else {
                return (StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "agent not found"}))).into_response();
            };
            let card = entry.get("agent_card");
            let level = entry.pointer("/lifecycle/sandbox_level")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let sig_ok = card.map(|c| c.get("signature").is_some()).unwrap_or(false);
            Json(serde_json::json!({
                "agent_id": id,
                "card": card,
                "signature_ok": sig_ok,
                "signature_reason": if sig_ok { "ok" } else { "no card" },
                "sandbox_level": level,
                "sandbox_desc": sandbox_desc(level),
                "allowed_tools": sandbox_tools(level),
                "allowed_network": sandbox_network(level),
            })).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// GET /api/platform/sandbox-levels — 沙箱级别说明（静态参考）
pub(crate) async fn handle_sandbox_levels() -> impl IntoResponse {
    Json(serde_json::json!({
        "levels": [
            {"level": 0, "desc": sandbox_desc(0), "network": sandbox_network(0)},
            {"level": 1, "desc": sandbox_desc(1), "network": sandbox_network(1)},
            {"level": 2, "desc": sandbox_desc(2), "network": sandbox_network(2)},
            {"level": 3, "desc": sandbox_desc(3), "network": sandbox_network(3)},
        ]
    }))
}
