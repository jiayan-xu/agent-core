//! 平台治理 handler（P3 解耦，2026-10-19）。
//!
//! Phase 1：只读（GET registry / agent-card / sandbox-levels / audit）
//! Phase 2：写操作（POST approve / revoke / mint / sandbox）
//! 从 dashboard 迁出，agent-core 为唯一平台网关（10-10 规范 §3）。

use std::path::PathBuf;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::auth::authenticate;
use crate::handlers::approval::is_admin;
use crate::state::AppState;

use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

// ── 固定路径常量（部署机固定，迁移时改这里）──
const REGISTRY_FILE: &str = r"C:\Users\user\pfaix-platform\apps.json";
const AUDIT_FILE: &str = r"C:\Users\user\pfaix-platform\audit_log.jsonl";
const PLATFORM_KEY_FILE: &str = r"C:\Users\user\.svc-secrets\pfaix-platform.env";

fn registry_path() -> PathBuf {
    if let Ok(p) = std::env::var("PFAIX_REGISTRY_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from(REGISTRY_FILE)
}

fn read_full() -> Result<Value, String> {
    let content = std::fs::read_to_string(registry_path())
        .map_err(|e| format!("registry: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("parse: {e}"))
}

fn write_full(data: &Value) -> Result<(), String> {
    let path = registry_path();
    let tmp = path.with_extension("json.tmp");
    let content = serde_json::to_string_pretty(data).map_err(|e| format!("ser: {e}"))?;
    std::fs::write(&tmp, content.as_bytes()).map_err(|e| format!("tmp: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename: {e}"))
}

fn audit(action: &str, entry_id: &str, actor: &str, detail: &str) {
    use std::io::Write;
    let line = json!({
        "ts": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "action": action, "entry_id": entry_id, "actor": actor,
        "detail": detail.chars().take(200).collect::<String>(),
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true).open(AUDIT_FILE) {
        let _ = writeln!(f, "{line}");
    }
}

fn load_platform_key() -> String {
    if let Ok(content) = std::fs::read_to_string(PLATFORM_KEY_FILE) {
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("PFAIX_PLATFORM_KEY=") {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

fn sign_hmac(canonical: &str, key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("hmac");
    mac.update(canonical.as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

// ═══ 沙箱策略 ═══
const READ_TOOLS: &[&str] = &[
    "hhv_health", "hhv_list_configs", "hhv_list_jobs", "hhv_job_status", "hhv_get_result",
    "ops_signals", "ops_efficiency", "ops_heatvalue", "ops_runparams",
];
const WRITE_TOOLS: &[&str] = &["hhv_run", "ops_pipeline", "ops_playbook"];

fn sandbox_tools(level: i64) -> Vec<&'static str> {
    match level {
        0 => vec![],
        1 => READ_TOOLS.to_vec(),
        _ => { let mut v = READ_TOOLS.to_vec(); v.extend_from_slice(WRITE_TOOLS); v }
    }
}
fn sandbox_net(level: i64) -> &'static str {
    match level { 0 => "none", 1 => "loopback", 2 => "lan", _ => "full" }
}
fn sandbox_desc(level: i64) -> &'static str {
    match level {
        0 => "观察（仅探活）", 1 => "试用（只读 MCP + 回环）",
        2 => "受信（白名单工具 + 局域网）", _ => "生产（全量 + 审计）",
    }
}

// ═══ 鉴权 ═══
async fn check_admin(
    headers: &HeaderMap, st: &Arc<AppState>,
) -> Result<String, (StatusCode, Json<Value>)> {
    match authenticate(headers, st).await {
        Ok((caller, _)) => {
            if is_admin(headers, st).await { Ok(caller) }
            else { Err((StatusCode::FORBIDDEN, Json(json!({"error": "admin required"})))) }
        }
        Err(_) => Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "auth failed"})))),
    }
}

/// 修改注册表中某条目的 lifecycle 字段（统一入口，单次 mutable）。
fn modify_lifecycle(data: &mut Value, id: &str, fields: Vec<(&str, Value)>) -> Result<(), String> {
    let arr_key = if data.get("entries").is_some() { "entries" } else { "apps" };
    let idx = data.get(arr_key).and_then(|v| v.as_array())
        .and_then(|a| a.iter().position(|e|
            e.get("id").and_then(|v| v.as_str()) == Some(id)))
        .ok_or_else(|| format!("entry not found: {id}"))?;
    if let Some(entry) = data.get_mut(arr_key)
        .and_then(|v| v.as_array_mut())
        .and_then(|a| a.get_mut(idx)) {
        let obj = entry.as_object_mut().ok_or("entry not object")?;
        let lc = obj.entry("lifecycle").or_insert_with(|| json!({}));
        let lc_obj = lc.as_object_mut().ok_or("lifecycle not object")?;
        for (k, v) in fields {
            lc_obj.insert(k.to_string(), v);
        }
        Ok(())
    } else {
        Err("internal: index out of range".into())
    }
}

/// 在注册表某条目上设置一个顶层字段（如 agent_card）。
fn set_entry_field(data: &mut Value, id: &str, key: &str, value: Value) -> Result<(), String> {
    let arr_key = if data.get("entries").is_some() { "entries" } else { "apps" };
    let idx = data.get(arr_key).and_then(|v| v.as_array())
        .and_then(|a| a.iter().position(|e|
            e.get("id").and_then(|v| v.as_str()) == Some(id)))
        .ok_or_else(|| format!("entry not found: {id}"))?;
    if let Some(entry) = data.get_mut(arr_key)
        .and_then(|v| v.as_array_mut())
        .and_then(|a| a.get_mut(idx)) {
        let obj = entry.as_object_mut().ok_or("entry not object")?;
        obj.insert(key.to_string(), value);
        Ok(())
    } else {
        Err("internal: index out of range".into())
    }
}

// ═══ Phase 1: 只读 ═══

pub(crate) async fn handle_registry_list() -> impl IntoResponse {
    match read_full() {
        Ok(data) => {
            let entries = data.get("entries").or_else(|| data.get("apps"))
                .cloned().unwrap_or(json!([]));
            Json(json!({"entries": entries})).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(),
    }
}

pub(crate) async fn handle_registry_entry(Path(id): Path<String>) -> impl IntoResponse {
    match read_full() {
        Ok(data) => {
            let entries = data.get("entries").or_else(|| data.get("apps"))
                .and_then(|v| v.as_array()).cloned().unwrap_or_default();
            match entries.iter().find(|e| e.get("id").and_then(|v| v.as_str()) == Some(id.as_str())) {
                Some(e) => Json(e.clone()).into_response(),
                None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found", "id": id}))).into_response(),
            }
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(),
    }
}

pub(crate) async fn handle_agent_card(Path(id): Path<String>) -> impl IntoResponse {
    match read_full() {
        Ok(data) => {
            let entries = data.get("entries").or_else(|| data.get("apps"))
                .and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let Some(entry) = entries.iter().find(|e|
                e.get("id").and_then(|v| v.as_str()) == Some(id.as_str())) else {
                return (StatusCode::NOT_FOUND, Json(json!({"error": "agent not found"}))).into_response();
            };
            let card = entry.get("agent_card");
            let level = entry.pointer("/lifecycle/sandbox_level")
                .and_then(|v| v.as_i64()).unwrap_or(0);
            let sig_ok = card.map(|c| c.get("signature").is_some()).unwrap_or(false);
            Json(json!({
                "agent_id": id, "card": card,
                "signature_ok": sig_ok,
                "signature_reason": if sig_ok { "ok" } else { "no card" },
                "sandbox_level": level, "sandbox_desc": sandbox_desc(level),
                "allowed_tools": sandbox_tools(level),
                "allowed_network": sandbox_net(level),
            })).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(),
    }
}

pub(crate) async fn handle_sandbox_levels() -> impl IntoResponse {
    Json(json!({"levels": [
        {"level": 0, "desc": sandbox_desc(0), "network": sandbox_net(0)},
        {"level": 1, "desc": sandbox_desc(1), "network": sandbox_net(1)},
        {"level": 2, "desc": sandbox_desc(2), "network": sandbox_net(2)},
        {"level": 3, "desc": sandbox_desc(3), "network": sandbox_net(3)},
    ]}))
}

// ═══ Phase 2: 写操作 ═══

pub(crate) async fn handle_approve(
    headers: HeaderMap, State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Ok(actor) = check_admin(&headers, &st).await else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "admin required"}))).into_response();
    };
    let mut data = match read_full() { Ok(d) => d, Err(e) =>
        return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response() };
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if let Err(e) = modify_lifecycle(&mut data, &id, vec![
        ("status", json!("active")), ("approved_by", json!(actor)), ("status_changed_at", json!(now)),
    ]) { return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(); }
    if let Err(e) = write_full(&data) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
    }
    audit("active", &id, &actor, "");
    Json(json!({"ok": true, "id": id, "status": "active", "actor": actor})).into_response()
}

pub(crate) async fn handle_revoke(
    headers: HeaderMap, State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Ok(actor) = check_admin(&headers, &st).await else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "admin required"}))).into_response();
    };
    let mut data = match read_full() { Ok(d) => d, Err(e) =>
        return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response() };
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if let Err(e) = modify_lifecycle(&mut data, &id, vec![
        ("status", json!("revoked")), ("revoked_by", json!(actor)), ("status_changed_at", json!(now)),
    ]) { return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(); }
    if let Err(e) = write_full(&data) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
    }
    audit("revoked", &id, &actor, "");
    Json(json!({"ok": true, "id": id, "status": "revoked", "actor": actor})).into_response()
}

pub(crate) async fn handle_mint_card(
    headers: HeaderMap, State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> impl IntoResponse {
    let Ok(actor) = check_admin(&headers, &st).await else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "admin required"}))).into_response();
    };
    let req = body.map(|Json(v)| v).unwrap_or_default();
    let mut data = match read_full() { Ok(d) => d, Err(e) =>
        return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response() };
    // 取条目默认值
    let entries = data.get("entries").or_else(|| data.get("apps"))
        .and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let Some(entry) = entries.iter().find(|e|
        e.get("id").and_then(|v| v.as_str()) == Some(id.as_str())) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "agent not found"}))).into_response();
    };
    let name = req.get("name").or(entry.get("name"))
        .and_then(|v| v.as_str()).unwrap_or(&id).to_string();
    let desc = req.get("description").or(entry.get("description"))
        .and_then(|v| v.as_str()).unwrap_or("").to_string();
    let scopes: Vec<String> = req.get("scopes").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let level = req.get("sandbox_level").and_then(|v| v.as_i64()).unwrap_or(0);
    let endpoints = req.get("endpoints").cloned().unwrap_or(json!({}));
    let ttl = req.get("ttl_days").and_then(|v| v.as_i64()).unwrap_or(90);
    let status = entry.pointer("/lifecycle/status")
        .and_then(|v| v.as_str()).unwrap_or("draft").to_string();
    // 签发
    let now_str = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let exp = (chrono::Local::now() + chrono::Duration::days(ttl))
        .format("%Y-%m-%dT%H:%M:%S").to_string();
    let mut card = json!({
        "schema": "pfaix-platform/agent-card-v1",
        "agent_id": id, "name": name, "description": desc,
        "scopes": scopes, "sandbox_level": level,
        "endpoints": endpoints, "status": status,
        "issued_at": now_str, "expires_at": exp,
    });
    let key = load_platform_key();
    let sig_short;
    if !key.is_empty() {
        let canonical = serde_json::to_string(&card).unwrap_or_default();
        let sig = sign_hmac(&canonical, &key);
        sig_short = format!("{}...", &sig[..12.min(sig.len())]);
        card["signature"] = json!(sig);
    } else {
        sig_short = String::new();
    }
    // 写入注册表
    if let Err(e) = modify_lifecycle(&mut data, &id, vec![
        ("sandbox_level", json!(level)),
    ]) { return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(); }
    if let Err(e) = set_entry_field(&mut data, &id, "agent_card", card) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
    }
    if let Err(e) = write_full(&data) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
    }
    audit("mint_card", &id, &actor, &format!("L{level} sig={sig_short}"));
    Json(json!({"ok": true, "agent_id": id, "signature": sig_short, "sandbox_level": level})).into_response()
}

pub(crate) async fn handle_set_sandbox(
    headers: HeaderMap, State(st): State<Arc<AppState>>,
    Path((id, level)): Path<(String, i64)>,
) -> impl IntoResponse {
    if !(0..=3).contains(&level) {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid level (0-3)", "got": level}))).into_response();
    }
    let Ok(actor) = check_admin(&headers, &st).await else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "admin required"}))).into_response();
    };
    let mut data = match read_full() { Ok(d) => d, Err(e) =>
        return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response() };
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if let Err(e) = modify_lifecycle(&mut data, &id, vec![
        ("sandbox_level", json!(level)),
        ("sandbox_changed_by", json!(actor)),
        ("sandbox_changed_at", json!(now)),
    ]) { return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(); }
    if let Err(e) = write_full(&data) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
    }
    audit("sandbox", &id, &actor, &format!("→L{level}"));
    Json(json!({
        "ok": true, "id": id, "sandbox_level": level,
        "desc": sandbox_desc(level),
        "tools": sandbox_tools(level), "network": sandbox_net(level),
    })).into_response()
}

pub(crate) async fn handle_audit_log(
    headers: HeaderMap, State(st): State<Arc<AppState>>,
) -> impl IntoResponse {
    let _ = check_admin(&headers, &st).await;
    if !std::path::Path::new(AUDIT_FILE).exists() {
        return Json(json!({"entries": []})).into_response();
    }
    let content = std::fs::read_to_string(AUDIT_FILE).unwrap_or_default();
    let entries: Vec<Value> = content.lines().rev().take(50)
        .filter_map(|l| serde_json::from_str(l).ok()).collect();
    Json(json!({"entries": entries})).into_response()
}
