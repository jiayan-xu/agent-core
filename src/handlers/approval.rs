//! 审批 handler（从 src/main.rs 拆出，P6 重构）。
//!
//! 承载：审批控制台 / pending / history / respond + 内嵌 HTML。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;

use agent_core::approval::ApprovalResponse;

use crate::auth::authenticate;
use crate::config::env_memoria_admin_key;
use crate::state::AppState;


/// 人工审批台页面（内嵌静态 HTML，浏览器打开后配合 admin key 使用）
pub(crate) async fn handle_approval_console() -> Html<&'static str> {
    Html(APPROVAL_CONSOLE_HTML)
}

/// 审批响应请求体（POST /api/approval/{id}/respond）
#[derive(serde::Deserialize)]
pub(crate) struct ApprovalRespondBody {
    approved: bool,
    #[serde(default)]
    reason: Option<String>,
    /// 创建时计算的操作指纹，必须回显一致，否则视为操作被偷换而拒绝。
    operation_hash: String,
}

/// admin 判定：请求携带的 x-agent-key 是否等于配置的 admin key（MEMORIA_ADMIN_KEY）
pub(crate) async fn is_admin(headers: &axum::http::HeaderMap, st: &Arc<AppState>) -> bool {
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let key = headers
        .get("x-agent-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    !admin_key.is_empty() && key == admin_key
}

/// admin 判定（独立头 x-admin-key）：避免把 admin_key 塞进 x-agent-key 破坏 a2a 的 badge 鉴权。
/// 协作收件箱注入 L2 审批、以及 L2 审批响应回退均用此标识，与日常 a2a badge 鉴权解耦。
pub(crate) async fn is_admin_by_admin_key(headers: &axum::http::HeaderMap, st: &Arc<AppState>) -> bool {
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    !admin_key.is_empty() && key == admin_key
}

/// 列出待人工审批项（仅 admin）
pub(crate) async fn handle_approval_pending(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let list = agent.approval_manager.list_pending().await;
        Json(serde_json::json!({ "count": list.len(), "items": list })).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// 审批历史（含已消费/已拒绝），仅 admin
pub(crate) async fn handle_approval_history(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    // 审批历史绑定注册人身份：任何已注册 agent（badge 认证通过）可查看，
    // 无需 admin key（审批人即注册用户本人）。写操作 respond 仍要求 admin。
    let (agent_id, _allowed_ns) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let _ = agent_id;
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let list = agent.approval_manager.list_history(100).await;
        Json(serde_json::json!({ "count": list.len(), "items": list })).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// 审批人（admin）对某项审批做出决定（批准/拒绝）；校验 operation_hash 防偷换
pub(crate) async fn handle_approval_respond(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ApprovalRespondBody>,
) -> Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        // 取回 pending，校验 operation_hash 与创建时一致（防 LLM/调用方偷换操作）
        let pending = agent.approval_manager.get_pending(&id).await;
        let expected_hash = match &pending {
            Some(p) => p.operation_hash.clone(),
            None => {
                return (
                    axum::http::StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "审批项不存在或已处理"})),
                )
                    .into_response()
            }
        };
        if body.operation_hash != expected_hash {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "operation_hash 不匹配，疑似操作被偷换，已拒绝"
                })),
            )
                .into_response();
        }
        let approved = body.approved;
        let resp = ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: id.clone(),
            approved,
            reason: body.reason.clone(),
            approver_id: "dashboard-admin".to_string(),
            operation_hash: expected_hash.clone(),
        };
        agent.approval_manager.record_response(resp).await;
        // 审计：批准 / 拒绝事件
        let decision = if approved { "approved" } else { "rejected" };
        let tool_name = pending
            .as_ref()
            .map(|p| p.tool_name.clone())
            .unwrap_or_default();
        agent
            .audit_logger
            .approval_event(
                decision,
                &agent.config.identity.agent_id,
                &tool_name,
                &body.reason.clone().unwrap_or_default(),
                "", // 审批台上下文无 trace_id，留空不影响解阻塞
                None,
            )
            .await;
        Json(serde_json::json!({ "ok": true, "decision": decision })).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// 人工审批台内嵌 HTML（fetch 直连本 agent-core 的 /api/approval/* 端点）
pub(crate) const APPROVAL_CONSOLE_HTML: &str = r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>人工审批台</title>
<style>
  body { font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0; background: #0f1115; color: #e6e6e6; }
  header { padding: 16px 20px; background: #171a21; border-bottom: 1px solid #2a2f3a; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 18px; margin: 0; }
  .wrap { padding: 20px; max-width: 1000px; margin: 0 auto; }
  .keybar { display: flex; gap: 8px; margin-bottom: 16px; }
  .keybar input { flex: 1; padding: 8px 10px; background: #1c2029; border: 1px solid #2a2f3a; color: #e6e6e6; border-radius: 6px; }
  button { cursor: pointer; border: none; border-radius: 6px; padding: 8px 14px; font-size: 14px; }
  .btn-refresh { background: #3a6df0; color: #fff; }
  .btn-approve { background: #2e9e5b; color: #fff; }
  .btn-reject { background: #c5453b; color: #fff; }
  .btn-history { background: #6b5bd6; color: #fff; }
  .card { background: #171a21; border: 1px solid #2a2f3a; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }
  .card h3 { margin: 0 0 6px; font-size: 15px; color: #ffd479; }
  .meta { font-size: 12px; color: #9aa4b2; margin-bottom: 8px; }
  pre { background: #0f1115; border: 1px solid #2a2f3a; border-radius: 6px; padding: 10px; overflow: auto; font-size: 12px; color: #cdd6e3; }
  .actions { display: flex; gap: 8px; margin-top: 10px; align-items: center; }
  .actions input { flex: 1; padding: 6px 8px; background: #1c2029; border: 1px solid #2a2f3a; color: #e6e6e6; border-radius: 6px; }
  .empty { color: #9aa4b2; text-align: center; padding: 40px; }
  .err { color: #c5453b; }
</style>
</head>
<body>
<header><h1>人工审批台</h1><span style="color:#9aa4b2;font-size:13px">危险/红线工具二次确认 · 真人兜底</span></header>
<div class="wrap">
  <div class="keybar">
    <input id="adminKey" type="password" placeholder="粘贴 admin key (MEMORIA_ADMIN_KEY)">
    <button class="btn-refresh" onclick="load()">刷新待审</button>
    <button class="btn-history" onclick="loadHistory()">审批历史</button>
  </div>
  <div id="list"><div class="empty">点击「刷新待审」加载待审批项</div></div>
  <div id="history" style="display:none"><div class="empty">点击「审批历史」查看审计留证</div></div>
</div>
<script>
pub(crate) const API = "http://127.0.0.1:9753";
async function load() {
  const key = document.getElementById("adminKey").value;
  const list = document.getElementById("list");
  if (!key) { list.innerHTML = '<div class="empty err">请先填写 admin key</div>'; return; }
  list.innerHTML = '<div class="empty">加载中…</div>';
  try {
    const r = await fetch(API + "/api/approval/pending", { headers: { "x-agent-key": key } });
    const j = await r.json();
    if (!r.ok) { list.innerHTML = '<div class="empty err">' + (j.error || "加载失败") + '</div>'; return; }
    if (!j.items || j.items.length === 0) { list.innerHTML = '<div class="empty">无待审批项</div>'; return; }
    list.innerHTML = "";
    for (const it of j.items) {
      const div = document.createElement("div");
      div.className = "card";
      const args = JSON.stringify(it.arguments, null, 2);
      div.innerHTML = '<h3>' + esc(it.tool_name) + '</h3>' +
        '<div class="meta">ID: ' + esc(it.approval_id) + ' · 请求方: ' + esc(it.requester_id) + ' · 创建: ' + new Date(it.created_at*1000).toLocaleString() + '</div>' +
        '<div class="meta">说明: ' + esc(it.description) + '</div>' +
        '<div class="meta">指纹: ' + esc(it.operation_hash) + '</div>' +
        '<pre>' + esc(args) + '</pre>' +
        '<div class="actions"><input id="reason-' + esc(it.approval_id) + '" placeholder="审批意见（可选）">' +
        '<button class="btn-approve" onclick="respond(\'' + esc(it.approval_id) + '\', \'' + esc(it.operation_hash) + '\', true)">批准</button>' +
        '<button class="btn-reject" onclick="respond(\'' + esc(it.approval_id) + '\', \'' + esc(it.operation_hash) + '\', false)">拒绝</button></div>';
      list.appendChild(div);
    }
  } catch (e) { list.innerHTML = '<div class="empty err">请求出错: ' + e + '</div>'; }
}
async function respond(id, hash, approved) {
  const key = document.getElementById("adminKey").value;
  const reason = document.getElementById("reason-" + id).value;
  const r = await fetch(API + "/api/approval/" + encodeURIComponent(id) + "/respond", {
    method: "POST",
    headers: { "x-agent-key": key, "Content-Type": "application/json" },
    body: JSON.stringify({ approved: approved, reason: reason || null, operation_hash: hash })
  });
  const j = await r.json();
  if (r.ok && j.ok) { alert((approved ? "已批准" : "已拒绝") + ": " + id); load(); }
  else { alert("失败：" + (j.error || "未知错误")); }
}
async function loadHistory() {
  const key = document.getElementById("adminKey").value;
  const list = document.getElementById("list");
  const hist = document.getElementById("history");
  if (!key) { alert("请先填写 admin key"); return; }
  list.style.display = "none";
  hist.style.display = "block";
  hist.innerHTML = '<div class="empty">加载中…</div>';
  try {
    const r = await fetch(API + "/api/approval/history", { headers: { "x-agent-key": key } });
    const j = await r.json();
    if (!r.ok) { hist.innerHTML = '<div class="empty err">' + (j.error || "加载失败") + '</div>'; return; }
    if (!j.items || j.items.length === 0) { hist.innerHTML = '<div class="empty">暂无审批历史</div>'; return; }
    hist.innerHTML = "";
    for (const it of j.items) {
      const div = document.createElement("div");
      div.className = "card";
      let argsTxt = "";
      try {
        const a = JSON.parse(it.arguments_json || "{}");
        const parts = [];
        if (a.plate) parts.push("车牌=" + a.plate);
        if (a.company_name) parts.push("公司=" + a.company_name);
        if (a.waste_type) parts.push("固废种类=" + a.waste_type);
        if (a.action) parts.push("操作=" + a.action);
        argsTxt = parts.length ? parts.join("，") : (it.arguments_json || "");
      } catch (e) { argsTxt = it.arguments_json || ""; }
      const statusMap = { "Pending":"待审批","Approved":"已批准","Denied":"已拒绝","Consumed":"已执行" };
      const st = statusMap[it.status] || it.status;
      const stColor = it.status === "Approved" || it.status === "Consumed" ? "#2e9e5b" : (it.status === "Denied" ? "#c5453b" : "#ffd479");
      const decided = it.decided_at ? new Date(it.decided_at*1000).toLocaleString() : "—";
      div.innerHTML = '<h3>' + esc(it.tool_name) + ' <span style="color:' + stColor + '">[' + esc(st) + ']</span></h3>' +
        '<div class="meta">ID: ' + esc(it.approval_id) + ' · 请求方: ' + esc(it.requester_id) + ' · 创建: ' + new Date(it.created_at*1000).toLocaleString() + '</div>' +
        '<div class="meta">参数: ' + esc(argsTxt) + '</div>' +
        '<div class="meta">说明: ' + esc(it.description) + '</div>' +
        (it.decision_reason ? '<div class="meta">审批意见: ' + esc(it.decision_reason) + '</div>' : '') +
        '<div class="meta">审批人: ' + esc(it.approver_id) + ' · 决策时间: ' + decided + '</div>';
      hist.appendChild(div);
    }
  } catch (e) { hist.innerHTML = '<div class="empty err">请求出错: ' + e + '</div>'; }
}
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
</script>
</body>
</html>"##;