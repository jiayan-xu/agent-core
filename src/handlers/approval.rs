//! 审批 handler（从 src/main.rs 拆出，P6 重构）。
//!
//! 承载：审批控制台 / pending / history / respond + 内嵌 HTML。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use std::sync::Arc;

/// R2：办公网口已做 IP-端口绑定，:9753 由防火墙收口（127.0.0.1 + 内网子网）。
/// 开启后审批端点免 admin key（网络位置即身份）；关闭回退密钥校验。
fn approval_open_lan() -> bool {
    std::env::var("APPROVAL_OPEN_LAN")
        .map(|v| v == "1")
        .unwrap_or(false)
}



use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use axum::http::StatusCode;

use agent_core::approval::ApprovalResponse;

use crate::auth::authenticate;
use crate::config::env_memoria_admin_key;
use crate::state::AppState;


/// 人工审批台页面（内嵌静态 HTML，浏览器打开后配合 admin key 使用）
pub(crate) async fn handle_approval_console() -> Html<&'static str> {
    Html(APPROVAL_CONSOLE_HTML)
}

/// R2 运维简报代理：转发 dashboard :8000/healthz 给审批台前端展示
pub(crate) async fn handle_ops_briefing() -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:8000/healthz")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;
    match resp {
        Ok(r) => {
            let body: serde_json::Value = r.json().await.unwrap_or(serde_json::json!({"error": "parse fail"}));
            Ok(Json(body))
        }
        Err(e) => Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": format!("dashboard unreachable: {e}")})),
        )),
    }
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
    if !(approval_open_lan() || is_admin(&headers, &st).await) {
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
    if !(approval_open_lan() || is_admin(&headers, &st).await) {
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

        // ── R2 网关链路：网关创建的审批，批准后自动恢复执行并回写终态 ──
        // （chat 会话的审批由 execute_chat 轮询消费；网关审批无会话轮询，
        //   必须在此处 spawn 恢复执行，否则批准后永远停在 AwaitingApproval）
        if approved {
            if let Some(p) = &pending {
                if p.session_id.starts_with("gateway/") {
                    let exec_args = p.arguments.clone();
                    let allowed_ns = p.allowed_ns.clone().unwrap_or_default();
                    let tool_name_gw = p.tool_name.clone();
                    let execution_id = p.execution_id.clone();
                    let agent_clone = Arc::clone(&agent);
                    tokio::spawn(async move {
                        // 与 chat 恢复执行同语义：注入 confirmed=true（受控写红线）
                        let mut exec_args = exec_args;
                        if let Some(obj) = exec_args.as_object_mut() {
                            obj.insert("confirmed".to_string(), serde_json::json!(true));
                            if tool_name_gw == "sync_exception_correction" {
                                obj.insert("dry_run".to_string(), serde_json::json!(false));
                            }
                            if tool_name_gw == "manage_samples" {
                                obj.insert("action".to_string(), serde_json::json!("sync"));
                                obj.insert("dry_run".to_string(), serde_json::json!(false));
                            }
                        }
                        let result = agent_clone
                            .call_tool_routed(&tool_name_gw, "default", &exec_args, &allowed_ns, "")
                            .await;
                        if let Some(exe_id) = &execution_id {
                            match &result {
                                Ok(text) => agent_core::gateway::update_status(
                                    exe_id,
                                    agent_core::gateway::GatewayStatus::Executed,
                                    Some(text.clone()),
                                    None,
                                ),
                                Err(e) => agent_core::gateway::update_status(
                                    exe_id,
                                    agent_core::gateway::GatewayStatus::Failed,
                                    None,
                                    Some(e.clone()),
                                ),
                            }
                        }
                    });
                }
            }
        }

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
<title>人工审批台 · 固废监管系统</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: "Microsoft YaHei", "Segoe UI", sans-serif; background: #f0f3f8; color: #1a2332; min-height: 100vh; }
  /* 头部（白底+品牌三色底线，对齐 dashboard 家族） */
  header { background: #fff; position: sticky; top: 0; z-index: 100;
    box-shadow: 0 1px 4px rgba(20,35,60,.08); }
  .header-line { height: 3px; background: linear-gradient(90deg,#F58220,#5DAF3B,#1E88E5); }
  .header-top { display: flex; align-items: center; height: 72px; padding: 0 32px; }
  .h-left { flex: 1; font-size: 12px; color: #5a6d82; }
  .h-center { flex: 1.2; display: flex; align-items: center; justify-content: center; gap: 12px; }
  .h-center .shield { font-size: 26px; }
  h1 { font-size: 21px; font-weight: 700; color: #1a2332; white-space: nowrap; }
  .h-sub { font-size: 11px; color: #8d9eb0; }
  .h-right { flex: 1; display: flex; align-items: center; justify-content: flex-end; gap: 10px; font-size: 12px; color: #5a6d82; }
  .wrap { max-width: 1000px; margin: 18px auto; padding: 0 20px; }
  .keybar { display: flex; gap: 8px; margin-bottom: 16px; align-items: center; flex-wrap: wrap; }
  .keybar input { flex: 1; min-width: 240px; padding: 8px 10px; background: #fbfcfe; border: 1px solid #cfd8e6; color: #1a2332; border-radius: 6px; }
  button { cursor: pointer; border: none; border-radius: 6px; padding: 8px 14px; font-size: 13px; transition: all .15s; }
  .btn-refresh { background: #1E88E5; color: #fff; font-weight: 600; }
  .btn-refresh:hover { background: #1976D2; }
  .btn-history { background: #fff; color: #6b5bd6; border: 1px solid #b9aee0; }
  .btn-history:hover { background: #f1eefb; }
  .btn-approve { background: #178a50; color: #fff; font-weight: 600; }
  .btn-approve:hover { background: #10693c; }
  .btn-reject { background: #c5453b; color: #fff; }
  .btn-reject:hover { background: #a33730; }
  .card { background: #fff; border: 1px solid #dfe6f0; border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(20,35,60,.04); }
  .card h3 { margin: 0 0 6px; font-size: 15px; color: #1a2332; }
  .meta { font-size: 12px; color: #5a6d82; margin-bottom: 6px; word-break: break-all; }
  pre { background: #f6f9fd; border: 1px solid #e3e9f2; border-radius: 6px; padding: 10px; overflow: auto; font-size: 12px; color: #33415c; }
  .actions { display: flex; gap: 8px; margin-top: 10px; align-items: center; flex-wrap: wrap; }
  .actions input { flex: 1; min-width: 160px; padding: 6px 8px; background: #fbfcfe; border: 1px solid #cfd8e6; color: #1a2332; border-radius: 6px; }
  .empty { color: #8d9eb0; text-align: center; padding: 40px; }
  .err { color: #c5453b; }
  .badge-warn { background: rgba(255,179,0,.15); color: #b37400; font-size: 11px; padding: 2px 8px; border-radius: 10px; }
  .st-approved { color: #178a50; font-weight: bold; } .st-denied { color: #c5453b; font-weight: bold; }
  .st-consumed { color: #1E88E5; font-weight: bold; } .st-pending { color: #b37400; font-weight: bold; }
  .auto-note { font-size: 11px; color: #8d9eb0; }
</style>
</head>
<body>
<div class="header-line"></div>
<header>
 <div class="header-top">
  <div class="h-left">固废监管系统 · agent-core</div>
  <div class="h-center"><span class="shield">🛡️</span><h1>人工审批台</h1></div>
  <div class="h-right"><span class="auto-note">危险/红线工具二次确认 · 真人兜底</span></div>
 </div>
</header>
<div class="wrap">
  <div class="keybar">
    <span class="auto-note">🔒 身份由办公网 IP 绑定 + 防火墙白名单保证（APPROVAL_OPEN_LAN=1）</span>
    <button class="btn-refresh" onclick="load()">刷新待审</button>
    <button class="btn-history" onclick="loadHistory()">审批历史</button>
  </div>
  <!-- 运维简报 -->
  <div class="card" style="margin-bottom:16px; border-left:3px solid #1E88E5;">
    <h3 style="color:#1E88E5">📋 今日运维简报</h3>
    <div id="ops-briefing"><span class="empty">加载中…</span></div>
  </div>
  <div id="list"><div class="empty">加载待审项…</div></div>
<script>
let AUTO = null;
async function load() {
  const list = document.getElementById("list");
  list.innerHTML = '<div class="empty">加载中…</div>';
  try {
    const r = await fetch("/api/approval/pending", {});
    const j = await r.json();
    if (!r.ok) { list.innerHTML = '<div class="empty err">' + (j.error || "加载失败") + '</div>'; return; }
    if (!j.items || j.items.length === 0) { list.innerHTML = '<div class="empty">无待审批项</div>'; return; }
    list.innerHTML = "";
    for (const it of j.items) {
      const div = document.createElement("div");
      div.className = "card";
      const args = JSON.stringify(it.arguments, null, 2);
      div.innerHTML = '<h3>' + esc(toolName(it.tool_name)) + ' <span class="badge-warn">需人工确认</span></h3>' +
        '<div class="meta">ID: ' + esc(it.approval_id) + ' · 请求方: ' + esc(it.requester_id) + ' · 创建: ' + new Date(it.created_at*1000).toLocaleString() + '</div>' +
        '<div class="meta">说明: ' + esc(it.description) + '</div>' +
        '<div class="meta">指纹: ' + esc(it.operation_hash) + '</div>' +
        '<pre>' + esc(args) + '</pre>' +
        '<div class="actions"><input id="reason-' + esc(it.approval_id) + '" placeholder="审批意见（可选）">' +
        '<button class="btn-approve" onclick="respond(\'' + esc(it.approval_id) + '\', \'' + esc(it.operation_hash) + '\', true)">✓ 批准</button>' +
        '<button class="btn-reject" onclick="respond(\'' + esc(it.approval_id) + '\', \'' + esc(it.operation_hash) + '\', false)">✕ 拒绝</button></div>';
      list.appendChild(div);
    }
    startAuto();
  } catch (e) { list.innerHTML = '<div class="empty err">请求出错: ' + e + '</div>'; }
}
async function loadOps() {
  try {
    const r = await fetch("/api/ops/briefing");
    const d = await r.json();
    const el = document.getElementById("ops-briefing");
    const svcs = d.services || {};
    const svcList = Object.entries(svcs).map(([k,v]) =>
      (v.running ? "✓" : "✗") + " " + k
    ).join(" · ");
    const dbInfo = d.db || {};
    el.innerHTML =
      '<div class="meta" style="font-size:13px;color:#1a2332">' +
      '<b>状态：</b>' + (d.status === "ok" ? "✅ 正常" : "⚠️ " + d.status) +
      (d.down && d.down.length ? '（' + d.down.join('、') + ' 不在位）' : '') + '<br>' +
      '<b>DB：</b>' + dbInfo.ok + ' · ' + dbInfo.size_mb + ' MB · ' + dbInfo.vehicle_entrance_rows + ' 条入场记录<br>' +
      '<span style="color:#8892aa;font-size:11px">' + (d.checked_at || '') + '</span>' +
      '</div>';
  } catch(e) {
    el.innerHTML = '<span class="err">运维简报加载失败: ' + esc(String(e)) + '</span>';
  }
}
async function respond(id, hash, approved) {
  const reasonEl = document.getElementById("reason-" + id);
  const reason = reasonEl ? reasonEl.value : "";
  const r = await fetch("/api/approval/" + encodeURIComponent(id) + "/respond", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approved: approved, reason: reason || null, operation_hash: hash })
  });
  const j = await r.json().catch(() => ({}));
  if (r.ok && j.ok) { toast((approved ? "✓ 已批准" : "✕ 已拒绝") + ": " + id); load(); }
  else { toast("失败：" + (j.error || "未知错误")); }
}
async function loadHistory() {
  const list = document.getElementById("history");
  if (!list) return;
  stopAuto();
  list.style.display = "none";
  hist.style.display = "block";
  hist.innerHTML = '<div class="empty">加载中…</div>';
  try {
    const r = await fetch("/api/approval/history", {});
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
      const stCls = it.status === "Denied" ? "st-denied" : (it.status === "Consumed" ? "st-consumed" : "st-approved");
      const decided = it.decided_at ? new Date(it.decided_at*1000).toLocaleString() : "—";
      div.innerHTML = '<h3>' + esc(toolName(it.tool_name)) + ' <span class="' + stCls + '">[' + esc(st) + ']</span></h3>' +
        '<div class="meta">ID: ' + esc(it.approval_id) + ' · 请求方: ' + esc(it.requester_id) + ' · 创建: ' + new Date(it.created_at*1000).toLocaleString() + '</div>' +
        '<div class="meta">参数: ' + esc(argsTxt) + '</div>' +
        '<div class="meta">说明: ' + esc(it.description) + '</div>' +
        (it.decision_reason ? '<div class="meta">审批意见: ' + esc(it.decision_reason) + '</div>' : '') +
        '<div class="meta">审批人: ' + esc(it.approver_id) + ' · 决策时间: ' + decided + '</div>';
      hist.appendChild(div);
    }
  } catch (e) { hist.innerHTML = '<div class="empty err">请求出错: ' + e + '</div>'; }
}
function startAuto(){ if(!AUTO){ AUTO = setInterval(load, 30000); } }
function stopAuto(){ if(AUTO){ clearInterval(AUTO); AUTO = null; } }
function toast(m){
  const t = document.createElement("div");
  t.textContent = m;
  t.style.cssText = "position:fixed;top:18px;right:18px;background:#178a50;color:#fff;padding:10px 16px;border-radius:8px;z-index:999;font-size:13px";
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 2500);
}
const TOOL_NAMES = {
  "manage_whitelist": "白名单管理",
  "sync_whitelist_plates": "白名单同步",
  "sync_exception_correction": "异常修正同步",
  "manage_samples": "取样台账同步",
  "memory_remember": "写入记忆",
  "memory_observe": "记忆观察",
};
function toolName(t){ return TOOL_NAMES[t] || t; }
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
window.addEventListener("DOMContentLoaded", () => { load(); });

window.onerror = function(msg, src, line) {
  document.getElementById('ops-briefing').innerHTML =
    '<span class="err">JS错误: ' + msg + ' @line ' + line + '</span>';
};
window.addEventListener('DOMContentLoaded', function() {
  loadOps();  // 独立触发运维简报，不依赖 load()
});
</script>
</body>
</html>"##;