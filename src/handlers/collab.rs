//! 协作 handler（从 src/main.rs 拆出，P6 重构）。
//!
//! 承载：收件箱 / 发送 / 审批 / peers / 删除 + 命名空间可达性辅助 + 策略单测。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;

use serde::Deserialize;

use agent_core::approval::ApprovalResponse;
use crate::auth::authenticate;
use crate::config::{env_memoria_admin_key, extract_register_badge, memoria_proxy_client, org_company};
use crate::handlers::approval::is_admin_by_admin_key;
use crate::state::AppState;



#[derive(Debug, Deserialize)]
pub(crate) struct CollabInboxQuery {
    /// 逗号分隔的 type 白名单：approval_request,approval_response,query,query_result,notify,message
    types: Option<String>,
    /// 逗号分隔的 scope 白名单：org,dept,proj,agent
    scopes: Option<String>,
    /// 页码（从 0 开始）
    page: Option<usize>,
    /// 每页大小（1..=200）
    limit: Option<usize>,
    /// 传 "1"/"true" 表示本次读取后标记已读（更新未读游标）
    mark_seen: Option<String>,
}

/// 协作发送请求体（POST /api/collab/send）
#[derive(Debug, serde::Deserialize)]
pub(crate) struct CollabSendBody {
    /// 单点收件人 agent_id（scope=agent 必填）
    to_agent: Option<String>,
    /// 广播范围：org | dept | proj | agent
    scope: String,
    /// 范围 id：org 公司根 / dept 部门名 / proj 项目名
    scope_id: Option<String>,
    /// 信封类型白名单：query | query_result | notify | approval_request | message
    #[serde(rename = "type")]
    r#type: String,
    subject: String,
    body: String,
    /// 结构化载荷（审批请求的工具名/参数等），可选
    payload: Option<serde_json::Value>,
    /// 关联线程 id，可选
    thread_id: Option<String>,
}

/// 协作审批响应请求体（POST /api/collab/approval）
#[derive(Debug, serde::Deserialize)]
pub(crate) struct CollabApprovalBody {
    /// 待响应的 approval_request 消息 id（调用者收件箱中的）
    id: String,
    /// 决策：approve | reject
    decision: String,
    /// 拒绝/备注理由，可选
    reason: Option<String>,
    /// 创建时计算的操作指纹，必须回显一致，否则视为操作被偷换而拒绝（防 LLM 自批）。
    /// serde default：PFAiX 前端（0.8.13）不发该字段；本地 L2 待批项由 admin 判定兜底，
    /// A2A 路径仍强制校验（见 handle_collab_approval 内 is_local 分支）。
    #[serde(default)]
    operation_hash: String,
}

/// 公司级广播白名单：环境变量 `COLLAB_ORG_BROADCASTERS`（逗号分隔 agent_id）。
/// 未设置时默认 `office-agent`（行政/办公室）；`*` 持有者仍可发。
pub(crate) fn org_broadcasters() -> Vec<String> {
    match std::env::var("COLLAB_ORG_BROADCASTERS") {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => vec!["office-agent".to_string()],
    }
}

pub(crate) fn ns_blob(ns: &[String]) -> String {
    ns.join(",")
}

pub(crate) fn caller_in_org(caller_ns: &[String]) -> bool {
    let blob = ns_blob(caller_ns);
    caller_ns.iter().any(|n| n == "*")
        || blob.contains(&format!("org/{}", org_company()))
}

pub(crate) fn caller_has_dept(caller_ns: &[String], dept: &str) -> bool {
    let needle = format!("dept/{}", dept);
    caller_ns.iter().any(|n| n == "*") || ns_blob(caller_ns).contains(&needle)
}

pub(crate) fn caller_has_proj(caller_ns: &[String], proj: &str) -> bool {
    let needle = format!("proj/{}", proj);
    caller_ns.iter().any(|n| n == "*") || ns_blob(caller_ns).contains(&needle)
}

pub(crate) fn can_org_broadcast(caller_id: &str, caller_ns: &[String]) -> bool {
    // 注意：持有 `*`（Memoria admin）也不自动获得公司广播权，
    // 避免 jarvis 等服务身份误发国庆通知；须显式进白名单或 role。
    let role_ok = caller_ns.iter().any(|n| {
        n == "role/office"
            || n == "role/hr"
            || n.ends_with("/role/office")
            || n.ends_with("/role/hr")
    });
    role_ok || org_broadcasters().iter().any(|id| id == caller_id)
}

/// 协作可达策略（§3.3）：校验「调用者能否以某类型发往某范围」。
/// - org：仅 notify/announcement，且须广播白名单 / role/office|hr（admin `*` 不自动放行）
/// - dept/proj：须 scope_id，且调用者 NS 含对应 dept/proj
pub(crate) fn collab_reachability(
    caller_id: &str,
    caller_ns: &[String],
    scope: &str,
    scope_id: &str,
    etype: &str,
) -> Result<(), String> {
    match scope {
        "org" => {
            if !matches!(etype, "notify" | "announcement") {
                return Err(format!("可达策略拒绝：scope=org 不允许 type={}", etype));
            }
            if !caller_in_org(caller_ns) {
                return Err("可达策略拒绝：非本公司成员不可发公司广播".into());
            }
            if !can_org_broadcast(caller_id, caller_ns) {
                return Err(
                    "可达策略拒绝：公司广播仅限办公室/HR 角色或 COLLAB_ORG_BROADCASTERS 白名单"
                        .into(),
                );
            }
            Ok(())
        }
        "dept" => {
            if scope_id.trim().is_empty() {
                return Err("可达策略拒绝：scope=dept 必须指定 scope_id".into());
            }
            if !matches!(etype, "notify" | "query" | "approval_request") {
                return Err(format!("可达策略拒绝：scope=dept 不允许 type={}", etype));
            }
            if !caller_has_dept(caller_ns, scope_id.trim()) {
                return Err(format!(
                    "可达策略拒绝：你不在部门「{}」内，无法向该部门广播",
                    scope_id.trim()
                ));
            }
            Ok(())
        }
        "proj" => {
            if scope_id.trim().is_empty() {
                return Err("可达策略拒绝：scope=proj 必须指定 scope_id".into());
            }
            if !matches!(etype, "notify" | "query") {
                return Err(format!("可达策略拒绝：scope=proj 不允许 type={}", etype));
            }
            if !caller_has_proj(caller_ns, scope_id.trim()) {
                return Err(format!(
                    "可达策略拒绝：你不在项目「{}」内，无法向该项目广播",
                    scope_id.trim()
                ));
            }
            Ok(())
        }
        "agent" => {
            if matches!(etype, "approval_request" | "query" | "notify" | "message") {
                Ok(())
            } else {
                Err(format!("可达策略拒绝：scope=agent 不允许 type={}", etype))
            }
        }
        _ => Err(format!("未知 scope: {}", scope)),
    }
}

pub(crate) fn peer_in_company(namespace: &str) -> bool {
    namespace.contains(&format!("org/{}", org_company())) || namespace.contains('*')
}





/// Phase 6 增强：列出调用者可见的圆桌会议（私有仅拥有者 / admin 可见；scope 会议同级成员可见）
pub(crate) async fn resolve_caller_memoria_key(
    st: &Arc<AppState>,
    agent_id: &str,
    headers: &axum::http::HeaderMap,
) -> String {
    // 1) 优先用 authenticate 已校验/注册并写入 auth_cache 的 badge
    {
        let cache = st.auth_cache.lock().await;
        if let Some((b, _)) = cache.get(agent_id) {
            return b.clone();
        }
    }
    // 2) 登录态：请求头携带 x-agent-key
    if let Some(hk) = headers
        .get("x-agent-key")
        .and_then(|v| v.to_str().ok())
    {
        if !hk.is_empty() {
            return hk.to_string();
        }
    }
    // 3) 兜底：admin 身份确保 agent 已在 Memoria 注册并取回 badge
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    if !admin_key.is_empty() {
        let server = st.config.lock().await.server.clone();
        let install_ns = format!("agent/{},org/cs-pufa-2nd-thermal", agent_id);
        let reg = memoria_proxy_client(&server, &cfg_admin);
        if let Ok(text) = reg
            .call_json(
                "register_agent",
                &serde_json::json!({
                    "agent_id": agent_id,
                    "display_name": agent_id,
                    "admin_key": &admin_key,
                    "namespace": &install_ns,
                }),
            )
            .await
        {
            if let Some(b) = extract_register_badge(&text) {
                st.auth_cache
                    .lock()
                    .await
                    .insert(agent_id.to_string(), (b.clone(), std::time::Instant::now()));
                return b;
            }
        }
    }
    String::new()
}

pub(crate) async fn handle_collab_inbox(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<CollabInboxQuery>,
) -> axum::response::Response {
    let (agent_id, allowed_ns, _) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let agent_key = resolve_caller_memoria_key(&st, &agent_id, &headers).await;
    // ADMIN 判定（badge 绑定，无需 x-admin-key 头）：
    // 调用者 allowed_ns 含 `*`（管理员注册提权后 namespace 追加 `*`）即视为 admin，
    // 协作收件箱注入待审批项。此前依赖 x-admin-key 需在每台 PFAiX 手动填 key，
    // 且 8/1 瘦身工程误删 PFAiX 的 adminKey 字段导致审批不可见。
    let is_admin_caller = allowed_ns.iter().any(|n| n == "*" || n == "system");
    // 兼容：仍接受 x-admin-key 头（存量客户端/脚本）
    let is_admin_caller = is_admin_caller || is_admin_by_admin_key(&headers, &st).await;

    // 拉取（持有 agent 锁的模式与 handle_chat 一致）
    let raw = {
        let agent_guard = st.agent.lock().await;
        if let Some(ref agent) = *agent_guard {
            let limit = q.limit.unwrap_or(50).clamp(1, 200) as u32;
            // 2026-11-16：同人别名合并——同一 display_name 的多条注册行（部门规范
            // 漂移 operation/yunxing、登录态 u_xxx 与安装 tag 并存）互为别名。
            // 发送按通讯录 username 投递、会话身份可能解析到另一条行，不合并则
            // 「发得出、对方收件箱看不到」。
            match agent.collab_inbox_merged(&agent_id, &agent_key, limit).await {
                Ok(v) => v,
                Err(e) => {
                    return (
                        axum::http::StatusCode::BAD_GATEWAY,
                        axum::Json(serde_json::json!({"error": e})),
                    )
                        .into_response();
                }
            }
        } else {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({"error": "agent 尚未就绪"})),
            )
                .into_response();
        }
    };

    // type / scope 过滤
    let types: Vec<&str> = q
        .types
        .as_deref()
        .map(|s| s.split(',').filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();
    let scopes: Vec<&str> = q
        .scopes
        .as_deref()
        .map(|s| s.split(',').filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();
    let mut filtered: Vec<serde_json::Value> = raw
        .into_iter()
        .filter(|m| {
            let t = m["type"].as_str().unwrap_or("");
            let sc = m["scope"].as_str().unwrap_or("agent");
            (types.is_empty() || types.contains(&t)) && (scopes.is_empty() || scopes.contains(&sc))
        })
        .collect();

    // L2 人工审批合并进协作收件箱：ADMIN（x-admin-key）可见本地 ApprovalManager 待批项。
    // 合成 approval_request 信封（不落 memoria）；审批响应走 handle_collab_approval 的 L2 回退分支。
    if is_admin_caller {
        let agent_guard = st.agent.lock().await;
        if let Some(ref agent) = *agent_guard {
            for p in agent.approval_manager.list_pending().await {
                let created_at_str = {
                    let secs = p.created_at as i64;
                    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
                };
                filtered.push(serde_json::json!({
                    "id": p.approval_id,
                    "type": "approval_request",
                    "subject": p.description.clone(),
                    "body": p.description.clone(),
                    "from_agent": p.requester_id.clone(),
                    "from_ns": "",
                    "to_agent": p.approver_id.clone(),
                    "scope": "agent",
                    "scope_id": "",
                    "workspace_id": "",
                    "thread_id": "",
                    "payload": {
                        "approval_id": p.approval_id,
                        "operation_hash": p.operation_hash,
                        "tool": p.tool_name,
                        "reason": p.description.clone(),
                        "arguments": p.arguments,
                    },
                    "created_at": created_at_str,
                }));
            }
        }
    }

    // 未读：与已读游标比较。信封 created_at 有两种常见格式
    // （PFAiX 结构化信封为 ISO `2026-07-13T23:50:00Z`，Memoria 旧消息为
    // `2026-07-13 23:50:00`），统一归一化为 `YYYY-MM-DD HH:MM:SS` 后再字典序比较，
    // 避免格式不一致导致 mark_seen 永远不生效（未读角标无法清零）。
    let norm_ts = |s: &str| -> String { s.replace('T', " ").replace('Z', "").replace('z', "") };
    let seen = { st.collab_seen.lock().await.get(&agent_id).cloned() };
    let seen_norm = seen.as_deref().map(|s| norm_ts(s));
    let unread_count = filtered
        .iter()
        .filter(|m| {
            let t = norm_ts(m["created_at"].as_str().unwrap_or(""));
            match &seen_norm {
                Some(s) => t > *s,
                None => true,
            }
        })
        .count();

    if q.mark_seen.as_deref() == Some("1") || q.mark_seen.as_deref() == Some("true") {
        // 游标推进到「当前返回信封中最大的 created_at」，而非服务器当前时间——
        // 否则当信封时间晚于真实当前时间（如回放/测试数据）时 mark_seen 永远不生效。
        let now_norm = norm_ts(&chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
        let max_item = filtered
            .iter()
            .map(|m| norm_ts(m["created_at"].as_str().unwrap_or("")))
            .max();
        let cursor = max_item
            .map(|x| if x > now_norm { x } else { now_norm.clone() })
            .unwrap_or(now_norm);
        st.collab_seen.lock().await.insert(agent_id.clone(), cursor);
    }

    let page = q.page.unwrap_or(0);
    let page_size = q.limit.unwrap_or(50).clamp(1, 200);
    let total = filtered.len();
    let start = page * page_size;
    let items: Vec<serde_json::Value> = filtered.into_iter().skip(start).take(page_size).collect();

    axum::Json(serde_json::json!({
        "items": items,
        "unread_count": unread_count,
        "total": total,
        "page": page,
        "page_size": page_size,
    }))
    .into_response()
}

/// 观点/肯定评价落盘（POST /api/memory/feedback）
///
/// body:
/// - `kind`: `preference` | `decision` | `affirm`（affirm→preference+pref）
/// - `content`: 正文（必填）
/// - `tag`: 可选 hard_rule|pref|style（仅 preference）
/// - `namespace`: 可选；默认 clamp 到 `agent/{x-agent-id}`；显式值须过 Memoria
///   原始授予（resolve_memory_ns 封存名单 + ns_grants_access 仅 ==/子级，
///   P1-1 修复；写闸不用 enrich 后列表，P1-1b）
pub(crate) async fn handle_memory_feedback(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> axum::response::Response {
    let (agent_id, _allowed_ns, _) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let kind = body
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("affirm")
        .trim();
    let content = body
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if content.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "content 必填"})),
        )
            .into_response();
    }
    let (category, default_tag) = match kind {
        "decision" => ("decision", "decision"),
        "preference" | "affirm" => ("preference", "pref"),
        other => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": format!("kind 须为 preference|decision|affirm，收到 {}", other)
                })),
            )
                .into_response();
        }
    };
    let tag = body
        .get("tag")
        .and_then(|v| v.as_str())
        .unwrap_or(default_tag);
    // P1-1 修复（2026-11-23 全量审查）：此前取 body 的 namespace 直接传 admin-key 的
    // remember_opinion（绕过 NS 门），任意认证 agent 可向任意 ns（含主库 agent/xujiayan）
    // 注入偏好/决策。现统一走 clamp_memory_feedback_ns 单点决策。
    // P1-1b：写闸只认 Memoria 原始授予。authenticate 返回的 allowed_ns 已被
    // enrich_allowed_ns 注入部门工具包 ns（org/…，仅为技能可见性），复用它会让
    // 任意认证 agent 显式写共享 org 库——Memoria badge 并未授予该 ns。
    let raw_ns = {
        let cache = st.ns_cache.lock().await;
        cache.get(&agent_id).map(|(raw, _, _)| raw.clone())
    };
    // 正常路径 authenticate 刚写入缓存，必有条目；缺失则 fail-closed（空授权），
    // 默认 clamp（不显式传 ns）不依赖授权，行为不受影响。
    let write_ns = raw_ns.unwrap_or_default();
    let ns = match clamp_memory_feedback_ns(
        &agent_id,
        &write_ns,
        body.get("namespace").and_then(|v| v.as_str()),
    ) {
        Ok(ns) => ns,
        Err(e) => {
            return (
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": format!("namespace 不可写: {}", e)})),
            )
                .into_response();
        }
    };

    let guard = st.agent.lock().await;
    let Some(ref agent) = *guard else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    match agent
        .remember_opinion(&ns, content, category, &[tag], 5)
        .await
    {
        Ok(id) => axum::Json(serde_json::json!({
            "ok": true,
            "id": id,
            "namespace": ns,
            "category": category,
            "tag": tag,
        }))
        .into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// P1-1 修复（2026-11-23 全量审查）：feedback ns 单点决策。
///
/// 此前 handler 取 body 的 namespace 直接传 admin-key 的 `remember_opinion`
/// （绕过 NS 门），任意认证 agent 可向任意 ns 注入偏好/决策。现口径对齐
/// `handle_assistant_memory_write`（assistants.rs 强制 `agent/{user_id}`）：
/// - 未显式传 ns → clamp 到 `agent/{agent_id}`（本人隔离库）；
/// - 显式 ns → 过 `resolve_memory_ns`（封存名单 + admin 例外），
///   其内部 `ns_grants_access` 仅放行 ==/子级授权（无祖先方向）。
/// 错误返回人类可读原因（NsError::Display），由调用方回传 403。
pub(crate) fn clamp_memory_feedback_ns(
    agent_id: &str,
    allowed_ns: &[String],
    explicit: Option<&str>,
) -> Result<String, String> {
    let Some(explicit) = explicit.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(format!("agent/{}", agent_id));
    };
    let cfg = agent_core::namespace::NamespaceConfig::default();
    let caller = agent_core::namespace::NsCaller {
        user_id: agent_id.to_string(),
        allowed_ns: allowed_ns.to_vec(),
        from_usertag: false,
    };
    match agent_core::namespace::resolve_memory_ns(&cfg, Some(&caller), None, Some(explicit)) {
        Ok(d) => Ok(d.ns),
        Err(e) => Err(e.to_string()),
    }
}

/// 协作发送（POST /api/collab/send）
///
/// 校验 type 白名单 + 可达策略（§3.3）后，按 scope 构建信封并投递：
/// - scope=agent → 点对点 a2a_send 到 `agent/{to_agent}`
/// - scope=org/dept/proj → 经 `agent_list` 展开 NS 树为多收件人，逐一 a2a_send（fan-out）
/// 实际送达经服务端受信身份（admin 中继）完成；Memoria NS 门控仅作纵深防御。
pub(crate) async fn handle_collab_send(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<CollabSendBody>,
) -> axum::response::Response {
    let (agent_id, _allowed_ns, _) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    // 1) type 白名单
    let etype = body.r#type.trim();
    let allowed_types = [
        "query",
        "query_result",
        "notify",
        "announcement",
        "approval_request",
        "message",
    ];
    if !allowed_types.contains(&etype) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": format!("不支持的信封类型: {}", etype)})),
        )
            .into_response();
    }

    // P1-1c（2026-11-23 生产验证）：可达闸只认 Memoria 原始授予。authenticate
    // 返回的 allowed_ns 已被 enrich_allowed_ns 注入部门工具包 ns（含
    // dept/engineering、proj/gufei，仅为 dashboard 技能可见性），复用它会让任意
    // 认证 agent 对整工程部广播（含 approval_request）/整固废项目广播——Memoria
    // badge 并未授予这些 ns。与 feedback 写闸（P1-1b）同根因、同处置。
    let raw_ns = {
        let cache = st.ns_cache.lock().await;
        cache.get(&agent_id).map(|(raw, _, _)| raw.clone())
    };
    // fail-closed：authenticate 成功后缓存必有条目；缺失（不应发生）时按空授权
    // 处理——scope=agent 私信不受影响（其闸不查 ns），org/dept/proj 广播一律拒绝。
    let reach_ns = raw_ns.unwrap_or_default();

    // 2) 可达策略（§3.3）
    let scope = body.scope.trim();
    let scope_id = body.scope_id.clone().unwrap_or_default();
    if let Err(msg) = collab_reachability(&agent_id, &reach_ns, scope, &scope_id, etype) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": msg})),
        )
            .into_response();
    }

    // 3) 构建信封（§3.1）
    // from_ns 取 Memoria 原始授予首项（调用方真实 canonical ns），不用 enrich 后列表
    let from_ns = reach_ns
        .first()
        .cloned()
        .unwrap_or_else(|| format!("agent/{}", agent_id));
    let now = chrono::Utc::now().to_rfc3339();
    let msg_id = format!("col_{}_{}", chrono::Utc::now().timestamp_millis(), etype);

    // 4) 投递
    let agent_guard = st.agent.lock().await;
    let sent = if let Some(ref agent) = *agent_guard {
        if scope == "agent" {
            // 点对点：必须指定收件人
            let to = match &body.to_agent {
                Some(t) if !t.is_empty() => t.clone(),
                _ => {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": "scope=agent 须指定 to_agent"})),
                    )
                        .into_response();
                }
            };
            let envelope = build_collab_envelope(
                &msg_id, etype, &body.subject, &body.body, &agent_id, &from_ns,
                &to, scope, &scope_id, body.thread_id.as_deref(),
                body.payload.as_ref(), &now,
            );
            match agent.collab_send_raw(&to, &envelope).await {
                Ok(s) => serde_json::json!({"sent": 1, "targets": [to], "detail": s}),
                Err(e) => {
                    return (
                        axum::http::StatusCode::BAD_GATEWAY,
                        axum::Json(serde_json::json!({"error": e})),
                    )
                        .into_response();
                }
            }
        } else {
            // fan-out：展开 NS 树为多个点对点收件人
            match agent.collab_list_peers().await {
                Ok(peers) => {
                    let targets: Vec<String> = peers
                        .iter()
                        .filter_map(|p| p["agent_id"].as_str().map(|s| s.to_string()))
                        .filter(|id| id != &agent_id) // 不自发
                        .filter(|id| {
                            // 按 scope 过滤同组织/同部门/同项目成员
                            let ns = peers_ns_of(&peers, id);
                            match scope {
                                "org" => ns.contains(&format!("org/{}", org_company())),
                                "dept" => ns.contains(&format!("dept/{}", scope_id)),
                                "proj" => ns.contains(&format!("proj/{}", scope_id)),
                                _ => false,
                            }
                        })
                        .collect();
                    if targets.is_empty() {
                        serde_json::json!({"sent": 0, "targets": Vec::<String>::new(), "detail": "无可投递的同组织收件人"})
                    } else {
                        let mut count = 0usize;
                        let mut failed = Vec::new();
                        for t in &targets {
                            let envelope = build_collab_envelope(
                                &msg_id, etype, &body.subject, &body.body, &agent_id,
                                &from_ns, t, scope, &scope_id,
                                body.thread_id.as_deref(), body.payload.as_ref(), &now,
                            );
                            match agent.collab_send_raw(t, &envelope).await {
                                Ok(_) => count += 1,
                                Err(e) => failed.push(serde_json::json!({"to": t, "error": e})),
                            }
                        }
                        serde_json::json!({"sent": count, "targets": targets, "failed": failed})
                    }
                }
                Err(e) => {
                    return (
                        axum::http::StatusCode::BAD_GATEWAY,
                        axum::Json(serde_json::json!({"error": e})),
                    )
                        .into_response();
                }
            }
        }
    } else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    drop(agent_guard);
    axum::Json(sent).into_response()
}

/// 从 agent_list 结果中取某 agent 的 namespace 字段（用于 fan-out 范围匹配）。
pub(crate) fn peers_ns_of(peers: &[serde_json::Value], id: &str) -> String {
    peers
        .iter()
        .find(|p| p["agent_id"].as_str() == Some(id))
        .and_then(|p| p["namespace"].as_str())
        .unwrap_or("")
        .to_string()
}

/// 构建标准协作信封（§3.1）。`to` 为单个收件人 agent_id（fan-out 时逐封改写）。
pub(crate) fn build_collab_envelope(
    id: &str,
    etype: &str,
    subject: &str,
    body: &str,
    from_agent: &str,
    from_ns: &str,
    to_agent: &str,
    scope: &str,
    scope_id: &str,
    thread_id: Option<&str>,
    payload: Option<&serde_json::Value>,
    created_at: &str,
) -> serde_json::Value {
    let mut env = serde_json::json!({
        "type": etype,
        "id": id,
        "subject": subject,
        "body": body,
        "from_agent": from_agent,
        "from_ns": from_ns,
        "to_agent": to_agent,
        "scope": scope,
        "scope_id": scope_id,
        "created_at": created_at,
    });
    if let Some(tid) = thread_id {
        env["thread_id"] = serde_json::Value::String(tid.to_string());
    }
    if let Some(p) = payload {
        env["payload"] = p.clone();
    }
    env
}

/// 协作审批响应（POST /api/collab/approval）
///
/// 在调用者收件箱中找到对应 approval_request，向 requester 回写 approval_response 信封，
/// 并记入本地 ApprovalManager（若本实例恰好是等待方，可即时解阻塞）。
pub(crate) async fn handle_collab_approval(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<CollabApprovalBody>,
) -> axum::response::Response {
    let (agent_id, allowed_ns, _) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let agent_key = resolve_caller_memoria_key(&st, &agent_id, &headers).await;

    // 在调用者收件箱中定位该 approval_request
    let agent_guard = st.agent.lock().await;
    let (requester, approval_id, is_local) = if let Some(ref agent) = *agent_guard {
        match agent
            .collab_find_message(&agent_id, &agent_key, &body.id)
            .await
        {
            Ok(Some(m)) => {
                if m["type"].as_str() != Some("approval_request") {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!(
                            {"error": "该消息不是 approval_request，无法审批"}
                        )),
                    )
                        .into_response();
                }
                let req = m["from_agent"].as_str().unwrap_or("").to_string();
                let aid = m["payload"]["approval_id"]
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| body.id.clone());
                (req, aid, false)
            }
            Ok(None) => {
                // 本地 L2 待批项（受控写触发，未推 A2A 收件箱）：仅 admin 可处理。
                // admin 判定 = 调用者 allowed_ns 含 `*`（badge 绑定，与 inbox 注入一致），
                // 兼容 x-admin-key 头（存量脚本）。
                let is_admin_badge = allowed_ns.iter().any(|n| n == "*" || n == "system");
                if !is_admin_badge && !is_admin_by_admin_key(&headers, &st).await {
                    return (
                        axum::http::StatusCode::FORBIDDEN,
                        axum::Json(serde_json::json!({"error": "需要 admin 权限"})),
                    )
                        .into_response();
                }
                match agent.approval_manager.get_pending(&body.id).await {
                    Some(p) => (String::new(), p.approval_id.clone(), true),
                    None => {
                        return (
                            axum::http::StatusCode::NOT_FOUND,
                            axum::Json(serde_json::json!({"error": "收件箱中找不到该审批请求"})),
                        )
                            .into_response();
                    }
                }
            }
            Err(e) => {
                return (
                    axum::http::StatusCode::BAD_GATEWAY,
                    axum::Json(serde_json::json!({"error": e})),
                )
                    .into_response();
            }
        }
    } else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };

    let decision_ok = matches!(body.decision.trim(), "approve" | "yes" | "通过" | "批准");

    // 回写 requester 收件箱（先校验 operation_hash，防 A2A 中转偷换）
    let send_res = if let Some(ref agent) = *agent_guard {
        // C1c: 取回 pending 的 operation_hash，校验 A2A 响应回显一致（防 LLM 自批 / 偷换）
        // 本地 L2 待批项（is_local=true，受控写触发未走 A2A）跳过 hash 校验：
        // 已过 admin 判定（allowed_ns 含 * 或 x-admin-key），且 PFAiX 前端不发该字段；
        // 防偷换语义由 admin 判定承担。A2A 中转路径仍强制校验。
        let expected_hash = match agent.approval_manager.get_pending(&approval_id).await {
            Some(p) => p.operation_hash,
            None => {
                return (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({"error": "审批项不存在或已处理"})),
                )
                    .into_response()
            }
        };
        if !is_local && body.operation_hash != expected_hash {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "operation_hash 不匹配，疑似操作被偷换，已拒绝"
                })),
            )
                .into_response();
        }
        if is_local {
            // 本地 L2 待批项：无 A2A requester，仅 record_response 解阻塞执行侧
            Ok(String::new())
        } else {
            // P0-1 修复：A2A 回传 requester 的 approval_response 必须携带 operation_hash，
            // 否则 requester 侧 record_response（C1c 校验）会因缺 hash 解析失败 / 指纹错配而拒批，
            // 导致跨实例人工审批死锁。此处回显 pending 的真实指纹（expected_hash 已在上方校验一致）。
            let resp_env = serde_json::json!({
                "type": "approval_response",
                "approval_id": approval_id,
                "approved": decision_ok,
                "reason": body.reason.clone(),
                "approver_id": agent_id,
                "operation_hash": expected_hash,
            });
            agent.collab_send_raw(&requester, &resp_env).await
        }
    } else {
        Err("agent 尚未就绪".to_string())
    };
    drop(agent_guard);

    match send_res {
        Ok(_) => {
            // 记录本地 ApprovalManager（解阻塞本实例等待中的审批）
            let agent_guard = st.agent.lock().await;
            if let Some(ref agent) = *agent_guard {
                // C1c: 已在上游校验过 operation_hash，此处直接绑定 pending 的 hash（不再强改）
                let op_hash = agent
                    .approval_manager
                    .get_pending(&approval_id)
                    .await
                    .map(|p| p.operation_hash)
                    .unwrap_or_default();
                let _ = agent.approval_manager.record_response(
                    ApprovalResponse {
                        r#type: "approval_response".to_string(),
                        approval_id: approval_id.clone(),
                        approved: decision_ok,
                        reason: body.reason.clone(),
                        approver_id: agent_id.clone(),
                        operation_hash: op_hash,
                    },
                ).await;
            }
            drop(agent_guard);
            axum::Json(serde_json::json!({
                "ok": true,
                "decision": if decision_ok { "approve" } else { "reject" },
                "to": requester,
            }))
            .into_response()
        }
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

// ─────────────────────────────────────────────────────────────
// L2：人工审批台（真人兜底，危险/红线工具二次确认）
// ─────────────────────────────────────────────────────────────

/// 人工审批台页面（内嵌静态 HTML，浏览器打开后配合 admin key 使用）

/// 协作通讯录（GET /api/collab/peers）
///
/// 返回同组织已注册 Agent 列表（经 admin 中继调 Memoria `agent_list`）。
#[derive(serde::Deserialize)]
pub(crate) struct CollabPeersQuery {
    /// humans=1：过滤系统/服务身份，仅返回真人注册（通讯录/邀请场景）
    humans: Option<String>,
}

/// 系统/服务身份注册表（非真人）：通讯录 humans=1 查询时剔除。
/// 新增服务身份时同步登记；真人同事不在此列。
const SYSTEM_AGENT_IDS: &[&str] = &[
    "admin", "default", "jarvis", "user", "office-agent", "workbuddy",
    "dsh", "dsh-main", "dsh-slot", "dsh-memoria", "pfaix-office",
    "dashboard", "monitor", "grok-bot", "agent/admin",
];

pub(crate) async fn handle_collab_peers(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<CollabPeersQuery>,
) -> axum::response::Response {
    let (_agent_id, _allowed_ns, _) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let agent_guard = st.agent.lock().await;
    let res = if let Some(ref agent) = *agent_guard {
        agent.collab_list_peers().await
    } else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    drop(agent_guard);
    match res {
        Ok(agents) => {
            let filtered: Vec<_> = agents
                .iter()
                .filter(|a| {
                    let ns = a["namespace"].as_str().unwrap_or("");
                    peer_in_company(ns)
                })
                .filter(|a| {
                    // humans=1：剔除系统/服务身份（通讯录与邀请只应出现"人"）
                    if q.humans.as_deref() == Some("1")
                        && SYSTEM_AGENT_IDS.contains(&a["agent_id"].as_str().unwrap_or(""))
                    {
                        return false;
                    }
                    true
                })
                .map(|a| {
                    serde_json::json!({
                        "agent_id": a["agent_id"],
                        "display_name": a["display_name"],
                        "namespace": a["namespace"],
                        "permission": a["permission"],
                    })
                })
                .collect();
            axum::Json(serde_json::json!({ "agents": filtered })).into_response()
        }
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// P2-1：协作画像（GET /api/collab/profile）——《程序化汇合改造方案》§8 P2。
///
/// 蜂群实验结论「信息可见性决定组织形态」：只看社交关系的 Agent 会「朋友的朋友」式抱团
/// （聚类系数 0.53），看到彼此的专长与活跃后才转向择优组队（降到 0.28）。本端点把同组织
/// Agent 的能力/活跃信号只读聚合暴露给协作面，供 a2a 择优。
///
/// 数据源（全部只读、零 LLM、逐项降级不阻断）：
/// - memoria `agent_list`：注册面（与 peers 同源同过滤）；
/// - memoria `audit_query` 近 2000 条行为样本：按 agent 聚合事件数 / 最近活跃 / 工具偏好；
/// - memoria `memory_quota_status`：当日写入量（配额窗口计数）。
/// 说明：任务级「正确率」需任务回执体系（未建），本版先暴露工具偏好与活跃度作为专长信号。
pub(crate) async fn handle_collab_profile(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let (_agent_id, _allowed_ns, _) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let agent_guard = st.agent.lock().await;
    let Some(ref agent) = *agent_guard else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };

    // 1. 注册面（与 peers 同源 + 同过滤）
    let peers = match agent.collab_list_peers().await {
        Ok(p) => p,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({"error": e})),
            )
                .into_response()
        }
    };
    let visible: Vec<&serde_json::Value> = peers
        .iter()
        .filter(|a| peer_in_company(a["namespace"].as_str().unwrap_or("")))
        .collect();

    // 2. 行为样本：audit_query 无 per-agent 过滤参数，单次拉取近 2000 条后程序分组
    const AUDIT_SAMPLE: u64 = 2000;
    let audit = agent
        .mcp
        .call_json("audit_query", &serde_json::json!({ "limit": AUDIT_SAMPLE }))
        .await
        .ok();
    // agent_id → (事件数, 最近活跃时间, 工具计数)——BTreeMap 保证 top_tools 输出稳定可复现
    let mut behavior: std::collections::HashMap<
        String,
        (u64, String, std::collections::BTreeMap<String, u64>),
    > = std::collections::HashMap::new();
    if let Some(a) = &audit {
        if let Some(logs) = a["logs"].as_array() {
            for log in logs {
                let id = log["agent_id"].as_str().unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let entry = behavior
                    .entry(id)
                    .or_insert_with(|| (0, String::new(), Default::default()));
                entry.0 += 1;
                let ts = log["timestamp"].as_str().unwrap_or("");
                if entry.1.is_empty() || ts > entry.1.as_str() {
                    entry.1 = ts.to_string();
                }
                let tool = log["tool"].as_str().unwrap_or("unknown").to_string();
                *entry.2.entry(tool).or_insert(0) += 1;
            }
        }
    }

    // 3. 组装画像（当日写入量逐 peer best-effort 查询；失败留 null 不阻断）
    let mut agents_json: Vec<serde_json::Value> = Vec::with_capacity(visible.len());
    for a in &visible {
        let agent_id = a["agent_id"].as_str().unwrap_or("").to_string();
        let ns = peers_ns_of(&peers, &agent_id);
        let writes_today = agent
            .mcp
            .call_json(
                "memory_quota_status",
                &serde_json::json!({ "namespace": ns }),
            )
            .await
            .ok()
            .and_then(|q| q["quotas"]["write"]["used"].as_u64());
        let activity = behavior.get(&agent_id).map(|(events, last, tools)| {
            let mut top: Vec<(String, u64)> =
                tools.iter().map(|(k, v)| (k.clone(), *v)).collect();
            top.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
            serde_json::json!({
                "sampled_events": events,
                "last_active": last,
                "top_tools": top
                    .into_iter()
                    .take(3)
                    .map(|(t, n)| serde_json::json!({"tool": t, "count": n}))
                    .collect::<Vec<_>>(),
            })
        });
        agents_json.push(serde_json::json!({
            "agent_id": a["agent_id"],
            "display_name": a["display_name"],
            "namespace": a["namespace"],
            "permission": a["permission"],
            "primary_ns": ns,
            "activity": activity,
            "writes_today": writes_today,
        }));
    }

    axum::Json(serde_json::json!({
        "agents": agents_json,
        "audit_sample_limit": AUDIT_SAMPLE,
        "audit_available": audit.is_some(),
        "note": "画像为只读聚合（零 LLM）：top_tools/活跃度来自 memoria 审计抽样，writes_today 为当日配额窗口计数；任务级正确率待任务回执体系建立后接入（方案 §8）",
    }))
    .into_response()
}

/// POST /api/collab/delete — 删除收件箱中的一条消息（通知清理）
#[derive(serde::Deserialize)]
pub(crate) struct CollabDeleteBody {
    /// 要删除的消息 id（collab/inbox 返回的 id）
    id: String,
}

pub(crate) async fn handle_collab_delete(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<CollabDeleteBody>,
) -> axum::response::Response {
    let (agent_id, _allowed_ns, _) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if body.id.trim().is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "缺少 id"})),
        )
            .into_response();
    }
    let agent_key = resolve_caller_memoria_key(&st, &agent_id, &headers).await;
    let agent_guard = st.agent.lock().await;
    let res = if let Some(ref agent) = *agent_guard {
        agent
            .collab_delete_message(&agent_id, &agent_key, &body.id)
            .await
    } else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    drop(agent_guard);
    match res {
        Ok(n) if n > 0 => {
            axum::Json(serde_json::json!({"status": "ok", "deleted": n})).into_response()
        }
        Ok(_) => (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "消息不存在或不属于当前账号"})),
        )
            .into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}


#[cfg(test)]
pub(crate) mod collab_policy_tests {
    use super::*;

    #[test]
    fn org_broadcast_requires_whitelist() {
        let ns = vec![format!("org/{}", org_company())];
        // 普通成员有 org ns 也不能发
        assert!(collab_reachability("random-user", &ns, "org", org_company(), "notify").is_err());
        // 白名单默认 office-agent
        assert!(collab_reachability("office-agent", &ns, "org", org_company(), "notify").is_ok());
        // org+query 仍拒绝
        assert!(collab_reachability("office-agent", &ns, "org", org_company(), "query").is_err());
    }

    #[test]
    fn dept_requires_scope_id_and_membership() {
        let ns = vec!["org/cs-pufa-2nd-thermal/dept/engineering/proj/gufei".to_string()];
        assert!(collab_reachability("u1", &ns, "dept", "", "notify").is_err());
        assert!(collab_reachability("u1", &ns, "dept", "engineering", "notify").is_ok());
        assert!(collab_reachability("u1", &ns, "dept", "finance", "notify").is_err());
    }

    #[test]
    fn peer_in_company_filter() {
        assert!(peer_in_company("agent/x,org/cs-pufa-2nd-thermal"));
        assert!(!peer_in_company("agent/y,org/other-co"));
    }

    /// P1-1 修复（2026-11-23）：feedback ns 越权写封堵——
    /// 默认 clamp 本人库；显式 ns 仅放行授权子树；admin 例外但对封存名单同样生效。
    #[test]
    fn feedback_ns_clamps_to_self_by_default() {
        assert_eq!(
            clamp_memory_feedback_ns("alice", &[], None).unwrap(),
            "agent/alice"
        );
        // 空串/纯空白显式值视同未传
        assert_eq!(
            clamp_memory_feedback_ns("alice", &[], Some("  ")).unwrap(),
            "agent/alice"
        );
    }

    #[test]
    fn feedback_ns_explicit_requires_subtree_grant() {
        let ns = vec!["agent/alice".to_string(), "org/co/dept/eng".to_string()];
        // 本人库与子级：放行
        assert!(clamp_memory_feedback_ns("alice", &ns, Some("agent/alice")).is_ok());
        assert!(clamp_memory_feedback_ns("alice", &ns, Some("agent/alice/notes")).is_ok());
        assert!(clamp_memory_feedback_ns("alice", &ns, Some("org/co/dept/eng")).is_ok());
        // 他人库 / 非授权子树 / 祖先方向：拒绝
        assert!(clamp_memory_feedback_ns("alice", &ns, Some("agent/bob")).is_err());
        assert!(clamp_memory_feedback_ns("alice", &ns, Some("org/co/dept/finance")).is_err());
        // 授权仅含子级时，祖先 agent/alice 不因子级授权而放行（ns_grants_access 仅 ==/子级）
        let child_only = vec!["agent/alice/sub".to_string()];
        assert!(clamp_memory_feedback_ns("alice", &child_only, Some("agent/alice")).is_err());
    }

    #[test]
    fn feedback_ns_admin_bypasses_grant_but_not_denylist() {
        let wildcard = vec!["*".to_string()];
        assert!(clamp_memory_feedback_ns("admin", &wildcard, Some("agent/other")).is_ok());
        // 封存名单对 admin 同样生效（resolve_memory_ns 显式分支先查 is_write_denied）
        assert!(clamp_memory_feedback_ns("admin", &wildcard, Some("agent/user")).is_err());
    }

    /// P1-1b 回归锁（2026-11-23 生产验证发现）：feedback 写闸必须取 ns_cache 中
    /// 的 Memoria 原始授予，不得复用 authenticate 返回的 enrich 后 allowed_ns——
    /// enrich 仅为技能可见性注入 org/dept ns，复用它等于任意认证 agent 可显式写
    /// 共享 org 库（Memoria badge 并未授予）。
    #[test]
    fn feedback_write_gate_uses_raw_memoria_grant_not_enriched() {
        const SOURCE: &str = include_str!("collab.rs");
        const START_ANCHOR: &str = "pub(crate) async fn handle_memory_feedback(";
        const END_ANCHOR: &str = "pub(crate) fn clamp_memory_feedback_ns(";
        // 2 处：函数定义 + 本测试的锚点常量字面量（与 identity.rs 同口径）
        assert_eq!(SOURCE.matches(START_ANCHOR).count(), 2);
        assert!(SOURCE.matches(END_ANCHOR).count() >= 2);
        // 归一 CRLF → LF，后续断言不依赖行尾风格
        let body: String = SOURCE
            .split(START_ANCHOR)
            .nth(1)
            .and_then(|s| s.split(END_ANCHOR).next())
            .expect("handle_memory_feedback body")
            .replace("\r\n", "\n");
        assert!(!body.is_empty());
        // 从 ns_cache 取原始授予（(raw, enriched, ts) 三元组首项）
        assert!(body.contains("cache.get(&agent_id).map(|(raw, _, _)| raw.clone())"));
        // clamp 传入 write_ns（原始授予），而非 allowed_ns（enrich 后）
        assert!(body.contains("&write_ns"));
        assert!(!body.contains(
            "clamp_memory_feedback_ns(\n        &agent_id,\n        &allowed_ns,"
        ));
    }

    /// P1-1c 回归锁（2026-11-23 生产验证发现）：collab 可达闸必须用 Memoria
    /// 原始授予。enrich 注入的 dept_toolkit_ns 含 `dept/engineering`/`proj/gufei`，
    /// 复用 enrich 后 allowed_ns 等于任意认证 agent 可对整工程部（含
    /// approval_request）/整固废项目广播。
    #[test]
    fn collab_reachability_gate_uses_raw_memoria_grant() {
        const SOURCE: &str = include_str!("collab.rs");
        const START_ANCHOR: &str = "pub(crate) async fn handle_collab_send(";
        const END_ANCHOR: &str = "pub(crate) fn peers_ns_of(";
        // 2 处：函数定义 + 本测试的锚点常量字面量
        assert_eq!(SOURCE.matches(START_ANCHOR).count(), 2);
        assert!(SOURCE.matches(END_ANCHOR).count() >= 2);
        // 归一 CRLF → LF，后续断言不依赖行尾风格
        let body: String = SOURCE
            .split(START_ANCHOR)
            .nth(1)
            .and_then(|s| s.split(END_ANCHOR).next())
            .expect("handle_collab_send body")
            .replace("\r\n", "\n");
        assert!(!body.is_empty());
        // 从 ns_cache 取原始授予
        assert!(body.contains("cache.get(&agent_id).map(|(raw, _, _)| raw.clone())"));
        // 可达闸与 from_ns 都基于 reach_ns（原始授予）
        assert!(body.contains("collab_reachability(&agent_id, &reach_ns"));
        assert!(body.contains("reach_ns\n        .first()"));
        // 不得回退到 enrich 后的 allowed_ns
        assert!(!body.contains("collab_reachability(&agent_id, &allowed_ns"));
    }

    /// 行为对照：enrich 后的部门工具包 ns 会让非部门成员通过 dept/proj 可达闸，
    /// 原始授予（不含 dept ns）则正确拒绝——证明写闸用原始授予的必要性。
    #[test]
    fn dept_toolkit_enrichment_cannot_satisfy_reachability_alone() {
        let raw = vec!["agent/u1".to_string(), "org/co".to_string()];
        let enriched = vec![
            "agent/u1".to_string(),
            "org/co".to_string(),
            "org/co/dept/engineering/proj/gufei".to_string(),
        ];
        // 原始授予：非工程部成员，dept 广播拒绝
        assert!(collab_reachability("u1", &raw, "dept", "engineering", "notify").is_err());
        assert!(collab_reachability("u1", &raw, "proj", "gufei", "notify").is_err());
        // enrich 后列表：会误放行（这正是 handler 不得传它的原因）
        assert!(collab_reachability("u1", &enriched, "dept", "engineering", "notify").is_ok());
        assert!(collab_reachability("u1", &enriched, "proj", "gufei", "notify").is_ok());
    }
}