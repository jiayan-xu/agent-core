//! 鉴权层（从 src/main.rs 拆出，P3 重构）。
//!
//! 承载：`authenticate`（X-Agent-Id/X-Agent-Key → Memoria 反查 allowed_ns）、
//! `auth_middleware`（统一鉴权中间件 + 豁免路径）、`AuthContext`（extension 身份）。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::IntoResponse;

use agent_core::mcp_client::McpClient;

use crate::config::{env_memoria_admin_key, extract_register_badge, memoria_proxy_client};
use crate::state::AppState;

/// 构造 401 未授权响应
pub(crate) fn unauthorized(message: &str) -> axum::response::Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "unauthorized", "message": message})),
    )
        .into_response()
}

/// 身份认证：从 header 取 X-Agent-Id + X-Agent-Key，向 Memoria 反查调用者命名空间授权。
/// 成功返回 (agent_id, allowed_ns)；失败返回 401 Response（由调用方 ? 直接返回）。
/// PFAiX toAsciiHeaderValue 的 percent-encode 解码：还原含中文的 agent_id。
/// 仅解码 `%XX`（UTF-8 字节），保留其余字符原样（agent_id 本是 ASCII 安全集）。
pub(crate) fn percent_decode_agent_id(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) async fn authenticate(
    headers: &axum::http::HeaderMap,
    st: &Arc<AppState>,
) -> Result<(String, Vec<String>), axum::response::Response> {
    // 主身份来自 x-agent-id；PFAiX 分发版只发 x-user-tag（随机安装ID），
    // 故在其为空时回退到 x-user-tag，实现「安装即身份」。
    let raw_agent_id = headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // PFAiX 对含中文的 agent_id 做 percent-encode（toAsciiHeaderValue），
    // 此处解码还原真实 agent_id，否则 badge 认证失败、协作审批不可见。
    let raw_agent_id = percent_decode_agent_id(&raw_agent_id);
    let user_tag = headers
        .get("x-user-tag")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let (agent_id, from_usertag) = if !raw_agent_id.is_empty() {
        (raw_agent_id, false)
    } else if !user_tag.is_empty() {
        (user_tag, true)
    } else {
        // P2-2：鉴权失败审计（无身份）
        if let Some(ref a) = *st.agent.lock().await {
            a.audit_logger
                .auth_fail("", "缺少身份标识（x-agent-id / x-user-tag 均未提供）")
                .await;
        }
        return Err(unauthorized("请先通过 /api/register 注册身份"));
    };

    // 鉴权密钥：显式 x-agent-key 优先；legacy usertag 优先用 auth_cache 中注册返回的 badge，
    // 禁止长期拿 jarvis badge 冒充安装实例身份（get_allowed_ns 会 -32001）。
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let cached_badge = {
        let cache = st.auth_cache.lock().await;
        cache.get(&agent_id).map(|(b, _)| b.clone())
    };
    let agent_key = if !from_usertag {
        headers
            .get("x-agent-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    } else if let Some(b) = cached_badge.clone() {
        b
    } else {
        // 首次 usertag：尚无 cache，先用空 key 走注册分支（勿用 jarvis 冒充）
        String::new()
    };
    let server = {
        let cfg = st.config.lock().await;
        cfg.server.clone()
    };
    let mut allowed_ns: Vec<String> = {
        let cache = st.ns_cache.lock().await;
        cache
            .get(&agent_id)
            .filter(|(_, ts)| ts.elapsed() < Duration::from_secs(60))
            .map(|(ns, _)| ns.clone())
            .unwrap_or_default()
    };
    if allowed_ns.is_empty() {
        let mcp = McpClient::new(&server, &agent_id, &agent_key);
        match mcp
            .call_json("get_allowed_ns", &serde_json::json!({}))
            .await
        {
            Ok(v) => {
                allowed_ns = v
                    .get("allowed_ns")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            Err(_) => {}
        }
        // 安装实例首次使用：Memoria 中尚无该身份 → 以管理员身份自动注册为公司组织成员，
        // 使其获得基础命名空间（org 根），随后即可通过鉴权闸门。
        // 仅 legacy 模式（无 x-agent-id，仅 x-user-tag 的 PFAiX 自动开户）才用 admin key 自动注册。
        // 登录模式（x-agent-id 已带 user_id）若身份不存在，必须走 Memoria `register_user`
        // 建号（带口令），禁止此处用 admin key 无口令自动建号，否则口令形同虚设。
        if allowed_ns.is_empty() && !admin_key.is_empty() && from_usertag {
            // B2（选项2）：每个 PFAiX 安装实例分配独立 `agent/{install_id}` ns，
            // 使安装间身份彼此隔离；同时保留组织级 ns `org/cs-pufa-2nd-thermal`，
            // 以维持 dashboard 等共享工具的可见性（其 mcp_source 位于 org/… 子树，
            // 工具门控依赖 allowed_ns 覆盖该子树，见 agent.toml）。两 ns 以逗号写入
            // 同一 namespace 字段，Memoria `get_allowed_ns` 会按逗号拆分回传，从而
            // 后续请求（缓存失效后重查）仍同时持有这两个 ns，不会因回读而丢失 dashboard。
            let install_ns = format!("agent/{},org/cs-pufa-2nd-thermal", agent_id);
            // 身份 = jarvis/admin 配对客户端；admin_key 仅作 register 参数
            let reg = memoria_proxy_client(&server, &cfg_admin);
            if let Ok(text) = reg
                .call_json(
                    "register_agent",
                    &serde_json::json!({
                        "agent_id": &agent_id,
                        "display_name": &agent_id,
                        "admin_key": &admin_key,
                        "namespace": &install_ns
                    }),
                )
                .await
            {
                if let Some(b) = extract_register_badge(&text) {
                    st.auth_cache
                        .lock()
                        .await
                        .insert(agent_id.clone(), (b, std::time::Instant::now()));
                }
            }
            allowed_ns = vec![
                format!("agent/{}", agent_id),
                "org/cs-pufa-2nd-thermal".to_string(),
            ];
        }
        // 登录态 badge 失效自愈（新增）：客户端携带 x-agent-id + 失配/过期 badge，
        // 因 Memoria 注册表重建或凭证漂移，该 agent 在 audit.db 无有效注册。
        // 以 jarvis 身份代为重新注册同一 agent_id（沿用 legacy 安装实例相同机制），
        // 恢复其 ns 授权，免客户端手动重走 Onboarding。仅对已携带 agent_id 的
        // 请求生效，不开匿名建号。注：会为登录态 agent 重建无口令注册，单组织
        // 内网可接受；若需严格口令边界，删除此块即可回滚。
        if allowed_ns.is_empty() && !admin_key.is_empty() && !from_usertag {
            let reg = memoria_proxy_client(&server, &cfg_admin);
            if let Ok(text) = reg
                .call_json(
                    "register_agent",
                    &serde_json::json!({
                        "agent_id": &agent_id,
                        "display_name": &agent_id,
                        "admin_key": &admin_key,
                        "namespace": &format!("agent/{},org/cs-pufa-2nd-thermal", agent_id)
                    }),
                )
                .await
            {
                if let Some(b) = extract_register_badge(&text) {
                    // 自愈后写入 cache；客户端旧 key 仍可能漂移，但下轮 usertag/同 id 可用
                    st.auth_cache
                        .lock()
                        .await
                        .insert(agent_id.clone(), (b, std::time::Instant::now()));
                }
            }
            // 与 legacy 安装实例自动开户保持一致：注册成功后直接授权该 agent 的
            // 命名空间，不依赖 register 返回值（register 仅用于恢复 Memoria 注册，
            // 授权由下方 allowed_ns 兜底，确保登录态 badge 漂移时不再 401）。
            allowed_ns = vec![
                format!("agent/{}", agent_id),
                "org/cs-pufa-2nd-thermal".to_string(),
            ];
        }
        if allowed_ns.is_empty() {
            // P2-2：鉴权失败审计（身份校验未通过）
            if let Some(ref a) = *st.agent.lock().await {
                a.audit_logger
                    .auth_fail(&agent_id, "身份校验未通过（Memoria 未返回授权命名空间）")
                    .await;
            }
            // 不向外部暴露内部错误细节（R6）
            return Err(unauthorized("身份校验失败，请稍后重试"));
        }
        // P0：固废本部门工具包 ns  enrichment，保证 dashboard 技能可见
        agent_core::dept_ops::enrich_allowed_ns(&mut allowed_ns);
        st.ns_cache.lock().await.insert(
            agent_id.clone(),
            (allowed_ns.clone(), std::time::Instant::now()),
        );
    }
    Ok((agent_id, allowed_ns))
}

#[derive(Clone)]
pub(crate) struct AuthContext {
    pub(crate) agent_id: String,
    pub(crate) allowed_ns: Vec<String>,
}

/// 统一鉴权中间件。成功时把身份写入 extension；失败直接返回 401。
/// 豁免路径：静态壳 / 健康检查 / 注册/登录 onboarding。
pub(crate) async fn auth_middleware(
    State(st): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    let path = request.uri().path();
    let exempt = path == "/"
        || path == "/health"
        || path == "/api/register"
        || path == "/api/register_user"
        || path == "/api/login"
        || path == "/api/config";
    if exempt {
        return next.run(request).await;
    }
    match authenticate(request.headers(), &st).await {
        Ok((agent_id, allowed_ns)) => {
            let mut req = request;
            req.extensions_mut().insert(AuthContext {
                agent_id,
                allowed_ns,
            });
            next.run(req).await
        }
        Err(resp) => resp,
    }
}
