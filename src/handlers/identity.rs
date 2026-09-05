//! 身份 handler（从 src/main.rs 拆出，P6 重构）。
//!
//! 承载：register / register_user / login / documents_archive / agent_repair + 清洗辅助。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use rand::Rng;
use serde::{Deserialize, Serialize};

use agent_core::agent::{AgentConfig, AgentCore, AgentIdentity};
use agent_core::audit::AuditLogger;
use agent_core::boundary::PermissionLevel;
use agent_core::checkpoint::CheckpointStore;
use agent_core::harness::HarnessStore;
use agent_core::llm::{LlmConfig, LlmProvider};
use agent_core::metrics::MetricsRegistry;
use agent_core::resources::SharedResourceSnapshot;
use crate::auth::authenticate;
use crate::config::{env_memoria_admin_key, env_memoria_jarvis_badge, extract_register_badge, memoria_audit_client, memoria_proxy_client, Config};
use crate::state::AppState;


#[derive(Deserialize)]
pub(crate) struct RegisterRequest {
    name: String,
    department: String,
    company: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    div: String,
    /// 展示用中文姓名；不进 agent_id / namespace / HTTP 头。
    #[serde(default)]
    display_name: String,
    /// 展示用部门名（如「固废」）；技术部门码仍取 `department`。
    #[serde(default)]
    department_display: String,
}
#[derive(Serialize)]
pub(crate) struct RegisterResponse {
    ok: bool,
    agent_id: String,
    badge_token: String,
    namespace: String,
    error: Option<String>,
}

/// 个人账号注册（本地账密）—— user_id + password → 代理转发到 Memoria register_user。
/// 财务机等分发端连不到内网 Memoria，注册/登录必须经 agent-core 代理。
#[derive(Deserialize)]
pub(crate) struct RegisterUserRequest {
    user_id: String,
    password: String,
    #[serde(default)]
    display_name: String,
    /// 管理/HR 预置的命名空间（部门/项目级）。仅当携带合法 admin_key 时才生效，
    /// 否则忽略并回退到默认 org 根——防止普通自助注册自我提权到任意部门/项目。
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    admin_key: String,
}
#[derive(Deserialize)]
pub(crate) struct LoginRequest {
    user_id: String,
    password: String,
}
#[derive(Serialize)]
pub(crate) struct LoginResponse {
    ok: bool,
    user_id: String,
    display_name: String,
    badge_token: String,
    namespace: String,
    error: Option<String>,
}

/// user_id 严格清洗：作为 agent_id 会进入 HTTP 头与 session_id，必须 ASCII 安全。
/// 仅保留字母/数字/下划线/连字符/点，避免破坏头部或命名空间层级。
pub(crate) fn sanitize_user_id(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect::<String>()
        .trim()
        .to_string()
}

/// 命名空间分段白名单清洗：仅保留字母/数字/中文/下划线/连字符，
/// 防止 '/' 或控制字符破坏 org/.../dept/... 的层级路径（R5）
pub(crate) fn sanitize_ns_segment(s: &str) -> String {
    s.chars()
        .filter(|c| {
            c.is_alphanumeric()
                || *c == '_'
                || *c == '-'
                || ((*c as u32) >= 0x4e00 && (*c as u32) <= 0x9fff)
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// 协作通讯录展示名：「{部门展示}部{姓名}」；部门/姓名缺失时回退到可用值。
/// 仅用于 display_name，绝不进入 agent_id / namespace / HTTP 头。
pub(crate) fn agent_display_name(dept_display: &str, name_display: &str, fallback: &str) -> String {
    let dept = dept_display.trim();
    let name = name_display.trim();
    let base = if name.is_empty() { fallback } else { name };
    if dept.is_empty() {
        return base.to_string();
    }
    if dept.ends_with('部') {
        format!("{}{}", dept, base)
    } else {
        format!("{}部{}", dept, base)
    }
}

/// 调用者 allowed_ns 是否覆盖目标 ns（与 Memoria check_ns_access 同逻辑）
pub(crate) fn caller_ns_covers(allowed: &[String], target: &str) -> bool {
    if allowed.iter().any(|n| n == "*") {
        return true;
    }
    allowed.iter().any(|ns| {
        ns == target
            || target.starts_with(&format!("{}/", ns))
            || ns.starts_with(&format!("{}/", target))
    })
}

#[derive(Deserialize)]
pub(crate) struct ArchiveDocumentRequest {
    /// 本机绝对路径（PFAiX 对话栏附件）
    path: String,
    #[serde(default)]
    filename: String,
    /// 默认固废部门共享 ns
    #[serde(default)]
    namespace: String,
}

/// PFAiX 对话栏 → 部门共享文档归档：读本机文件，转发 Memoria `POST /api/documents`
pub(crate) async fn handle_documents_archive(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ArchiveDocumentRequest>,
) -> axum::response::Response {
    let (agent_id, allowed_ns) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let agent_key = headers
        .get("x-agent-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if agent_key.is_empty() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "缺少 X-Agent-Key"})),
        )
            .into_response();
    }

    let path = req.path.trim();
    if path.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "path 不能为空"})),
        )
            .into_response();
    }
    let p = std::path::Path::new(path);
    if !p.is_absolute() || !p.is_file() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "path 须为本机已存在的绝对文件路径"})),
        )
            .into_response();
    }

    let filename = if req.filename.trim().is_empty() {
        p.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("upload.bin")
            .to_string()
    } else {
        req.filename.trim().to_string()
    };
    let lower = filename.to_lowercase();
    if !(lower.ends_with(".pdf")
        || lower.ends_with(".docx")
        || lower.ends_with(".xlsx")
        || lower.ends_with(".xls"))
    {
        return (
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            axum::Json(serde_json::json!({"error": "仅支持 .pdf / .docx / .xlsx / .xls"})),
        )
            .into_response();
    }

    let namespace = if req.namespace.trim().is_empty() {
        "org/cs-pufa-2nd-thermal/dept/engineering/proj/gufei".to_string()
    } else {
        req.namespace.trim().to_string()
    };
    if !caller_ns_covers(&allowed_ns, &namespace) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": format!("无权限写入命名空间 {namespace}")
            })),
        )
            .into_response();
    }

    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": format!("无法读取文件: {e}")})),
            )
                .into_response();
        }
    };
    const MAX: u64 = 20 * 1024 * 1024;
    if meta.len() > MAX {
        return (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            axum::Json(serde_json::json!({"error": "文件过大（上限 20 MiB）"})),
        )
            .into_response();
    }
    let bytes = match std::fs::read(p) {
        Ok(b) => b,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": format!("读文件失败: {e}")})),
            )
                .into_response();
        }
    };

    let server = { st.config.lock().await.server.clone() };
    let mime = if lower.ends_with(".pdf") {
        "application/pdf"
    } else if lower.ends_with(".docx") {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    } else if lower.ends_with(".xlsx") {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    } else {
        "application/vnd.ms-excel"
    };
    let part = match reqwest::multipart::Part::bytes(bytes)
        .file_name(filename.clone())
        .mime_str(mime)
    {
        Ok(p) => p,
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error": format!("构造上传部件失败: {e}")})),
            )
                .into_response();
        }
    };
    let form = reqwest::multipart::Form::new()
        .text("namespace", namespace.clone())
        .part("file", part);

    let client = reqwest::Client::new();
    let url = format!("{}/api/documents", server.trim_end_matches('/'));
    match client
        .post(&url)
        .header("X-Agent-Id", &agent_id)
        .header("X-Agent-Key", &agent_key)
        .multipart(form)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let code = axum::http::StatusCode::from_u16(status.as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                (code, axum::Json(v)).into_response()
            } else {
                (
                    code,
                    axum::Json(serde_json::json!({
                        "error": if body.is_empty() { status.to_string() } else { body }
                    })),
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({
                "error": format!("转发 Memoria 失败: {e}")
            })),
        )
            .into_response(),
    }
}

pub(crate) async fn handle_register(
    State(st): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Json<RegisterResponse> {
    // 公司名为固定常量（部署时确定），禁止客户端篡改，避免命名空间 org/ 前缀漂移。
    // P0 修复：技术命名空间必须使用 ASCII（HTTP 头与 session_id 均不接受非 ASCII），
    // 中文名「常熟浦发第二热电能源有限公司」仅作 Jan UI 展示（OnboardingScreen），不进入 agent_id/namespace。
    // 须与 agent.toml 的 mcp_source namespace org/ 前缀保持一致。
    const COMPANY: &str = "cs-pufa-2nd-thermal";
    // 命名空间分段做字符白名单清洗，避免 '/' 或特殊字符破坏层级路径（R5）
    let department = sanitize_ns_segment(&req.department);
    let div = sanitize_ns_segment(&req.div);
    let project = sanitize_ns_segment(&req.project);
    let name = sanitize_ns_segment(&req.name);
    if department.is_empty() || name.is_empty() {
        return Json(RegisterResponse {
            ok: false,
            agent_id: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("部门或姓名包含非法字符".to_string()),
        });
    }
    let agent_id = format!("{}_{}_{}", COMPANY, department, name);
    let display_name = if req.display_name.trim().is_empty() {
        name.clone()
    } else {
        req.display_name.trim().to_string()
    };
    let department_display = if req.department_display.trim().is_empty() {
        department.clone()
    } else {
        req.department_display.trim().to_string()
    };
    let memoria_display_name = agent_display_name(&department_display, &display_name, &agent_id);
    // B2 双 ns（与 /api/register_user、legacy 自动开户一致）：
    //   1) agent/{agent_id} —— 私人记忆隔离
    //   2) org/.../dept/... —— 部门/组织共享（工具可见 + 部门记忆）
    // 此前本路径只写了 org 树，漏挂私人 ns，属相对 B2 拍板的实现漂移。
    // 层级：org/{company}[/div/{div}]/dept/{department}[/proj/{project}]
    let mut org_ns = if div.is_empty() {
        format!("org/{}/dept/{}", COMPANY, department)
    } else {
        format!("org/{}/div/{}/dept/{}", COMPANY, div, department)
    };
    if !project.is_empty() {
        org_ns = format!("{}/proj/{}", org_ns, project);
    }
    let namespace = format!("agent/{},{}", agent_id, org_ns);
    // 先生成一个本地兜底 token；若 Memoria 注册成功，会用 Memoria 实际返回的 badge 覆盖（P0 修复：必须一致，否则客户端 key 与 Memoria 存值不符导致鉴权失败）
    let mut badge_token = format!("sk-{:x}", rand::thread_rng().gen::<u128>());

    // 注册到 Memoria — admin_key 作参数；MCP 身份用 jarvis/admin 配对客户端
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    // P0 修复：以 jarvis（或 admin）配对身份代理注册，
    // 禁止 cfg.agent_id="user" + jarvis badge（Memoria -32001）。
    let server = {
        let cfg = st.config.lock().await;
        cfg.server.clone()
    };
    let mcp = memoria_proxy_client(&server, &cfg_admin);
    // P0 修复：Memoria 的 register_agent 会自行生成 badge 并在响应里返回；
    // 必须用它作为后续鉴权 key，否则客户端拿本地随机 token 与 Memoria 存值对不上 → -32001。
    let memoria_ok = if admin_key.is_empty() {
        false
    } else {
        match mcp
            .call_json(
                "register_agent",
                &serde_json::json!({
                    "agent_id": &agent_id,
                    "display_name": &memoria_display_name,
                    "admin_key": &admin_key,
                    "namespace": &namespace,
                }),
            )
            .await
        {
            Ok(text) => {
                if let Some(b) = extract_register_badge(&text) {
                    badge_token = b;
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    };

    // 缓存身份（使用 admin key 写入 Memoria 后，auth_cache 也存一份）
    // P2-10: 记录创建时间用于 TTL
    if memoria_ok {
        st.auth_cache.lock().await.insert(
            agent_id.clone(),
            (badge_token.clone(), std::time::Instant::now()),
        );
        // 管理员名单提权：display_name（中文名）命中 AGENT_ADMIN_NAMES 的注册者，
        // 自动提升 permission=admin + namespace 追加 `*`——PFAiX 用自己身份即可见审批，
        // 无需在每台客户端手动填 MEMORIA_ADMIN_KEY（老大反馈：手动填 key 多此一举且有泄密面）。
        let admin_names = std::env::var("AGENT_ADMIN_NAMES").unwrap_or_default();
        let is_admin_reg = admin_names
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .any(|n| {
                n == display_name.trim()
                    || n == name.trim()
                    || n == agent_id
            });
        if is_admin_reg {
            let admin_key2 = env_memoria_admin_key(&cfg_admin);
            let mcp2 = memoria_proxy_client(&server, &cfg_admin);
            let admin_ns = if namespace.contains('*') {
                namespace.clone()
            } else {
                format!("{},*", namespace)
            };
            let _ = mcp2
                .call_json(
                    "agent_update",
                    &serde_json::json!({
                        "agent_id": &agent_id,
                        "admin_key": &admin_key2,
                        "namespace": &admin_ns,
                        "permission": "admin",
                    }),
                )
                .await;
            tracing::info!(target: "agent.register", agent=%agent_id, "管理员名单命中，已提权 admin");
        }
    }

    // 审计日志：记录身份注册（admin + ADMIN_KEY，禁止 admin + jarvis badge）
    let audit = AuditLogger::new(memoria_audit_client(&server, &cfg_admin));
    audit
        .log_identity(
            &agent_id,
            "register",
            &format!(
                "name={}, department={}, company={}, div={}, project={}",
                req.name, req.department, req.company, req.div, req.project
            ),
        )
        .await;

    if !memoria_ok {
        return Json(RegisterResponse {
            ok: false,
            agent_id: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some(
                "Memoria 注册失败：请确认 agent-core 已加载 MEMORIA_ADMIN_KEY，且 Memoria(:9003) 可用"
                    .into(),
            ),
        });
    }

    Json(RegisterResponse {
        ok: true,
        agent_id,
        badge_token,
        namespace,
        error: None,
    })
}

#[derive(Deserialize)]
pub(crate) struct AgentRepairRequest {
    agent_id: String,
    /// 技术部门码（如 gufei）；提供时会重建 `agent/{id},org/.../dept/...[/proj/...]`。
    #[serde(default)]
    department: String,
    #[serde(default)]
    project: String,
    /// 展示用中文姓名；与 department_display 组成「固废部张三」。
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    department_display: String,
    #[serde(default)]
    permission: String,
}

/// 修复已注册 Agent 的协作档案（admin）：更新 Memoria display_name / namespace / permission，
/// 不更换 badge_token，避免已分发客户端凭证失效。
pub(crate) async fn handle_agent_repair(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AgentRepairRequest>,
) -> axum::response::Response {
    let (caller_id, allowed_ns) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let is_admin = caller_id == "admin" || allowed_ns.iter().any(|n| n == "*");
    if !is_admin {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "需要 admin 身份"})),
        )
            .into_response();
    }

    let agent_id = req.agent_id.trim().to_string();
    if agent_id.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "agent_id 必填"})),
        )
            .into_response();
    }

    const COMPANY: &str = "cs-pufa-2nd-thermal";
    let department = sanitize_ns_segment(&req.department);
    let project = sanitize_ns_segment(&req.project);
    let namespace = if department.is_empty() {
        String::new()
    } else {
        let mut org_ns = format!("org/{}/dept/{}", COMPANY, department);
        if !project.is_empty() {
            org_ns = format!("{}/proj/{}", org_ns, project);
        }
        format!("agent/{},{}", agent_id, org_ns)
    };

    let fallback_name = agent_id.rsplit('_').next().unwrap_or(agent_id.as_str());
    let display_name = if req.display_name.trim().is_empty() && req.department_display.trim().is_empty() {
        String::new()
    } else {
        agent_display_name(
            req.department_display.trim(),
            if req.display_name.trim().is_empty() {
                fallback_name
            } else {
                req.display_name.trim()
            },
            &agent_id,
        )
    };
    let permission = req.permission.trim();

    if namespace.is_empty() && display_name.is_empty() && permission.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "至少提供 department / display_name / permission 之一"})),
        )
            .into_response();
    }

    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    if admin_key.is_empty() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error": "MEMORIA_ADMIN_KEY 未配置"})),
        )
            .into_response();
    }
    let server = {
        let cfg = st.config.lock().await;
        cfg.server.clone()
    };
    let mcp = memoria_proxy_client(&server, &cfg_admin);
    let mut args = serde_json::json!({
        "agent_id": &agent_id,
        "admin_key": &admin_key,
    });
    if !display_name.is_empty() {
        args["display_name"] = serde_json::Value::String(display_name.clone());
    }
    if !namespace.is_empty() {
        args["namespace"] = serde_json::Value::String(namespace.clone());
    }
    if !permission.is_empty() {
        args["permission"] = serde_json::Value::String(permission.to_string());
    }

    match mcp.call_json("agent_update", &args).await {
        Ok(v) => {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status == "updated" {
                axum::Json(serde_json::json!({
                    "ok": true,
                    "agent_id": v.get("agent_id").and_then(|x| x.as_str()).unwrap_or(&agent_id),
                    "display_name": v.get("display_name").and_then(|x| x.as_str()).unwrap_or(&display_name),
                    "namespace": v.get("namespace").and_then(|x| x.as_str()).unwrap_or(&namespace),
                    "permission": v.get("permission").and_then(|x| x.as_str()).unwrap_or(permission),
                }))
                .into_response()
            } else {
                let msg = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("agent_update 失败");
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    axum::Json(serde_json::json!({"error": msg})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({"error": format!("Memoria agent_update 不可用: {}", e)})),
        )
            .into_response(),
    }
}

/// 个人账号注册代理：转发到 Memoria `register_user`（以 admin 身份）。
/// 命名空间在此层追加部署级 org（cs-pufa-2nd-thermal），使登录用户获得 dashboard 等
/// 共享工具可见性，同时保留 agent/{user_id} 作个人记忆隔离。
pub(crate) async fn handle_register_user(
    State(st): State<Arc<AppState>>,
    Json(req): Json<RegisterUserRequest>,
) -> Json<LoginResponse> {
    let user_id = sanitize_user_id(&req.user_id);
    if user_id.is_empty() || user_id != req.user_id.trim() {
        return Json(LoginResponse {
            ok: false,
            user_id: String::new(),
            display_name: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("用户名仅允许字母/数字/下划线/连字符/点".to_string()),
        });
    }
    if req.password.len() < 6 {
        return Json(LoginResponse {
            ok: false,
            user_id: String::new(),
            display_name: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("口令至少 6 位".to_string()),
        });
    }
    let display_name = if req.display_name.trim().is_empty() {
        user_id.clone()
    } else {
        req.display_name.trim().to_string()
    };
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let jarvis_badge = env_memoria_jarvis_badge(&cfg_admin);
    if admin_key.is_empty() || jarvis_badge.is_empty() {
        return Json(LoginResponse {
            ok: false,
            user_id: String::new(),
            display_name: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("服务未就绪，请稍后重试".to_string()),
        });
    }
    // 默认命名空间：个人 agent + 组织根（可见 org 下全部共享工具）。
    // HR/管理员（持 admin_key）可预置部门/项目命名空间；否则回退默认（个人 agent + 组织根）。
    // 始终携带 effective_ns 作为 register_user 的 `namespace` 参数（与 Memoria dispatch 读取的
    // 键名一致；此前误用 namespace_override 导致覆盖被静默丢弃），使自助注册员工也能获得
    // org 根可见性；权限提升仅限持合法 admin_key 者，杜绝普通用户越权指定命名空间。
    let default_ns = format!("agent/{},org/cs-pufa-2nd-thermal", user_id);
    let effective_ns = if !req.admin_key.is_empty()
        && req.admin_key == admin_key
        && !req.namespace.trim().is_empty()
    {
        req.namespace.trim().to_string()
    } else {
        default_ns.clone()
    };
    // 以 jarvis/admin 配对客户端调 Memoria（permission=admin），
    // 可代理 register_user/login_user；不得与 MEMORIA_ADMIN_KEY 同 token。
    let server = {
        let cfg = st.config.lock().await;
        cfg.server.clone()
    };
    let mcp = memoria_proxy_client(&server, &cfg_admin);
    match mcp
        .call_json(
            "register_user",
            &serde_json::json!({
                "user_id": &user_id,
                "display_name": &display_name,
                "password": &req.password,
                "namespace": effective_ns.clone(),
            }),
        )
        .await
    {
        Ok(v) => {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status == "registered" {
                Json(LoginResponse {
                    ok: true,
                    user_id,
                    display_name,
                    badge_token: String::new(),
                    namespace: effective_ns,
                    error: None,
                })
            } else {
                let msg = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("注册失败")
                    .to_string();
                Json(LoginResponse {
                    ok: false,
                    user_id: String::new(),
                    display_name: String::new(),
                    badge_token: String::new(),
                    namespace: String::new(),
                    error: Some(msg),
                })
            }
        }
        Err(_) => Json(LoginResponse {
            ok: false,
            user_id: String::new(),
            display_name: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("Memoria 暂时不可用".to_string()),
        }),
    }
}

/// 个人账号登录代理：转发到 Memoria `login_user`（以 admin 身份），
/// 成功回传 badge_token，客户端存储后作为 x-agent-id / x-agent-key 用于聊天鉴权。
pub(crate) async fn handle_login(
    State(st): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Json<LoginResponse> {
    let user_id = sanitize_user_id(&req.user_id);
    if user_id.is_empty() || req.password.is_empty() {
        return Json(LoginResponse {
            ok: false,
            user_id: String::new(),
            display_name: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("用户名或口令错误".to_string()),
        });
    }
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let jarvis_badge = env_memoria_jarvis_badge(&cfg_admin);
    if admin_key.is_empty() || jarvis_badge.is_empty() {
        return Json(LoginResponse {
            ok: false,
            user_id: String::new(),
            display_name: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("服务未就绪，请稍后重试".to_string()),
        });
    }
    // P0 修复：以 jarvis/admin 配对客户端代理登录，
    // 禁止 cfg.agent_id="user" + jarvis badge。
    let server = {
        let cfg = st.config.lock().await;
        cfg.server.clone()
    };
    let mcp = memoria_proxy_client(&server, &cfg_admin);
    match mcp
        .call_json(
            "login_user",
            &serde_json::json!({
                "user_id": &user_id,
                "password": &req.password,
            }),
        )
        .await
    {
        Ok(v) => {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status == "ok" {
                let badge_token = v
                    .get("badge_token")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let display_name = v
                    .get("display_name")
                    .and_then(|s| s.as_str())
                    .unwrap_or(&user_id)
                    .to_string();
                let namespace = v
                    .get("namespace")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                // 登录成功即写入 auth_cache，减少首条聊天的鉴权往返
                st.auth_cache.lock().await.insert(
                    user_id.clone(),
                    (badge_token.clone(), std::time::Instant::now()),
                );
                Json(LoginResponse {
                    ok: true,
                    user_id,
                    display_name,
                    badge_token,
                    namespace,
                    error: None,
                })
            } else {
                Json(LoginResponse {
                    ok: false,
                    user_id: String::new(),
                    display_name: String::new(),
                    badge_token: String::new(),
                    namespace: String::new(),
                    error: Some("用户名或口令错误".to_string()),
                })
            }
        }
        Err(_) => Json(LoginResponse {
            ok: false,
            user_id: String::new(),
            display_name: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("Memoria 暂时不可用".to_string()),
        }),
    }
}

pub(crate) async fn build_agent(
    config: &Config,
    local_resources: SharedResourceSnapshot,
    metrics: Arc<MetricsRegistry>,
) -> Result<AgentCore, String> {
    // K3：身份 badge 与 admin 钥匙分钥（badge_token UNIQUE）
    let admin_key = if !config.memoria_admin_key.is_empty() {
        config.memoria_admin_key.clone()
    } else {
        env_memoria_admin_key("")
    };
    let badge_token = env_memoria_jarvis_badge(&admin_key);
    let admin_key = if !admin_key.is_empty() {
        admin_key
    } else if !badge_token.is_empty() {
        // 过渡：未设 admin 时勿把 dashboard badge 当 admin（UNIQUE 风险）；仅兼容空配置联调
        badge_token.clone()
    } else {
        config.api_key.clone()
    };

    // 以 jarvis/admin 配对身份代理注册本机 agent；成功则采用返回的 badge 作为运行时身份。
    // 禁止 agent_id="user" + jarvis badge（Memoria -32001，启动注册会静默失败）。
    let proxy = memoria_proxy_client(&config.server, &admin_key);
    let mut runtime_badge = badge_token.clone();
    if let Ok(text) = proxy
        .call_json(
            "register_agent",
            &serde_json::json!({
                "agent_id": &config.agent_id,
                "display_name": &config.agent_id,
                "admin_key": &admin_key,
                "namespace": format!("agent/{}", config.agent_id),
            }),
        )
        .await
    {
        if let Some(b) = extract_register_badge(&text) {
            runtime_badge = b;
        }
    }

    // P2-C: 从 agent_id 解析多租户命名空间（handle_register 格式：{company}_{department}_{name}）
    let ns_full_path = {
        let parts: Vec<&str> = config.agent_id.splitn(3, '_').collect();
        if parts.len() == 3 {
            Some(format!(
                "/dept/{}/project/{}/user/{}",
                parts[0], parts[1], parts[2]
            ))
        } else {
            None
        }
    };

    let identity = AgentIdentity {
        agent_id: config.agent_id.clone(),
        namespace: format!("agent/{}", config.agent_id),
        badge_token: runtime_badge.clone(),
        ns_full_path,
        persona_id: None,
        owner_user_id: None,
        workspace_dir: None,
        tool_allowlist: Vec::new(),
        memory_namespace: None,
    };
    // P0-1: LLM 池来源优先级：agent.toml 的 [llm] 段（用户显式配置）> 旧硬编码 deepseek 主 + DOUBAO_API_KEY 备用
    // 圆桌多 LLM 自动分配复用此池（llm_pool = 主 + fallbacks）
    let llm_config = if let Some(explicit) = &config.llm {
        // ${ENV} 已在 load_or_create_config().expand_config_llm_env 统一展开
        // （全局池 + 分身池 + code_evolution 池三处一处搞定），此处直接 clone 即可，
        // 不再重复展开，彻底消除「load 展开分身 / build 展开全局」的分裂导致漏字段。
        explicit.clone()
    } else {
        let doubao_key = std::env::var("DOUBAO_API_KEY").unwrap_or_default();
        let fallbacks = if !doubao_key.is_empty() {
            vec![LlmProvider {
                base_url: "https://ark.cn-beijing.volces.com/api/v3".to_string(),
                model: "doubao-lite-32k".to_string(),
                api_key: doubao_key,
                chat_path: "/chat/completions".to_string(),
            }]
        } else {
            Vec::new()
        };
        LlmConfig {
            api_key: config.api_key.clone(),
            fallbacks,
            ..Default::default()
        }
    };
    let mut additional_mcp = Vec::new();
    for src in &config.mcp_source {
        if !src.command.is_empty() {
            additional_mcp.push((
                src.name.clone(),
                src.url.clone(),
                src.token.clone(),
                Some((src.command.clone(), src.args.clone())),
                src.namespace.clone(),
            ));
        } else {
            additional_mcp.push((
                src.name.clone(),
                src.url.clone(),
                src.token.clone(),
                None,
                src.namespace.clone(),
            ));
        }
    }
    // L2：从 [safety] approval_mode 推导人工审批通道。
    // HumanInLoop → 开启 human_approval（危险工具改走 dashboard 审批台，真人兜底），
    // 审批人固定标识 dashboard-admin（由 dashboard 审批台经 HTTP 回执，非 AI agent，避免 AI 批 AI）。
    let safety_cfg = config.safety.clone().unwrap_or_default();
    let human_approval =
        safety_cfg.approval_mode == agent_core::meta_evolve::ApprovalMode::HumanInLoop;
    let approver_id = if human_approval {
        Some("dashboard-admin".to_string())
    } else {
        None
    };
    let agent_config = AgentConfig {
        identity,
        llm: llm_config,
        memoria_url: config.server.clone(),
        additional_mcp,
        skill_whitelist: None,
        max_tool_rounds: 20, // P0 调优：固废多步推理(进厂调度/称重/企业信息多步查询)需更多轮次，原 3 轮易过早触顶"轮数耗尽"
        parent_permission: PermissionLevel::Write,
        enable_compositional_routing: true,
        compositional_preview: true, // P1-2: 企业默认开启计划预览（HITL）
        strict_schema: false,        // P1-4: 默认回灌 LLM 修正参数（非严格报错）
        system_prompt_template: None, // P2-3: 使用内置默认模板
        approver_id,                 // L2: HumanInLoop → dashboard-admin 审批台
        human_approval,              // L2: 人工审批通道（真人兜底）
        meta_evolution: config.meta_evolution.clone().unwrap_or_default(),
        safety: safety_cfg,
        gateway_approval: config.gateway_approval.clone().unwrap_or_default(),
        features: config.features.clone(),
        lats: config.lats.clone(),
        multiagent: config.multiagent.clone(),
        ttc: config.ttc.clone(),
        intake_filter: config.intake_filter.clone().unwrap_or_default(),
        orchestration: config.orchestration.clone().unwrap_or_default(),
        tool_overrides: config
            .boundary
            .as_ref()
            .map(|b| {
                let mut pairs = Vec::new();
                for i in &b.tool_overrides {
                    match agent_core::boundary::ToolClass::parse(&i.level) {
                        Some(level) => pairs.push((i.tool.clone(), level)),
                        None => tracing::error!(
                            target = "boundary",
                            tool = %i.tool,
                            level = %i.level,
                            "agent.toml [boundary.tool_overrides] 非法级别，跳过该条——operator 的收紧被丢弃，工具保持默认启发式级别（仅接受 read/write/dangerous/unknown）"
                        ),
                    }
                }
                pairs
            })
            .unwrap_or_default(),
    };
    // A1 (OpenClaw 吸收): 记录启动并判定是否进入 safe_mode（崩溃循环保护）。
    // 返回 (启动记录 id, 是否需抑制危险/未分类/外发工具自动执行)。
    let (boot_id, boot_safe) = agent_core::boot_lifecycle::enter_phase_a();
    let cwd = std::env::current_dir().unwrap_or_default();
    let harness = HarnessStore::open(&cwd.join("harness.db").to_string_lossy())
        .map_err(|e| format!("创建 Harness 存储失败: {}", e))?;
    let checkpoint = CheckpointStore::open(&cwd.join("checkpoints.db").to_string_lossy())
        .map_err(|e| format!("创建 Checkpoint 存储失败: {}", e))?;
    let agent = AgentCore::new(
        agent_config,
        harness,
        checkpoint,
        local_resources,
        metrics,
    );
    // A1: safe_mode 激活时，抑制危险/未分类/外发工具的自动执行（需人工介入解除）。
    {
        let b = agent.boundary.lock().await;
        b.set_safe_mode(boot_safe);
    }
    // A3 (OpenClaw 吸收): 挂载本地耐久审计库（与 harness/checkpoint 同目录）。
    let audit_db = cwd.join("audit_events.db").to_string_lossy().to_string();
    agent.audit_logger.attach_db(&audit_db);
    // P2-C: 同步 Memoria 注册的 namespace 到本地 NamespaceRegistry
    agent.sync_namespace_from_identity();
    // A1: 本次启动健康完成，标记后不再计入「不干净启动」。
    agent_core::boot_lifecycle::mark_healthy(boot_id);
    Ok(agent)
}