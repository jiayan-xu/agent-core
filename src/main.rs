//! agent-core Desktop — 双击即用，零配置
//!
//! 内嵌 WebView（无浏览器），系统托盘图标。
//! 首次运行自动打开配置页，填个名字和密钥就能聊。
//! 内置巡检循环：每 30 分钟调用 Dashboard MCP 执行定时任务。

// P2-1 修复：仅 release 模式下隐藏控制台窗口，debug 模式保留
// --service 模式仍需控制台输出用于调试，通过 Cargo features 控制
#![cfg_attr(all(not(debug_assertions), not(feature = "service")), windows_subsystem = "windows")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::convert::Infallible;
use std::collections::HashMap;
use axum::{
    Router, routing::{get, post, delete},
    Json, extract::State, response::{sse::{Sse, Event as SseEvent}, IntoResponse},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

use agent_core::agent::{AgentConfig, AgentCore, AgentIdentity};
use agent_core::audit::AuditLogger;
use agent_core::boundary::PermissionLevel;
use agent_core::harness::HarnessStore;
use agent_core::llm::LlmConfig;
use agent_core::mcp_client::McpClient;

/// 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    agent_id: String,
    #[serde(default)]
    api_key: String,
    #[serde(default = "default_server")]
    server: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    memoria_admin_key: String,
    #[serde(default)]
    mcp_source: Vec<McpSourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpSourceConfig {
    name: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    token: String,
    /// stdio 模式：可执行文件路径
    #[serde(default)]
    command: String,
    /// stdio 模式：命令行参数
    #[serde(default)]
    args: Vec<String>,
    /// 该 MCP 源所属命名空间（可选）。用于按调用者 allowed_ns 过滤可见工具。
    /// 例：`dept/工程部/proj/P1` 仅对该命名空间及其祖先/后代可见；留空=全局可见。
    #[serde(default)]
    namespace: Option<String>,
}

fn default_server() -> String { "http://127.0.0.1:9003".to_string() }
fn default_port() -> u16 { 9753 }

impl Config {
    fn configured(&self) -> bool {
        !self.agent_id.is_empty() && !self.api_key.is_empty()
    }
}

#[derive(Debug, Deserialize)]
struct ChatRequest { message: String, #[serde(default = "default_sid")] session_id: String }
fn default_sid() -> String { "default".to_string() }
#[derive(Debug, Serialize)]
struct ChatResponse { reply: String, session_id: String }
#[derive(Debug, Deserialize)]
struct SetupRequest { agent_id: String, api_key: String, #[serde(default)] server: String }
#[derive(Debug, Serialize)]
struct SetupResponse { ok: bool, error: Option<String> }

struct AppState {
    config: Mutex<Config>,
    agent: Mutex<Option<AgentCore>>,
    #[allow(dead_code)]
    config_path: String,
    /// 身份认证缓存 (agent_id → (badge_token, expires_at))
    /// P2-10 修复：添加 TTL 过期
    auth_cache: tokio::sync::Mutex<HashMap<String, (String, std::time::Instant)>>,
    /// 命名空间授权缓存 agent_id → (allowed_ns, 获取时间)
    /// 仅以 agent_id 为 key（token 已在 Memoria 端验证过，不在内存留存明文 key，P1-1）
    /// 短 TTL（60s）以在「每次请求反查 memoria」的性能与「权限即时生效」间取平衡（R1）
    ns_cache: tokio::sync::Mutex<HashMap<String, (Vec<String>, std::time::Instant)>>,
}

/// 构造 401 未授权响应
fn unauthorized(message: &str) -> axum::response::Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "unauthorized", "message": message})),
    ).into_response()
}

/// 身份认证：从 header 取 X-Agent-Id + X-Agent-Key，向 Memoria 反查调用者命名空间授权。
/// 成功返回 (agent_id, allowed_ns)；失败返回 401 Response（由调用方 ? 直接返回）。
async fn authenticate(
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
        return Err(unauthorized("请先通过 /api/register 注册身份"));
    };

    // 鉴权密钥：显式 x-agent-key 优先；回退到安装ID身份时改用 admin key
    // （安装实例自身没有独立 key，由 agent-core 以管理员身份代为在 Memoria 注册）。
    let admin_key = match std::env::var("MEMORIA_ADMIN_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => st.config.lock().await.memoria_admin_key.clone(),
    };
    let agent_key = if !from_usertag {
        headers
            .get("x-agent-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    } else {
        admin_key.clone()
    };
    let server = { let cfg = st.config.lock().await; cfg.server.clone() };
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
        match mcp.call_json("get_allowed_ns", &serde_json::json!({})).await {
            Ok(v) => {
                allowed_ns = v
                    .get("allowed_ns")
                    .and_then(|a| a.as_array())
                    .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
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
            let reg = McpClient::new(&server, "admin", &admin_key);
            let _ = reg.call_json("register_agent", &serde_json::json!({
                "agent_id": &agent_id,
                "display_name": &agent_id,
                "admin_key": &admin_key,
                "namespace": &install_ns
            })).await;
            allowed_ns = vec![
                format!("agent/{}", agent_id),
                "org/cs-pufa-2nd-thermal".to_string(),
            ];
        }
        if allowed_ns.is_empty() {
            // 不向外部暴露内部错误细节（R6）
            return Err(unauthorized("身份校验失败，请稍后重试"));
        }
        st.ns_cache
            .lock()
            .await
            .insert(agent_id.clone(), (allowed_ns.clone(), std::time::Instant::now()));
    }
    Ok((agent_id, allowed_ns))
}

fn config_path() -> String {
    std::env::current_dir()
        .unwrap_or_default()
        .join("agent.toml")
        .to_string_lossy()
        .to_string()
}

fn load_or_create_config() -> Config {
    let path = config_path();
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(mut cfg) = toml::from_str::<Config>(&text) {
            // 环境变量覆盖（环境变量 > 配置文件）
            if let Ok(key) = std::env::var("AGENT_API_KEY") {
                if !key.is_empty() {
                    cfg.api_key = key;
                }
            }
            if let Ok(key) = std::env::var("MEMORIA_ADMIN_KEY") {
                if !key.is_empty() {
                    cfg.memoria_admin_key = key;
                }
            }
            return cfg;
        }
    }
    let cfg = Config {
        agent_id: whoami().unwrap_or_else(|| "default".to_string()),
        api_key: String::new(),
        server: default_server(),
        port: 9753,
        memoria_admin_key: String::new(),
        mcp_source: Vec::new(),
    };
    let _ = std::fs::write(&path, toml::to_string_pretty(&cfg).unwrap_or_default());
    cfg
}

fn save_config(cfg: &Config) {
    let path = config_path();
    let _ = std::fs::write(&path, toml::to_string_pretty(cfg).unwrap_or_default());
}

fn main() {
    // --service 模式：无窗口后台服务
    let is_service = std::env::args().any(|a| a == "--service");

    let config = load_or_create_config();
    let path = config_path();
    let port = config.port;
    let addr = format!("0.0.0.0:{}", port);
    let url = format!("http://{}/", addr);

    // ── 启动 axum 后台服务 ──
    let server_ready = Arc::new(AtomicBool::new(false));
    let server_ready_clone = server_ready.clone();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("✗ Tokio 运行时创建失败: {}", e);
                std::process::exit(1);
            }
        };
        rt.block_on(async move {
            let state = Arc::new(AppState {
                config: Mutex::new(config.clone()),
                agent: Mutex::new(None),
                config_path: path,
                auth_cache: tokio::sync::Mutex::new(HashMap::new()),
                ns_cache: tokio::sync::Mutex::new(HashMap::new()),
            });

            // 先绑定端口，确保服务立即可用（即使 Memoria 慢/未就绪也不阻塞启动）
            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("✗ 端口 {} 绑定失败: {}", &addr, e);
                    std::process::exit(1);
                }
            };
            server_ready_clone.store(true, Ordering::SeqCst);

            if config.configured() {
                // 后台异步注册 Agent：避免 register_agent 阻塞端口绑定与请求服务
                let reg_state = state.clone();
                let reg_config = config.clone();
                tokio::spawn(async move {
                    match build_agent(&reg_config).await {
                        Ok(agent) => {
                            println!("✓ Agent 已就绪（{}@{}）", reg_config.agent_id, reg_config.server);
                            *reg_state.agent.lock().await = Some(agent);
                        }
                        Err(e) => {
                            println!("! Agent 初始化失败: {}（可在设置页重试）", e);
                        }
                    }
                });
            }

            // 巡检循环（含失败计数）
            let patrol_state = state.clone();
            tokio::spawn(async move {
                let mut timer = interval(Duration::from_secs(1800));
                timer.tick().await;
                let mut fail_count = 0u32;
                let mut insight_cycle = 0u32;
                loop {
                    timer.tick().await;
                    insight_cycle += 1;
                    let agent_guard = patrol_state.agent.lock().await;
                    if let Some(ref agent) = *agent_guard {
                        let tasks = [("system_ops", serde_json::json!({"action": "status"}))];
                        for (tool, args) in &tasks {
                            match agent.call_tool_routed(tool, args).await {
                                Ok(reply) => {
                                    fail_count = 0;
                                    tracing::info!("巡检 {}: {}", tool, &reply.chars().take(60).collect::<String>());
                                }
                                Err(e) => {
                                    fail_count = fail_count.saturating_add(1);
                                    if fail_count >= 3 {
                                        tracing::error!("巡检连续失败 {} 次，工具 {}", fail_count, tool);
                                    } else {
                                        tracing::warn!("巡检 {} 失败: {}（第 {} 次）", tool, e, fail_count);
                                    }
                                }
                            }
                        }
                    // 每 4 轮（约 2 小时）执行一次洞见发现
                        if insight_cycle % 4 == 0 {
                            let insight = agent.run_insights().await;
                            tracing::info!("{}", insight);
                        }
                        // 每轮检查 dashboard agent_worker 健康（端口 8011）
                        let agent_ok = reqwest::get("http://127.0.0.1:8011/health")
                            .await
                            .map(|r| r.status().is_success())
                            .unwrap_or(false);
                        if !agent_ok {
                            // P0-3 修复：dashboard 凭据移出源码，改读环境变量。
                            // DASHBOARD_USER 默认 admin；DASHBOARD_PASSWORD 未设置则跳过重启（不泄露/不崩溃）。
                            let dash_user = std::env::var("DASHBOARD_USER").unwrap_or_else(|_| "admin".to_string());
                            let dash_pass = std::env::var("DASHBOARD_PASSWORD").unwrap_or_default();
                            if dash_pass.is_empty() {
                                tracing::warn!("未设置 DASHBOARD_PASSWORD，跳过 dashboard agent worker 重启");
                            } else {
                                tracing::warn!("Agent worker 无响应，通过 dashboard API 重启");
                                let client = reqwest::Client::new();
                                if let Ok(login) = client.post("http://127.0.0.1:8000/api/login")
                                    .form(&[("username", dash_user.as_str()), ("password", dash_pass.as_str())])
                                    .send().await
                                {
                                    let cookie = login.headers().get("set-cookie")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or("")
                                        .to_string();
                                    if !cookie.is_empty() {
                                        let _ = client.post("http://127.0.0.1:8000/api/snmis/agent/start")
                                            .header("Cookie", &cookie)
                                            .send().await;
                                    }
                                }
                            }
                        }
                    }
                    drop(agent_guard);
                }
            });

            let app = Router::new()
                .route("/", get(handle_index))
                .route("/logo.png", get(handle_logo))
                .route("/api/config", get(handle_config))
                .route("/api/save-config", post(handle_save_config))
                .route("/api/chat", post(handle_chat))
                .route("/api/chat/stream", get(handle_chat_stream))
                .route("/api/sessions", get(handle_sessions))
                .route("/api/sessions/{id}", get(handle_session_load))
                .route("/api/sessions/{id}", delete(handle_session_delete))
                .route("/v1/chat/completions", post(handle_v1_chat))
                .route("/api/register", post(handle_register))
                .route("/api/register_user", post(handle_register_user))
                .route("/api/login", post(handle_login))
                .layer(tower_http::cors::CorsLayer::permissive())
                .with_state(state);

            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("HTTP 服务异常终止: {}", e);
            }
        });
    });

    while !server_ready.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    if is_service {
        // 服务模式：保持后台运行
        println!("[agent-core] 服务模式运行中 :{}", port);
        loop { std::thread::sleep(Duration::from_secs(3600)); }
    }

    // ── tao 桌面窗口（无黑框） ──
    let event_loop = EventLoopBuilder::new().build();

    let window = WindowBuilder::new()
        .with_title("AI 助手")
        .with_window_icon(_load_icon())
        .with_inner_size(tao::dpi::LogicalSize::new(800.0, 710.0))
        .build(&event_loop)
        .expect("创建窗口失败");

    let _webview = WebViewBuilder::new()
        .with_url(&url)
        .build(&window);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                *control_flow = ControlFlow::Exit;
            }
            _ => (),
        }
    });
}

// ── Axum handlers ──

async fn handle_index() -> impl axum::response::IntoResponse {
    axum::response::Html(include_str!("chat.html"))
}

async fn handle_logo() -> impl axum::response::IntoResponse {
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
    ([(axum::http::header::CONTENT_TYPE, "text/plain")], "logo not found".into())
}

async fn handle_config(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let cfg = st.config.lock().await;
    Json(serde_json::json!({
        "configured": cfg.configured(),
        "agent_id": cfg.agent_id,
        "server": cfg.server,
    }))
}

async fn handle_save_config(
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
    match build_agent(&cfg).await {
        Ok(agent) => {
            *st.agent.lock().await = Some(agent);
            Json(SetupResponse { ok: true, error: None }).into_response()
        }
        Err(e) => Json(SetupResponse { ok: false, error: Some(e) }).into_response(),
    }
}

async fn handle_chat(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChatRequest>,
) -> axum::response::Response {
    // P0-1 修复：统一鉴权（与 /v1/chat 一致），并传真实 allowed_ns 取代 ["*"] 绕过
    let (agent_id, allowed_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let agent_guard = st.agent.lock().await;
    if let Some(ref agent) = *agent_guard {
        let reply = agent.chat(&req.message, &agent_id, &req.session_id, &allowed_ns).await;
        Json(ChatResponse { reply, session_id: req.session_id }).into_response()
    } else {
        Json(ChatResponse { reply: "请先在设置页面配置 API 密钥。".to_string(), session_id: req.session_id }).into_response()
    }
}

/// SSE 流式聊天（包装 chat() 结果，分块推送）
async fn handle_chat_stream(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ChatRequest>,
) -> axum::response::Response {
    // P0-1 修复：统一鉴权 + 真实 allowed_ns（与 /api/chat 一致）
    let (agent_id, allowed_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let (tx, rx): (tokio::sync::mpsc::UnboundedSender<Result<SseEvent, Infallible>>,
                   tokio::sync::mpsc::UnboundedReceiver<Result<SseEvent, Infallible>>)
        = tokio::sync::mpsc::unbounded_channel();

    let agent_guard = st.agent.lock().await;
    let has_agent = agent_guard.is_some();
    drop(agent_guard);

    if has_agent {
        let st_clone = st.clone();
        let msg = params.message.clone();
        let sid = params.session_id.clone();
        tokio::spawn(async move {
            let guard = st_clone.agent.lock().await;
            if let Some(ref agent) = *guard {
                let reply = agent.chat(&msg, &agent_id, &sid, &allowed_ns).await;
                let chars: Vec<char> = reply.chars().collect();
                let mut i = 0;
                while i < chars.len() {
                    let end = (i + 3).min(chars.len());
                    let chunk: String = chars[i..end].iter().collect();
                    let _ = tx.send(Ok(SseEvent::default().data(chunk).event("text")));
                    i = end;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            let _ = tx.send(Ok(SseEvent::default().data("").event("done")));
        });
    } else {
        let _ = tx.send(Ok(SseEvent::default().data("请先在设置页面配置 API 密钥。").event("text")));
        let _ = tx.send(Ok(SseEvent::default().data("").event("done")));
    }

    Sse::new(UnboundedReceiverStream::new(rx)).into_response()
}

/// 获取会话列表
async fn handle_sessions(State(_st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let db_path = std::env::current_dir().unwrap_or_default().join("harness.db").to_string_lossy().to_string();

    let sessions = tokio::task::spawn_blocking(move || {
        let mut result = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT session_id, role, content, created_at FROM chat_history WHERE id IN (
                    SELECT MIN(id) FROM chat_history GROUP BY session_id
                ) AND role = 'user' ORDER BY id DESC LIMIT 50"
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    let sid: String = row.get(0)?;
                    let content: String = row.get(2)?;
                    let created: String = row.get(3)?;
                    Ok((sid, content, created))
                }) {
                    for row in rows.flatten() {
                        let summary = row.1.chars().take(40).collect::<String>();
                        result.push(serde_json::json!({
                            "session_id": row.0,
                            "summary": summary,
                            "created_at": row.2,
                        }));
                    }
                }
            }
        }
        result
    }).await.unwrap_or_default();

    Json(serde_json::json!({"sessions": sessions}))
}

/// 加载指定会话的历史
async fn handle_session_load(
    State(_st): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db_path = {
        std::env::current_dir().unwrap_or_default().join("harness.db").to_string_lossy().to_string()
    };

    let sid = id.clone();
    let messages = tokio::task::spawn_blocking(move || {
        let mut result = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT role, content, created_at FROM chat_history WHERE session_id=?1 ORDER BY id ASC"
            ) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![sid], |row| {
                    let role: String = row.get(0)?;
                    let content: String = row.get(1)?;
                    let created: String = row.get(2)?;
                    Ok((role, content, created))
                }) {
                    for row in rows.flatten() {
                        result.push(serde_json::json!({
                            "role": row.0,
                            "content": row.1,
                            "time": row.2,
                        }));
                    }
                }
            }
        }
        result
    }).await.unwrap_or_default();

    Json(serde_json::json!({"messages": messages, "session_id": id}))
}

/// 删除指定会话
async fn handle_session_delete(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db_path = std::env::current_dir().unwrap_or_default().join("harness.db").to_string_lossy().to_string();
    let sid = id.clone();

    let deleted = tokio::task::spawn_blocking(move || {
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            if let Ok(cnt) = conn.execute("DELETE FROM chat_history WHERE session_id=?1", rusqlite::params![sid]) {
                return cnt;
            }
        }
        0
    }).await.unwrap_or(0);

    Json(serde_json::json!({"deleted": deleted, "session_id": id}))
}

/// OpenAI 兼容聊天补全端点（供 JAN / 第三方客户端调用）
#[derive(Deserialize)]
struct V1ChatRequest {
    model: Option<String>,
    messages: Vec<V1Message>,
    #[allow(dead_code)]
    stream: Option<bool>,
}
#[derive(Deserialize)]
struct V1Message {
    #[allow(dead_code)]
    role: String,
    content: Option<String>,
}

async fn handle_v1_chat(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<V1ChatRequest>,
) -> axum::response::Response {
    // 身份认证：复用 authenticate()（X-Agent-Id/Key → Memoria 反查 allowed_ns）
    let (agent_id, allowed_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let agent_guard = st.agent.lock().await;
    let reply = if let Some(ref agent) = *agent_guard {
        // 输入校验：消息长度限制 32KB，消息数限制 100
        if req.messages.len() > 100 {
            return axum::response::Json(serde_json::json!({
                "error": "too many messages"
            })).into_response();
        }
        // PFAiX 强制上下文隔离：每个安装实例 + 每个对话独立 session。
        // x-user-tag 是壳首次启动生成的随机 install_id；x-conversation-id
        // 是壳内当前对话 id。两者缺省时向后兼容旧客户端。
        let user_tag = headers
            .get("x-user-tag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect::<String>())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_string());
        let conversation_id = headers
            .get("x-conversation-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect::<String>())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_string());

        let session_id = format!("jan/{}/{}/{}", agent_id, user_tag, conversation_id);
        if session_id.len() > 128 || !session_id.chars().all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_') {
            return axum::response::Json(serde_json::json!({
                "error": "invalid session_id"
            })).into_response();
        }
        let user_text: String = req.messages.iter()
            .filter_map(|m| m.content.as_deref())
            .collect::<Vec<_>>()
            .join("\n")
            .chars()
            .take(32768)
            .collect();
        if user_text.is_empty() {
            "请输入消息".to_string()
        } else {
            agent.chat(&user_text, &agent_id, &session_id, &allowed_ns).await
        }
    } else {
        "Agent 未就绪".to_string()
    };
    drop(agent_guard);

    axum::response::Json(serde_json::json!({
        "id": "chatcmpl-agent",
        "object": "chat.completion",
        "created": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        "model": req.model.unwrap_or_else(|| "agent-core".to_string()),
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": reply,
            },
            "finish_reason": "stop",
        }],
    })).into_response()
}

/// 用户注册（boarding）—— 姓名 + 部门 → 登记到 Memoria，返回 badge_token
#[derive(Deserialize)]
struct RegisterRequest {
    name: String,
    department: String,
    company: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    div: String,
}
#[derive(Serialize)]
struct RegisterResponse {
    ok: bool,
    agent_id: String,
    badge_token: String,
    namespace: String,
    error: Option<String>,
}

/// 个人账号注册（本地账密）—— user_id + password → 代理转发到 Memoria register_user。
/// 财务机等分发端连不到内网 Memoria，注册/登录必须经 agent-core 代理。
#[derive(Deserialize)]
struct RegisterUserRequest {
    user_id: String,
    password: String,
    #[serde(default)]
    display_name: String,
}
#[derive(Deserialize)]
struct LoginRequest {
    user_id: String,
    password: String,
}
#[derive(Serialize)]
struct LoginResponse {
    ok: bool,
    user_id: String,
    display_name: String,
    badge_token: String,
    namespace: String,
    error: Option<String>,
}

/// user_id 严格清洗：作为 agent_id 会进入 HTTP 头与 session_id，必须 ASCII 安全。
/// 仅保留字母/数字/下划线/连字符/点，避免破坏头部或命名空间层级。
fn sanitize_user_id(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect::<String>()
        .trim()
        .to_string()
}

/// 命名空间分段白名单清洗：仅保留字母/数字/中文/下划线/连字符，
/// 防止 '/' 或控制字符破坏 org/.../dept/... 的层级路径（R5）
fn sanitize_ns_segment(s: &str) -> String {
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

async fn handle_register(
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
    // 层级命名空间树：org/{company}[/div/{div}]/dept/{department}[/proj/{project}]
    // 部门领导（无项目）止于 dept；分管副总（无部门）可止于 div；CEO 可仅 org。
    let mut namespace = if div.is_empty() {
        format!("org/{}/dept/{}", COMPANY, department)
    } else {
        format!("org/{}/div/{}/dept/{}", COMPANY, div, department)
    };
    if !project.is_empty() {
        namespace = format!("{}/proj/{}", namespace, project);
    }
    // 先生成一个本地兜底 token；若 Memoria 注册成功，会用 Memoria 实际返回的 badge 覆盖（P0 修复：必须一致，否则客户端 key 与 Memoria 存值不符导致鉴权失败）
    let mut badge_token = format!("sk-{:x}", rand::thread_rng().gen::<u128>());

    // 注册到 Memoria — 从环境变量或配置读取 admin_key
    let admin_key = match std::env::var("MEMORIA_ADMIN_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => st.config.lock().await.memoria_admin_key.clone(),
    };
    let mcp = McpClient::new("http://127.0.0.1:9003", "admin", &admin_key);
    // P0 修复：Memoria 的 register_agent 会自行生成 badge 并在响应里返回；
    // 必须用它作为后续鉴权 key，否则客户端拿本地随机 token 与 Memoria 存值对不上 → -32001。
    let memoria_ok = if admin_key.is_empty() {
        false
    } else {
        match mcp.call_json("register_agent", &serde_json::json!({
            "agent_id": &agent_id,
            "display_name": &req.name,
            "admin_key": &admin_key,
            "namespace": &namespace,
        })).await {
            Ok(text) => {
                // Memoria register_agent 返回 {"status":"registered","badge":<AgentBadge对象 或 字符串>}
                // 其中 badge.badge_token 才是后续鉴权用的 key 字符串；兼容 badge 直接是字符串的旧格式。
                let badge_str = text.get("badge").and_then(|x| {
                    if x.is_string() { x.as_str() }
                    else { x.get("badge_token").and_then(|t| t.as_str()) }
                });
                if let Some(b) = badge_str {
                    badge_token = b.to_string();
                    true
                } else { false }
            }
            Err(_) => false,
        }
    };

    // 缓存身份（使用 admin key 写入 Memoria 后，auth_cache 也存一份）
    // P2-10: 记录创建时间用于 TTL
    if memoria_ok {
        st.auth_cache.lock().await.insert(agent_id.clone(), (badge_token.clone(), std::time::Instant::now()));
    }

    // 审计日志：记录身份注册
    let audit = AuditLogger::new(McpClient::new("http://127.0.0.1:9003", "admin", &admin_key));
    audit.log_identity(&agent_id, "register",
        &format!("name={}, department={}, company={}, div={}, project={}",
            req.name, req.department, req.company, req.div, req.project)
    ).await;

    Json(RegisterResponse {
        ok: true,
        agent_id,
        badge_token,
        namespace,
        error: if memoria_ok { None } else { Some("Memoria 暂时不可用，token 已生成".to_string()) },
    })
}

/// 个人账号注册代理：转发到 Memoria `register_user`（以 admin 身份）。
/// 命名空间在此层追加部署级 org（cs-pufa-2nd-thermal），使登录用户获得 dashboard 等
/// 共享工具可见性，同时保留 agent/{user_id} 作个人记忆隔离。
async fn handle_register_user(
    State(st): State<Arc<AppState>>,
    Json(req): Json<RegisterUserRequest>,
) -> Json<LoginResponse> {
    let user_id = sanitize_user_id(&req.user_id);
    if user_id.is_empty() || user_id != req.user_id.trim() {
        return Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
            badge_token: String::new(), namespace: String::new(),
            error: Some("用户名仅允许字母/数字/下划线/连字符/点".to_string()) });
    }
    if req.password.len() < 6 {
        return Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
            badge_token: String::new(), namespace: String::new(),
            error: Some("口令至少 6 位".to_string()) });
    }
    let display_name = if req.display_name.trim().is_empty() { user_id.clone() } else { req.display_name.trim().to_string() };
    let admin_key = match std::env::var("MEMORIA_ADMIN_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => st.config.lock().await.memoria_admin_key.clone(),
    };
    if admin_key.is_empty() {
        return Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
            badge_token: String::new(), namespace: String::new(),
            error: Some("服务未就绪，请稍后重试".to_string()) });
    }
    // 部署级组织命名空间：agent/{user_id}（个人记忆） + org/...（共享工具可见性）
    let namespace = format!("agent/{},org/cs-pufa-2nd-thermal", user_id);
    let mcp = McpClient::new("http://127.0.0.1:9003", "admin", &admin_key);
    match mcp.call_json("register_user", &serde_json::json!({
        "user_id": &user_id,
        "display_name": &display_name,
        "password": &req.password,
        "namespace": &namespace,
    })).await {
        Ok(v) => {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status == "registered" {
                Json(LoginResponse { ok: true, user_id, display_name,
                    badge_token: String::new(), namespace, error: None })
            } else {
                let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("注册失败").to_string();
                Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
                    badge_token: String::new(), namespace: String::new(), error: Some(msg) })
            }
        }
        Err(_) => Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
            badge_token: String::new(), namespace: String::new(),
            error: Some("Memoria 暂时不可用".to_string()) }),
    }
}

/// 个人账号登录代理：转发到 Memoria `login_user`（以 admin 身份），
/// 成功回传 badge_token，客户端存储后作为 x-agent-id / x-agent-key 用于聊天鉴权。
async fn handle_login(
    State(st): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Json<LoginResponse> {
    let user_id = sanitize_user_id(&req.user_id);
    if user_id.is_empty() || req.password.is_empty() {
        return Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
            badge_token: String::new(), namespace: String::new(),
            error: Some("用户名或口令错误".to_string()) });
    }
    let admin_key = match std::env::var("MEMORIA_ADMIN_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => st.config.lock().await.memoria_admin_key.clone(),
    };
    if admin_key.is_empty() {
        return Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
            badge_token: String::new(), namespace: String::new(),
            error: Some("服务未就绪，请稍后重试".to_string()) });
    }
    let mcp = McpClient::new("http://127.0.0.1:9003", "admin", &admin_key);
    match mcp.call_json("login_user", &serde_json::json!({
        "user_id": &user_id,
        "password": &req.password,
    })).await {
        Ok(v) => {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status == "ok" {
                let badge_token = v.get("badge_token").and_then(|s| s.as_str()).unwrap_or("").to_string();
                let display_name = v.get("display_name").and_then(|s| s.as_str()).unwrap_or(&user_id).to_string();
                let namespace = v.get("namespace").and_then(|s| s.as_str()).unwrap_or("").to_string();
                // 登录成功即写入 auth_cache，减少首条聊天的鉴权往返
                st.auth_cache.lock().await.insert(user_id.clone(), (badge_token.clone(), std::time::Instant::now()));
                Json(LoginResponse { ok: true, user_id, display_name, badge_token, namespace, error: None })
            } else {
                Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
                    badge_token: String::new(), namespace: String::new(),
                    error: Some("用户名或口令错误".to_string()) })
            }
        }
        Err(_) => Json(LoginResponse { ok: false, user_id: String::new(), display_name: String::new(),
            badge_token: String::new(), namespace: String::new(),
            error: Some("Memoria 暂时不可用".to_string()) }),
    }
}

async fn build_agent(config: &Config) -> Result<AgentCore, String> {
    // P1-1: 分离密钥用途
    let badge_token = std::env::var("MEMORIA_ADMIN_KEY").unwrap_or_default();
    let admin_key = if !config.memoria_admin_key.is_empty() {
        config.memoria_admin_key.clone()
    } else if !badge_token.is_empty() {
        badge_token.clone()
    } else {
        config.api_key.clone()
    };

    let mcp = McpClient::new(&config.server, &config.agent_id, &badge_token);
    let _ = mcp.call_json("register_agent", &serde_json::json!({
        "agent_id": &config.agent_id,
        "display_name": &config.agent_id,
        "admin_key": &admin_key,
        "namespace": format!("agent/{}", config.agent_id),
    })).await;

    // P2-C: 从 agent_id 解析多租户命名空间（handle_register 格式：{company}_{department}_{name}）
    let ns_full_path = {
        let parts: Vec<&str> = config.agent_id.splitn(3, '_').collect();
        if parts.len() == 3 {
            Some(format!("/dept/{}/project/{}/user/{}", parts[0], parts[1], parts[2]))
        } else {
            None
        }
    };

    let identity = AgentIdentity {
        agent_id: config.agent_id.clone(),
        namespace: format!("agent/{}", config.agent_id),
        badge_token: badge_token.clone(),
        ns_full_path,
    };
    // P0-1: 设置 failover fallbacks
    let doubao_key = std::env::var("DOUBAO_API_KEY").unwrap_or_default();
    let fallbacks = if !doubao_key.is_empty() {
        vec![
            ("https://ark.cn-beijing.volces.com/api/v3".to_string(),
             "doubao-lite-32k".to_string(),
             doubao_key),
        ]
    } else {
        Vec::new()
    };
    let llm_config = LlmConfig {
        api_key: config.api_key.clone(),
        fallbacks,
        ..Default::default()
    };
    let mut additional_mcp = Vec::new();
    for src in &config.mcp_source {
        if !src.command.is_empty() {
            additional_mcp.push((src.name.clone(), src.url.clone(), src.token.clone(), Some((src.command.clone(), src.args.clone())), src.namespace.clone()));
        } else {
            additional_mcp.push((src.name.clone(), src.url.clone(), src.token.clone(), None, src.namespace.clone()));
        }
    }
    let agent_config = AgentConfig {
        identity,
        llm: llm_config,
        memoria_url: config.server.clone(),
        additional_mcp,
        skill_whitelist: None,
        max_tool_rounds: 3,
        parent_permission: PermissionLevel::Write,
        enable_compositional_routing: true,
        system_prompt_template: None, // P2-3: 使用内置默认模板
        approver_id: None, // P2-D: 无审批人（保持现有行为）
    };
    let cwd = std::env::current_dir().unwrap_or_default();
    let harness = HarnessStore::open(&cwd.join("harness.db").to_string_lossy())
        .map_err(|e| format!("创建 Harness 存储失败: {}", e))?;
    let agent = AgentCore::new(agent_config, harness);
    // P2-C: 同步 Memoria 注册的 namespace 到本地 NamespaceRegistry
    agent.sync_namespace_from_identity();
    Ok(agent)
}

fn whoami() -> Option<String> {
    std::env::var("USERNAME").or_else(|_| std::env::var("USER")).ok()
}

/// 加载窗口图标（从 logo.png 解码，保留 2:1 比例）
/// P2-2 修复：优先用相对路径
fn _load_icon() -> Option<tao::window::Icon> {
    let cwd = std::env::current_dir().unwrap_or_default();
    for path in &[
        cwd.join("logo.png"),
        cwd.join("static").join("logo.png"),
        cwd.join("assets").join("logo.png"),
    ] {
        if let Ok(data) = std::fs::read(path) {
            if let Ok(img) = image::load_from_memory(&data) {
                // 原图 2114x1051 (2:1)，缩放到 48x24 保留比例
                let resized = img.resize(48, 24, image::imageops::FilterType::Lanczos3);
                let rgba = resized.to_rgba8();
                let (w, h) = rgba.dimensions();
                if let Ok(icon) = tao::window::Icon::from_rgba(rgba.into_raw(), w, h) {
                    return Some(icon);
                }
            }
        }
    }
    None
}
