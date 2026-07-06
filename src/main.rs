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
use futures::stream::Stream;
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
        if let Ok(cfg) = toml::from_str::<Config>(&text) {
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
            });

            if config.configured() {
                match build_agent(&config).await {
                    Ok(agent) => {
                        println!("✓ Agent 已就绪（{}@{}）", config.agent_id, config.server);
                        *state.agent.lock().await = Some(agent);
                    }
                    Err(e) => {
                        println!("! Agent 初始化失败: {}（可在设置页重试）", e);
                    }
                }
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
                .layer(tower_http::cors::CorsLayer::permissive())
                .with_state(state);

            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("✗ 端口 {} 绑定失败: {}", &addr, e);
                    std::process::exit(1);
                }
            };
            server_ready_clone.store(true, Ordering::SeqCst);
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
    // P2-2 修复：优先用相对路径，fallback 到绝对路径
    let cwd = std::env::current_dir().unwrap_or_default();
    for path in &[
        cwd.join("logo.png"),
        cwd.join("static").join("logo.png"),
        cwd.join("assets").join("logo.png"),
        std::path::PathBuf::from(r"C:\Users\user\dashboard\dashboard-frontend\dist\logo.png"),
        std::path::PathBuf::from(r"C:\Users\user\dashboard\static\logo.png"),
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
    Json(req): Json<SetupRequest>,
) -> Json<SetupResponse> {
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
            Json(SetupResponse { ok: true, error: None })
        }
        Err(e) => Json(SetupResponse { ok: false, error: Some(e) }),
    }
}

async fn handle_chat(
    State(st): State<Arc<AppState>>,
    Json(req): Json<ChatRequest>,
) -> Json<ChatResponse> {
    let agent_guard = st.agent.lock().await;
    if let Some(ref agent) = *agent_guard {
        let reply = agent.chat(&req.message, "user", &req.session_id).await;
        Json(ChatResponse { reply, session_id: req.session_id })
    } else {
        Json(ChatResponse { reply: "请先在设置页面配置 API 密钥。".to_string(), session_id: req.session_id })
    }
}

/// SSE 流式聊天（包装 chat() 结果，分块推送）
async fn handle_chat_stream(
    State(st): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<ChatRequest>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

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
                let reply = agent.chat(&msg, "user", &sid).await;
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

    Sse::new(UnboundedReceiverStream::new(rx))
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
    // 身份认证：从 header 取 X-Agent-Id + X-Agent-Key
    let agent_id = headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let agent_key = headers
        .get("x-agent-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // 验证令牌
    if agent_id.is_empty() {
        return axum::response::Json(serde_json::json!({
            "error": "unauthorized",
            "message": "请先通过 /api/register 注册身份"
        })).into_response();
    }
    {
        let cache = st.auth_cache.lock().await;
        // P2-10: 检查过期（TTL = 1 小时）
        const AUTH_TTL: Duration = Duration::from_secs(3600);
        match cache.get(&agent_id) {
            Some((expected_key, created_at)) if expected_key == &agent_key => {
                // 检查是否过期
                if created_at.elapsed() > AUTH_TTL {
                    drop(cache);
                    return axum::response::Json(serde_json::json!({
                        "error": "unauthorized",
                        "message": "身份已过期，请重新注册"
                    })).into_response();
                }
                drop(cache);
            }
            Some(_) => {
                return axum::response::Json(serde_json::json!({
                    "error": "unauthorized",
                    "message": "X-Agent-Key 不匹配"
                })).into_response();
            }
            None => {
                // 未注册的 agent_id
                return axum::response::Json(serde_json::json!({
                    "error": "unauthorized",
                    "message": "未注册的身份，请先通过 /api/register 注册"
                })).into_response();
            }
        }
    }

    let agent_guard = st.agent.lock().await;
    let reply = if let Some(ref agent) = *agent_guard {
        // 输入校验：消息长度限制 32KB，消息数限制 100
        if req.messages.len() > 100 {
            return axum::response::Json(serde_json::json!({
                "error": "too many messages"
            })).into_response();
        }
        let session_id = format!("jan/{}", agent_id);
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
            agent.chat(&user_text, &agent_id, &format!("jan/{}", agent_id)).await
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
}
#[derive(Serialize)]
struct RegisterResponse {
    ok: bool,
    agent_id: String,
    badge_token: String,
    namespace: String,
    error: Option<String>,
}

async fn handle_register(
    State(st): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Json<RegisterResponse> {
    let agent_id = format!("{}_{}_{}", req.company, req.department, req.name);
    let namespace = format!("agent/{}/{}/{}", req.company, req.department, req.name);
    let badge_token = format!("sk-{:x}", rand::thread_rng().gen::<u128>());

    // 注册到 Memoria — 从环境变量或配置读取 admin_key
    let admin_key = match std::env::var("MEMORIA_ADMIN_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => st.config.lock().await.memoria_admin_key.clone(),
    };
    let mcp = McpClient::new("http://127.0.0.1:9003", "admin", &admin_key);
    let memoria_ok = !admin_key.is_empty() && mcp.call_json("register_agent", &serde_json::json!({
        "agent_id": &agent_id,
        "display_name": &req.name,
        "admin_key": &admin_key,
        "namespace": &namespace,
    })).await.is_ok();

    // 缓存身份（使用 admin key 写入 Memoria 后，auth_cache 也存一份）
    // P2-10: 记录创建时间用于 TTL
    if memoria_ok {
        st.auth_cache.lock().await.insert(agent_id.clone(), (badge_token.clone(), std::time::Instant::now()));
    }

    // 审计日志：记录身份注册
    let audit = AuditLogger::new(McpClient::new("http://127.0.0.1:9003", "admin", &admin_key));
    audit.log_identity(&agent_id, "register",
        &format!("name={}, department={}, company={}", req.name, req.department, req.company)
    ).await;

    Json(RegisterResponse {
        ok: true,
        agent_id,
        badge_token,
        namespace,
        error: if memoria_ok { None } else { Some("Memoria 暂时不可用，token 已生成".to_string()) },
    })
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
            additional_mcp.push((src.name.clone(), src.url.clone(), src.token.clone(), Some((src.command.clone(), src.args.clone()))));
        } else {
            additional_mcp.push((src.name.clone(), src.url.clone(), src.token.clone(), None));
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
        std::path::PathBuf::from(r"C:\Users\user\dashboard\dashboard-frontend\dist\logo.png"),
        std::path::PathBuf::from(r"C:\Users\user\dashboard\static\logo.png"),
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
