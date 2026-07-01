//! agent-core Desktop — 双击即用，零配置
//!
//! 内嵌 WebView（无浏览器），系统托盘图标。
//! 首次运行自动打开配置页，填个名字和密钥就能聊。
//! 内置巡检循环：每 30 分钟调用 Dashboard MCP 执行定时任务。

#![windows_subsystem = "windows"]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::convert::Infallible;
use axum::{
    Router, routing::get, routing::post,
    Json, extract::State,
    response::sse::{Sse, Event as SseEvent},
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

use agent_core::agent::{AgentConfig, AgentCore, AgentIdentity};
use agent_core::boundary::PermissionLevel;
use agent_core::harness::HarnessStore;
use agent_core::llm::LlmConfig;
use agent_core::mcp_client::{McpClient, McpSource};

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
    mcp_source: Vec<McpSourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpSourceConfig {
    name: String,
    url: String,
    #[serde(default)]
    token: String,
}

fn default_server() -> String { "http://192.168.1.171:9003".to_string() }
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
    config_path: String,
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
    let config = load_or_create_config();
    let path = config_path();
    let port = config.port;
    let addr = format!("127.0.0.1:{}", port);
    let url = format!("http://{}/", addr);

    // ── 启动 axum 后台服务 ──
    let server_ready = Arc::new(AtomicBool::new(false));
    let server_ready_clone = server_ready.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let state = Arc::new(AppState {
                config: Mutex::new(config.clone()),
                agent: Mutex::new(None),
                config_path: path,
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

            // 巡检循环
            let patrol_state = state.clone();
            tokio::spawn(async move {
                let mut timer = interval(Duration::from_secs(1800));
                timer.tick().await;
                loop {
                    timer.tick().await;
                    let agent_guard = patrol_state.agent.lock().await;
                    if let Some(ref agent) = *agent_guard {
                        tracing::info!("巡检: 开始定时检查");
                        let tasks = [("system_ops", serde_json::json!({"action": "status"}))];
                        for (tool, args) in &tasks {
                            match agent.call_tool_routed(tool, args).await {
                                Ok(reply) => tracing::info!("巡检 {}: {}", tool, &reply.chars().take(60).collect::<String>()),
                                Err(e) => tracing::info!("巡检 {} 跳过: {}", tool, e),
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
                .layer(tower_http::cors::CorsLayer::permissive())
                .with_state(state);

            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            server_ready_clone.store(true, Ordering::SeqCst);
            axum::serve(listener, app).await.unwrap();
        });
    });

    while !server_ready.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
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

    let mut close_requested = false;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                // 点击关闭 → 退出（后续可改为缩托盘）
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
    for path in &[
        r"C:\Users\user\dashboard\dashboard-frontend\dist\logo.png",
        r"C:\Users\user\dashboard\static\logo.png",
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
async fn handle_sessions(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
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
    State(st): State<Arc<AppState>>,
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

async fn build_agent(config: &Config) -> Result<AgentCore, String> {
    let mcp = McpClient::new(&config.server, &config.agent_id, &config.api_key);
    let _ = mcp.call_json("register_agent", &serde_json::json!({
        "agent_id": &config.agent_id,
        "display_name": &config.agent_id,
        "admin_key": &config.api_key,
        "namespace": format!("agent/{}", config.agent_id),
    })).await;

    let identity = AgentIdentity {
        agent_id: config.agent_id.clone(),
        namespace: format!("agent/{}", config.agent_id),
        badge_token: config.api_key.clone(),
    };
    let llm_config = LlmConfig {
        api_key: config.api_key.clone(),
        ..Default::default()
    };
    let mut additional_mcp = Vec::new();
    for src in &config.mcp_source {
        additional_mcp.push((src.name.clone(), src.url.clone(), src.token.clone()));
    }
    let agent_config = AgentConfig {
        identity,
        llm: llm_config,
        memoria_url: config.server.clone(),
        additional_mcp,
        skill_whitelist: None,
        max_tool_rounds: 3,
        parent_permission: PermissionLevel::Write,
    };
    let cwd = std::env::current_dir().unwrap_or_default();
    let harness = HarnessStore::open(&cwd.join("harness.db").to_string_lossy())
        .map_err(|e| format!("创建 Harness 存储失败: {}", e))?;
    Ok(AgentCore::new(agent_config, harness))
}

fn whoami() -> Option<String> {
    std::env::var("USERNAME").or_else(|_| std::env::var("USER")).ok()
}

/// 加载窗口图标（从 logo.png 解码，保留 2:1 比例）
fn _load_icon() -> Option<tao::window::Icon> {
    for path in &[
        r"C:\Users\user\dashboard\dashboard-frontend\dist\logo.png",
        r"C:\Users\user\dashboard\static\logo.png",
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
