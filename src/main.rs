//! agent-core Desktop — 双击即用，零配置
//!
//! 内嵌 WebView（无浏览器），系统托盘图标。
//! 首次运行自动打开配置页，填个名字和密钥就能聊。
//! 内置巡检循环：每 30 分钟调用 Dashboard MCP 执行定时任务。

#![windows_subsystem = "windows"]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use axum::{Router, routing::get, routing::post, Json, extract::State};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::interval;
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
                .route("/api/config", get(handle_config))
                .route("/api/save-config", post(handle_save_config))
                .route("/api/chat", post(handle_chat))
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
        .with_inner_size(tao::dpi::LogicalSize::new(480.0, 720.0))
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

/// SSE 流式聊天（包装 chat() 的回复，分块推送）

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
