//! agent-core Desktop — 双击即用，零配置
//!
//! 首次运行自动打开浏览器，填个名字和密钥就能聊。

use std::sync::Arc;
use axum::{Router, routing::get, routing::post, Json, extract::State};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use agent_core::agent::{AgentConfig, AgentCore, AgentIdentity};
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
}

fn default_server() -> String { "http://192.168.1.171:9003".to_string() }
fn default_port() -> u16 { 9753 }

impl Config {
    fn configured(&self) -> bool {
        !self.agent_id.is_empty() && !self.api_key.is_empty()
    }
}

#[derive(Debug, Deserialize)]
struct ChatRequest { message: String }
#[derive(Debug, Serialize)]
struct ChatResponse { reply: String }
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
    // 自动生成默认配置
    let cfg = Config {
        agent_id: whoami().unwrap_or_else(|| "default".to_string()),
        api_key: String::new(),
        server: default_server(),
        port: 9753,
    };
    let _ = std::fs::write(&path, toml::to_string_pretty(&cfg).unwrap_or_default());
    cfg
}

fn save_config(cfg: &Config) {
    let path = config_path();
    let _ = std::fs::write(&path, toml::to_string_pretty(cfg).unwrap_or_default());
}

#[tokio::main]
async fn main() {
    let config = load_or_create_config();
    let path = config_path();
    println!("agent-core Desktop  (Ctrl+C 停止)");
    println!("配置文件: {}", path);

    let state = Arc::new(AppState {
        config: Mutex::new(config.clone()),
        agent: Mutex::new(None),
        config_path: path,
    });

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/api/config", get(handle_config))
        .route("/api/save-config", post(handle_save_config))
        .route("/api/chat", post(handle_chat))
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state);

    let port = config.port;
    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    let url = format!("http://{}", addr);
    println!("浏览器打开: {}", url);
    let _ = open::that(&url);
    axum::serve(listener, app).await.unwrap();
}

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

    // 用新配置重建 AgentCore
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
        let reply = agent.chat(&req.message, "user", "default").await;
        Json(ChatResponse { reply })
    } else {
        Json(ChatResponse { reply: "请先在设置页面配置 API 密钥。".to_string() })
    }
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
    let agent_config = AgentConfig {
        identity,
        llm: llm_config,
        memoria_url: config.server.clone(),
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
