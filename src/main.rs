//! agent-core — HTTP 引擎（默认无窗）
//!
//! 默认以服务模式运行（仅 `:9753` HTTP，不弹桌面窗）。
//! 需要内嵌 WebView「AI 助手」调试窗时显式传 `--gui`。
//! `--service` 仍保留，与默认行为等价（兼容旧脚本/托盘）。
//! 内置巡检循环：每 30 分钟调用 Dashboard MCP 执行定时任务。

// P2-1 修复：仅 release 模式下隐藏控制台窗口，debug 模式保留
// GUI 模式用 windows subsystem；默认/service 保留控制台便于运维日志
#![cfg_attr(
    all(not(debug_assertions), not(feature = "service")),
    windows_subsystem = "windows"
)]

use agent_core::checkpoint::CheckpointStore;
use axum::{
    extract::{Path, Request, State},
    middleware::{from_fn_with_state, Next},
    response::{
        sse::{Event as SseEvent, Sse},
        Html, IntoResponse, Response,
    },
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{Local, Timelike};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::Instrument;
use tracing_subscriber::EnvFilter;
use wry::WebViewBuilder;

use agent_core::agent::{
    AgentConfig, AgentCore, AgentIdentity, EventKind,
};
use agent_core::audit::AuditLogger;
use agent_core::boundary::PermissionLevel;
use agent_core::harness::HarnessStore;
use agent_core::llm::{LlmConfig, LlmProvider};
use agent_core::metrics::MetricsRegistry;
use agent_core::approval::ApprovalResponse;
use agent_core::resources::SharedResourceSnapshot;

mod config;
use config::*;
mod state;
use state::*;
mod auth;
use auth::*;
mod handlers;
use handlers::admin::*;
use handlers::chat::*;
use handlers::evolve::*;
use handlers::meetings::*;
use handlers::system::*;


#[derive(Debug, Deserialize)]
struct CollabInboxQuery {
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
struct CollabSendBody {
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
struct CollabApprovalBody {
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
fn org_broadcasters() -> Vec<String> {
    match std::env::var("COLLAB_ORG_BROADCASTERS") {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => vec!["office-agent".to_string()],
    }
}

fn ns_blob(ns: &[String]) -> String {
    ns.join(",")
}

fn caller_in_org(caller_ns: &[String]) -> bool {
    let blob = ns_blob(caller_ns);
    caller_ns.iter().any(|n| n == "*")
        || blob.contains(&format!("org/{}", org_company()))
}

fn caller_has_dept(caller_ns: &[String], dept: &str) -> bool {
    let needle = format!("dept/{}", dept);
    caller_ns.iter().any(|n| n == "*") || ns_blob(caller_ns).contains(&needle)
}

fn caller_has_proj(caller_ns: &[String], proj: &str) -> bool {
    let needle = format!("proj/{}", proj);
    caller_ns.iter().any(|n| n == "*") || ns_blob(caller_ns).contains(&needle)
}

fn can_org_broadcast(caller_id: &str, caller_ns: &[String]) -> bool {
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
fn collab_reachability(
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

fn peer_in_company(namespace: &str) -> bool {
    namespace.contains(&format!("org/{}", org_company())) || namespace.contains('*')
}




fn build_cors_layer(host: &str, port: u16, configured: &[String]) -> CorsLayer {
    // 未配置 cors_origins 时：本地壳（Tauri / vite）任意 Origin 可探测/聊天；
    // 生产若收紧，在 config.toml 显式填写 cors_origins 白名单。
    if configured.is_empty() {
        let _ = (host, port);
        return CorsLayer::new()
            .allow_origin(AllowOrigin::mirror_request())
            .allow_methods(Any)
            .allow_headers(Any);
    }
    let header_values: Vec<axum::http::HeaderValue> = configured
        .iter()
        .cloned()
        .filter_map(|o| axum::http::HeaderValue::try_from(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(header_values))
        .allow_methods(Any)
        .allow_headers(Any)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("AGENT_CORE_LOG")
        .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

async fn trace_middleware(request: Request, next: Next) -> axum::response::Response {
    let trace_id = format!("{:x}", rand::thread_rng().gen::<u128>());
    let path = request.uri().path().to_string();
    let method = request.method().to_string();
    let span =
        tracing::info_span!("http.request", trace_id = %trace_id, method = %method, path = %path);
    let mut res = next.run(request).instrument(span).await;
    if let Ok(v) = axum::http::HeaderValue::try_from(trace_id) {
        res.headers_mut().insert("x-trace-id", v);
    }
    res
}

fn main() {
    // 默认无窗服务；仅 --gui / --desktop 才开「AI 助手」WebView。
    // --service 与默认等价（兼容托盘与旧启动脚本）。
    init_tracing();
    let args: Vec<String> = std::env::args().collect();
    let want_gui = args.iter().any(|a| a == "--gui" || a == "--desktop");
    let is_service = !want_gui; // 默认 / --service → 无窗

    let config = load_or_create_config();
    let path = config_path();
    let port = config.port;
    let host = config.host.clone();
    let addr = format!("{}:{}", host, port);
    let url = format!("http://{}/", addr);

    if host != "127.0.0.1" && host != "::1" && host != "localhost" {
        eprintln!(
            "⚠️  服务监听地址 {} 不是本地回环，生产环境请确认防火墙/CORS 策略",
            host
        );
    }

    // ── 启动 axum 后台服务 ──
    let server_ready = Arc::new(AtomicBool::new(false));
    let server_ready_clone = server_ready.clone();
    // 战略罗盘「可观测」：在 main 作用域构建共享指标注册表（AppState 与 AgentCore 共享同一 Arc）
    let metrics = Arc::new(MetricsRegistry::new());

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("✗ Tokio 运行时创建失败: {}", e);
                std::process::exit(1);
            }
        };
        // 白龙马 Phase C: 启动扫描一次本机资源只读元数据（ssh/git），供条件式门控注入
        let local_resources: SharedResourceSnapshot =
            Arc::new(std::sync::Mutex::new(agent_core::resources::scan_local_resources()));
        rt.block_on(async move {
            let state = Arc::new(AppState {
                config: Mutex::new(config.clone()),
                agent: Mutex::new(None),
                config_path: path,
                auth_cache: tokio::sync::Mutex::new(HashMap::new()),
                ns_cache: tokio::sync::Mutex::new(HashMap::new()),
                collab_seen: tokio::sync::Mutex::new(HashMap::new()),
                consolidate_last_ymd: tokio::sync::Mutex::new(String::new()),
                consolidate_last: tokio::sync::Mutex::new(serde_json::json!({"status":"never"})),
                consciousness: tokio::sync::Mutex::new(None),
                local_resources: local_resources.clone(),
                consolidate_cursor: tokio::sync::Mutex::new(0),
                background_events: tokio::sync::Mutex::new(std::collections::VecDeque::new()),
                next_event_id: AtomicU64::new(1),
                evolve_running: AtomicBool::new(false),
                metrics: metrics.clone(),
                meeting_tx: tokio::sync::Mutex::new(HashMap::new()),
                meeting_presence: tokio::sync::Mutex::new(HashMap::new()),
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
                let mut reg_config = config.clone();
                // 双保险：确保分身专属 llm 的 ${ENV} 也展开（与全局池一致），
                // 避免 reg_config 在 load 展开之后被重新填充未展开副本时，persona tick 把字面量 ${...} 发往平台。
                expand_config_llm_env(&mut reg_config);
                tokio::spawn(async move {
                    match build_agent(&resolve_config_for_runtime(&reg_config), local_resources.clone(), reg_state.metrics.clone()).await {
                        Ok(agent) => {
                            println!(
                                "✓ Agent 已就绪（{}@{}）",
                                reg_config.agent_id, reg_config.server
                            );
                            *reg_state.agent.lock().await = Some(Arc::new(agent));
                            // Phase 5：从 agent.toml [[personas]] 配置表加载并联分身（default 已在 AgentCore::new 注册）
                            {
                                let g = reg_state.agent.lock().await;
                                if let Some(ref a) = *g {
                                    for pc in &reg_config.personas {
                                        let owner = if pc.owner_user_id.is_empty() { &reg_config.agent_id } else { &pc.owner_user_id };
                                        let _ = a.create_persona(
                                            &pc.id,
                                            &pc.display_name,
                                            owner,
                                            pc.tool_allowlist.clone(),
                                            pc.memory_namespace.clone(),
                                            pc.llm.clone(),
                                            false,
                                        );
                                        for goal in &pc.goals {
                                            let _ = a.push_persona_goal(&pc.id, goal);
                                        }
                                    }
                                    // 启动恢复：分身私有属性 + 圆桌会议记录（跨重启不丢）
                                    a.load_personas_from_disk();
                                    a.load_meetings_from_disk();
                                }
                            }
                            // A2: 启动白龙马 TICK 心跳（空闲 20min / 抢占 / 600s watchdog）
                            let cons = Consciousness::new(reg_state.clone());
                            tokio::spawn(cons.clone().run());
                            *reg_state.consciousness.lock().await = Some(cons);
                            // 启动回填 /health.dream：避免进程重启后假象 status=never
                            // agent 已就绪，同步回填（失败不阻断）；TICK 稍后还会再写 trigger=tick
                            hydrate_dream_health_from_memoria(&reg_state).await;
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
                        // 巡检须覆盖 dashboard 部门 ns（system_ops 挂在 dept/gufei）
                        let mut agent_ns = vec![agent.config.identity.ns()];
                        agent_core::dept_ops::enrich_allowed_ns(&mut agent_ns);
                        let tasks = [("system_ops", serde_json::json!({"action": "status"}))];
                        for (tool, args) in &tasks {
                            match agent.call_tool_routed(tool, "default", args, &agent_ns, "").await {
                                Ok(reply) => {
                                    fail_count = 0;
                                    tracing::info!(
                                        "巡检 {}: {}",
                                        tool,
                                        &reply.chars().take(60).collect::<String>()
                                    );
                                }
                                Err(e) => {
                                    fail_count = fail_count.saturating_add(1);
                                    if fail_count >= 3 {
                                        tracing::error!(
                                            "巡检连续失败 {} 次，工具 {}",
                                            fail_count,
                                            tool
                                        );
                                    } else {
                                        tracing::warn!(
                                            "巡检 {} 失败: {}（第 {} 次）",
                                            tool,
                                            e,
                                            fail_count
                                        );
                                    }
                                }
                            }
                        }
                        // 每 4 轮（约 2 小时）执行一次洞见发现
                        if insight_cycle % 4 == 0 {
                            let insight = agent.run_insights(&agent_ns).await;
                            tracing::info!("{}", insight);
                        }
                        // 暗知识层 A2：低峰（02:00-04:59 本地）每日最多巩固一轮
                        let now_local = Local::now();
                        let hour = now_local.hour();
                        let ymd = now_local.format("%Y-%m-%d").to_string();
                        let already = {
                            let g = patrol_state.consolidate_last_ymd.lock().await;
                            *g == ymd
                        };
                        if (2..=4).contains(&hour) && !already {
                            let default_ns = format!("agent/{}", agent.config.identity.agent_id);
            let ns_list = std::env::var("CONSOLIDATE_NAMESPACES")
                .unwrap_or(default_ns.clone());
                            let mut results = Vec::new();
                            for ns in ns_list
                                .split(',')
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                            {
                                let res = agent.consolidate(ns).await;
                                tracing::info!("[consolidate] {}", res);
                                results.push(serde_json::json!({"ns": ns, "result": res}));
                            }
                            // PR5 自驱：低峰 consolidate 维护周期后触发一轮元进化
                            // （受 meta_evolution.enabled + cooldown_hours 双重保护，非低峰/未开启则不动作）
                            let me_val = agent.run_meta_evolution(&default_ns).await;
                            tracing::info!(target: "consciousness", "meta_evolution(nightly): {}", me_val);
                            results.push(serde_json::json!({"ns": default_ns, "meta_evolution": me_val}));
                            record_dream_health(&patrol_state, "nightly", results, true).await;
                        }
                        // 每轮检查 dashboard agent_worker 健康（端口 8011）
                        let agent_ok = reqwest::get("http://127.0.0.1:8011/health")
                            .await
                            .map(|r| r.status().is_success())
                            .unwrap_or(false);
                        if !agent_ok {
                            // P0-3 修复：dashboard 凭据移出源码，改读环境变量。
                            // DASHBOARD_USER 默认 admin；DASHBOARD_PASSWORD 未设置则跳过重启（不泄露/不崩溃）。
                            let dash_user = std::env::var("DASHBOARD_USER")
                                .unwrap_or_else(|_| "admin".to_string());
                            let dash_pass = std::env::var("DASHBOARD_PASSWORD").unwrap_or_default();
                            if dash_pass.is_empty() {
                                tracing::warn!(
                                    "未设置 DASHBOARD_PASSWORD，跳过 dashboard agent worker 重启"
                                );
                            } else {
                                tracing::warn!("Agent worker 无响应，通过 dashboard API 重启");
                                let client = reqwest::Client::new();
                                if let Ok(login) = client
                                    .post("http://127.0.0.1:8000/api/login")
                                    .form(&[
                                        ("username", dash_user.as_str()),
                                        ("password", dash_pass.as_str()),
                                    ])
                                    .send()
                                    .await
                                {
                                    let cookie = login
                                        .headers()
                                        .get("set-cookie")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or("")
                                        .to_string();
                                    if !cookie.is_empty() {
                                        let _ = client
                                            .post("http://127.0.0.1:8000/api/snmis/agent/start")
                                            .header("Cookie", &cookie)
                                            .send()
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                    drop(agent_guard);
                }
            });

            let public = Router::new()
                .route("/", get(handle_index))
                .route("/logo.png", get(handle_logo))
                .route("/health", get(handle_health))
                .route("/api/config", get(handle_config))
                .route("/api/register", post(handle_register))
                .route("/api/register_user", post(handle_register_user))
                .route("/api/login", post(handle_login))
                .route("/api/approval/pending", get(handle_approval_pending))
                .route("/api/approval/history", get(handle_approval_history))
                .route("/api/approval/{id}/respond", post(handle_approval_respond))
                .route("/approval-console", get(handle_approval_console))
                .route("/updates/pfaix/latest.json", get(handle_updates_latest))
                .route("/updates/pfaix/{file}", get(handle_updates_static))
                // /v1 别名：PFAiX 的 getAgentCoreBaseUrl() 返回带 /v1 的 base，
                // lanManifestUrl 直接拼接导致请求 /v1/updates/...——旧版客户端无法改，
                // 服务端同时挂别名兼容（review/修复：检查更新 401 根因）
                .route("/v1/updates/pfaix/latest.json", get(handle_updates_latest))
                .route("/v1/updates/pfaix/{file}", get(handle_updates_static));

            let protected = Router::new()
                .route("/api/chat", post(handle_chat))
                .route("/api/chat/stream", get(handle_chat_stream))
                .nest(
                    "/api/sessions",
                    Router::new()
                        .route("/", get(handle_sessions))
                        .route("/{id}", get(handle_session_load).delete(handle_session_delete)),
                )
                .route("/api/admin/degrade", get(handle_admin_degrade))
                .route("/api/admin/killswitch", post(handle_admin_killswitch))
                .route("/api/metrics", get(handle_metrics))
                .route(
                    "/api/admin/quota",
                    get(handle_admin_quota_get).put(handle_admin_quota_put),
                )
                .route("/api/admin/audit", get(handle_admin_audit))
                .route(
                    "/api/admin/harness/activate",
                    post(handle_admin_harness_activate),
                )
                .route("/api/admin/consolidate", post(handle_admin_consolidate))
                .route("/api/admin/agent/repair", post(handle_agent_repair))
                .route("/api/agent/events", axum::routing::get(handle_agent_events))
                .route("/api/save-config", post(handle_save_config))
                .route("/api/collab/inbox", get(handle_collab_inbox))
                .route("/api/collab/send", post(handle_collab_send))
                .route("/api/collab/approval", post(handle_collab_approval))
                .route("/api/collab/delete", post(handle_collab_delete))
                .route("/api/collab/peers", get(handle_collab_peers))
                .route("/api/memory/feedback", post(handle_memory_feedback))
                .route("/v1/chat/completions", post(handle_v1_chat))
                .route("/api/persona", post(handle_persona_create).get(handle_persona_list))
                .route("/api/persona/{id}", delete(handle_persona_delete).get(handle_persona_get))
                .route("/api/persona/{id}/goal", post(handle_persona_goal_push))
                .route("/api/session/persona", post(handle_session_persona_bind))
                .route("/api/documents/archive", post(handle_documents_archive))
                .route("/api/roundtable", post(handle_panel_discuss))
                .route("/api/meetings", get(handle_meetings_list))
                .route("/api/meetings/{id}", delete(handle_meeting_delete))
                .route("/api/meetings/{id}/stream", get(handle_meeting_stream))
                .route("/api/meetings/{id}/heartbeat", post(handle_meeting_heartbeat))
                .route("/api/meetings/{id}/message", post(handle_meeting_message))
                .route("/api/meetings/{id}/end", post(handle_meeting_end))
                .route("/api/evolve", post(handle_code_evolve))
                .route("/api/meta-evolution/run", post(handle_meta_evolution_run))
                .route("/api/meta-evolution/status", get(handle_meta_evolution_status))
                .layer(from_fn_with_state(state.clone(), auth_middleware));

            let cors = build_cors_layer(&host, port, &config.cors_origins);
            let app = public
                .merge(protected)
                .layer(cors)
                .layer(axum::middleware::from_fn(trace_middleware))
                .with_state(state.clone());

            // 后台周期回收无接收者的会议 broadcast 通道（兜底清理并发退出竞态导致的 Sender 泄漏）
            spawn_meeting_channel_sweeper(state.clone());
            spawn_meeting_presence_sweeper(state.clone());

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
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // ── tao 桌面窗口（无黑框） ──
    let event_loop = EventLoopBuilder::new().build();

    let window = WindowBuilder::new()
        .with_title("AI 助手")
        .with_window_icon(_load_icon())
        .with_inner_size(tao::dpi::LogicalSize::new(800.0, 710.0))
        .build(&event_loop)
        .expect("创建窗口失败");

    let _webview = WebViewBuilder::new().with_url(&url).build(&window);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            _ => (),
        }
    });
}

// ── Axum handlers ──

async fn handle_panel_discuss(
    headers: axum::http::HeaderMap,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let topic = match v.get("topic").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST, "topic required").into_response(),
    };
    let chair = v.get("chair").and_then(|x| x.as_str()).map(|s| s.to_string());
    let session_id = v.get("session_id").and_then(|x| x.as_str()).unwrap_or("");
    // 可选 personas 筛选：前端分身多选生效。空/缺省则全部参与。
    let selected_ids: Option<Vec<String>> = v
        .get("personas")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty());
    // 圆桌默认私有（仅拥有者 / admin 可见）；显式 visibility=public 才公开
    let is_private = !(v
        .get("visibility")
        .and_then(|x| x.as_str())
        .map(|s| s == "public")
        .unwrap_or(false));
    // 会议升级 Step1：层级范围（dept:<id> / org:<company>）。
    // 提供时按 scope 过滤分身；缺省走全部（兼容旧客户端）。
    let scope: Option<String> = v
        .get("scope")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    // 会议升级 Step1：发起者只能创建自己所属 scope 的会议（非 admin 时），
    // 防止越权创建他人 scope 的部门/公司会议。
    if let Some(ref sc) = scope {
        if !admin && !agent_core::agent::scope_matches_caller(sc, &caller_ns) {
            return (
                axum::http::StatusCode::FORBIDDEN,
                format!("无权发起该 scope 的会议：{}", sc),
            )
                .into_response();
        }
    }

    // 会议升级 Step2：真人 A2A 参会者（agent_id 列表）。
    // 前端「真人参会」多选产生；每人以 `agent/<id>` 收件箱接收会议开播通知。
    let participant_agents: Vec<String> = v
        .get("participants")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let participant_agents_c = participant_agents.clone();

    // 计算实际参与者（用于会议记录），并预建会议记录（status=running）
    let g0 = st.agent.lock().await;
    let has_agent = g0.is_some();
    let mut participants: Vec<String> = Vec::new();
    if let Some(ref agent) = *g0 {
        let mut personas = agent.list_personas_scoped(scope.as_deref());
        personas.sort_by(|a, b| a.persona_id.cmp(&b.persona_id));
        if let Some(ids) = &selected_ids {
            personas.retain(|p| ids.contains(&p.persona_id));
        }
        participants = personas.iter().map(|p| p.persona_id.clone()).collect();
    }
    drop(g0);
    if !has_agent {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    }
    let (meeting_id, create_arc) = {
        let g = st.agent.lock().await;
        match &*g {
            Some(ref agent) => {
                let arc = agent.clone();
                let id = agent.create_meeting(
                    &topic,
                    &caller,
                    participants.clone(),
                    participant_agents,
                    is_private,
                    scope.clone(),
                );
                (id, Some(arc))
            }
            None => (String::new(), None),
        }
    };
    // 【round-17 #2】create_meeting 已不再内部落盘：在全局 st.agent 锁释放后、于锁外用
    // spawn_blocking 持久化新建会议，避免同步 fsync 阻塞 tokio worker / 全局锁。
    if let Some(arc) = &create_arc {
        let _ = persist_meetings_for(arc, |e| {
            // reviewer round-21 #2 maintainability·low：日志标签用实际 handler——本路径由
            // `handle_panel_discuss`（/api/roundtable）创建会议，非「handle_meetings_create」，
            // 错误标签会误导排障者定位错误 handler。
            tracing::error!(error = %e, meeting = %meeting_id, "roundtable: 会议已创建但落盘失败（可能进程崩溃丢失，请排查磁盘）");
        }).await;
    }

    let st_clone = st.clone();
    let (tx, rx): (
        tokio::sync::mpsc::UnboundedSender<Result<SseEvent, Infallible>>,
        tokio::sync::mpsc::UnboundedReceiver<Result<SseEvent, Infallible>>,
    ) = tokio::sync::mpsc::unbounded_channel();

    let topic_c = topic.clone();
    let chair_c = chair.clone();
    let session_c = session_id.to_string();
    let sel_c = selected_ids;
    let scope_c = scope;
    let meeting_id_c = meeting_id.clone();
    let owner_c = caller.clone();
    tokio::spawn(async move {
        // 仅取 Arc<AgentCore> 克隆后立即释放全局 agent 锁：
        // 收敛过程含 LLM 调用 / A2A 投递，绝不能在整个 SSE 任务期间持全局锁
        // （reviewer round-11 F2：原 `let Some(ref agent) = *g` 让 guard 活到任务结束，
        // 嵌套 agent→meeting_tx 广播且阻塞所有并发 agent 操作）。
        // 克隆出的 Arc 全程持有，所有 agent 方法经 &AgentCore 调用，不再依赖全局锁。
        let agent_arc: std::sync::Arc<AgentCore> = {
            let g = st_clone.agent.lock().await;
            match g.as_ref() {
                Some(a) => a.clone(),
                None => {
                    let _ = tx.send(Ok(SseEvent::default().event("done").data("")));
                    return;
                }
            }
        };
        let agent = agent_arc.as_ref();
        let ns = agent.caller_ns(&session_c);
        // 会议升级 Step2：开场即 A2A 通知真人参与者（agent/<id> 收件箱）
        if !meeting_id_c.is_empty() && !participant_agents_c.is_empty() {
            let notice = serde_json::json!({
                "type": "meeting",
                "subject": format!("会议「{}」已开始，等待你的参会意见", topic_c),
                "meeting": meeting_id_c,
                "from": owner_c,
                "content": format!("会议「{}」已由 {} 发起并开始，会议 ID={}。请通过 /api/meetings/{}/message 提交你的意见。", topic_c, owner_c, meeting_id_c, meeting_id_c),
                "kind": "meeting-notice",
            });
            for t in &participant_agents_c {
                if let Err(e) = agent.collab_send_raw(t, &notice).await {
                    tracing::warn!(target = %t, "会议开播通知 A2A 投递失败: {}", e);
                }
            }
        }
        let mut personas = agent.list_personas_scoped(scope_c.as_deref());
        personas.sort_by(|a, b| a.persona_id.cmp(&b.persona_id));
        if let Some(ids) = &sel_c {
            personas.retain(|p| ids.contains(&p.persona_id));
        }
        let pool = agent.llm_pool();
        let mut stances: Vec<(String, String)> = Vec::new();
        for (i, p) in personas.iter().enumerate() {
            let (id, stance, prov) = agent.persona_stance(p, &topic_c, i, &pool).await;
            let payload = serde_json::json!({
                "persona_id": id,
                "display_name": p.display_name,
                "stance": stance,
                "provider": prov,
            });
            let _ = tx.send(Ok(SseEvent::default().event("stance").data(payload.to_string())));
            stances.push((id, stance));
        }
        let consensus = agent.chair_consensus(&topic_c, &stances, chair_c.as_deref()).await;
        let _ = tx.send(Ok(SseEvent::default().event("consensus").data(
            serde_json::json!({ "consensus": consensus }).to_string(),
        )));
        // 回填会议记录（共识 + 状态机跃迁），并把收敛结果实时广播给订阅端：
        // - 终态（status=done / phase=Done）→ ended，关闭订阅流；
        // - 非终态（真人待接手）→ state，订阅端更新 phase（ai_speaking → awaiting_humans）。
        // 否则订阅者永远看不到本次跃迁，停留在陈旧状态。
        if !meeting_id_c.is_empty() {
            if let Some((status, phase)) = agent.finish_meeting(&meeting_id_c, &consensus) {
                // 【reviewer round-24 #2 performance·medium】**先广播实时事件 + 清理 presence，
                // 再后台持久化**——与 handle_meeting_message（round-21 #1）的原则一致。persist 是
                // spawn_blocking 全文件序列化 + fsync 且被 persist_lock 串行化，若 await 它再广播，
                // 磁盘延迟会排在实时 phase 转换（ai_speaking → awaiting_humans，正是真人订阅者等待
                // 的信号）之前，并发写时订阅者要多等一次 fsync。持久化是 best-effort（失败仅 error
                // 日志、会议已在内存、后续 save 会带上），故把实时广播/清理放最前。
                // 【round-20 #5】终态判定用 meeting_state 的 terminal flag（单一来源，覆盖 phase_raw）：
                // finish_meeting 内部已保证 status/phase 已知，但统一走权威谓词避免未来新增终态漏改。
                let terminal = agent
                    .meeting_state(&meeting_id_c)
                    .map_or(true, |(_, _, _, term)| term);
                if terminal {
                    broadcast_meeting_event(
                        &st,
                        &meeting_id_c,
                        EventKind::Ended,
                        serde_json::json!({ "status": status, "phase": phase, "terminal": true }),
                    ).await;
                    // 【round-20 #6】纯 AI 圆桌收敛到终态时，与 handle_meeting_end / delete 一致
                    // 移除 presence 条目，避免该会议已终态、无人再心跳而滞留（sweeper 仍兜底）。
                    st.meeting_presence.lock().await.remove(&meeting_id_c);
                } else {
                    broadcast_meeting_event(
                        &st,
                        &meeting_id_c,
                        EventKind::State,
                        serde_json::json!({ "status": status, "phase": phase }),
                    ).await;
                }
                // 【round-17 #5 + round-24 #2】收敛状态持久化移到广播**之后**：spawn_blocking 迁移
                // 写盘到阻塞线程池，避免同步 fsync 阻塞 tokio worker / 挡住实时广播。
                let _ = persist_meetings_for(&agent_arc, |e| {
                    tracing::error!(error = %e, meeting = %meeting_id_c, "roundtable: 共识已回填但落盘失败（可能进程崩溃丢失，请排查磁盘）");
                }).await;
            }
        }
        // 最佳努力写入 Memoria（调用者自身 ns）
        let stances_text = stances
            .iter()
            .map(|(id, s)| format!("【{}】{}", id, s))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!(
            "[roundtable] topic={}\nconsensus={}\n---\n{}",
            topic_c, consensus, stances_text
        );
        // Profile/dynamic 主源读 memories(category=decision)；勿再写 category=roundtable
        let args = serde_json::json!({
            "content": content,
            "tags": ["decision", "roundtable"],
            "category": "decision",
            "confidence": 80,
            "importance": 5,
            "namespace": ns,
        });
        if agent.mcp.call_json("memory_remember", &args).await.is_ok() {
            tracing::info!(ns = %ns, "roundtable 共识已写入 Memoria(category=decision)");
        }
        let _ = tx.send(Ok(SseEvent::default().event("done").data("")));
    });

    Sse::new(UnboundedReceiverStream::new(rx)).into_response()
}

/// Phase 6 增强：列出调用者可见的圆桌会议（私有仅拥有者 / admin 可见；scope 会议同级成员可见）
async fn resolve_caller_memoria_key(
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

async fn handle_collab_inbox(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<CollabInboxQuery>,
) -> axum::response::Response {
    let (agent_id, allowed_ns) = match authenticate(&headers, &st).await {
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
            match agent.collab_inbox_raw(&agent_id, &agent_key, limit).await {
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
/// - `namespace`: 可选；默认 `agent/{x-agent-id}`
async fn handle_memory_feedback(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> axum::response::Response {
    let (agent_id, _allowed_ns) = match authenticate(&headers, &st).await {
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
    let ns = body
        .get("namespace")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("agent/{}", agent_id));

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

/// 协作发送（POST /api/collab/send）
///
/// 校验 type 白名单 + 可达策略（§3.3）后，按 scope 构建信封并投递：
/// - scope=agent → 点对点 a2a_send 到 `agent/{to_agent}`
/// - scope=org/dept/proj → 经 `agent_list` 展开 NS 树为多收件人，逐一 a2a_send（fan-out）
/// 实际送达经服务端受信身份（admin 中继）完成；Memoria NS 门控仅作纵深防御。
async fn handle_collab_send(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<CollabSendBody>,
) -> axum::response::Response {
    let (agent_id, allowed_ns) = match authenticate(&headers, &st).await {
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

    // 2) 可达策略（§3.3）
    let scope = body.scope.trim();
    let scope_id = body.scope_id.clone().unwrap_or_default();
    if let Err(msg) = collab_reachability(&agent_id, &allowed_ns, scope, &scope_id, etype) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": msg})),
        )
            .into_response();
    }

    // 3) 构建信封（§3.1）
    let from_ns = allowed_ns
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
fn peers_ns_of(peers: &[serde_json::Value], id: &str) -> String {
    peers
        .iter()
        .find(|p| p["agent_id"].as_str() == Some(id))
        .and_then(|p| p["namespace"].as_str())
        .unwrap_or("")
        .to_string()
}

/// 构建标准协作信封（§3.1）。`to` 为单个收件人 agent_id（fan-out 时逐封改写）。
fn build_collab_envelope(
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
async fn handle_collab_approval(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<CollabApprovalBody>,
) -> axum::response::Response {
    let (agent_id, allowed_ns) = match authenticate(&headers, &st).await {
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
async fn handle_approval_console() -> Html<&'static str> {
    Html(APPROVAL_CONSOLE_HTML)
}

/// 审批响应请求体（POST /api/approval/{id}/respond）
#[derive(serde::Deserialize)]
struct ApprovalRespondBody {
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
async fn is_admin_by_admin_key(headers: &axum::http::HeaderMap, st: &Arc<AppState>) -> bool {
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    !admin_key.is_empty() && key == admin_key
}

/// 列出待人工审批项（仅 admin）
async fn handle_approval_pending(
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
async fn handle_approval_history(
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
async fn handle_approval_respond(
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
const APPROVAL_CONSOLE_HTML: &str = r##"<!DOCTYPE html>
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
const API = "http://127.0.0.1:9753";
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

/// 协作通讯录（GET /api/collab/peers）
///
/// 返回同组织已注册 Agent 列表（经 admin 中继调 Memoria `agent_list`）。
async fn handle_collab_peers(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let (_agent_id, _allowed_ns) = match authenticate(&headers, &st).await {
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

/// POST /api/collab/delete — 删除收件箱中的一条消息（通知清理）
#[derive(serde::Deserialize)]
struct CollabDeleteBody {
    /// 要删除的消息 id（collab/inbox 返回的 id）
    id: String,
}

async fn handle_collab_delete(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<CollabDeleteBody>,
) -> axum::response::Response {
    let (agent_id, _allowed_ns) = match authenticate(&headers, &st).await {
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

#[derive(Deserialize)]
struct RegisterRequest {
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
    /// 管理/HR 预置的命名空间（部门/项目级）。仅当携带合法 admin_key 时才生效，
    /// 否则忽略并回退到默认 org 根——防止普通自助注册自我提权到任意部门/项目。
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    admin_key: String,
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

/// 协作通讯录展示名：「{部门展示}部{姓名}」；部门/姓名缺失时回退到可用值。
/// 仅用于 display_name，绝不进入 agent_id / namespace / HTTP 头。
fn agent_display_name(dept_display: &str, name_display: &str, fallback: &str) -> String {
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
struct ArchiveDocumentRequest {
    /// 本机绝对路径（PFAiX 对话栏附件）
    path: String,
    #[serde(default)]
    filename: String,
    /// 默认固废部门共享 ns
    #[serde(default)]
    namespace: String,
}

/// PFAiX 对话栏 → 部门共享文档归档：读本机文件，转发 Memoria `POST /api/documents`
async fn handle_documents_archive(
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
struct AgentRepairRequest {
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
async fn handle_agent_repair(
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
async fn handle_register_user(
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
async fn handle_login(
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
        features: config.features.clone(),
        lats: config.lats.clone(),
        multiagent: config.multiagent.clone(),
        ttc: config.ttc.clone(),
        intake_filter: config.intake_filter.clone().unwrap_or_default(),
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

#[cfg(test)]
mod collab_policy_tests {
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
}

