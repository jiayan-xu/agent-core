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

use axum::{
    extract::{Request, State},
    middleware::{from_fn_with_state, Next},
    response::{
        sse::{Event as SseEvent, Sse},
        IntoResponse,
    },
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{Local, Timelike};
use rand::Rng;
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

use agent_core::agent::{AgentCore, EventKind};
use agent_core::metrics::MetricsRegistry;
use agent_core::resources::SharedResourceSnapshot;

mod config;
use config::*;
mod state;
use state::*;
mod auth;
use auth::*;
mod handlers;
use handlers::admin::*;
use handlers::approval::*;
use handlers::chat::*;
use handlers::collab::*;
use handlers::evolve::*;
use handlers::identity::*;
use handlers::meetings::*;
use handlers::system::*;

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
