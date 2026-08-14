//! 启动辅助（从 src/main.rs 拆出，P7 重构）。
//!
//! 承载：CORS 层构造、tracing 初始化、trace 中间件、窗口图标加载，
//! 以及服务端启动（`spawn_server`：AppState 构造 / 端口绑定 / agent 注册 /
//! 巡检循环 / 路由装配 / HTTP serve）。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::middleware::Next;
use chrono::{Local, Timelike};
use rand::Rng;
use tokio::sync::Mutex;
use tokio::time::interval;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::Instrument;
use tracing_subscriber::EnvFilter;

use agent_core::metrics::MetricsRegistry;
use agent_core::resources::SharedResourceSnapshot;

use crate::config::*;
use crate::handlers::identity::build_agent;
use crate::handlers::meetings::{
    spawn_meeting_channel_sweeper, spawn_meeting_presence_sweeper,
};
use crate::routes::build_router;
use crate::state::*;

pub(crate) fn build_cors_layer(host: &str, port: u16, configured: &[String]) -> CorsLayer {
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

pub(crate) fn init_tracing() {
    let filter = EnvFilter::try_from_env("AGENT_CORE_LOG")
        .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

pub(crate) async fn trace_middleware(request: Request, next: Next) -> axum::response::Response {
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

/// 后台线程启动 axum 服务：AppState 构造 → 端口绑定 → agent 注册 →
/// 巡检循环 → 路由装配 → HTTP serve。`server_ready` 在端口绑定成功后置位。
/// 从 src/main.rs 迁入，零行为变更。
pub(crate) fn spawn_server(
    config: Config,
    path: String,
    server_ready: Arc<AtomicBool>,
    metrics: Arc<MetricsRegistry>,
) {
    let addr = format!("{}:{}", config.host, config.port);
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
            server_ready.store(true, Ordering::SeqCst);

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
                            // 记忆库维护：衰减循环 + GFS 轮转备份（每日一次，与 consolidate 同周期）
                            let maint = agent.memoria_maintenance().await;
                            results.push(serde_json::json!({"ns": "system", "maintenance": maint}));
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

            let cors = build_cors_layer(&config.host, config.port, &config.cors_origins);
            let app = build_router(state.clone(), cors);

            // 后台周期回收无接收者的会议 broadcast 通道（兜底清理并发退出竞态导致的 Sender 泄漏）
            spawn_meeting_channel_sweeper(state.clone());
            spawn_meeting_presence_sweeper(state.clone());

            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("HTTP 服务异常终止: {}", e);
            }
        });
    });
}

/// 加载窗口图标（从 logo.png 解码，保留 2:1 比例；仅 GUI 模式使用）
pub(crate) fn _load_icon() -> Option<tao::window::Icon> {
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
