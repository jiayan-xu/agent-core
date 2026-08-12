//! agent-core — HTTP 引擎（默认无窗）
//!
//! 默认以服务模式运行（仅 `:9753` HTTP，不弹桌面窗）。
//! 需要内嵌 WebView「AI 助手」调试窗时显式传 `--gui`。
//! `--service` 仍保留，与默认行为等价（兼容旧脚本/托盘）。
//! 内置巡检循环：每 30 分钟调用 Dashboard MCP 执行定时任务。
//!
//! 重构后本文件仅保留：入口参数解析 + 服务启动调用 + GUI 窗口（P7）。
//! 服务端启动逻辑见 `bootstrap::spawn_server`，路由装配见 `routes::build_router`。

// P2-1 修复：仅 release 模式下隐藏控制台窗口，debug 模式保留
// GUI 模式用 windows subsystem；默认/service 保留控制台便于运维日志
#![cfg_attr(
    all(not(debug_assertions), not(feature = "service")),
    windows_subsystem = "windows"
)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

use agent_core::metrics::MetricsRegistry;

mod auth;
mod bootstrap;
mod config;
mod handlers;
mod routes;
mod state;

use bootstrap::*;
use config::*;

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

    // ── 启动 axum 后台服务（AppState 构造/agent 注册/巡检循环/路由装配见 bootstrap） ──
    let server_ready = Arc::new(AtomicBool::new(false));
    // 战略罗盘「可观测」：共享指标注册表（AppState 与 AgentCore 共享同一 Arc）
    let metrics = Arc::new(MetricsRegistry::new());
    spawn_server(config, path, server_ready.clone(), metrics);

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
