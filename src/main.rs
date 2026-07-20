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
    extract::{Extension, Request, State},
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

use agent_core::agent::{AgentConfig, AgentCore, AgentIdentity};
use agent_core::audit::AuditLogger;
use agent_core::boundary::PermissionLevel;
use agent_core::harness::HarnessStore;
use agent_core::llm::LlmConfig;
use agent_core::approval::ApprovalResponse;
use agent_core::mcp_client::McpClient;
use agent_core::resources::SharedResourceSnapshot;

/// 公司根命名空间（与 agent.toml 的 mcp_source namespace org/ 前缀、Memoria 注册一致）
const ORG_COMPANY: &str = "cs-pufa-2nd-thermal";

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
    #[serde(default = "default_host")]
    host: String,
    #[serde(default)]
    cors_origins: Vec<String>,
    #[serde(default)]
    memoria_admin_key: String,
    #[serde(default)]
    mcp_source: Vec<McpSourceConfig>,
    #[serde(default)]
    personas: Vec<PersonaConfig>,
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

/// Phase 5：配置化分身定义（agent.toml [[personas]] 表）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersonaConfig {
    /// 分身 id（必填，不得为 "default"）
    id: String,
    #[serde(default)]
    display_name: String,
    /// 拥有者 user_id；缺省用 Config.agent_id
    #[serde(default)]
    owner_user_id: String,
    /// 工具白名单；缺省空 = 不限制
    #[serde(default)]
    tool_allowlist: Vec<String>,
    /// 该分身专属 memory 命名空间；缺省空
    #[serde(default)]
    memory_namespace: String,
    /// 启动即压入的目标栈（goals）
    #[serde(default)]
    goals: Vec<String>,
    /// 该分身专属 LLM 配置；缺省空 = 圆桌/tick 时回退全局 client，并由圆桌自动从 LLM 池分配
    #[serde(default)]
    llm: Option<LlmConfig>,
}

fn default_server() -> String {
    "http://127.0.0.1:9003".to_string()
}

/// Memoria admin 钥匙（运维 `.env` / `MEMORIA_ADMIN_KEY`）。用于 admin 参数与字面 admin 身份。
fn env_memoria_admin_key(fallback: &str) -> String {
    match std::env::var("MEMORIA_ADMIN_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => fallback.to_string(),
    }
}

/// dashboard-agent 专属 badge（`MEMORIA_DASHBOARD_BADGE`）；与 admin 不得同 token（UNIQUE）。
/// 未设置时回退 `MEMORIA_ADMIN_KEY`（过渡兼容，生产应显式分钥）。
fn env_memoria_dashboard_badge(admin_fallback: &str) -> String {
    match std::env::var("MEMORIA_DASHBOARD_BADGE") {
        Ok(k) if !k.is_empty() => k,
        _ => env_memoria_admin_key(admin_fallback),
    }
}

fn default_port() -> u16 {
    9753
}
fn default_host() -> String {
    "127.0.0.1".to_string()
}

/// P2-6：配置字符串脱敏——将 `${VAR}` / `$VAR` 替换为环境变量值。
/// 用于让 `agent.toml` 不落盘明文密钥：写 `token = "${DEPT_MCP_TOKEN}"`，
/// 运行时从环境注入。未设置的变量原样保留（便于发现配置缺失）。
/// 仅作用于字符串字段，不影响数字/布尔。
fn expand_env(value: &str) -> String {
    if !value.contains('$') {
        return value.to_string();
    }
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'{') {
                chars.next(); // 消费 '{'
                let mut name = String::new();
                let mut closed = false;
                while let Some(&nc) = chars.peek() {
                    if nc == '}' {
                        chars.next();
                        closed = true;
                        break;
                    }
                    name.push(nc);
                    chars.next();
                }
                if closed {
                    if let Ok(v) = std::env::var(&name) {
                        result.push_str(&v);
                    }
                    // 未设置：保留 ${NAME} 原样
                } else {
                    result.push_str("${");
                    result.push_str(&name);
                }
            } else {
                let mut name = String::new();
                while let Some(&nc) = chars.peek() {
                    if nc.is_alphanumeric() || nc == '_' {
                        name.push(nc);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if !name.is_empty() {
                    if let Ok(v) = std::env::var(&name) {
                        result.push_str(&v);
                    }
                } else {
                    result.push('$');
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

impl Config {
    fn configured(&self) -> bool {
        !self.agent_id.is_empty() && !self.api_key.is_empty()
    }
}

#[derive(Debug, Deserialize)]
struct ChatRequest {
    message: String,
    #[serde(default = "default_sid")]
    session_id: String,
}
fn default_sid() -> String {
    "default".to_string()
}
#[derive(Debug, Serialize)]
struct ChatResponse {
    reply: String,
    session_id: String,
}
#[derive(Debug, Deserialize)]
struct SetupRequest {
    agent_id: String,
    api_key: String,
    #[serde(default)]
    server: String,
}
#[derive(Debug, Serialize)]
struct SetupResponse {
    ok: bool,
    error: Option<String>,
}

/// 协作收件箱列表查询参数（GET /api/collab/inbox）
#[derive(Debug, serde::Deserialize)]
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
        || blob.contains(&format!("org/{}", ORG_COMPANY))
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
    // 避免 dashboard-agent 等服务身份误发国庆通知；须显式进白名单或 role。
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
    namespace.contains(&format!("org/{}", ORG_COMPANY)) || namespace.contains('*')
}

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
    /// 协作收件箱「已读游标」：agent_id → 最近一次查看的 ISO 时间（用于未读计数）
    collab_seen: tokio::sync::Mutex<HashMap<String, String>>,
    /// Dream 巩固：上次成功跑完的本地日历日（YYYY-MM-DD），避免 02–05 点巡检重复巩固
    consolidate_last_ymd: tokio::sync::Mutex<String>,
    /// Dream 巩固：最近一次结果摘要（供 /health、/api/admin/consolidate）
    consolidate_last: tokio::sync::Mutex<serde_json::Value>,
    /// 白龙马 A2 TICK 心跳句柄（用户消息到达时 interrupt 抢占在途 tick）
    consciousness: tokio::sync::Mutex<Option<Arc<Consciousness>>>,
    /// 白龙马 Phase B A4: consolidation round-robin 游标（内存态，v1 不持久化，对齐白龙马游标）
    consolidate_cursor: tokio::sync::Mutex<usize>,
    /// 白龙马 Phase B: 多端唤醒 —— 后台活动事件队列（供 PFAiX 轮询拉取"唤醒"）
    background_events: tokio::sync::Mutex<std::collections::VecDeque<BackgroundEvent>>,
    /// 白龙马 Phase C: 条件式本地资源门控 —— 启动扫描的只读资源快照句柄（与 AgentCore 共享）
    local_resources: SharedResourceSnapshot,
    /// 白龙马 Phase B: 事件自增 id
    next_event_id: AtomicU64,
}

/// 白龙马 Phase B：多端唤醒 —— 后台活动事件（心跳自主产生的活动，供 PFAiX 拉取"唤醒"）
/// 采用拉模型：agent-core 单方面维护队列 + 暴露 /api/agent/events，不依赖 PFAiX 改代码。
#[derive(Clone, serde::Serialize)]
struct BackgroundEvent {
    id: u64,
    ts: String,
    kind: String, // "consolidate" | "prefetch"
    summary: String,
}
impl BackgroundEvent {
    fn new(kind: &str, summary: String) -> Self {
        Self {
            id: 0, // 由 emit_event 分配自增 id
            ts: Local::now().to_rfc3339(),
            kind: kind.to_string(),
            summary,
        }
    }
}

/// 白龙马 A2: TICK 意识主循环（心跳 / 抢占 / watchdog）
/// 持有 AppState 以便空闲 tick 访问 Agent；interrupt 由用户消息 handler 触发抢占。
struct Consciousness {
    state: Arc<AppState>,
    interrupt: Arc<tokio::sync::Notify>,
}

impl Consciousness {
    fn new(state: Arc<AppState>) -> Arc<Self> {
        Arc::new(Self {
            state,
            interrupt: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// 用户消息到达 → 打断在途 tick（等价白龙马 AbortController.abort）
    fn interrupt(&self) {
        self.interrupt.notify_one();
    }

    async fn run(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(20 * 60)); // 空闲默认 20 分钟
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tracing::info!("consciousness: TICK 循环启动（空闲 20min / 抢占 / 600s watchdog）");
        loop {
            tokio::select! {
                _ = self.interrupt.notified() => {
                    tracing::info!("consciousness: 收到抢占信号（用户消息在途），跳过本轮空闲 tick");
                    continue;
                }
                _ = tick.tick() => {}
            }
            let st = self.state.clone();
            let intr = self.interrupt.clone();
            let wd = tokio::time::timeout(Duration::from_secs(600), async move {
                tokio::select! {
                    _ = intr.notified() => {
                        tracing::info!("consciousness: tick 工作进行中被抢占，终止");
                    }
                    _ = Consciousness::tick_once(&st) => {}
                }
            }).await;
            if wd.is_err() {
                tracing::warn!(target: "consciousness_watchdog", "consciousness: 空闲 tick 超时(>600s)被 watchdog 回收");
            }
        }
    }

    async fn tick_once(state: &AppState) {
        // 取 agent 引用（沿用 A2 模式：持锁跨 await 调用 silent 心跳 + A4）
        let guard = state.agent.lock().await;
        let Some(agent) = guard.as_ref() else { return; };

        // 1) 静默心跳（更新内部状态，不回复用户）—— A2 原始语义
        agent.run_idle_tick().await;

        // 2) A4: round-robin consolidation（对齐白龙马每 30min 一个实体；我方按 ns 推进）
        if let Some(ev) = Self::consolidate_round_robin(state, agent).await {
            Self::emit_event(state, ev).await;
        }

        // 3) 主动预取实验（guarded，默认关）
        if let Some(ev) = Self::guarded_prefetch(agent).await {
            Self::emit_event(state, ev).await;
        }

        // Phase 2: 分身真实 tick（复用空闲 tick 循环，每个已注册分身跑一次真实 LLM tick）
        for (pid, line) in agent.persona_tick_all().await {
            tracing::info!(target: "consciousness", "persona tick [{}]: {}", pid, line);
        }
    }

    /// A4: 空闲 tick 推进一个 namespace 的 consolidation（round-robin 游标）
    /// 对齐白龙马 consolidation-loop.js：每轮只处理一个候选，游标内存态不持久化。
    async fn consolidate_round_robin(state: &AppState, agent: &AgentCore) -> Option<BackgroundEvent> {
        let default_ns = format!("agent/{}", agent.config.identity.agent_id);
        let ns_list: Vec<String> = std::env::var("CONSOLIDATE_NAMESPACES")
            .unwrap_or_else(|_| default_ns.clone())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if ns_list.is_empty() {
            return None;
        }
        let idx = {
            let mut c = state.consolidate_cursor.lock().await;
            let i = *c % ns_list.len();
            *c = *c + 1;
            i
        };
        let ns = &ns_list[idx];
        tracing::info!(target: "consciousness", ns = %ns, cursor = idx, "A4: 空闲 tick 推进 consolidation round-robin");
        // 内层预算超时（外层 TICK 已有 600s watchdog），避免单次 consolidate 卡住整轮
        let res = tokio::time::timeout(Duration::from_secs(300), agent.consolidate(ns)).await;
        match res {
            Ok(summary) => {
                let summary = format!("consolidate[{}]: {}", ns, summary);
                tracing::info!(target: "consciousness", "{}", summary);
                Some(BackgroundEvent::new("consolidate", summary))
            }
            Err(_) => {
                tracing::warn!(target: "consciousness_watchdog", ns = %ns, "A4: consolidate 超时(>300s)跳过");
                None
            }
        }
    }

    /// 主动预取实验（对齐白龙马死代码 cron 预热的反面：只探测工具可用性，不预执行业务数据）
    /// 默认关闭；AGENT_PRETEST=1 才识别候选，AGENT_PRETEST_EXEC=1 才实际 dummy 调用（默认关）。
    async fn guarded_prefetch(agent: &AgentCore) -> Option<BackgroundEvent> {
        let enabled = std::env::var("AGENT_PRETEST")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let allowed_ns: Vec<String> = vec![format!("agent/{}", agent.config.identity.agent_id)];
        let tools = agent.fetch_tools_filtered(&allowed_ns).await;
        // 选第一个「只读 + 无必填参数」的工具做 liveness probe
        let candidate = tools.iter().find(|t| {
            let name = t.function.name.as_str();
            if !agent_core::boundary::is_read_only_tool(name) {
                return false;
            }
            let required = t.function.parameters.get("required").and_then(|r| r.as_array());
            match required {
                None => true,
                Some(arr) => arr.is_empty(),
            }
        });
        let Some(tool) = candidate else {
            tracing::info!(target: "consciousness", "guarded_prefetch: 无合适只读候选工具");
            return None;
        };
        let tool_name = tool.function.name.clone();
        let exec = std::env::var("AGENT_PRETEST_EXEC")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !exec {
            let summary = format!(
                "prefetch[probe]: 候选只读工具={}（未实际调用，AGENT_PRETEST_EXEC 未开）",
                tool_name
            );
            tracing::info!(target: "consciousness", "{}", summary);
            return Some(BackgroundEvent::new("prefetch", summary));
        }
        // 实际 dummy 调用（仅无副作用的空参 READ 工具），带 60s 预算
        let trace_id = format!("prefetch-{}", Local::now().timestamp());
        let call = tokio::time::timeout(
            Duration::from_secs(60),
            agent.call_tool_routed(&tool_name, "default", &serde_json::json!({}), &allowed_ns, &trace_id),
        )
        .await;
        let summary = match call {
            Ok(Ok(out)) => format!("prefetch[exec]: {}=ok ({}B)", tool_name, out.len()),
            Ok(Err(e)) => format!("prefetch[exec]: {}=err: {}", tool_name, e),
            Err(_) => format!("prefetch[exec]: {}=timeout(>60s)", tool_name),
        };
        tracing::info!(target: "consciousness", "{}", summary);
        Some(BackgroundEvent::new("prefetch", summary))
    }

    /// 多端唤醒：把后台活动事件入队（供 PFAiX 轮询 /api/agent/events 拉取"唤醒"）
    async fn emit_event(state: &AppState, mut ev: BackgroundEvent) {
        let id = state.next_event_id.fetch_add(1, Ordering::SeqCst);
        ev.id = id;
        let mut q = state.background_events.lock().await;
        q.push_back(ev);
        while q.len() > 200 {
            q.pop_front();
        }
    }
}

/// 构造 401 未授权响应
fn unauthorized(message: &str) -> axum::response::Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "unauthorized", "message": message})),
    )
        .into_response()
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
        // P2-2：鉴权失败审计（无身份）
        if let Some(ref a) = *st.agent.lock().await {
            a.audit_logger
                .auth_fail("", "缺少身份标识（x-agent-id / x-user-tag 均未提供）")
                .await;
        }
        return Err(unauthorized("请先通过 /api/register 注册身份"));
    };

    // 鉴权密钥：显式 x-agent-key 优先；legacy usertag 回退用 dashboard badge
    // （安装实例自身没有独立 key，由 agent-core 以 dashboard-agent 身份代为在 Memoria 注册）。
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let dash_badge = env_memoria_dashboard_badge(&cfg_admin);
    let agent_key = if !from_usertag {
        headers
            .get("x-agent-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    } else {
        dash_badge.clone()
    };
    let (server, actor) = {
        let cfg = st.config.lock().await;
        (cfg.server.clone(), cfg.agent_id.clone())
    };
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
        match mcp
            .call_json("get_allowed_ns", &serde_json::json!({}))
            .await
        {
            Ok(v) => {
                allowed_ns = v
                    .get("allowed_ns")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
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
            // 身份 = dashboard-agent + 专属 badge；admin_key 仅作 register 参数
            let reg = McpClient::new(&server, &actor, &dash_badge);
            let _ = reg
                .call_json(
                    "register_agent",
                    &serde_json::json!({
                        "agent_id": &agent_id,
                        "display_name": &agent_id,
                        "admin_key": &admin_key,
                        "namespace": &install_ns
                    }),
                )
                .await;
            allowed_ns = vec![
                format!("agent/{}", agent_id),
                "org/cs-pufa-2nd-thermal".to_string(),
            ];
        }
        if allowed_ns.is_empty() {
            // P2-2：鉴权失败审计（身份校验未通过）
            if let Some(ref a) = *st.agent.lock().await {
                a.audit_logger
                    .auth_fail(&agent_id, "身份校验未通过（Memoria 未返回授权命名空间）")
                    .await;
            }
            // 不向外部暴露内部错误细节（R6）
            return Err(unauthorized("身份校验失败，请稍后重试"));
        }
        st.ns_cache.lock().await.insert(
            agent_id.clone(),
            (allowed_ns.clone(), std::time::Instant::now()),
        );
    }
    Ok((agent_id, allowed_ns))
}

#[derive(Clone)]
struct AuthContext {
    agent_id: String,
    allowed_ns: Vec<String>,
}

/// 统一鉴权中间件。成功时把身份写入 extension；失败直接返回 401。
/// 豁免路径：静态壳 / 健康检查 / 注册/登录 onboarding。
async fn auth_middleware(
    State(st): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    let path = request.uri().path();
    let exempt = path == "/"
        || path == "/health"
        || path == "/api/register"
        || path == "/api/register_user"
        || path == "/api/login"
        || path == "/api/config";
    if exempt {
        return next.run(request).await;
    }
    match authenticate(request.headers(), &st).await {
        Ok((agent_id, allowed_ns)) => {
            let mut req = request;
            req.extensions_mut().insert(AuthContext {
                agent_id,
                allowed_ns,
            });
            next.run(req).await
        }
        Err(resp) => resp,
    }
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
            // P2-6：先展开配置中的 ${ENV} 占位符，避免明文密钥落盘
            cfg.api_key = expand_env(&cfg.api_key);
            cfg.memoria_admin_key = expand_env(&cfg.memoria_admin_key);
            cfg.server = expand_env(&cfg.server);
            for src in &mut cfg.mcp_source {
                src.url = expand_env(&src.url);
                src.token = expand_env(&src.token);
                src.command = expand_env(&src.command);
                src.args = src.args.iter().map(|a| expand_env(a)).collect();
                if let Some(ns) = src.namespace.as_mut() {
                    *ns = expand_env(ns);
                }
            }
            // 环境变量覆盖（环境变量 > 配置文件，仍生效）
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
        host: default_host(),
        cors_origins: Vec::new(),
        memoria_admin_key: String::new(),
        mcp_source: Vec::new(),
        personas: Vec::new(),
    };
    let _ = std::fs::write(&path, toml::to_string_pretty(&cfg).unwrap_or_default());
    cfg
}

fn save_config(cfg: &Config) {
    let path = config_path();
    let _ = std::fs::write(&path, toml::to_string_pretty(cfg).unwrap_or_default());
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
                    match build_agent(&reg_config, local_resources.clone()).await {
                        Ok(agent) => {
                            println!(
                                "✓ Agent 已就绪（{}@{}）",
                                reg_config.agent_id, reg_config.server
                            );
                            *reg_state.agent.lock().await = Some(agent);
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
                                        );
                                        for goal in &pc.goals {
                                            let _ = a.push_persona_goal(&pc.id, goal);
                                        }
                                    }
                                }
                            }
                            // A2: 启动白龙马 TICK 心跳（空闲 20min / 抢占 / 600s watchdog）
                            let cons = Consciousness::new(reg_state.clone());
                            tokio::spawn(cons.clone().run());
                            *reg_state.consciousness.lock().await = Some(cons);
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
                        // 系统巡检使用 Agent 自身命名空间作为 allowed_ns（无 namespace 的 MCP 源不受影响）
                        let agent_ns = vec![agent.config.identity.ns()];
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
                                .unwrap_or(default_ns);
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
                            *patrol_state.consolidate_last_ymd.lock().await = ymd.clone();
                            *patrol_state.consolidate_last.lock().await = serde_json::json!({
                                "status": "ok",
                                "trigger": "nightly",
                                "ymd": ymd,
                                "at": now_local.to_rfc3339(),
                                "results": results,
                            });
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
                .route("/api/login", post(handle_login));

            let protected = Router::new()
                .route("/api/chat", post(handle_chat))
                .route("/api/chat/stream", get(handle_chat_stream))
                .route("/api/sessions", get(handle_sessions))
                .route("/api/sessions/{id}", get(handle_session_load))
                .route("/api/sessions/{id}", delete(handle_session_delete))
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
                .route("/api/agent/events", axum::routing::get(handle_agent_events))
                .route("/api/save-config", post(handle_save_config))
                .route("/api/collab/inbox", get(handle_collab_inbox))
                .route("/api/collab/send", post(handle_collab_send))
                .route("/api/collab/approval", post(handle_collab_approval))
                .route("/api/collab/peers", get(handle_collab_peers))
                .route("/v1/chat/completions", post(handle_v1_chat))
                .route("/api/persona", post(handle_persona_create).get(handle_persona_list))
                .route("/api/persona/{id}", delete(handle_persona_delete).get(handle_persona_get))
                .route("/api/persona/{id}/goal", post(handle_persona_goal_push))
                .route("/api/session/persona", post(handle_session_persona_bind))
                .route("/api/roundtable", post(handle_panel_discuss))
                .layer(from_fn_with_state(state.clone(), auth_middleware));

            let cors = build_cors_layer(&host, port, &config.cors_origins);
            let app = public
                .merge(protected)
                .layer(cors)
                .layer(axum::middleware::from_fn(trace_middleware))
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
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        "logo not found".into(),
    )
}

/// 公开健康检查（无鉴权）。供 PFAiX 状态条 / 诊断包探测。
/// 附带 Memoria 公开 /health 的 embed 摘要 + 最近 Dream 巩固状态。
async fn handle_health(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let memoria_url = {
        let cfg = st.config.lock().await;
        cfg.server.clone()
    };
    let memoria_health = reqwest::Client::new()
        .get(format!("{}/health", memoria_url.trim_end_matches('/')))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok();
    let (memoria_ok, embed) = if let Some(resp) = memoria_health {
        let status = resp.status().is_success();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        (status, body.get("embed").cloned().unwrap_or(serde_json::Value::Null))
    } else {
        (false, serde_json::json!({"status":"fail","message":"memoria /health 不可达"}))
    };
    let dream = st.consolidate_last.lock().await.clone();
    let overall = if memoria_ok
        && embed
            .get("status")
            .and_then(|s| s.as_str())
            .map(|s| s == "pass")
            .unwrap_or(false)
    {
        "ok"
    } else if memoria_ok {
        "degraded"
    } else {
        "fail"
    };
    Json(serde_json::json!({
        "service": "agent-core",
        "status": overall,
        "version": env!("CARGO_PKG_VERSION"),
        "memoria": { "reachable": memoria_ok, "embed": embed },
        "dream": dream,
    }))
}

/// 手动触发 Dream 巩固（鉴权路由）。body 可选 `{ "namespaces": ["agent/xxx"] }`。
async fn handle_admin_consolidate(
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let agent_guard = st.agent.lock().await;
    let Some(ref agent) = *agent_guard else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    let default_ns = format!("agent/{}", agent.config.identity.agent_id);
    let ns_list: Vec<String> = body
        .as_ref()
        .and_then(|Json(v)| v.get("namespaces").and_then(|a| a.as_array()).cloned())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| {
            std::env::var("CONSOLIDATE_NAMESPACES")
                .unwrap_or(default_ns)
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        });
    let mut results = Vec::new();
    for ns in &ns_list {
        let res = agent.consolidate(ns).await;
        results.push(serde_json::json!({"ns": ns, "result": res}));
    }
    drop(agent_guard);
    let now_local = Local::now();
    let ymd = now_local.format("%Y-%m-%d").to_string();
    let summary = serde_json::json!({
        "status": "ok",
        "trigger": "manual",
        "ymd": ymd,
        "at": now_local.to_rfc3339(),
        "results": results,
    });
    *st.consolidate_last_ymd.lock().await = ymd;
    *st.consolidate_last.lock().await = summary.clone();
    Json(summary).into_response()
}

/// Phase 3：运行时创建分身
async fn handle_persona_create(
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let persona_id = match v.get("persona_id").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST, "persona_id required").into_response(),
    };
    let display_name = v.get("display_name").and_then(|x| x.as_str()).unwrap_or(&persona_id).to_string();
    let owner_user_id = v.get("owner_user_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let tool_allowlist: Vec<String> = v
        .get("tool_allowlist")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let memory_namespace = v.get("memory_namespace").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let llm: Option<LlmConfig> = v
        .get("llm")
        .and_then(|x| serde_json::from_value(x.clone()).ok());
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    match agent.create_persona(&persona_id, &display_name, &owner_user_id, tool_allowlist, memory_namespace, llm) {
        Ok(()) => Json(serde_json::json!({"ok": true, "persona_id": persona_id})).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Phase 3：列出所有分身
async fn handle_persona_list(
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    let list: Vec<serde_json::Value> = agent
        .list_personas()
        .iter()
        .map(|p| {
            serde_json::json!({
                "persona_id": p.persona_id,
                "display_name": p.display_name,
                "owner_user_id": p.owner_user_id,
                "tool_allowlist": p.tool_allowlist,
                "memory_namespace": p.memory_namespace,
            })
        })
        .collect();
    Json(serde_json::json!({"personas": list})).into_response()
}

/// Phase 3：删除分身
async fn handle_persona_delete(
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    match agent.remove_persona(&id) {
        Ok(()) => Json(serde_json::json!({"ok": true, "removed": id})).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Phase 3：把会话绑定到某分身
async fn handle_session_persona_bind(
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let session_id = match v.get("session_id").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST, "session_id required").into_response(),
    };
    let persona_id = match v.get("persona_id").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST, "persona_id required").into_response(),
    };
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    agent.bind_session_persona(&session_id, &persona_id);
    Json(serde_json::json!({"ok": true, "session_id": session_id, "persona_id": persona_id})).into_response()
}

/// Phase 4：给分身压入目标，驱动真实 tick
async fn handle_persona_goal_push(
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let goal = match body.and_then(|Json(v)| v.get("goal").and_then(|x| x.as_str().map(|s| s.to_string()))) {
        Some(s) if !s.is_empty() => s,
        _ => return (axum::http::StatusCode::BAD_REQUEST, "goal required").into_response(),
    };
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    match agent.push_persona_goal(&id, &goal) {
        Ok(()) => Json(serde_json::json!({"ok": true, "persona_id": id, "goal": goal})).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Phase 4：查询单分身详情（含目标栈）
async fn handle_persona_get(
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    let p = agent.get_persona(&id);
    let goals = agent.get_persona_goals(&id);
    Json(serde_json::json!({
        "persona_id": p.persona_id,
        "display_name": p.display_name,
        "owner_user_id": p.owner_user_id,
        "tool_allowlist": p.tool_allowlist,
        "memory_namespace": p.memory_namespace,
        "goals": goals,
    })).into_response()
}

/// Phase 6：圆桌（native，自动分配 LLM，不依赖 qclaw）—— SSE 流式
///
/// 多分身就同一议题发表立场 → 主席（默认 default）收敛共识；
/// 每个分身立场完成即推 `stance` 事件，主席收敛推 `consensus`，最后推 `done`。
/// 结论最佳努力写入 Memoria（调用者自身 ns）。LLM 分配由 `AgentCore::persona_stance`
/// 完成：配置/圆桌池自动轮询到多个 provider，做到真多 LLM。
async fn handle_panel_discuss(
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
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
    let g = st.agent.lock().await;
    let has_agent = g.is_some();
    drop(g);
    if !has_agent {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
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
    tokio::spawn(async move {
        let g = st_clone.agent.lock().await;
        let Some(ref agent) = *g else {
            let _ = tx.send(Ok(SseEvent::default().event("done").data("")));
            return;
        };
        let ns = agent.caller_ns(&session_c);
        let mut personas = agent.list_personas();
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
        let args = serde_json::json!({
            "content": content,
            "tags": ["roundtable"],
            "category": "roundtable",
            "confidence": 80,
            "namespace": ns,
        });
        if agent.mcp.call_json("memory_remember", &args).await.is_ok() {
            tracing::info!(ns = %ns, "roundtable 结论已写入 Memoria");
        }
        let _ = tx.send(Ok(SseEvent::default().event("done").data("")));
    });

    Sse::new(UnboundedReceiverStream::new(rx)).into_response()
}

/// 白龙马 Phase B 多端唤醒：返回后台活动事件（since 之后的增量），供 PFAiX 轮询"唤醒"
/// 不依赖 PFAiX 改代码（拉模型）；事件由空闲 tick 的 A4 consolidation / 主动预取产生。
async fn handle_agent_events(
    State(st): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> axum::response::Response {
    let since: u64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let limit: usize = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let (events, cursor) = {
        let qd = st.background_events.lock().await;
        let events: Vec<BackgroundEvent> = qd
            .iter()
            .filter(|e| e.id > since)
            .take(limit)
            .cloned()
            .collect();
        let cursor = *st.consolidate_cursor.lock().await;
        (events, cursor)
    };
    let next_since = events.last().map(|e| e.id).unwrap_or(since);
    Json(serde_json::json!({
        "events": events,
        "cursor": cursor,
        "next_since": next_since,
    }))
    .into_response()
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
    match build_agent(&cfg, st.local_resources.clone()).await {
        Ok(agent) => {
            *st.agent.lock().await = Some(agent);
            Json(SetupResponse {
                ok: true,
                error: None,
            })
            .into_response()
        }
        Err(e) => Json(SetupResponse {
            ok: false,
            error: Some(e),
        })
        .into_response(),
    }
}

async fn handle_chat(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<ChatRequest>,
) -> axum::response::Response {
    // A2: 白龙马 TICK 心跳 —— 用户消息到达，抢占在途空闲 tick
    if let Some(ref c) = *st.consciousness.lock().await {
        c.interrupt();
    }
    let agent_guard = st.agent.lock().await;
    if let Some(ref agent) = *agent_guard {
        let reply = agent
            .chat(
                &req.message,
                &ctx.agent_id,
                &req.session_id,
                &ctx.allowed_ns,
            )
            .await;
        Json(ChatResponse {
            reply,
            session_id: req.session_id,
        })
        .into_response()
    } else {
        Json(ChatResponse {
            reply: "请先在设置页面配置 API 密钥。".to_string(),
            session_id: req.session_id,
        })
        .into_response()
    }
}

/// SSE 流式聊天（包装 chat() 结果，分块推送）
async fn handle_chat_stream(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    axum::extract::Query(params): axum::extract::Query<ChatRequest>,
) -> axum::response::Response {
    let (tx, rx): (
        tokio::sync::mpsc::UnboundedSender<Result<SseEvent, Infallible>>,
        tokio::sync::mpsc::UnboundedReceiver<Result<SseEvent, Infallible>>,
    ) = tokio::sync::mpsc::unbounded_channel();

    // A2: 白龙马 TICK 心跳 —— 用户消息到达，抢占在途空闲 tick
    if let Some(ref c) = *st.consciousness.lock().await {
        c.interrupt();
    }
    let agent_guard = st.agent.lock().await;
    let has_agent = agent_guard.is_some();
    drop(agent_guard);

    if has_agent {
        let st_clone = st.clone();
        let msg = params.message.clone();
        let sid = params.session_id.clone();
        let agent_id = ctx.agent_id.clone();
        let allowed_ns = ctx.allowed_ns.clone();
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
        let _ = tx.send(Ok(SseEvent::default()
            .data("请先在设置页面配置 API 密钥。")
            .event("text")));
        let _ = tx.send(Ok(SseEvent::default().data("").event("done")));
    }

    Sse::new(UnboundedReceiverStream::new(rx)).into_response()
}

/// 获取会话列表
async fn handle_sessions(State(_st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let db_path = std::env::current_dir()
        .unwrap_or_default()
        .join("harness.db")
        .to_string_lossy()
        .to_string();

    let sessions = tokio::task::spawn_blocking(move || {
        let mut result = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT session_id, role, content, created_at FROM chat_history WHERE id IN (
                    SELECT MIN(id) FROM chat_history GROUP BY session_id
                ) AND role = 'user' ORDER BY id DESC LIMIT 50",
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
    })
    .await
    .unwrap_or_default();

    Json(serde_json::json!({"sessions": sessions}))
}

/// 协作收件箱（A2A）：拉取调用者身份下的规范化信封，支持 type/scope 过滤与未读计数。
/// 读操作，沿用 authenticate 中间件（x-agent-id / x-agent-key）。
async fn handle_collab_inbox(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<CollabInboxQuery>,
) -> axum::response::Response {
    let (agent_id, _allowed_ns) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let agent_key = headers
        .get("x-agent-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

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
    let filtered: Vec<serde_json::Value> = raw
        .into_iter()
        .filter(|m| {
            let t = m["type"].as_str().unwrap_or("");
            let sc = m["scope"].as_str().unwrap_or("agent");
            (types.is_empty() || types.contains(&t)) && (scopes.is_empty() || scopes.contains(&sc))
        })
        .collect();

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
                                "org" => ns.contains(&format!("org/{}", ORG_COMPANY)),
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
    let (agent_id, _allowed_ns) = match authenticate(&headers, &st).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let agent_key = headers
        .get("x-agent-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // 在调用者收件箱中定位该 approval_request
    let agent_guard = st.agent.lock().await;
    let (requester, approval_id) = if let Some(ref agent) = *agent_guard {
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
                (req, aid)
            }
            Ok(None) => {
                return (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({"error": "收件箱中找不到该审批请求"})),
                )
                    .into_response();
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
    let resp_env = serde_json::json!({
        "type": "approval_response",
        "approval_id": approval_id,
        "approved": decision_ok,
        "reason": body.reason.clone(),
        "approver_id": agent_id,
    });

    // 回写 requester 收件箱
    let send_res = if let Some(ref agent) = *agent_guard {
        agent.collab_send_raw(&requester, &resp_env).await
    } else {
        Err("agent 尚未就绪".to_string())
    };
    drop(agent_guard);

    match send_res {
        Ok(_) => {
            // 记录本地 ApprovalManager（解阻塞本实例等待中的审批）
            let agent_guard = st.agent.lock().await;
            if let Some(ref agent) = *agent_guard {
                // A2: 从 pending 审批取回 operation_hash，使响应与请求绑定（防 LLM 自批）。
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

/// 加载指定会话的历史
async fn handle_session_load(
    State(_st): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db_path = {
        std::env::current_dir()
            .unwrap_or_default()
            .join("harness.db")
            .to_string_lossy()
            .to_string()
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
    let db_path = std::env::current_dir()
        .unwrap_or_default()
        .join("harness.db")
        .to_string_lossy()
        .to_string();
    let sid = id.clone();

    let deleted = tokio::task::spawn_blocking(move || {
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            if let Ok(cnt) = conn.execute(
                "DELETE FROM chat_history WHERE session_id=?1",
                rusqlite::params![sid],
            ) {
                return cnt;
            }
        }
        0
    })
    .await
    .unwrap_or(0);

    Json(serde_json::json!({"deleted": deleted, "session_id": id}))
}

/// P1-5：查询当前降级收缩状态（Kill switch / 各 MCP 源健康 / 模式）
async fn handle_admin_degrade(State(st): State<Arc<AppState>>) -> axum::response::Response {
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        Json(agent.degrade_status()).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P1-5：运行时切换 Kill switch（全局禁用/恢复工具调用）
#[derive(Deserialize)]
struct KillSwitchRequest {
    enabled: bool,
}

async fn handle_admin_killswitch(
    State(st): State<Arc<AppState>>,
    Json(req): Json<KillSwitchRequest>,
) -> axum::response::Response {
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        agent.set_kill_switch(req.enabled);
        Json(agent.degrade_status()).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-1：本机运行指标（命名空间配额用量 + 降级状态）
async fn handle_metrics(State(st): State<Arc<AppState>>) -> axum::response::Response {
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        Json(agent.quota_status()).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-1：查询配额（管理员视角，与 /api/metrics 的 quota 段一致）
async fn handle_admin_quota_get(State(st): State<Arc<AppState>>) -> axum::response::Response {
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        Json(agent.quota_status()).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-1：临时调整某命名空间配额策略（管理员）
#[derive(Deserialize)]
struct QuotaPolicyUpdate {
    namespace: String,
    #[serde(default)]
    max_tool_rounds: Option<u32>,
    #[serde(default)]
    daily_token_budget: Option<u64>,
    #[serde(default)]
    max_concurrent_sessions: Option<u32>,
}

async fn handle_admin_quota_put(
    State(st): State<Arc<AppState>>,
    Json(req): Json<QuotaPolicyUpdate>,
) -> axum::response::Response {
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let mut policy = {
            let s = agent.quota.lock().unwrap_or_else(|p| p.into_inner());
            s.get_policy(&req.namespace)
        };
        if let Some(v) = req.max_tool_rounds {
            policy.max_tool_rounds = v;
        }
        if let Some(v) = req.daily_token_budget {
            policy.daily_token_budget = v;
        }
        if let Some(v) = req.max_concurrent_sessions {
            policy.max_concurrent_sessions = v;
        }
        agent.set_ns_quota(&req.namespace, policy.clone());
        Json(serde_json::json!({
            "ok": true,
            "namespace": req.namespace,
            "policy": {
                "max_tool_rounds": policy.max_tool_rounds,
                "daily_token_budget": policy.daily_token_budget,
                "max_concurrent_sessions": policy.max_concurrent_sessions,
            }
        }))
        .into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-2：审计事件只读查询（本地有界环形缓冲即时返回，支持 trace_id / event_type 过滤）
#[derive(serde::Deserialize)]
struct AuditQuery {
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn handle_admin_audit(
    State(st): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> axum::response::Response {
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let limit = q.limit.unwrap_or(50).min(500);
        let events =
            agent
                .audit_logger
                .recent_events(q.trace_id.as_deref(), q.event.as_deref(), limit);
        Json(serde_json::json!({
            "count": events.len(),
            "events": events,
        }))
        .into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-3：批准并激活待审批的 Harness 模板（含危险工具的蒸馏模板须经此人工 / admin 批准）
#[derive(serde::Deserialize)]
struct HarnessActivate {
    id: i64,
}

async fn handle_admin_harness_activate(
    State(st): State<Arc<AppState>>,
    Json(req): Json<HarnessActivate>,
) -> axum::response::Response {
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let ok = agent.harness.lock().await.activate(req.id);
        Json(serde_json::json!({
            "ok": ok,
            "id": req.id,
            "is_active": ok,
        }))
        .into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
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
    Extension(ctx): Extension<AuthContext>,
    headers: axum::http::HeaderMap,
    Json(req): Json<V1ChatRequest>,
) -> axum::response::Response {
    // A2: 白龙马 TICK 心跳 —— 用户消息到达，抢占在途空闲 tick
    if let Some(ref c) = *st.consciousness.lock().await {
        c.interrupt();
    }
    let agent_guard = st.agent.lock().await;
    let reply = if let Some(ref agent) = *agent_guard {
        // 输入校验：消息长度限制 32KB，消息数限制 100
        if req.messages.len() > 100 {
            return axum::response::Json(serde_json::json!({
                "error": "too many messages"
            }))
            .into_response();
        }
        // PFAiX 强制上下文隔离：每个安装实例 + 每个对话独立 session。
        // x-user-tag 是壳首次启动生成的随机 install_id；x-conversation-id
        // 是壳内当前对话 id。两者缺省时向后兼容旧客户端。
        let user_tag = headers
            .get("x-user-tag")
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                s.chars()
                    .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                    .collect::<String>()
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_string());
        let conversation_id = headers
            .get("x-conversation-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                s.chars()
                    .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                    .collect::<String>()
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_string());

        let session_id = format!("jan/{}/{}/{}", ctx.agent_id, user_tag, conversation_id);
        if session_id.len() > 128
            || !session_id
                .chars()
                .all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_')
        {
            return axum::response::Json(serde_json::json!({
                "error": "invalid session_id"
            }))
            .into_response();
        }
        // 只取最后一条 user 消息。Jan 会带上完整 history；若把 assistant 自我介绍也 join
        // 进 user_text，模型容易反复只回身份介绍、不调工具。
        let user_text: String = req
            .messages
            .iter()
            .rev()
            .find(|m| m.role.eq_ignore_ascii_case("user"))
            .and_then(|m| m.content.clone())
            .unwrap_or_default()
            .chars()
            .take(32768)
            .collect();
        if user_text.trim().is_empty() {
            "请输入消息".to_string()
        } else {
            agent
                .chat(&user_text, &ctx.agent_id, &session_id, &ctx.allowed_ns)
                .await
        }
    } else {
        "Agent 未就绪".to_string()
    };
    drop(agent_guard);

    // PFAiX SSE 兼容：stream=true 时返回 text/event-stream
    if req.stream.unwrap_or(false) {
        let model = req.model.unwrap_or_else(|| "agent-core".to_string());
        let id = "chatcmpl-agent".to_string();
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (tx, rx): (
            tokio::sync::mpsc::UnboundedSender<Result<SseEvent, Infallible>>,
            tokio::sync::mpsc::UnboundedReceiver<Result<SseEvent, Infallible>>,
        ) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            // role 起始事件
            let _ = tx.send(Ok(SseEvent::default().data(
                serde_json::json!({
                    "id": &id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": &model,
                    "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
                })
                .to_string(),
            )));
            // 内容分块（与 /api/chat/stream 一致的 3 字/20ms 节奏）
            let chars: Vec<char> = reply.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let end = (i + 3).min(chars.len());
                let chunk: String = chars[i..end].iter().collect();
                let _ = tx.send(Ok(SseEvent::default().data(serde_json::json!({
                    "id": &id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": &model,
                    "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": null}]
                }).to_string())));
                i = end;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // finish_reason
            let _ = tx.send(Ok(SseEvent::default().data(
                serde_json::json!({
                    "id": &id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": &model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                })
                .to_string(),
            )));
            // [DONE]
            let _ = tx.send(Ok(SseEvent::default().data("[DONE]")));
        });
        return Sse::new(UnboundedReceiverStream::new(rx)).into_response();
    }

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

    // 注册到 Memoria — admin_key 作参数；身份用 dashboard-agent 专属 badge
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let dash_badge = env_memoria_dashboard_badge(&cfg_admin);
    // P0 修复：以 dashboard-agent 身份（专属 badge，permission=admin）代理注册，
    // 而非字面 "admin"（DB 中持有过期 key，会导致 Memoria require_admin 401）。
    let (actor, server) = {
        let cfg = st.config.lock().await;
        (cfg.agent_id.clone(), cfg.server.clone())
    };
    let mcp = McpClient::new(&server, &actor, &dash_badge);
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
                    "display_name": &req.name,
                    "admin_key": &admin_key,
                    "namespace": &namespace,
                }),
            )
            .await
        {
            Ok(text) => {
                // Memoria register_agent 返回 {"status":"registered","badge":<AgentBadge对象 或 字符串>}
                // 其中 badge.badge_token 才是后续鉴权用的 key 字符串；兼容 badge 直接是字符串的旧格式。
                let badge_str = text.get("badge").and_then(|x| {
                    if x.is_string() {
                        x.as_str()
                    } else {
                        x.get("badge_token").and_then(|t| t.as_str())
                    }
                });
                if let Some(b) = badge_str {
                    badge_token = b.to_string();
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
    }

    // 审计日志：记录身份注册
    let audit = AuditLogger::new(McpClient::new(&server, &actor, &dash_badge));
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
    let dash_badge = env_memoria_dashboard_badge(&cfg_admin);
    if admin_key.is_empty() || dash_badge.is_empty() {
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
    // 以 dashboard-agent + MEMORIA_DASHBOARD_BADGE 调 Memoria（permission=admin），
    // 可代理 register_user/login_user；不得与 MEMORIA_ADMIN_KEY 同 token。
    let (actor, server) = {
        let cfg = st.config.lock().await;
        (cfg.agent_id.clone(), cfg.server.clone())
    };
    let mcp = McpClient::new(&server, &actor, &dash_badge);
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
    let dash_badge = env_memoria_dashboard_badge(&cfg_admin);
    if admin_key.is_empty() || dash_badge.is_empty() {
        return Json(LoginResponse {
            ok: false,
            user_id: String::new(),
            display_name: String::new(),
            badge_token: String::new(),
            namespace: String::new(),
            error: Some("服务未就绪，请稍后重试".to_string()),
        });
    }
    // P0 修复：以 dashboard-agent + 专属 badge 代理登录，
    // 而非字面 "admin"（DB 中过期 key 会导致 require_admin 401）。
    let (actor, server) = {
        let cfg = st.config.lock().await;
        (cfg.agent_id.clone(), cfg.server.clone())
    };
    let mcp = McpClient::new(&server, &actor, &dash_badge);
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

async fn build_agent(config: &Config, local_resources: SharedResourceSnapshot) -> Result<AgentCore, String> {
    // K3：身份 badge 与 admin 钥匙分钥（badge_token UNIQUE）
    let admin_key = if !config.memoria_admin_key.is_empty() {
        config.memoria_admin_key.clone()
    } else {
        env_memoria_admin_key("")
    };
    let badge_token = env_memoria_dashboard_badge(&admin_key);
    let admin_key = if !admin_key.is_empty() {
        admin_key
    } else if !badge_token.is_empty() {
        // 过渡：未设 admin 时勿把 dashboard badge 当 admin（UNIQUE 风险）；仅兼容空配置联调
        badge_token.clone()
    } else {
        config.api_key.clone()
    };

    let mcp = McpClient::new(&config.server, &config.agent_id, &badge_token);
    let _ = mcp
        .call_json(
            "register_agent",
            &serde_json::json!({
                "agent_id": &config.agent_id,
                "display_name": &config.agent_id,
                "admin_key": &admin_key,
                "namespace": format!("agent/{}", config.agent_id),
            }),
        )
        .await;

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
        badge_token: badge_token.clone(),
        ns_full_path,
        persona_id: None,
        owner_user_id: None,
        workspace_dir: None,
        tool_allowlist: Vec::new(),
        memory_namespace: None,
    };
    // P0-1: 设置 failover fallbacks（备用层不变；圆桌多 LLM 自动分配复用此池）
    let doubao_key = std::env::var("DOUBAO_API_KEY").unwrap_or_default();
    let fallbacks = if !doubao_key.is_empty() {
        vec![(
            "https://ark.cn-beijing.volces.com/api/v3".to_string(),
            "doubao-lite-32k".to_string(),
            doubao_key,
        )]
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
    let agent_config = AgentConfig {
        identity,
        llm: llm_config,
        memoria_url: config.server.clone(),
        additional_mcp,
        skill_whitelist: None,
        max_tool_rounds: 3,
        parent_permission: PermissionLevel::Write,
        enable_compositional_routing: true,
        compositional_preview: true, // P1-2: 企业默认开启计划预览（HITL）
        strict_schema: false,        // P1-4: 默认回灌 LLM 修正参数（非严格报错）
        system_prompt_template: None, // P2-3: 使用内置默认模板
        approver_id: None,           // P2-D: 无审批人（保持现有行为）
    };
    // A1 (OpenClaw 吸收): 记录启动并判定是否进入 safe_mode（崩溃循环保护）。
    // 返回 (启动记录 id, 是否需抑制危险/未分类/外发工具自动执行)。
    let (boot_id, boot_safe) = agent_core::boot_lifecycle::enter_phase_a();
    let cwd = std::env::current_dir().unwrap_or_default();
    let harness = HarnessStore::open(&cwd.join("harness.db").to_string_lossy())
        .map_err(|e| format!("创建 Harness 存储失败: {}", e))?;
    let checkpoint = CheckpointStore::open(&cwd.join("checkpoints.db").to_string_lossy())
        .map_err(|e| format!("创建 Checkpoint 存储失败: {}", e))?;
    let agent = AgentCore::new(agent_config, harness, checkpoint, local_resources);
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

fn whoami() -> Option<String> {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .ok()
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
        let ns = vec![format!("org/{}", ORG_COMPANY)];
        // 普通成员有 org ns 也不能发
        assert!(collab_reachability("random-user", &ns, "org", ORG_COMPANY, "notify").is_err());
        // 白名单默认 office-agent
        assert!(collab_reachability("office-agent", &ns, "org", ORG_COMPANY, "notify").is_ok());
        // org+query 仍拒绝
        assert!(collab_reachability("office-agent", &ns, "org", ORG_COMPANY, "query").is_err());
    }

    #[test]
    fn dept_requires_scope_id_and_membership() {
        let ns = vec!["org/cs-pufa-2nd-thermal/dept/gufei".to_string()];
        assert!(collab_reachability("u1", &ns, "dept", "", "notify").is_err());
        assert!(collab_reachability("u1", &ns, "dept", "gufei", "notify").is_ok());
        assert!(collab_reachability("u1", &ns, "dept", "finance", "notify").is_err());
    }

    #[test]
    fn peer_in_company_filter() {
        assert!(peer_in_company("agent/x,org/cs-pufa-2nd-thermal"));
        assert!(!peer_in_company("agent/y,org/other-co"));
    }
}
