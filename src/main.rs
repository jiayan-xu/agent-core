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
    extract::{Extension, Path, Request, State},
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tokio::time::interval;
use tokio_stream::wrappers::{ReceiverStream, UnboundedReceiverStream};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::Instrument;
use tracing_subscriber::EnvFilter;
use wry::WebViewBuilder;

use agent_core::agent::{AgentConfig, AgentCore, AgentIdentity, EventKind, MeetingEvent};
use agent_core::audit::AuditLogger;
use agent_core::meta_evolve::{MetaEvolutionConfig, SafetyConfig};
use agent_core::code_evolve::{apply_patch, eval_crate, find_up, git_commit, git_diff, git_revert, propose_fn, EvalResult};
use agent_core::boundary::PermissionLevel;
use agent_core::harness::HarnessStore;
use agent_core::llm::{LlmClient, LlmConfig, LlmProvider};
use agent_core::metrics::MetricsRegistry;
use agent_core::approval::ApprovalResponse;
use agent_core::mcp_client::McpClient;
use agent_core::resources::SharedResourceSnapshot;
use std::sync::OnceLock;

/// 公司根命名空间（与 agent.toml 的 mcp_source namespace org/ 前缀、Memoria 注册一致）。
/// 改为运行时配置：启动时由 agent.toml `org_company` 注入（默认 cs-pufa-2nd-thermal，行为不变）。
static ORG_COMPANY: OnceLock<String> = OnceLock::new();

/// 取当前公司根标识（未初始化时回退默认，保证测试/旧路径不崩）。
fn org_company() -> &'static str {
    ORG_COMPANY.get().map(|s| s.as_str()).unwrap_or("cs-pufa-2nd-thermal")
}

/// 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    agent_id: String,
    /// 领域模式：`solid_waste`（默认，保持固废行为）/ `office` / `general`。
    /// 非 solid_waste 下关闭「固废本部门运维纪律 / 证据门禁 / 部门工具包自动注入」。
    #[serde(default = "default_domain_mode")]
    domain_mode: String,
    /// 公司根标识（命名空间 org/<org_company> 前缀）。默认 cs-pufa-2nd-thermal。
    #[serde(default = "default_org_company")]
    org_company: String,
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
    /// 全局 LLM 池（主 + fallbacks）。缺省则回退旧硬编码 deepseek 主 + DOUBAO_API_KEY 备用。
    #[serde(default)]
    llm: Option<LlmConfig>,
    /// PR5：元进化配置（落 [meta_evolution]，缺省全默认：enabled=false）
    #[serde(default)]
    meta_evolution: Option<MetaEvolutionConfig>,
    /// PR5：安全配置（落 [safety]，缺省 ApprovalMode::Auto 免人工审批）
    #[serde(default)]
    safety: Option<SafetyConfig>,
    /// Phase 7：代码自我进化引擎配置（落 [code_evolution]）。缺省全默认：enabled=false（关闭）。
    /// 安全要点：默认 dry_run（只产 diff 不提交）、allow_commit=false（双重闸门）、目标必须在隔离仓库。
    #[serde(default)]
    code_evolution: Option<CodeEvolutionConfig>,
    /// HY3 1.3 三大项热路径接线开关（缺省全 false；G 门未复验前不得开启）
    #[serde(default)]
    features: agent_core::agent::FeatureFlags,
    /// HY3 1.3 LATS 配置（缺省全默认：enabled=false）
    #[serde(default)]
    lats: agent_core::lats::LatsConfig,
    /// HY3 1.3 MultiAgent Compose 配置（缺省全默认：enabled=false）
    #[serde(default)]
    multiagent: agent_core::multiagent::MultiAgentConfig,
    /// HY3 TTC 推理时计算配置（缺省全默认：enabled=false）
    #[serde(default)]
    ttc: agent_core::ttc::TtcConfig,
    /// 摄入侧治本过滤（落 [intake_filter]，缺省全默认：enabled=false，opt-in）
    #[serde(default)]
    intake_filter: Option<agent_core::intake_filter::IntakeFilterConfig>,
}

/// Phase 7：代码自我进化引擎配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CodeEvolutionConfig {
    /// 总开关。缺省 false（关闭）。
    #[serde(default)]
    enabled: bool,
    /// 进化目标源文件路径（必须是隔离仓库内的文件；含 agent-core/memoria 路径的请求会被拒绝）。
    #[serde(default)]
    target_path: Option<String>,
    /// 进化代数预算。缺省 4。
    #[serde(default = "default_evo_gens")]
    generations: usize,
    /// 连续失败/无进展达此数 → 熔断 HARD STOP。缺省 3。
    #[serde(default = "default_evo_circuit")]
    circuit_failures: usize,
    /// 默认 dry_run：true=只产 diff 不提交（人类否决闸门），false=允许在 apply 时提交。
    #[serde(default = "default_true")]
    dry_run_default: bool,
    /// 是否允许真正提交到 git（与请求参数 apply 双重闸门，两者皆 true 才落盘）。缺省 false。
    #[serde(default)]
    allow_commit: bool,
    /// 专用进化密钥（建议走 ${ENV} 注入，如 ${EVOLVE_KEY}）。触发进化必须携带匹配的 `x-evolve-key` 头，
    /// 否则 401；配置为空则 fail-closed 拒绝任何进化请求（P0-1，避免「端口可达即可触发进化」）。
    #[serde(default)]
    evolve_key: Option<String>,
    /// 目标函数名（默认 "fib"）。引擎只改这一个函数，其余（含测试）不动。
    #[serde(default = "default_fn_name")]
    fn_name: String,
    /// 提议用的专属 LLM 配置；缺省空 = 复用全局主 LlmClient。
    #[serde(default)]
    model: Option<LlmConfig>,
}

fn default_evo_gens() -> usize {
    4
}
fn default_evo_circuit() -> usize {
    3
}
fn default_fn_name() -> String {
    "fib".to_string()
}
fn default_true() -> bool {
    true
}

fn default_domain_mode() -> String {
    "solid_waste".to_string()
}
fn default_org_company() -> String {
    "cs-pufa-2nd-thermal".to_string()
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

/// jarvis 专属 badge（`MEMORIA_JARVIS_BADGE`）；与 admin 不得同 token（UNIQUE）。
/// 未设置时回退 `MEMORIA_ADMIN_KEY`（过渡兼容，生产应显式分钥）。
fn env_memoria_jarvis_badge(admin_fallback: &str) -> String {
    match std::env::var("MEMORIA_JARVIS_BADGE") {
        Ok(k) if !k.is_empty() => k,
        _ => env_memoria_admin_key(admin_fallback),
    }
}

/// Memoria 代理管理客户端：`X-Agent-Id` 必须与 badge 配对。
///
/// 本函数当前仅用于 `register_agent`（管理操作，需 admin 权限），故**一律以 `admin`
/// 身份 + `MEMORIA_ADMIN_KEY` 发起**。原因：Memoria 要求身份与密钥严格配对，
/// `jarvis` 身份配 admin key 会触发 -32001（auth_matrix 实测）；而外部 launcher 常把
/// `MEMORIA_JARVIS_BADGE` 误设为与 admin key 同值，若此处走 jarvis 分支会让「自动注册 /
/// 审批代理」等链路静默失败（协作收件箱 502 即此根因）。仅当完全无 admin key 的极端
/// 情况才回退 jarvis 身份。
fn memoria_proxy_client(server: &str, admin_fallback: &str) -> McpClient {
    let admin_key = env_memoria_admin_key(admin_fallback);
    if !admin_key.is_empty() {
        return McpClient::new(server, "admin", &admin_key);
    }
    if let Ok(badge) = std::env::var("MEMORIA_JARVIS_BADGE") {
        if !badge.is_empty() {
            return McpClient::new(server, "jarvis", &badge);
        }
    }
    McpClient::new(server, "admin", &admin_key)
}

/// 审计 / observe 写入客户端：`admin` 身份只接受 `MEMORIA_ADMIN_KEY`。
fn memoria_audit_client(server: &str, admin_fallback: &str) -> McpClient {
    let admin_key = env_memoria_admin_key(admin_fallback);
    if !admin_key.is_empty() {
        return McpClient::new(server, "admin", &admin_key);
    }
    memoria_proxy_client(server, admin_fallback)
}

/// 从 Memoria `register_agent` 响应提取 badge_token（兼容对象 / 字符串两种格式）。
fn extract_register_badge(text: &serde_json::Value) -> Option<String> {
    text.get("badge").and_then(|x| {
        if let Some(s) = x.as_str() {
            Some(s.to_string())
        } else {
            x.get("badge_token")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        }
    })
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
                    } else {
                        // 未设置：保留 ${NAME} 原样（与 $NAME 行为一致，便于发现配置缺失）
                        result.push_str("${");
                        result.push_str(&name);
                        result.push('}');
                    }
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
                    } else {
                        // 未设置：保留 $NAME 原样（与 ${NAME} 行为一致，便于发现配置缺失）
                        result.push('$');
                        result.push_str(&name);
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

/// 展开单个 Provider 的所有 ${ENV} 占位符字段（base_url / api_key / chat_path）。
/// 统一入口：主池 / fallbacks / 难度三路都走这里，避免「修一条漏一条」。
fn expand_provider(p: &mut LlmProvider) {
    p.base_url = expand_env(&p.base_url);
    p.api_key = expand_env(&p.api_key);
    p.chat_path = expand_env(&p.chat_path);
}

/// 展开整份 LlmConfig 的 ${ENV} 占位符：主池字段 + fallbacks + 难度三路。
/// build_agent 全局池统一调用此处，替代原先只展开 api_key/fallbacks 部分字段的写法，
/// 杜绝「只展开 api_key 漏掉 base_url/chat_path」导致路由 401（见 build_agent 历史 bug）。
fn expand_llm_config(cfg: &mut LlmConfig) {
    cfg.base_url = expand_env(&cfg.base_url);
    cfg.api_key = expand_env(&cfg.api_key);
    cfg.chat_path = expand_env(&cfg.chat_path);
    for p in cfg.fallbacks.iter_mut() {
        expand_provider(p);
    }
    if let Some(p) = cfg.difficulty.easy.as_mut() {
        expand_provider(p);
    }
    if let Some(p) = cfg.difficulty.hard.as_mut() {
        expand_provider(p);
    }
    if let Some(p) = cfg.difficulty.judge_provider.as_mut() {
        expand_provider(p);
    }
}

/// 统一展开 Config 内所有 LlmConfig 的 ${ENV} 占位符：全局池 + 分身专属池 + code_evolution 专属池。
/// 单一入口，彻底消除「personas 在 load 展开、全局 llm 在 build_agent 展开」的分裂
/// （分裂曾导致新增字段时漏改一处 → 路由 401）。新增任何嵌套 provider 字段，
/// 只改 `expand_provider` / `expand_llm_config` 一处即可。
fn expand_config_llm_env(cfg: &mut Config) {
    if let Some(llm) = cfg.llm.as_mut() {
        expand_llm_config(llm);
    }
    for pc in cfg.personas.iter_mut() {
        if let Some(llm) = pc.llm.as_mut() {
            expand_llm_config(llm);
        }
    }
    if let Some(ce) = cfg.code_evolution.as_mut() {
        if let Some(k) = ce.evolve_key.as_mut() {
            *k = expand_env(k);
        }
        if let Some(m) = ce.model.as_mut() {
            expand_llm_config(m);
        }
    }
}

/// P1-4：运行时解析——克隆后展开全部 ${ENV} 占位符（顶层 + mcp_source + 三处 LlmConfig）+ 环境变量覆盖。
/// 关键：只作用于克隆体，绝不修改存储态 config；从而 save_config 序列化的是带占位的原始配置，不泄漏明文密钥。
/// 单一展开入口仍为 `expand_config_llm_env` + `expand_env`，未引入第二套展开逻辑。
fn resolve_config_for_runtime(cfg: &Config) -> Config {
    let mut r = cfg.clone();
    // 顶层字段
    r.api_key = expand_env(&r.api_key);
    r.memoria_admin_key = expand_env(&r.memoria_admin_key);
    r.server = expand_env(&r.server);
    for src in &mut r.mcp_source {
        src.url = expand_env(&src.url);
        src.token = expand_env(&src.token);
        src.command = expand_env(&src.command);
        src.args = src.args.iter().map(|a| expand_env(a)).collect();
        if let Some(ns) = src.namespace.as_mut() {
            *ns = expand_env(ns);
        }
    }
    // 统一展开所有 LlmConfig（全局池 + 分身池 + code_evolution 池）——单一入口
    expand_config_llm_env(&mut r);
    // 环境变量覆盖（环境变量 > 配置文件）
    if let Ok(key) = std::env::var("AGENT_API_KEY") {
        if !key.is_empty() {
            r.api_key = key;
        }
    }
    if let Ok(key) = std::env::var("MEMORIA_ADMIN_KEY") {
        if !key.is_empty() {
            r.memoria_admin_key = key;
        }
    }
    r
}

impl Config {
    /// 是否已配置：agent_id 非空，且 api_key 经「占位符展开 / 环境变量 / 字面量」任一方式可得。
    /// 关键：判定时解析，但**不原地改写**存储态 config —— 保持 `${ENV}` 占位，避免 handle_save_config
    /// 把占位回写成明文（P1-4）。运行时真实 key 由 resolve_config_for_runtime 在克隆体上展开。
    fn configured(&self) -> bool {
        if self.agent_id.is_empty() {
            return false;
        }
        if !expand_env(&self.api_key).is_empty() {
            return true;
        }
        std::env::var("AGENT_API_KEY").map(|k| !k.is_empty()).unwrap_or(false)
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

struct AppState {
    config: Mutex<Config>,
    /// 用 Arc 包装：chat/consolidate 等 handler 克隆 Arc 后立即释放全局锁，
    /// 使 LLM 往返在锁外并发执行（解除单点串行瓶颈）。
    agent: Mutex<Option<Arc<AgentCore>>>,
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
    /// Phase 7：进化回路并发守卫（true=正在跑 /api/evolve，防止多请求并发覆盖隔离仓库）
    evolve_running: AtomicBool,
    /// 战略罗盘「可观测」：运行指标注册表（与 AgentCore 共享同一 Arc，供 /api/metrics 暴露）
    metrics: Arc<MetricsRegistry>,
    /// Step3：会议实时事件广播中枢（所有 SSE 订阅者从此订阅，按 meeting_id 过滤）
    meeting_tx: broadcast::Sender<MeetingEvent>,
    /// Step3：会议在线表 meeting_id → (agent_id → 最近心跳 Instant)
    meeting_presence: tokio::sync::Mutex<HashMap<String, HashMap<String, std::time::Instant>>>,
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
    /// 白龙马 A2 深化：最近一次用户活动 unix 秒（interrupt 时刷新），驱动自适应 TICK 节奏。
    /// 用 AtomicU64 避免 Arc<Self> 内部可变性的锁开销（interrupt 与 run 并发访问）。
    last_activity_secs: AtomicU64,
}

/// 读 env 并解析为给定类型，失败/缺失回退 default（仅用于整数类配置）。
fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<T>().ok())
        .unwrap_or(default)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 写 `/health.dream` 摘要。`touch_ymd=true` 时同步夜间去重游标（manual/nightly）；
/// tick/hydrate 必须 `false`，以免挡住当日低峰 meta_evolution。
async fn record_dream_health(
    state: &AppState,
    trigger: &str,
    results: Vec<serde_json::Value>,
    touch_ymd: bool,
) {
    let now_local = Local::now();
    let ymd = now_local.format("%Y-%m-%d").to_string();
    let summary = serde_json::json!({
        "status": "ok",
        "trigger": trigger,
        "ymd": ymd,
        "at": now_local.to_rfc3339(),
        "results": results,
    });
    if touch_ymd {
        *state.consolidate_last_ymd.lock().await = ymd;
    }
    *state.consolidate_last.lock().await = summary;
}

/// 启动时从 Memoria dream_state 回填 health（仅当仍为 never）。
async fn hydrate_dream_health_from_memoria(state: &AppState) {
    let still_never = {
        let g = state.consolidate_last.lock().await;
        g.get("status").and_then(|s| s.as_str()) == Some("never")
    };
    if !still_never {
        return;
    }
    let guard = state.agent.lock().await;
    let Some(agent) = guard.as_ref() else { return };
    let default_ns = format!("agent/{}", agent.config.identity.agent_id);
    let ns_list: Vec<String> = std::env::var("CONSOLIDATE_NAMESPACES")
        .unwrap_or_else(|_| default_ns.clone())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut results = Vec::new();
    for ns in &ns_list {
        match agent.peek_dream_consolidate(ns).await {
            Some(v) => {
                results.push(serde_json::json!({
                    "ns": ns,
                    "last_run": v.get("last_run").cloned().unwrap_or(serde_json::Value::Null),
                    "cursor_ts": v.get("cursor_ts").cloned().unwrap_or(serde_json::Value::Null),
                    "runs": v.get("runs").cloned().unwrap_or(serde_json::Value::Null),
                }));
            }
            None => {
                results.push(serde_json::json!({"ns": ns, "error": "dream_state_get failed"}));
            }
        }
    }
    drop(guard);
    if results.iter().any(|r| r.get("last_run").is_some()) {
        tracing::info!(target: "consciousness", "hydrate /health.dream from memoria dream_state");
        record_dream_health(state, "hydrate", results, false).await;
    }
}

impl Consciousness {
    fn new(state: Arc<AppState>) -> Arc<Self> {
        Arc::new(Self {
            state,
            interrupt: Arc::new(tokio::sync::Notify::new()),
            last_activity_secs: AtomicU64::new(now_unix_secs()),
        })
    }

    /// 用户消息到达 → 打断在途 tick（等价白龙马 AbortController.abort），并刷新活动时间戳。
    fn interrupt(&self) {
        self.last_activity_secs.store(now_unix_secs(), Ordering::SeqCst);
        self.interrupt.notify_one();
    }

    async fn run(self: Arc<Self>) {
        // 白龙马 A2 深化：自适应节奏（env 可配，默认向后兼容）
        // - AGENT_TICK_IDLE_SEC：无近期活动时空闲节奏（默认 1200s=20min）
        // - AGENT_TICK_ACTIVE_WINDOW_SEC：用户活动窗口（默认 600s）；窗口内下一跳缩到 min(idle, 120s)
        // - AGENT_TICK_BOOTSTRAP_SEC：启动后首跳（默认 15s），让 dream health 尽快离开 never
        // - 活跃期下限 120s：避免对话密集时 tick 过频挤占响应
        let idle_sec: u64 = env_parse("AGENT_TICK_IDLE_SEC", 1200);
        let active_window_sec: u64 = env_parse("AGENT_TICK_ACTIVE_WINDOW_SEC", 600);
        let bootstrap_sec: u64 = env_parse("AGENT_TICK_BOOTSTRAP_SEC", 15);
        let fast_sec: u64 = 120;
        let mut bootstrapped = false;
        tracing::info!(
            target: "consciousness",
            idle_sec, active_window_sec, fast_sec, bootstrap_sec,
            "consciousness: TICK 循环启动（自适应节奏 / 抢占 / 600s watchdog）"
        );
        loop {
            // 计算下一跳：首跳 bootstrap；其后最近有用户活动 → 加速；否则按 idle 节奏
            let next_sec = if !bootstrapped {
                bootstrapped = true;
                bootstrap_sec.max(1)
            } else {
                let since = now_unix_secs().saturating_sub(self.last_activity_secs.load(Ordering::SeqCst));
                if since < active_window_sec {
                    idle_sec.min(fast_sec)
                } else {
                    idle_sec
                }
            };
            let sleep = tokio::time::sleep(Duration::from_secs(next_sec));
            tokio::select! {
                _ = self.interrupt.notified() => {
                    tracing::info!("consciousness: 收到抢占信号（用户消息在途），跳过本轮空闲 tick");
                    continue;
                }
                _ = sleep => {}
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

        // 2) A4 深化: round-robin consolidation（每 tick 可推进 K 个 namespace）
        let events = Self::consolidate_round_robin(state, agent).await;
        for ev in events {
            Self::emit_event(state, ev).await;
        }

        // 3) 主动预取（深化：默认在线探针；exec 需显式开）
        if let Some(ev) = Self::guarded_prefetch(agent).await {
            Self::emit_event(state, ev).await;
        }

        // Phase 2: 分身真实 tick（复用空闲 tick 循环，每个已注册分身跑一次真实 LLM tick）
        for (pid, line) in agent.persona_tick_all().await {
            tracing::info!(target: "consciousness", "persona tick [{}]: {}", pid, line);
        }
    }

    /// A4 深化: 空闲 tick 推进 K 个 namespace 的 consolidation（round-robin 游标）
    /// 对齐白龙马 consolidation-loop.js：每轮按 `AGENT_CONSOLIDATE_PER_TICK`（默认 1，封顶 ns 数）推进，游标内存态不持久化。
    async fn consolidate_round_robin(state: &AppState, agent: &AgentCore) -> Vec<BackgroundEvent> {
        let default_ns = format!("agent/{}", agent.config.identity.agent_id);
        let ns_list: Vec<String> = std::env::var("CONSOLIDATE_NAMESPACES")
            .unwrap_or_else(|_| default_ns.clone())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if ns_list.is_empty() {
            return Vec::new();
        }
        let per_tick: usize = env_parse("AGENT_CONSOLIDATE_PER_TICK", 1).clamp(1, ns_list.len());
        let mut out = Vec::with_capacity(per_tick);
        let mut results_json: Vec<serde_json::Value> = Vec::with_capacity(per_tick);
        for _ in 0..per_tick {
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
                    let line = format!("consolidate[{}]: {}", ns, summary);
                    tracing::info!(target: "consciousness", "{}", line);
                    results_json.push(serde_json::json!({"ns": ns, "result": summary}));
                    out.push(BackgroundEvent::new("consolidate", line));
                }
                Err(_) => {
                    tracing::warn!(target: "consciousness_watchdog", ns = %ns, "A4: consolidate 超时(>300s)跳过");
                    results_json.push(serde_json::json!({"ns": ns, "result": "timeout"}));
                }
            }
        }
        // 回写 /health.dream（不碰 consolidate_last_ymd，避免挡掉夜间 meta_evolution）
        if !results_json.is_empty() {
            record_dream_health(state, "tick", results_json, false).await;
        }
        out
    }

    /// 主动预取实验（深化：默认在线探针）
    /// 对齐白龙马死代码 cron 预热的反面：识别「只读 + 无必填参数」的候选工具并发事件，不预执行业务数据。
    /// 默认开启（AGENT_PRETEST=0/false 才关）；AGENT_PRETEST_EXEC=1 才实际 dummy 调用（默认关）。
    async fn guarded_prefetch(agent: &AgentCore) -> Option<BackgroundEvent> {
        // 深化：默认开启探针；仅 AGENT_PRETEST=0/false 才彻底关闭
        let enabled = std::env::var("AGENT_PRETEST")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        if !enabled {
            return None;
        }
        let allowed_ns: Vec<String> = vec![format!("agent/{}", agent.config.identity.agent_id)];
        let tools = agent.fetch_tools_filtered(&allowed_ns).await;
        // 收集至多 5 个「只读 + 无必填参数」的工具做 liveness probe 候选
        let mut candidates: Vec<String> = tools
            .iter()
            .filter(|t| {
                let name = t.function.name.as_str();
                if !agent_core::boundary::is_read_only_tool(name) {
                    return false;
                }
                let required = t.function.parameters.get("required").and_then(|r| r.as_array());
                match required {
                    None => true,
                    Some(arr) => arr.is_empty(),
                }
            })
            .map(|t| t.function.name.clone())
            .take(5)
            .collect();
        if candidates.is_empty() {
            tracing::info!(target: "consciousness", "guarded_prefetch: 无合适只读候选工具");
            return None;
        }
        let exec = std::env::var("AGENT_PRETEST_EXEC")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !exec {
            let summary = format!(
                "prefetch[probe]: 候选只读工具={}（未实际调用，AGENT_PRETEST_EXEC 未开）",
                candidates.join(", ")
            );
            tracing::info!(target: "consciousness", "{}", summary);
            return Some(BackgroundEvent::new("prefetch", summary));
        }
        // 实际 dummy 调用（仅无副作用的空参 READ 工具），带 60s 预算（取首个候选）
        let tool_name = candidates.remove(0);
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
/// PFAiX toAsciiHeaderValue 的 percent-encode 解码：还原含中文的 agent_id。
/// 仅解码 `%XX`（UTF-8 字节），保留其余字符原样（agent_id 本是 ASCII 安全集）。
fn percent_decode_agent_id(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

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
    // PFAiX 对含中文的 agent_id 做 percent-encode（toAsciiHeaderValue），
    // 此处解码还原真实 agent_id，否则 badge 认证失败、协作审批不可见。
    let raw_agent_id = percent_decode_agent_id(&raw_agent_id);
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

    // 鉴权密钥：显式 x-agent-key 优先；legacy usertag 优先用 auth_cache 中注册返回的 badge，
    // 禁止长期拿 jarvis badge 冒充安装实例身份（get_allowed_ns 会 -32001）。
    let cfg_admin = st.config.lock().await.memoria_admin_key.clone();
    let admin_key = env_memoria_admin_key(&cfg_admin);
    let cached_badge = {
        let cache = st.auth_cache.lock().await;
        cache.get(&agent_id).map(|(b, _)| b.clone())
    };
    let agent_key = if !from_usertag {
        headers
            .get("x-agent-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    } else if let Some(b) = cached_badge.clone() {
        b
    } else {
        // 首次 usertag：尚无 cache，先用空 key 走注册分支（勿用 jarvis 冒充）
        String::new()
    };
    let server = {
        let cfg = st.config.lock().await;
        cfg.server.clone()
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
            // 身份 = jarvis/admin 配对客户端；admin_key 仅作 register 参数
            let reg = memoria_proxy_client(&server, &cfg_admin);
            if let Ok(text) = reg
                .call_json(
                    "register_agent",
                    &serde_json::json!({
                        "agent_id": &agent_id,
                        "display_name": &agent_id,
                        "admin_key": &admin_key,
                        "namespace": &install_ns
                    }),
                )
                .await
            {
                if let Some(b) = extract_register_badge(&text) {
                    st.auth_cache
                        .lock()
                        .await
                        .insert(agent_id.clone(), (b, std::time::Instant::now()));
                }
            }
            allowed_ns = vec![
                format!("agent/{}", agent_id),
                "org/cs-pufa-2nd-thermal".to_string(),
            ];
        }
        // 登录态 badge 失效自愈（新增）：客户端携带 x-agent-id + 失配/过期 badge，
        // 因 Memoria 注册表重建或凭证漂移，该 agent 在 audit.db 无有效注册。
        // 以 jarvis 身份代为重新注册同一 agent_id（沿用 legacy 安装实例相同机制），
        // 恢复其 ns 授权，免客户端手动重走 Onboarding。仅对已携带 agent_id 的
        // 请求生效，不开匿名建号。注：会为登录态 agent 重建无口令注册，单组织
        // 内网可接受；若需严格口令边界，删除此块即可回滚。
        if allowed_ns.is_empty() && !admin_key.is_empty() && !from_usertag {
            let reg = memoria_proxy_client(&server, &cfg_admin);
            if let Ok(text) = reg
                .call_json(
                    "register_agent",
                    &serde_json::json!({
                        "agent_id": &agent_id,
                        "display_name": &agent_id,
                        "admin_key": &admin_key,
                        "namespace": &format!("agent/{},org/cs-pufa-2nd-thermal", agent_id)
                    }),
                )
                .await
            {
                if let Some(b) = extract_register_badge(&text) {
                    // 自愈后写入 cache；客户端旧 key 仍可能漂移，但下轮 usertag/同 id 可用
                    st.auth_cache
                        .lock()
                        .await
                        .insert(agent_id.clone(), (b, std::time::Instant::now()));
                }
            }
            // 与 legacy 安装实例自动开户保持一致：注册成功后直接授权该 agent 的
            // 命名空间，不依赖 register 返回值（register 仅用于恢复 Memoria 注册，
            // 授权由下方 allowed_ns 兜底，确保登录态 badge 漂移时不再 401）。
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
        // P0：固废本部门工具包 ns  enrichment，保证 dashboard 技能可见
        agent_core::dept_ops::enrich_allowed_ns(&mut allowed_ns);
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
        if let Ok(cfg) = toml::from_str::<Config>(&text) {
            // P1-4 修复：load 阶段不再原地展开 ${ENV} 占位符。
            // 存储态（AppState.config）始终保留占位符，save 时不会把 ${AGENT_API_KEY} 回写成明文。
            // 运行时展开交由 resolve_config_for_runtime（克隆后展开），见 build_agent 调用点。
            init_domain_and_org(&cfg);
            return cfg;
        }
    }
    let cfg = Config {
        agent_id: whoami().unwrap_or_else(|| "default".to_string()),
        domain_mode: default_domain_mode(),
        org_company: default_org_company(),
        api_key: String::new(),
        server: default_server(),
        port: 9753,
        host: default_host(),
        cors_origins: Vec::new(),
        memoria_admin_key: String::new(),
        mcp_source: Vec::new(),
        personas: Vec::new(),
        llm: None,
        meta_evolution: None,
        safety: None,
        code_evolution: None,
        features: Default::default(),
        lats: Default::default(),
        multiagent: Default::default(),
        ttc: Default::default(),
        intake_filter: None,
    };
    init_domain_and_org(&cfg);
    let _ = std::fs::write(&path, toml::to_string_pretty(&cfg).unwrap_or_default());
    cfg
}

fn save_config(cfg: &Config) {
    let path = config_path();
    let _ = std::fs::write(&path, toml::to_string_pretty(cfg).unwrap_or_default());
}

/// 启动时把配置里的 domain_mode / org_company 注入全局（dept_ops 门禁、命名空间判定读取）。
fn init_domain_and_org(cfg: &Config) {
    agent_core::dept_ops::init_domain_mode(agent_core::dept_ops::DomainMode::from_str(&cfg.domain_mode));
    agent_core::dept_ops::init_org_ns(&cfg.org_company);
    let _ = ORG_COMPANY.set(cfg.org_company.clone());
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
                meeting_tx: broadcast::channel(256).0,
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

/// PFAiX 局域网升级：静态目录根，默认在 agent-core.exe 同目录下 `updates/pfaix/`。
/// 允许通过 PFAIX_UPDATES_DIR 环境变量覆盖。
fn pfaix_updates_dir() -> std::path::PathBuf {
    std::env::var("PFAIX_UPDATES_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("updates")
                .join("pfaix")
        })
}

/// 返回当前最新版本的 manifest；若目录下没有放置 latest.json 则返回 404。
async fn handle_updates_latest() -> impl axum::response::IntoResponse {
    let path = pfaix_updates_dir().join("latest.json");
    match tokio::fs::read(&path).await {
        Ok(data) => (
            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
            data,
        )
            .into_response(),
        Err(_) => (axum::http::StatusCode::NOT_FOUND, "no update manifest").into_response(),
    }
}

/// 下载安装包等静态文件，做路径穿越防御 + 简单 MIME 推断。
async fn handle_updates_static(
    axum::extract::Path(file): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    let root = pfaix_updates_dir();
    let candidate = root.join(file.replace('\\', "/"));
    // 路径穿越防御：必须在 root 下
    let (Ok(root_canon), Ok(cand_canon)) = (
        std::fs::canonicalize(&root),
        std::fs::canonicalize(&candidate),
    ) else {
        return (axum::http::StatusCode::NOT_FOUND, "not found").into_response();
    };
    if !cand_canon.starts_with(&root_canon) || !cand_canon.is_file() {
        return (axum::http::StatusCode::NOT_FOUND, "not found").into_response();
    }
    let data = match tokio::fs::read(&cand_canon).await {
        Ok(d) => d,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let ct = match cand_canon
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "exe" => "application/octet-stream",
        "json" => "application/json; charset=utf-8",
        "txt" | "md" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    };
    ([(axum::http::header::CONTENT_TYPE, ct)], data).into_response()
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
    headers: axum::http::HeaderMap,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    // 解串行：克隆 Arc 后释放全局锁，consolidate() 循环在锁外执行
    let agent = {
        let g = st.agent.lock().await;
        g.as_ref().map(|a| a.clone())
    };
    let Some(agent) = agent else {
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
                .unwrap_or(default_ns.clone())
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
    // PR5 自驱：手动 consolidate 后可选元进化（追平时默认关，防拖垮）
    let skip_meta = std::env::var("CONSOLIDATE_SKIP_META")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);
    if !skip_meta {
        let me_val = agent.run_meta_evolution(&default_ns).await;
        tracing::info!(target: "consciousness", "meta_evolution(manual): {}", me_val);
        results.push(serde_json::json!({"ns": default_ns, "meta_evolution": me_val}));
    } else {
        results.push(serde_json::json!({"ns": default_ns, "meta_evolution": "skipped"}));
    }
    record_dream_health(&st, "manual", results.clone(), true).await;
    let summary = st.consolidate_last.lock().await.clone();
    Json(summary).into_response()
}

/// Phase 3：运行时创建分身
async fn handle_persona_create(
    headers: axum::http::HeaderMap,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let persona_id = match v.get("persona_id").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST, "persona_id required").into_response(),
    };
    let display_name = v.get("display_name").and_then(|x| x.as_str()).unwrap_or(&persona_id).to_string();
    // owner 一律由鉴权身份推导，不信任请求体（防越权声明他人身份）
    let owner_user_id = caller.clone();
    let is_private = v.get("is_private").and_then(|x| x.as_bool()).unwrap_or(false);
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
    match agent.create_persona(&persona_id, &display_name, &owner_user_id, tool_allowlist, memory_namespace, llm, is_private) {
        Ok(()) => {
            agent.save_personas();
            Json(serde_json::json!({"ok": true, "persona_id": persona_id, "owner_user_id": owner_user_id, "is_private": is_private})).into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Phase 3：列出分身（仅返回调用者可见的：公开 / 拥有者 / admin）
async fn handle_persona_list(
    headers: axum::http::HeaderMap,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    let list: Vec<serde_json::Value> = agent
        .list_personas()
        .iter()
        .filter(|p| !p.is_private || admin || p.owner_user_id == caller)
        .map(|p| {
            serde_json::json!({
                "persona_id": p.persona_id,
                "display_name": p.display_name,
                "owner_user_id": p.owner_user_id,
                "tool_allowlist": p.tool_allowlist,
                "memory_namespace": p.memory_namespace,
                "is_private": p.is_private,
            })
        })
        .collect();
    Json(serde_json::json!({"personas": list})).into_response()
}

/// Phase 3：删除分身（私有分身仅拥有者 / admin 可删）
async fn handle_persona_delete(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    // 私有分身：非拥有者 / 非 admin 一律隐藏（404 不泄露存在）
    if let Some(p) = agent.persona_by_id(&id) {
        if p.is_private && !admin && p.owner_user_id != caller {
            return (axum::http::StatusCode::NOT_FOUND, "persona not found").into_response();
        }
    }
    match agent.remove_persona(&id) {
        Ok(()) => {
            agent.save_personas();
            Json(serde_json::json!({"ok": true, "removed": id})).into_response()
        }
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

/// Phase 4：查询单分身详情（含目标栈；私有分身仅拥有者 / admin 可见）
async fn handle_persona_get(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    let p = match agent.persona_by_id(&id) {
        Some(p) => p,
        None => return (axum::http::StatusCode::NOT_FOUND, "persona not found").into_response(),
    };
    if p.is_private && !admin && p.owner_user_id != caller {
        return (axum::http::StatusCode::NOT_FOUND, "persona not found").into_response();
    }
    let goals = agent.get_persona_goals(&id);
    Json(serde_json::json!({
        "persona_id": p.persona_id,
        "display_name": p.display_name,
        "owner_user_id": p.owner_user_id,
        "tool_allowlist": p.tool_allowlist,
        "memory_namespace": p.memory_namespace,
        "is_private": p.is_private,
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
    let meeting_id = {
        let g = st.agent.lock().await;
        match &*g {
            Some(ref agent) => agent.create_meeting(
                &topic,
                &caller,
                participants.clone(),
                participant_agents,
                is_private,
                scope.clone(),
            ),
            None => String::new(),
        }
    };

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
        let g = st_clone.agent.lock().await;
        let Some(ref agent) = *g else {
            let _ = tx.send(Ok(SseEvent::default().event("done").data("")));
            return;
        };
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
        // 回填会议记录（共识 + done）
        if !meeting_id_c.is_empty() {
            agent.finish_meeting(&meeting_id_c, &consensus);
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
async fn handle_meetings_list(
    headers: axum::http::HeaderMap,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    let list = agent.list_meetings(&caller, admin, &caller_ns);
    // scope 会议的可见性已在 AgentCore::list_meetings 内权威判定（public within scope）
    let items: Vec<serde_json::Value> = list
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id,
                "topic": m.topic,
                "owner_user_id": m.owner_user_id,
                "participant_personas": m.participant_personas,
                "is_private": m.is_private,
                "created_at": m.created_at,
                "status": m.status,
                "consensus": m.consensus,
                "scope": m.scope,
                "participant_agents": m.participant_agents,
                "messages": m.messages,
                "phase": m.phase,
            })
        })
        .collect();
    Json(serde_json::json!({ "meetings": items })).into_response()
}

/// Phase 6 增强：删除圆桌会议（私有仅拥有者 / admin 可删）
async fn handle_meeting_delete(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    match agent.remove_meeting(&id, &caller, admin) {
        Ok(()) => {
            // 清理该会议的在线态，防止 meeting_presence 无界增长
            st.meeting_presence.lock().await.remove(&id);
            // Step3 实时同步：广播终止事件。会议已被删除，get_meeting 之后恒为 None，
            // 若不广播，订阅端拿不到任何终止信号 → 本地状态永久陈旧、SSE 任务空转到客户端断开为止。
            broadcast_meeting_event(
                &st,
                &id,
                EventKind::Ended,
                serde_json::json!({ "deleted": true, "status": "done" }),
            );
            Json(serde_json::json!({"ok": true, "removed": id})).into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Phase 6 增强 (Step2)：真人 A2A 参会——向会议发言。
/// body: { "from": agent_id, "content": "..." }
/// 记录发言后，将该消息 A2A 投递到会议其余 participant_agents 的收件箱。
async fn handle_meeting_message(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let from = v.get("from").and_then(|x| x.as_str()).unwrap_or(&caller).to_string();
    let content = match v.get("content").and_then(|x| x.as_str()) {
        Some(c) if !c.trim().is_empty() => c.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "content required"}))).into_response(),
    };
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    // 记录发言（kind=human，A2A 真人消息）
    let msg = match agent.add_meeting_message(&id, &from, "human", &content) {
        Ok(m) => m,
        Err(e) => {
            return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
                .into_response()
        }
    };
    // A2A 投递到其余真人参与者收件箱
    let targets: Vec<String> = agent
        .meeting_agent_participants(&id)
        .into_iter()
        .filter(|a| *a != from)
        .collect();
    let mut delivered = 0usize;
    for t in &targets {
        let envelope = serde_json::json!({
            "type": "meeting",
            "subject": format!("会议 {}：{} 发言", id, from),
            "meeting": id,
            "from": from,
            "content": content,
            "kind": "human-message",
        });
        if agent.collab_send_raw(t, &envelope).await.is_ok() {
            delivered += 1;
        }
    }
    // Step3 实时同步：广播**增量**（仅新发言 + 状态字段）。
    // 不再序列化完整 Meeting：否则每条发言都是 O(n)，broadcast 通道又保留最近 256 条，
    // 长会议会累积 O(n²) 的数据量。完整快照只保留给初始订阅 / Lagged 重同步路径。
    let (status, phase) = agent
        .meeting_state(&id)
        .unwrap_or_else(|| ("running".to_string(), None));
    broadcast_meeting_event(
        &st,
        &id,
        EventKind::Message,
        serde_json::json!({ "message": msg, "status": status, "phase": phase }),
    );
    Json(serde_json::json!({"ok": true, "delivered": delivered, "targets": targets.len()})).into_response()
}

/// Phase 6 增强 (Step2)：结束会议并回填共识。
/// body: { "requested_by": "<owner>", "consensus": "..." }
/// consensus 可选，缺省用 caller 的 ""。
async fn handle_meeting_end(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, _) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let v = match body {
        Some(Json(v)) => v,
        None => serde_json::json!({}),
    };
    let requested_by = v.get("requested_by").and_then(|x| x.as_str()).unwrap_or(&caller).to_string();
    let consensus = v.get("consensus").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    match agent.end_meeting(&id, &consensus, &requested_by, admin) {
        Ok(()) => {
            // 清理该会议的在线态，防止 meeting_presence 无界增长
            st.meeting_presence.lock().await.remove(&id);
            // Step3 实时同步：广播结束事件（增量，不含完整消息历史）
            broadcast_meeting_event(
                &st,
                &id,
                EventKind::Ended,
                serde_json::json!({
                    "status": "done",
                    "phase": "done",
                    "consensus": consensus,
                }),
            );
            Json(serde_json::json!({"ok": true, "ended": id})).into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// Step3：向会议实时广播通道推送一条事件。
///
/// payload 由调用方决定粒度：
/// - `Message` / `Ended`：**增量**（新发言 + status/phase，或终止状态），O(1)；
/// - `Snapshot`：完整 Meeting JSON，仅用于初始订阅与 Lagged 重同步。
///
/// 无订阅者时 `send` 返回 Err，属正常情况，忽略。
fn broadcast_meeting_event(
    st: &Arc<AppState>,
    id: &str,
    kind: EventKind,
    payload: serde_json::Value,
) {
    let _ = st.meeting_tx.send(MeetingEvent {
        meeting_id: id.to_string(),
        kind,
        payload,
        at: chrono::Utc::now().to_rfc3339(),
    });
}

/// Step3：会议可见性判定的**取锁便捷包装**（供 SSE 订阅使用）。
///
/// 判定规则的唯一实现在 `AgentCore::meeting_visible`（owner / admin / scope 成员 / 公开会议），
/// 心跳 handler 直接调用该核心方法——因为它需要把「校验 + 写 presence」放在同一个 agent 锁
/// 临界区内以消除竞态，不能在这里提前释放锁。两条路径共享同一份规则，不会各写一份而漂移。
///
/// 会议不存在时返回 false（不区分「不存在 / 无权」，避免被用来探测会议 ID）。
async fn meeting_visible(
    st: &Arc<AppState>,
    id: &str,
    caller: &str,
    caller_ns: &[String],
    admin: bool,
) -> bool {
    let g = st.agent.lock().await;
    match &*g {
        Some(agent) => agent
            .meeting_visible(id, caller, caller_ns, admin)
            .unwrap_or(false),
        None => false,
    }
}

/// Step3：实时同步 —— SSE 订阅某会议的实时事件流。
/// 事件类型：snapshot（初始快照）/ message / state / ended（会议状态变更）/ presence（在线列表）。
async fn handle_meeting_stream(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    // 可见性校验：owner / admin / scope 成员 / 公开会议 可订阅（与心跳共用同一判定）
    if !meeting_visible(&st, &id, &caller, &caller_ns, admin).await {
        return (axum::http::StatusCode::FORBIDDEN, "无权订阅该会议").into_response();
    }

    let mut rx = st.meeting_tx.subscribe();
    // 有界通道 + try_send：SSE 是长连接，若客户端保持 TCP 打开却停止读取（网络卡死 / 标签页挂起），
    // hyper 不再轮询流，无界通道会把每 5s 的 presence/ping 与所有广播无限堆积到内存里。
    // 这里缓冲满即判定该连接已失活，直接结束推送任务并关闭流。
    let (tx, rx_out) = tokio::sync::mpsc::channel::<Result<SseEvent, Infallible>>(64);
    let st2 = st.clone();
    let id2 = id.clone();
    tokio::spawn(async move {
        // 初始快照：先在最小临界区内取出会议克隆，**出锁后**再做 JSON 序列化，
        // 避免长会议序列化期间阻塞所有共享 st.agent 的 handler（message/end/list/delete）。
        let snap = {
            let g = st2.agent.lock().await;
            g.as_ref().and_then(|a| a.get_meeting(&id2))
        };
        if let Some(m) = snap {
            let data = serde_json::to_string(&m).unwrap_or_default();
            if tx
                .try_send(Ok(SseEvent::default().event("snapshot").data(data)))
                .is_err()
            {
                return;
            }
        }
        // 心跳保活 + 在线表推送（每 5s）
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let online = {
                        let map = st2.meeting_presence.lock().await;
                        match map.get(&id2) {
                            Some(p) => p
                                .iter()
                                .filter(|(_, t)| t.elapsed().as_secs() < 15)
                                .map(|(k, _)| k.clone())
                                .collect::<Vec::<_>>(),
                            None => Vec::new(),
                        }
                    };
                    // 客户端断开（Closed）或已失活致缓冲写满（Full）时立即退出，避免任务与内存泄漏
                    if tx.try_send(Ok(SseEvent::default().event("presence").data(
                        serde_json::json!({ "online": online }).to_string(),
                    ))).is_err() { break; }
                    // SSE 注释行心跳：axum 以 ':' 前缀发出，客户端忽略，不产生伪 message 事件
                    if tx.try_send(Ok(SseEvent::default().comment("ping"))).is_err() { break; }
                }
                msg = rx.recv() => {
                    match msg {
                        Ok(ev) if ev.meeting_id == id2 => {
                            if tx.try_send(Ok(SseEvent::default().event(ev.kind.as_str()).data(ev.payload.to_string()))).is_err() { break; }
                        }
                        Ok(_) => {}
                        // 客户端落后超过缓冲：重新发送完整快照以重同步，避免静默丢事件
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // 同初始快照：克隆在锁内、序列化在锁外
                            let m = {
                                let g = st2.agent.lock().await;
                                g.as_ref().and_then(|a| a.get_meeting(&id2))
                            };
                            if let Some(m) = m {
                                let s = serde_json::to_string(&m).unwrap_or_default();
                                if tx.try_send(Ok(SseEvent::default().event("snapshot").data(s))).is_err() { break; }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
        let _ = tx.try_send(Ok(SseEvent::default().event("done").data("")));
    });
    let mut resp = Sse::new(ReceiverStream::new(rx_out)).into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    resp.headers_mut().insert(
        "x-accel-buffering",
        axum::http::HeaderValue::from_static("no"),
    );
    resp
}

/// Step3：实时同步 —— 心跳保活。记录调用者在该会议的在线状态，返回当前在线列表。
async fn handle_meeting_heartbeat(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    // 可见性校验 + 在线态写入，**在同一个 agent 锁临界区内完成**，消除 check-then-act 竞态：
    // 若只做「先校验、后插入」，并发的 delete/end 可能在两步之间删掉会议，
    // 使 or_default() 为一个已不存在的会议重建孤儿 presence 条目（复活刚被清理的状态）。
    // 锁顺序 agent → presence，与 handle_meeting_delete / handle_meeting_end 保持一致，无死锁风险。
    //
    // 会议不存在时同样按「无权」处理，避免任意认证用户借错误码探测会议 ID 是否存在。
    {
        let g = st.agent.lock().await;
        let visible = match &*g {
            Some(agent) => agent
                .meeting_visible(&id, &caller, &caller_ns, admin)
                .unwrap_or(false),
            None => false,
        };
        if !visible {
            return (axum::http::StatusCode::FORBIDDEN, "无权访问该会议").into_response();
        }
        // 写入前先裁剪过期条目（elapsed >= 15s），防止 meeting_presence 无界增长
        let mut map = st.meeting_presence.lock().await;
        let entry = map.entry(id.clone()).or_default();
        entry.retain(|_, t| t.elapsed().as_secs() < 15);
        entry.insert(caller.clone(), std::time::Instant::now());
    }
    let online: Vec<String> = {
        let map = st.meeting_presence.lock().await;
        match map.get(&id) {
            Some(p) => p
                .iter()
                .filter(|(_, t)| t.elapsed().as_secs() < 15)
                .map(|(k, _)| k.clone())
                .collect(),
            None => Vec::new(),
        }
    };
    Json(serde_json::json!({ "ok": true, "online": online })).into_response()
}

/// Phase 7：进化任务并发守卫（Drop 时复位，确保任何退出路径都释放锁）
struct EvolveGuard<'a> {
    flag: &'a AtomicBool,
}
impl<'a> Drop for EvolveGuard<'a> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

/// Phase 7：代码自我进化引擎（POST /api/evolve，SSE 流式）
///
/// 安全模型（对齐圆桌共识 + 人类否决闸门 + P0 加固）：
/// - 必须由 `[code_evolution] enabled = true` 开启，否则 403。
/// - 必须由 `[code_evolution] evolve_key` 配置密钥，且请求携带匹配的 `x-evolve-key`（P0-1）；
///   否则 401 / fail-closed。全局 auth_middleware 的自动开户不足以触发进化。
/// - 目标路径经 `resolve_isolated_target` 规范化校验：拒 symlink、拒落入 agent-core / memoria
///   源码树（含改名克隆、memoria-open）（P0-2）。
/// - 真签名冻结：apply_patch 归一化比对签名，仅替换函数体（P0-3）。
/// - 默认 dry_run 由 `dry_run_default` 决定（默认 true）：只产 diff（veto 事件），不落盘；
///   须显式 `apply=true` 且配置 `allow_commit=true` 才 git commit（人类否决闸门）。
/// - 熔断：连续失败/无进展达 `circuit_failures` 代立即停。
async fn handle_code_evolve(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    // 取 code_evolution 配置
    let ce = { let c = st.config.lock().await; c.code_evolution.clone() };
    let ce = match ce {
        Some(c) if c.enabled => c,
        _ => return (axum::http::StatusCode::FORBIDDEN, "code evolution disabled").into_response(),
    };
    // P0-1：专用进化密钥闸门（fail-closed）。即便已通过全局 auth_middleware 的自动开户，
    // 触发进化仍必须携带与配置匹配的 `x-evolve-key`，否则 401。避免「端口可达 + 自动开户 = 即可触发进化」。
    let cfg_evolve_key = ce.evolve_key.clone().unwrap_or_default();
    if cfg_evolve_key.is_empty() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "evolution key not configured (fail-closed)",
        )
            .into_response();
    }
    let supplied_key = headers
        .get("x-evolve-key")
        .and_then(|x| x.to_str().ok())
        .unwrap_or("")
        .to_string();
    if supplied_key != cfg_evolve_key {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "missing/invalid x-evolve-key",
        )
            .into_response();
    }
    // 解析参数
    let target = v
        .get("target_path")
        .and_then(|x| x.as_str())
        .map(String::from)
        .or(ce.target_path.clone());
    let target = match target {
        Some(t) => t,
        None => return (axum::http::StatusCode::BAD_REQUEST, "target_path required").into_response(),
    };
    // P0-2：路径隔离强化 —— 规范化 + 拒 symlink + 拒落入 agent-core/memoria 源码树（含改名克隆、memoria-open）
    let target_p = match agent_core::code_evolve::resolve_isolated_target(&target) {
        Ok(p) => p,
        Err(e) => return (axum::http::StatusCode::FORBIDDEN, e).into_response(),
    };
    let fn_name = v
        .get("fn_name")
        .and_then(|x| x.as_str())
        .map(String::from)
        .unwrap_or_else(|| ce.fn_name.clone());
    let generations = v
        .get("generations")
        .and_then(|x| x.as_u64())
        .map(|n| n as usize)
        .unwrap_or(ce.generations);
    let circuit = ce.circuit_failures.max(1);
    // P1：apply 默认值由配置 dry_run_default 决定（默认 true → 默认 dry_run）。
    // 此前该字段是死字段（handler 未读），现已接线生效。
    let apply_param = v
        .get("apply")
        .and_then(|x| x.as_bool())
        .unwrap_or(!ce.dry_run_default);
    let effective_apply = apply_param && ce.allow_commit;
    let goal = v.get("goal").and_then(|x| x.as_str()).map(String::from).unwrap_or_else(|| {
        "在保持正确性、签名与 `pub fn fib` 不变、且不改动 #[cfg(test)] 测试模块的前提下，优化实现使其运行更快；禁止使用 unsafe、外部 IO 或新增依赖。".to_string()
    });

    // 并发守卫：同一时刻只允许一个进化任务（防止多请求并发覆盖隔离仓库）
    if st.evolve_running.swap(true, Ordering::SeqCst) {
        return (
            axum::http::StatusCode::CONFLICT,
            "evolution already running",
        )
            .into_response();
    }

    // agent 就绪 + 选取提议用 LLM（专属 model 或全局主 client）
    let g = st.agent.lock().await;
    if g.is_none() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "agent 尚未就绪",
        )
            .into_response();
    }
    let proposer = match &ce.model {
        Some(m) => LlmClient::new(m.clone()),
        None => g.as_ref().unwrap().llm.clone(),
    };
    drop(g);

    let (tx, rx): (
        tokio::sync::mpsc::UnboundedSender<Result<SseEvent, Infallible>>,
        tokio::sync::mpsc::UnboundedReceiver<Result<SseEvent, Infallible>>,
    ) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        // 任务结束（含任意 early break）自动复位并发守卫
        let _guard = EvolveGuard {
            flag: &st.evolve_running,
        };
        let send = |ev: &str, data: serde_json::Value| {
            let _ = tx.send(Ok(SseEvent::default().event(ev).data(data.to_string())));
        };
        // 派生隔离仓库的 manifest 与 git 根
        let manifest = find_up(&target_p, "Cargo.toml").unwrap_or_else(|| target_p.clone());
        let repo = match find_up(&target_p, ".git") {
            Some(gd) => gd
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or(gd),
            None => target_p.parent().unwrap_or(&target_p).to_path_buf(),
        };

        // 种子最优：以当前已提交状态为基线
        let mut best: Option<f64> = {
            let m = manifest.clone();
            let e = tokio::task::spawn_blocking(move || eval_crate(&m))
                .await
                .unwrap_or(EvalResult {
                    passed: false,
                    bench_ms: None,
                    log: "eval 失败".into(),
                });
            if e.passed {
                e.bench_ms
            } else {
                None
            }
        };
        send(
            "info",
            serde_json::json!({
                "repo": repo.to_string_lossy(),
                "manifest": manifest.to_string_lossy(),
                "apply": effective_apply,
                "best_seed_ms": best,
                "goal": goal,
            }),
        );

        let mut consecutive = 0usize;
        let mut gens_run = 0usize;
        for gen in 1..=generations {
            gens_run += 1;
            let current = match std::fs::read_to_string(&target_p) {
                Ok(c) => c,
                Err(e) => {
                    send("error", serde_json::json!({"gen": gen, "msg": format!("读目标文件失败: {}", e)}));
                    break;
                }
            };
            send("gen_start", serde_json::json!({"gen": gen, "best_ms": best}));

            // 1) LLM 提议
            let new_fn = match propose_fn(&proposer, &fn_name, &current, &goal).await {
                Ok(f) => f,
                Err(e) => {
                    send("proposal_error", serde_json::json!({"gen": gen, "msg": e}));
                    consecutive += 1;
                    if consecutive >= circuit {
                        send("circuit_break", serde_json::json!({"reason": format!("连续 {} 代提议失败/超时", consecutive)}));
                        break;
                    }
                    continue;
                }
            };
            send("proposal", serde_json::json!({"gen": gen, "code": new_fn}));

            // 2) 外科替换
            let new_src = match apply_patch(&current, &fn_name, &new_fn) {
                Ok(s) => s,
                Err(e) => {
                    send("rejected", serde_json::json!({"gen": gen, "reason": e}));
                    consecutive += 1;
                    if consecutive >= circuit {
                        send("circuit_break", serde_json::json!({"reason": "连续被拒达上限"}));
                        break;
                    }
                    continue;
                }
            };
            if std::fs::write(&target_p, &new_src).is_err() {
                send("rejected", serde_json::json!({"gen": gen, "reason": "写目标文件失败"}));
                consecutive += 1;
                if consecutive >= circuit {
                    send("circuit_break", serde_json::json!({"reason": "连续失败达上限"}));
                    break;
                }
                continue;
            }

            // 3) 评估（在阻塞线程跑 cargo，避免占用 async 工作线程）
            let m = manifest.clone();
            let ev = tokio::task::spawn_blocking(move || eval_crate(&m))
                .await
                .unwrap_or(EvalResult {
                    passed: false,
                    bench_ms: None,
                    log: "eval 失败".into(),
                });

            if !ev.passed {
                let _ = git_revert(&repo, &target_p);
                send("reverted", serde_json::json!({"gen": gen, "reason": "测试/编译失败", "log": ev.log}));
                consecutive += 1;
                if consecutive >= circuit {
                    send("circuit_break", serde_json::json!({"reason": "连续失败达上限"}));
                    break;
                }
                continue;
            }

            // 4) 判定是否优于当前最优
            let improved = match best {
                None => true,
                Some(b) => ev.bench_ms.map_or(false, |m| m < b - 1e-9),
            };
            if improved {
                best = ev.bench_ms;
                consecutive = 0;
                if effective_apply {
                    match git_commit(&repo, &target_p, &format!("代码进化(gen {}): 优化 {}", gen, fn_name)) {
                        Ok(h) => send(
                            "committed",
                            serde_json::json!({"gen": gen, "commit": h, "bench_ms": ev.bench_ms, "log": ev.log}),
                        ),
                        Err(e) => {
                            let _ = git_revert(&repo, &target_p);
                            send("rejected", serde_json::json!({"gen": gen, "reason": format!("commit 失败: {}", e)}));
                        }
                    }
                } else {
                    let diff = git_diff(&repo, &target_p);
                    send("veto", serde_json::json!({"gen": gen, "bench_ms": ev.bench_ms, "diff": diff, "log": ev.log}));
                    let _ = git_revert(&repo, &target_p); // 不落盘，等待人工批准
                }
            } else {
                let _ = git_revert(&repo, &target_p);
                send("reverted", serde_json::json!({"gen": gen, "reason": "未优于当前最优", "bench_ms": ev.bench_ms}));
                consecutive += 1;
                if consecutive >= circuit {
                    send("circuit_break", serde_json::json!({"reason": "连续无进展达上限"}));
                    break;
                }
            }
        }
        send(
            "done",
            serde_json::json!({"gens_run": gens_run, "best_ms": best, "applied": effective_apply}),
        );
    });

    Sse::new(UnboundedReceiverStream::new(rx)).into_response()
}

/// PR5：触发一轮元进化（POST /api/meta-evolution/run）
async fn handle_meta_evolution_run(
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
    let ns = body
        .as_ref()
        .and_then(|Json(v)| v.get("namespace").and_then(|x| x.as_str()).map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or(default_ns);
    let res = agent.run_meta_evolution(&ns).await;
    drop(agent_guard);
    Json(res).into_response()
}

/// PR5：元进化状态（GET /api/meta-evolution/status）
async fn handle_meta_evolution_status(
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let agent_guard = st.agent.lock().await;
    let Some(ref agent) = *agent_guard else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "agent 尚未就绪"})),
        )
            .into_response();
    };
    let res = agent.meta_evolution_status().await;
    drop(agent_guard);
    Json(res).into_response()
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
    match build_agent(&resolve_config_for_runtime(&cfg), st.local_resources.clone(), st.metrics.clone()).await {
        Ok(agent) => {
            *st.agent.lock().await = Some(Arc::new(agent));
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
    // 解串行：克隆 Arc 后立即释放全局锁，chat() 在锁外并发执行
    let agent = {
        let g = st.agent.lock().await;
        g.as_ref().map(|a| a.clone())
    };
    if let Some(agent) = agent {
        let start = std::time::Instant::now();
        let reply = agent
            .chat(
                &req.message,
                &ctx.agent_id,
                &req.session_id,
                &ctx.allowed_ns,
                None,
            )
            .await;
        st.metrics
            .record_latency(start.elapsed().as_secs_f64() * 1000.0);
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
            // 解串行：克隆 Arc 后释放锁，chat() 并发执行
            let agent = {
                let g = st_clone.agent.lock().await;
                g.as_ref().map(|a| a.clone())
            };
            if let Some(agent) = agent {
                let start = std::time::Instant::now();
                let reply = agent.chat(&msg, &agent_id, &sid, &allowed_ns, None).await;
                st_clone
                    .metrics
                    .record_latency(start.elapsed().as_secs_f64() * 1000.0);
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
async fn handle_sessions(
    State(_st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
) -> Json<serde_json::Value> {
    let allowed_ns = ctx.allowed_ns.clone();
    let db_path = std::env::current_dir()
        .unwrap_or_default()
        .join("harness.db")
        .to_string_lossy()
        .to_string();

    let sessions = tokio::task::spawn_blocking(move || {
        let mut result = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT session_id, namespace, role, content, created_at FROM chat_history WHERE id IN (
                    SELECT MIN(id) FROM chat_history GROUP BY session_id
                ) AND role = 'user' ORDER BY id DESC LIMIT 50",
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    let sid: String = row.get(0)?;
                    let ns: String = row.get(1)?;
                    let content: String = row.get(2)?;
                    let created: String = row.get(3)?;
                    Ok((sid, ns, content, created))
                }) {
                    for row in rows.flatten() {
                        // C2 修复：仅返回调用方命名空间覆盖的会话，防跨 agent 泄露
                        if !caller_ns_covers(&allowed_ns, &row.1) {
                            continue;
                        }
                        let summary = row.2.chars().take(40).collect::<String>();
                        result.push(serde_json::json!({
                            "session_id": row.0,
                            "summary": summary,
                            "created_at": row.3,
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
/// 解析转发给 Memoria 的有效调用者密钥。
///
/// PFAiX legacy 模式仅发 `x-user-tag`（随机安装ID），不携带 `x-agent-key`；
/// 若此处直接读 `x-agent-key` 头会得到空串，导致 Memoria `a2a_recv` 返回 -32001
/// （协作收件箱 502）。三级兜底：
///   1) `auth_cache` 中 `authenticate` 已校验/注册的 badge（legacy 自动注册 / 登录态自愈写入）；
///   2) 请求头 `x-agent-key`（登录态正常携带，且 `authenticate` 已据此成功鉴权）；
///   3) 兜底：以 admin 身份确保该 agent 在 Memoria 注册并取回 badge，再缓存复用。
/// 这样无论 `authenticate` 的注册 badge 是否成功落入 cache，调用方都能拿到可鉴权的密钥。
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
async fn is_admin(headers: &axum::http::HeaderMap, st: &Arc<AppState>) -> bool {
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

/// 加载指定会话的历史
async fn handle_session_load(
    State(_st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let allowed_ns = ctx.allowed_ns.clone();
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
            // C2 修复：校验会话归属，仅当调用方命名空间覆盖该会话时才返回
            let owned = {
                let mut flag = false;
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT DISTINCT namespace FROM chat_history WHERE session_id=?1",
                ) {
                    if let Ok(rows) = stmt.query_map(rusqlite::params![&sid], |row| {
                        row.get::<_, String>(0)
                    }) {
                        flag = rows.flatten().any(|ns| caller_ns_covers(&allowed_ns, &ns));
                    }
                }
                flag
            };
            if !owned {
                return result;
            }
            if let Ok(mut stmt) = conn.prepare(
                "SELECT role, content, created_at FROM chat_history WHERE session_id=?1 ORDER BY id ASC"
            ) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![&sid], |row| {
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
    Extension(ctx): Extension<AuthContext>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let allowed_ns = ctx.allowed_ns.clone();
    let db_path = std::env::current_dir()
        .unwrap_or_default()
        .join("harness.db")
        .to_string_lossy()
        .to_string();
    let sid = id.clone();

    let deleted = tokio::task::spawn_blocking(move || {
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            // C2 修复：校验会话归属，仅当调用方命名空间覆盖该会话时才允许删除
            let owned = {
                let mut flag = false;
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT DISTINCT namespace FROM chat_history WHERE session_id=?1",
                ) {
                    if let Ok(rows) = stmt.query_map(rusqlite::params![&sid], |row| {
                        row.get::<_, String>(0)
                    }) {
                        flag = rows.flatten().any(|ns| caller_ns_covers(&allowed_ns, &ns));
                    }
                }
                flag
            };
            if !owned {
                return 0;
            }
            if let Ok(cnt) = conn.execute(
                "DELETE FROM chat_history WHERE session_id=?1",
                rusqlite::params![&sid],
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
async fn handle_admin_degrade(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
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
    headers: axum::http::HeaderMap,
    Json(req): Json<KillSwitchRequest>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
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
        // 战略罗盘「可观测」：特性门状态 + 运行计数器/时延/持久执行 gauge 全量快照
        let features = agent.feature_gates();
        let quota = agent.quota_status();
        Json(st.metrics.snapshot(features, quota)).into_response()
    } else {
        Json(serde_json::json!({"error": "agent not ready"})).into_response()
    }
}

/// P2-1：查询配额（管理员视角，与 /api/metrics 的 quota 段一致）
async fn handle_admin_quota_get(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
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
    headers: axum::http::HeaderMap,
    Json(req): Json<QuotaPolicyUpdate>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
    let guard = st.agent.lock().await;
    if let Some(ref agent) = *guard {
        let mut policy = {
            let s = agent.quota.lock().unwrap_or_else(|p| p.into_inner());
            s.get_policy(&req.namespace)
        };
        if let Some(v) = req.max_tool_rounds {
            policy.max_tool_rounds_per_day = v;
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
                "max_tool_rounds": policy.max_tool_rounds_per_day,
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
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
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
    headers: axum::http::HeaderMap,
    Json(req): Json<HarnessActivate>,
) -> axum::response::Response {
    if !is_admin(&headers, &st).await {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "需要 admin 权限"})),
        )
            .into_response();
    }
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

/// OpenAI content 可能是 string，也可能是 [{type,text}, ...] 多段
#[derive(Deserialize)]
#[serde(untagged)]
enum V1Content {
    Text(String),
    Parts(Vec<V1ContentPart>),
}

#[derive(Deserialize)]
struct V1ContentPart {
    #[serde(default)]
    text: Option<String>,
}

impl V1Content {
    fn as_text(&self) -> String {
        match self {
            V1Content::Text(s) => s.clone(),
            V1Content::Parts(parts) => parts
                .iter()
                .filter_map(|p| p.text.as_ref())
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

#[derive(Deserialize)]
struct V1Message {
    #[allow(dead_code)]
    role: String,
    content: Option<V1Content>,
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
    // PFAiX 强制上下文隔离：每个安装实例 + 每个对话独立 session（提到 if 外，stream 分支共用）。
    // x-user-tag 是壳首次启动生成的随机 install_id；x-conversation-id 是壳内当前对话 id。
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
    // 折叠 OpenAI messages 提到 if 外（stream 分支需要 user_text/external_history）
    let pairs: Vec<(String, String)> = req
        .messages
        .iter()
        .filter_map(|m| {
            m.content
                .as_ref()
                .map(|c| (m.role.clone(), c.as_text()))
        })
        .collect();
    let folded = agent_core::v1_compat::fold_v1_messages(&pairs);
    let user_text = folded.user_message;
    let external_history = if folded.history.is_empty() {
        None
    } else {
        Some(folded.history)
    };
    let reply = if let Some(ref agent) = *agent_guard {
        // 输入校验：消息长度限制 32KB，消息数限制 100
        if req.messages.len() > 100 {
            return axum::response::Json(serde_json::json!({
                "error": "too many messages"
            }))
            .into_response();
        }
        // P2-6：stream=true 时跳过预生成（reply 由 stream 分支真流式产出，避免重复 LLM 调用）
        if req.stream.unwrap_or(false) {
            String::new()
        } else if user_text.trim().is_empty() {
            "请输入消息".to_string()
        } else {
            if !folded.system_ctx.is_empty() {
                tracing::info!(
                    system_chars = folded.system_ctx.chars().count(),
                    "v1_chat: folded client system into user message"
                );
            }
            agent
                .chat(
                    &user_text,
                    &ctx.agent_id,
                    &session_id,
                    &ctx.allowed_ns,
                    external_history.clone(),
                )
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
            // 空消息校验（与非 stream 路径一致，防空消息跑完整 agent 管线）
            if user_text.trim().is_empty() {
                let _ = tx.send(Ok(SseEvent::default().data(
                    serde_json::json!({
                        "id": &id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": &model,
                        "choices": [{"index": 0, "delta": {"content": "请输入消息"}, "finish_reason": null}]
                    })
                    .to_string(),
                )));
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
                let _ = tx.send(Ok(SseEvent::default().data("[DONE]")));
                return;
            }
            // P2-6 真流式：快速通道命中 → provider 流式逐 chunk（首 token 秒出）；
            // 未命中/失败 → agent.chat_stream 内部降级伪流式（完整生成后分块推）。
            let agent = {
                let g = st.agent.lock().await;
                g.as_ref().map(|a| a.clone())
            };
            if let Some(agent) = agent {
                // llm 事件 → chat.completion.chunk 格式的转发层
                let (tx_llm, mut rx_llm): (
                    tokio::sync::mpsc::UnboundedSender<agent_core::llm::SseEvent>,
                    tokio::sync::mpsc::UnboundedReceiver<agent_core::llm::SseEvent>,
                ) = tokio::sync::mpsc::unbounded_channel();
                let tx_fwd = tx.clone();
                let fwd_id = id.clone(); // id/model 已被外层 async move 捕获，转发 task 用 clone
                let fwd_model = model.clone();
                // 转发 task：llm 事件 → chat.completion.chunk。ErrorEvt 不立即转发
                // （延迟到主流程决定：补推全文时混推 error 会语义混乱）；统计已推 TextEvt 数。
                let fwd = tokio::spawn(async move {
                    let mut errored = false;
                    let mut pushed: usize = 0;
                    let mut err_msg: Option<String> = None;
                    while let Some(ev) = rx_llm.recv().await {
                        let out: Option<String> = match ev {
                            agent_core::llm::SseEvent::TextEvt { content } => {
                                pushed += 1;
                                Some(
                                    serde_json::json!({
                                        "id": &fwd_id,
                                        "object": "chat.completion.chunk",
                                        "created": created,
                                        "model": &fwd_model,
                                        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
                                    })
                                    .to_string(),
                                )
                            }
                            agent_core::llm::SseEvent::ThinkingEvt { content } => Some(
                                serde_json::json!({
                                    "id": &fwd_id,
                                    "object": "chat.completion.chunk",
                                    "created": created,
                                    "model": &fwd_model,
                                    "choices": [{"index": 0, "delta": {"reasoning_content": content}, "finish_reason": null}]
                                })
                                .to_string(),
                            ),
                            agent_core::llm::SseEvent::ErrorEvt { message } => {
                                errored = true;
                                err_msg = Some(message);
                                None // 延迟转发，避免与补推全文混推
                            }
                            agent_core::llm::SseEvent::DoneEvt | _ => None,
                        };
                        if let Some(data) = out {
                            let _ = tx_fwd.send(Ok(SseEvent::default().data(data)));
                        }
                    }
                    (errored, Some(pushed), err_msg)
                });
                let full = agent
                    .chat_stream(&user_text, &ctx.agent_id, &session_id, &ctx.allowed_ns, external_history.clone(), &tx_llm)
                    .await;
                // 关闭 tx_llm 并等待转发 task flush 完（防 finish 截断最后内容）
                drop(tx_llm);
                let (stream_errored, pushed, _err_msg) = match fwd.await {
                    Ok(r) => r,
                    Err(je) => {
                        // 转发 task panic/abort：pushed 未知（None）→ 保守视为已推（不补推防重复）
                        tracing::warn!(err = %je, "SSE 转发 task 异常结束");
                        (true, None, Some("SSE 转发任务异常".to_string()))
                    }
                };
                // pushed: Option<usize>（None=未知）；已推与否 = pushed.map_or(true, |p| p>0)
                let pushed_any = pushed.map_or(true, |p| p > 0);
                if stream_errored && pushed_any {
                    // 中途失败（已推部分内容）：error 事件（可区分失败/成功；中性措辞覆盖
                    // 认证/限流/连接/内部异常等所有来源）+ 内容提示不完整 + stop
                    let _ = tx.send(Ok(SseEvent::default()
                        .event("error")
                        .data("流式响应异常，本次回复可能不完整")));
                    let _ = tx.send(Ok(SseEvent::default().data(
                        serde_json::json!({
                            "id": &id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": &model,
                            "choices": [{"index": 0, "delta": {"content": "\n\n⚠️ 流式响应异常，本次回复可能不完整。请重试。"}, "finish_reason": null}]
                        })
                        .to_string(),
                    )));
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
                } else if !pushed_any {
                    // 未推任何内容（首包失败/流式未命中/正常 fallback）→ 伪流式补推 llm_loop
                    // 的完整结果（真实降级答案，诚实呈现——即使 full 是错误文本也如实展示）
                    let mut chars = full.chars();
                    loop {
                        let mut chunk = String::new();
                        for _ in 0..3 {
                            match chars.next() {
                                Some(c) => chunk.push(c),
                                None => break,
                            }
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        let data = serde_json::json!({
                            "id": &id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": &model,
                            "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": null}]
                        })
                        .to_string();
                        if tx.send(Ok(SseEvent::default().data(data))).is_err() {
                            break; // 客户端断开立即退出
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    // 首包失败：补推内容后标注降级（error 事件，可区分、不伪装成功）
                    if stream_errored {
                        let _ = tx.send(Ok(SseEvent::default()
                            .event("error")
                            .data("流式响应异常，已切换普通模式返回。")));
                    }
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
                } else {
                    // 真流式成功（已推完整内容）→ 仅终态 finish:stop
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
                }
            } else {
                let _ = tx.send(Ok(SseEvent::default().data(
                    serde_json::json!({
                        "id": &id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": &model,
                        "choices": [{"index": 0, "delta": {"content": "Agent 未就绪"}, "finish_reason": null}]
                    })
                    .to_string(),
                )));
                // Agent 未就绪分支也发终态 finish_reason（客户端依赖 finish 终结）
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
            }
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
fn caller_ns_covers(allowed: &[String], target: &str) -> bool {
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

async fn build_agent(
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

/// expand_env 的 ${ENV} 展开单测（覆盖 P2 的对称性修复与三类 ${X} 占位场景）。
#[cfg(test)]
mod env_expand_tests {
    use super::expand_env;

    #[test]
    fn expands_braced_var_when_set() {
        std::env::set_var("HY3_EV_SET", "secret123");
        assert_eq!(expand_env("token=${HY3_EV_SET}"), "token=secret123");
        std::env::remove_var("HY3_EV_SET");
    }

    #[test]
    fn preserves_braced_var_when_unset() {
        std::env::remove_var("HY3_EV_MISSING");
        assert_eq!(
            expand_env("token=${HY3_EV_MISSING}"),
            "token=${HY3_EV_MISSING}"
        );
    }

    #[test]
    fn expands_braced_var_embedded_in_url() {
        std::env::set_var("HY3_EV_MODEL", "gpt-4");
        assert_eq!(
            expand_env("https://api.example.com/v1/${HY3_EV_MODEL}/chat"),
            "https://api.example.com/v1/gpt-4/chat"
        );
        std::env::remove_var("HY3_EV_MODEL");
    }

    #[test]
    fn expands_bare_var_when_set() {
        std::env::set_var("HY3_EV_BARE", "val");
        assert_eq!(expand_env("x=$HY3_EV_BARE"), "x=val");
        std::env::remove_var("HY3_EV_BARE");
    }

    #[test]
    fn preserves_bare_var_when_unset_is_symmetric() {
        std::env::remove_var("HY3_EV_BARE2");
        assert_eq!(expand_env("token=$HY3_EV_BARE2"), "token=$HY3_EV_BARE2");
    }

    #[test]
    fn no_dollar_passthrough() {
        assert_eq!(expand_env("plain text no placeholder"), "plain text no placeholder");
    }

    #[test]
    fn mixed_braced_and_literal() {
        std::env::set_var("HY3_EV_MIX", "abc");
        assert_eq!(
            expand_env("pre/${HY3_EV_MIX}/mid/$HY3_EV_MIX/post"),
            "pre/abc/mid/abc/post"
        );
        std::env::remove_var("HY3_EV_MIX");
    }
}
