//! 配置层（从 src/main.rs 拆出，P1 重构）。
//!
//! 承载：配置类型（Config / CodeEvolutionConfig / McpSourceConfig / PersonaConfig）、
//! `${ENV}` 占位展开、运行时解析、agent.toml 读写、启动期 domain/org 注入。
//! 硬约束（P1-4）：存储态 config 保留 `${ENV}` 占位，绝不落盘明文密钥；
//! 运行时展开只作用于 `resolve_config_for_runtime` 的克隆体。

use std::sync::OnceLock;

use agent_core::autonomy_budget::AutonomyBudget;
use agent_core::dept_ops;
use agent_core::llm::{LlmConfig, LlmProvider};
use agent_core::meta_evolve::{MetaEvolutionConfig, SafetyConfig};
use agent_core::mcp_client::McpClient;
use serde::{Deserialize, Serialize};

/// 公司根命名空间（与 agent.toml 的 mcp_source namespace org/ 前缀、Memoria 注册一致）。
/// 改为运行时配置：启动时由 agent.toml `org_company` 注入（默认 cs-pufa-2nd-thermal，行为不变）。
static ORG_COMPANY: OnceLock<String> = OnceLock::new();

/// 取当前公司根标识（未初始化时回退默认，保证测试/旧路径不崩）。
pub(crate) fn org_company() -> &'static str {
    ORG_COMPANY
        .get()
        .map(|s| s.as_str())
        .unwrap_or("cs-pufa-2nd-thermal")
}

/// 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Config {
    pub(crate) agent_id: String,
    /// 领域模式：`solid_waste`（默认，保持固废行为）/ `office` / `general`。
    /// 非 solid_waste 下关闭「固废本部门运维纪律 / 证据门禁 / 部门工具包自动注入」。
    #[serde(default = "default_domain_mode")]
    pub(crate) domain_mode: String,
    /// 公司根标识（命名空间 org/<org_company> 前缀）。默认 cs-pufa-2nd-thermal。
    #[serde(default = "default_org_company")]
    pub(crate) org_company: String,
    #[serde(default)]
    pub(crate) api_key: String,
    #[serde(default = "default_server")]
    pub(crate) server: String,
    #[serde(default = "default_port")]
    pub(crate) port: u16,
    #[serde(default = "default_host")]
    pub(crate) host: String,
    #[serde(default)]
    pub(crate) cors_origins: Vec<String>,
    #[serde(default)]
    pub(crate) memoria_admin_key: String,
    #[serde(default)]
    pub(crate) mcp_source: Vec<McpSourceConfig>,
    #[serde(default)]
    pub(crate) personas: Vec<PersonaConfig>,
    /// 全局 LLM 池（主 + fallbacks）。缺省则回退旧硬编码 deepseek 主 + DOUBAO_API_KEY 备用。
    #[serde(default)]
    pub(crate) llm: Option<LlmConfig>,
    /// PR5：元进化配置（落 [meta_evolution]，缺省全默认：enabled=false）
    #[serde(default)]
    pub(crate) meta_evolution: Option<MetaEvolutionConfig>,
    /// PR5：安全配置（落 [safety]，缺省 ApprovalMode::Auto 免人工审批）
    #[serde(default)]
    pub(crate) safety: Option<SafetyConfig>,
    /// Phase 7：代码自我进化引擎配置（落 [code_evolution]）。缺省全默认：enabled=false（关闭）。
    /// 安全要点：默认 dry_run（只产 diff 不提交）、allow_commit=false（双重闸门）、目标必须在隔离仓库。
    #[serde(default)]
    pub(crate) code_evolution: Option<CodeEvolutionConfig>,
    /// HY3 1.3 三大项热路径接线开关（缺省全 false；G 门未复验前不得开启）
    #[serde(default)]
    pub(crate) features: agent_core::agent::FeatureFlags,
    /// HY3 1.3 LATS 配置（缺省全默认：enabled=false）
    #[serde(default)]
    pub(crate) lats: agent_core::lats::LatsConfig,
    /// HY3 1.3 MultiAgent Compose 配置（缺省全默认：enabled=false）
    #[serde(default)]
    pub(crate) multiagent: agent_core::multiagent::MultiAgentConfig,
    /// HY3 TTC 推理时计算配置（缺省全默认：enabled=false）
    #[serde(default)]
    pub(crate) ttc: agent_core::ttc::TtcConfig,
    /// 摄入侧治本过滤（落 [intake_filter]，缺省全默认：enabled=false，opt-in）
    #[serde(default)]
    pub(crate) intake_filter: Option<agent_core::intake_filter::IntakeFilterConfig>,
    /// ADR-017：LLM 编排层 v2（落 [orchestration]，缺省全默认 OFF，flag-off 零行为变化）
    #[serde(default)]
    pub(crate) orchestration: Option<agent_core::orchestration::OrchestrationConfig>,
    /// 工具分类手动收紧（落 [boundary.tool_overrides]，缺省空）。
    /// 与 register_tool 同语义：learn_tools 刷新不覆盖；进程启动时自动重放，
    /// 使 operator 的 pin 跨重启生效。
    #[serde(default)]
    pub(crate) boundary: Option<BoundaryConfig>,
    /// 分级审批（落 [gateway_approval]，缺省 human_all=现状全人工）
    #[serde(default)]
    pub(crate) gateway_approval: Option<agent_core::gateway_approval::GatewayApprovalConfig>,
    /// P2 服务编排（落 `[[services]]` 表）。缺省空表 = 不接管任何服务，零行为变化。
    /// 该表放在 agent.toml 里（已 gitignore），可写本机绝对路径与端口。
    #[serde(default)]
    pub(crate) services: Vec<agent_core::service_manager::ServiceConfig>,
}

/// 工具分类手动收紧配置（[boundary]）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct BoundaryConfig {
    #[serde(default)]
    pub(crate) tool_overrides: Vec<ToolOverrideItem>,
}

/// 单条手动收紧：tool 名（大小写不敏感，存储侧 canonical 小写）+ 权限级别
/// （仅接受 read/write/dangerous/unknown，非法值启动时告警并跳过）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ToolOverrideItem {
    pub(crate) tool: String,
    pub(crate) level: String,
}

/// Phase 7：代码自我进化引擎配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct CodeEvolutionConfig {
    /// 总开关。缺省 false（关闭）。
    #[serde(default)]
    pub(crate) enabled: bool,
    /// 进化目标源文件路径（必须是隔离仓库内的文件；含 agent-core/memoria 路径的请求会被拒绝）。
    #[serde(default)]
    pub(crate) target_path: Option<String>,
    /// 进化代数预算。缺省 4。
    #[serde(default = "default_evo_gens")]
    pub(crate) generations: usize,
    /// 连续失败/无进展达此数 → 熔断 HARD STOP。缺省 3。
    #[serde(default = "default_evo_circuit")]
    pub(crate) circuit_failures: usize,
    /// 默认 dry_run：true=只产 diff 不提交（人类否决闸门），false=允许在 apply 时提交。
    #[serde(default = "default_true")]
    pub(crate) dry_run_default: bool,
    /// 是否允许真正提交到 git（与请求参数 apply 双重闸门，两者皆 true 才落盘）。缺省 false。
    #[serde(default)]
    pub(crate) allow_commit: bool,
    /// 专用进化密钥（建议走 ${ENV} 注入，如 ${EVOLVE_KEY}）。触发进化必须携带匹配的 `x-evolve-key` 头，
    /// 否则 401；配置为空则 fail-closed 拒绝任何进化请求（P0-1，避免「端口可达即可触发进化」）。
    #[serde(default)]
    pub(crate) evolve_key: Option<String>,
    /// 目标函数名（默认 "fib"）。引擎只改这一个函数，其余（含测试）不动。
    #[serde(default = "default_fn_name")]
    pub(crate) fn_name: String,
    /// 提议用的专属 LLM 配置；缺省空 = 复用全局主 LlmClient。
    #[serde(default)]
    pub(crate) model: Option<LlmConfig>,
    /// 四预算自治封套（P0，借鉴 Prime Agent）。缺省全 0 = 不限制（向后兼容旧配置）。
    #[serde(default)]
    pub(crate) budget: AutonomyBudget,
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
pub(crate) struct McpSourceConfig {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) token: String,
    /// stdio 模式：可执行文件路径
    #[serde(default)]
    pub(crate) command: String,
    /// stdio 模式：命令行参数
    #[serde(default)]
    pub(crate) args: Vec<String>,
    /// 该 MCP 源所属命名空间（可选）。用于按调用者 allowed_ns 过滤可见工具。
    /// 例：`dept/工程部/proj/P1` 仅对该命名空间及其祖先/后代可见；留空=全局可见。
    #[serde(default)]
    pub(crate) namespace: Option<String>,
}

/// Phase 5：配置化分身定义（agent.toml [[personas]] 表）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PersonaConfig {
    /// 分身 id（必填，不得为 "default"）
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) display_name: String,
    /// 拥有者 user_id；缺省用 Config.agent_id
    #[serde(default)]
    pub(crate) owner_user_id: String,
    /// 工具白名单；缺省空 = 不限制
    #[serde(default)]
    pub(crate) tool_allowlist: Vec<String>,
    /// 该分身专属 memory 命名空间；缺省空
    #[serde(default)]
    pub(crate) memory_namespace: String,
    /// 启动即压入的目标栈（goals）
    #[serde(default)]
    pub(crate) goals: Vec<String>,
    /// 该分身专属 LLM 配置；缺省空 = 圆桌/tick 时回退全局 client，并由圆桌自动从 LLM 池分配
    #[serde(default)]
    pub(crate) llm: Option<LlmConfig>,
}

fn default_server() -> String {
    "http://127.0.0.1:9003".to_string()
}

/// Memoria admin 钥匙（运维 `.env` / `MEMORIA_ADMIN_KEY`）。用于 admin 参数与字面 admin 身份。
pub(crate) fn env_memoria_admin_key(fallback: &str) -> String {
    match std::env::var("MEMORIA_ADMIN_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => fallback.to_string(),
    }
}

/// jarvis 专属 badge（`MEMORIA_JARVIS_BADGE`）；与 admin 不得同 token（UNIQUE）。
/// 未设置时回退 `MEMORIA_ADMIN_KEY`（过渡兼容，生产应显式分钥）。
pub(crate) fn env_memoria_jarvis_badge(admin_fallback: &str) -> String {
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
pub(crate) fn memoria_proxy_client(server: &str, admin_fallback: &str) -> McpClient {
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
pub(crate) fn memoria_audit_client(server: &str, admin_fallback: &str) -> McpClient {
    let admin_key = env_memoria_admin_key(admin_fallback);
    if !admin_key.is_empty() {
        return McpClient::new(server, "admin", &admin_key);
    }
    memoria_proxy_client(server, admin_fallback)
}

/// 从 Memoria `register_agent` 响应提取 badge_token（兼容对象 / 字符串两种格式）。
pub(crate) fn extract_register_badge(text: &serde_json::Value) -> Option<String> {
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
pub(crate) fn expand_env(value: &str) -> String {
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
pub(crate) fn expand_config_llm_env(cfg: &mut Config) {
    if let Some(llm) = cfg.llm.as_mut() {
        expand_llm_config(llm);
    }
    for pc in cfg.personas.iter_mut() {
        if let Some(llm) = pc.llm.as_mut() {
            expand_llm_config(llm);
        }
    }
    if let Some(ga) = cfg.gateway_approval.as_mut() {
        if let Some(j) = ga.judge.as_mut() {
            expand_provider(j);
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
#[derive(Debug, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    entries: Vec<RegistryEntry>,
}

#[derive(Debug, Deserialize)]
struct RegistryEntry {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    endpoints: Option<RegistryEndpoints>,
    #[serde(default)]
    lifecycle: Option<RegistryLifecycle>,
}

#[derive(Debug, Deserialize)]
struct RegistryEndpoints {
    #[serde(default)]
    mcp: Option<RegistryMcpEndpoint>,
}

#[derive(Debug, Deserialize)]
struct RegistryMcpEndpoint {
    #[serde(default)]
    transport: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    url: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegistryLifecycle {
    #[serde(default)]
    status: Option<String>,
}

fn registry_status_active(status: &Option<String>) -> bool {
    !matches!(
        status.as_deref().unwrap_or("").trim().to_ascii_lowercase().as_str(),
        "retired" | "disabled" | "archived" | "deleted"
    )
}

/// MCP source 去重键：stdio 取首个脚本参数（如 dashboard_mcp_server.py），
/// 无脚本时取 command；HTTP 取 url。仅做字符串归一用于去重，不用于文件访问。
fn mcp_source_dedup_key(command: &str, args: &[String], url: &str) -> String {
    fn norm(value: &str) -> String {
        value
            .trim_matches('"')
            .trim_matches('\'')
            .to_ascii_lowercase()
            .split(['/', '\\'])
            .collect::<Vec<_>>()
            .join("\\")
    }
    let script = args.iter().find(|a| {
        let l = a.to_ascii_lowercase();
        l.ends_with(".py") || l.ends_with(".exe") || l.ends_with(".cmd") || l.ends_with(".bat")
    });
    if let Some(s) = script {
        return format!("script:{}", norm(s));
    }
    if !command.trim().is_empty() {
        return format!("command:{}", norm(command));
    }
    format!("url:{}", norm(url))
}

/// P3：把平台注册表 `type=mcp` 条目合并进运行时 MCP source 列表。
/// 注册表条目按去重键/名称压过 agent.toml 的同名同源静态配置（agent.toml 保留
/// 作为注册表缺失时的回退，不回写、不落盘）。返回合并条数供启动日志观测。
fn merge_registry_mcp_sources_into(sources: &mut Vec<McpSourceConfig>, registry_text: &str) -> usize {
    let registry: RegistryFile = match serde_json::from_str(registry_text) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target: "agent.config", "PFAiX registry parse failed, keep agent.toml sources: {e}");
            return 0;
        }
    };

    let mut merged: Vec<McpSourceConfig> = Vec::new();
    let mut seen_keys: std::collections::HashSet<String> = Default::default();
    let mut seen_names: std::collections::HashSet<String> = Default::default();
    for entry in registry.entries {
        if entry.kind != "mcp" || !registry_status_active(&entry.lifecycle.and_then(|l| l.status)) {
            continue;
        }
        let Some(mcp) = entry.endpoints.and_then(|e| e.mcp) else {
            continue;
        };
        let transport = mcp.transport.trim().to_ascii_lowercase();
        let src = match transport.as_str() {
            "stdio" if !mcp.command.trim().is_empty() => McpSourceConfig {
                name: entry.id.clone(),
                url: String::new(),
                token: mcp.token.clone(),
                command: mcp.command.clone(),
                args: mcp.args.clone(),
                namespace: mcp.namespace.clone(),
            },
            "http" | "sse" if !mcp.url.trim().is_empty() => McpSourceConfig {
                name: entry.id.clone(),
                url: mcp.url.clone(),
                token: mcp.token.clone(),
                command: String::new(),
                args: Vec::new(),
                namespace: mcp.namespace.clone(),
            },
            _ => continue,
        };
        let key = mcp_source_dedup_key(&src.command, &src.args, &src.url);
        if seen_keys.contains(&key) || seen_names.contains(&src.name) {
            tracing::warn!(target: "agent.config", "PFAiX registry duplicate mcp entry skipped: {}", src.name);
            continue;
        }
        seen_keys.insert(key);
        seen_names.insert(src.name.clone());
        merged.push(src);
    }

    let registry_keys: std::collections::HashSet<String> = merged
        .iter()
        .map(|s| mcp_source_dedup_key(&s.command, &s.args, &s.url))
        .collect();
    let registry_names: std::collections::HashSet<String> =
        merged.iter().map(|s| s.name.to_ascii_lowercase()).collect();
    sources.retain(|s| {
        let key = mcp_source_dedup_key(&s.command, &s.args, &s.url);
        !registry_keys.contains(&key) && !registry_names.contains(&s.name.to_ascii_lowercase())
    });
    let count = merged.len();
    sources.extend(merged);
    count
}

/// 注册表只读路径固定在用户 profile 下的 pfaix-platform 目录，且拒绝包含
/// 上跳分量，避免把配置读取指到允许目录之外的文件。
/// SCM LocalSystem 部署下 USERPROFILE 指向 systemprofile（用户目录不可达，
/// 2026-10-25 实证：注册表 MCP 加载一直静默失败）——PFAIX_REGISTRY 显式
/// 覆盖优先（agent-core.env 注入，该文件 ACL 仅 user/SYSTEM/Admins）。
fn registry_file_path() -> Option<std::path::PathBuf> {
    let resolve = |path: std::path::PathBuf| -> Option<std::path::PathBuf> {
        let normalized = std::fs::canonicalize(&path).ok()?;
        let parent = normalized.parent()?.to_path_buf();
        let normalized_base = std::fs::canonicalize(&parent).ok()?;
        if normalized.parent() != Some(normalized_base.as_path()) {
            return None;
        }
        Some(normalized)
    };
    if let Ok(v) = std::env::var("PFAIX_REGISTRY") {
        let v = v.trim();
        if !v.is_empty() && !v.contains("..") {
            // 覆盖值可为 apps.json 文件或其父目录
            let p = std::path::PathBuf::from(v);
            let file = if p.extension().map(|e| e == "json").unwrap_or(false) {
                p
            } else {
                p.join("apps.json")
            };
            return resolve(file);
        }
    }
    let home = std::env::var("USERPROFILE").ok()?;
    if home.trim().is_empty() || home.contains("..") {
        return None;
    }
    resolve(std::path::Path::new(&home).join("pfaix-platform").join("apps.json"))
}

fn merge_registry_mcp_sources(cfg: &mut Config) -> usize {
    let Some(path) = registry_file_path() else {
        tracing::warn!(target: "agent.config", "PFAiX registry path unavailable, keep agent.toml sources");
        return 0;
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => merge_registry_mcp_sources_into(&mut cfg.mcp_source, &text),
        Err(e) => {
            tracing::warn!(target: "agent.config", "PFAiX registry unavailable ({}: {e}), keep agent.toml sources", path.display());
            0
        }
    }
}

pub(crate) fn resolve_config_for_runtime(cfg: &Config) -> Config {
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
    // P3：项目 MCP source 以平台注册表为权威；agent.toml 仅保留内置/回退源。
    // 测试二进制默认关闭（避免单测意外挂真实项目进程），可用 PFAIX_REGISTRY_MCP=1 显式开启。
    let registry_enabled = !cfg!(test)
        && std::env::var("PFAIX_REGISTRY_MCP")
            .map(|v| v != "0")
            .unwrap_or(true);
    let merged = if registry_enabled {
        merge_registry_mcp_sources(&mut r)
    } else {
        0
    };
    if merged > 0 {
        tracing::info!(target: "agent.config", "PFAiX registry merged {merged} mcp source(s) at runtime");
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
    pub(crate) fn configured(&self) -> bool {
        if self.agent_id.is_empty() {
            return false;
        }
        if !expand_env(&self.api_key).is_empty() {
            return true;
        }
        std::env::var("AGENT_API_KEY")
            .map(|k| !k.is_empty())
            .unwrap_or(false)
    }
}

/// 取当前系统用户名（用于缺省 agent_id / 日志归属；跨平台 USERNAME / USER）。
pub(crate) fn whoami() -> Option<String> {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .ok()
}

pub(crate) fn config_path() -> String {
    std::env::current_dir()
        .unwrap_or_default()
        .join("agent.toml")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn load_or_create_config() -> Config {
    let path = config_path();
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(cfg) = toml::from_str::<Config>(&text) {
            // P1-4 修复：load 阶段不再原地展开 ${ENV} 占位符。
            // 存储态（AppState.config）始终保留占位符，save 时不会把 ${AGENT_API_KEY} 回写成明文。
            // 运行时展开交由 resolve_config_for_runtime（克隆后展开），见 build_agent 调用点。
            init_domain_and_org(&cfg);
            // 预算配置一致性校验（第十二轮 bug·medium）：continuation 窗口/次数不配对
            // 在启动时显式告警，而非运行期静默（validate 仅在测试调用过）
            if let Some(me) = &cfg.meta_evolution {
                if let Err(e) = me.budget.validate() {
                    tracing::warn!(target: "agent.meta_evolve", "meta_evolution {}", e);
                }
            }
            if let Some(ce) = &cfg.code_evolution {
                if let Err(e) = ce.budget.validate() {
                    tracing::warn!(target: "agent.code_evolve", "code_evolution {}", e);
                }
            }
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
        orchestration: None,
        boundary: None,
        gateway_approval: None,
        services: Vec::new(),
    };
    init_domain_and_org(&cfg);
    let _ = std::fs::write(&path, toml::to_string_pretty(&cfg).unwrap_or_default());
    cfg
}

pub(crate) fn save_config(cfg: &Config) {
    let path = config_path();
    let _ = std::fs::write(&path, toml::to_string_pretty(cfg).unwrap_or_default());
}

/// 启动时把配置里的 domain_mode / org_company 注入全局（dept_ops 门禁、命名空间判定读取）。
fn init_domain_and_org(cfg: &Config) {
    dept_ops::init_domain_mode(dept_ops::DomainMode::from_str(&cfg.domain_mode));
    dept_ops::init_org_ns(&cfg.org_company);
    let _ = ORG_COMPANY.set(cfg.org_company.clone());
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
        assert_eq!(
            expand_env("plain text no placeholder"),
            "plain text no placeholder"
        );
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

#[cfg(test)]
mod registry_mcp_tests {
    use super::*;

    fn static_src(name: &str, command: &str, args: &[&str]) -> McpSourceConfig {
        McpSourceConfig {
            name: name.to_string(),
            url: String::new(),
            token: String::new(),
            command: command.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            namespace: None,
        }
    }

    #[test]
    fn registry_sources_override_duplicates_and_add_projects() {
        let mut sources = vec![
            static_src("dashboard", "C:/Python314/python.exe", &["C:\\Users\\user\\dashboard\\dashboard_mcp_server.py"]),
            static_src("fsutil", "C:/Python314/python.exe", &["C:\\Users\\user\\office-tools\\office_mcp_server.py"]),
        ];
        let registry = r#"{
          "entries": [
            {"id":"solid-waste","type":"mcp","endpoints":{"mcp":{"transport":"stdio","command":"C:/Python314/python.exe","args":["C:/Users/user/dashboard/dashboard_mcp_server.py"],"namespace":"org/test"}}},
            {"id":"data-pipeline","type":"mcp","endpoints":{"mcp":{"transport":"stdio","command":"C:/Python314/python.exe","args":["C:/Users/user/hhv-model/scripts/pipeline_mcp.py"]}}}
          ]
        }"#;
        let merged = merge_registry_mcp_sources_into(&mut sources, registry);
        assert_eq!(merged, 2);
        let names: Vec<&str> = sources.iter().map(|s| s.name.as_str()).collect();
        assert!(!names.contains(&"dashboard"), "注册表 solid-waste 应压过 agent.toml 的同源 dashboard");
        assert!(names.contains(&"fsutil"), "内置源不应被注册表误删");
        assert!(names.contains(&"solid-waste"));
        assert!(names.contains(&"data-pipeline"));
        assert_eq!(
            sources.iter().find(|s| s.name == "solid-waste").and_then(|s| s.namespace.as_deref()),
            Some("org/test")
        );
    }

    #[test]
    fn registry_retired_and_non_mcp_entries_are_ignored() {
        let mut sources = vec![static_src("fsutil", "C:/Python314/python.exe", &["office.py"])];
        let registry = r#"{
          "entries": [
            {"id":"retired-project","type":"mcp","lifecycle":{"status":"retired"},"endpoints":{"mcp":{"transport":"stdio","command":"x.exe"}}},
            {"id":"some-app","type":"app"}
          ]
        }"#;
        let merged = merge_registry_mcp_sources_into(&mut sources, registry);
        assert_eq!(merged, 0);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].name, "fsutil");
    }
}

#[cfg(test)]
mod budget_serde_tests {
    use super::*;

    #[test]
    fn code_evolution_config_missing_budget_parses() {
        // 向后兼容：旧配置无 budget 字段仍可解析（默认全 0 = 不限制）。
        // 注意：直接反序列化 CodeEvolutionConfig 时 TOML 键在顶层（无 [code_evolution] 前缀，
        // 该前缀由 Config 顶层消费）。
        let toml = r#"
enabled = true
generations = 4
circuit_failures = 3
dry_run_default = true
allow_commit = false
fn_name = "fib"
"#;
        let cfg: CodeEvolutionConfig = toml::from_str(toml).expect("缺 budget 字段应可解析");
        assert!(cfg.budget.is_unset(), "缺省 budget 应为不限制");
        assert_eq!(cfg.generations, 4);
    }

    #[test]
    fn code_evolution_config_budget_parses() {
        // 直接反序列化 CodeEvolutionConfig：budget 为嵌套子表 [budget]
        let toml = r#"
enabled = true
[budget]
max_turns = 8
max_tokens = 200000
max_wall_clock_secs = 300
max_continuations_per_window = 0
continuation_window_secs = 3600
gate_command = "cargo test"
"#;
        let cfg: CodeEvolutionConfig = toml::from_str(toml).expect("嵌套 budget 应可解析");
        assert_eq!(cfg.budget.max_turns, 8);
        assert_eq!(cfg.budget.max_tokens, 200_000);
        assert_eq!(cfg.budget.max_wall_clock_secs, 300);
        assert_eq!(cfg.budget.gate_command.as_deref(), Some("cargo test"));
        assert!(!cfg.budget.is_unset());
    }

    #[test]
    fn config_top_level_with_nested_budget_parses() {
        // 真实场景：agent.toml 顶层 [code_evolution.budget] 经 Config 解析后正确落到
        // CodeEvolutionConfig.budget（验证完整链路，非仅孤立结构）
        let toml = r#"
agent_id = "test"
[code_evolution]
enabled = true
[code_evolution.budget]
max_turns = 8
max_wall_clock_secs = 300
"#;
        let cfg: Config = toml::from_str(toml).expect("完整 Config 应可解析");
        let ce = cfg.code_evolution.expect("code_evolution 应存在");
        assert_eq!(ce.budget.max_turns, 8, "经 Config 嵌套解析后 max_turns 应为 8");
        assert_eq!(ce.budget.max_wall_clock_secs, 300);
    }

    #[test]
    fn meta_evolution_config_missing_budget_parses() {
        let toml = r#"
enabled = false
window_days = 30
min_samples = 20
"#;
        let cfg: MetaEvolutionConfig = toml::from_str(toml).expect("缺 budget 字段应可解析");
        assert!(cfg.budget.is_unset());
        assert_eq!(cfg.min_samples, 20);
    }
}
