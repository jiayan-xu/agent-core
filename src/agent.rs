//! Agent 核心 — chat 循环 + 工具执行

use chrono::Datelike;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::approval::ApprovalManager;
use crate::audit::{new_trace_id, AuditLogger};
use crate::boundary::prompt_injection::{PromptInjectionDetector, ThreatLevel};
use crate::boundary::{self, BlockLevel, ComplianceBoundary, PermissionLevel};
use crate::checkpoint::{CheckpointState, CheckpointStore};
use crate::degrade::{DegradeMode, DegradeMonitor, UNHEALTHY_THRESHOLD};
use crate::harness::{self, ExecutionLog, HarnessStore};
use crate::llm::{LlmClient, LlmConfig, Message, ToolDef};
use crate::mcp_client::{McpClient, McpSource};
use crate::namespace::NamespaceRegistry;
use crate::quota::NsQuotaStore;
use crate::session::{PendingAction, SessionManager, SessionState};
use std::collections::HashMap;

/// Agent 身份
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub namespace: String,
    pub badge_token: String,
    /// 多租户层级命名空间完整路径（如 `/dept/运营部/project/固废平台`）
    /// 为 None 时保持旧行为：`agent/{agent_id}`
    pub ns_full_path: Option<String>,
    /// 分身维度字段（Phase 1）—— 可选/可空，不影响旧单 agent 行为
    pub persona_id: Option<String>,
    pub owner_user_id: Option<String>,
    pub workspace_dir: Option<std::path::PathBuf>,
    pub tool_allowlist: Vec<String>,
    pub memory_namespace: Option<String>,
}

impl AgentIdentity {
    pub fn ns(&self) -> String {
        match &self.ns_full_path {
            Some(path) => {
                let flat = path.trim_start_matches('/');
                format!("agent/{}/{}", self.agent_id, flat)
            }
            None => format!("agent/{}", self.agent_id),
        }
    }

    /// 获取纯 namespace 路径（不含 agent/ 前缀）
    pub fn ns_path(&self) -> Option<&str> {
        self.ns_full_path.as_deref()
    }
}

/// Agent 配置
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub identity: AgentIdentity,
    pub llm: LlmConfig,
    pub memoria_url: String,
    /// 可选 MCP 源（名称 + URL + 令牌 + 可选的 stdio (命令, 参数) + 可选的命名空间），
    /// 例 HTTP:  [("dashboard", "http://127.0.0.1:8000", "", None, Some("dept/工程部/proj/P1".into()))]
    /// 例 stdio: [("dashboard", "", "", Some(("python".into(), ["-m","mcp_server"].map(String::from).to_vec())), None)]
    pub additional_mcp: Vec<(
        String,
        String,
        String,
        Option<(String, Vec<String>)>,
        Option<String>,
    )>,
    pub skill_whitelist: Option<Vec<String>>,
    pub max_tool_rounds: u32,
    pub parent_permission: PermissionLevel,
    /// 启用组合路由（多 Skill 分解 + 按序执行）
    pub enable_compositional_routing: bool,
    /// P1-2: 组合计划预览（HITL）。企业默认 true：多步计划先返回预览，用户确认后才执行。
    pub compositional_preview: bool,
    /// P1-4: 工具参数 JSON Schema 严格校验。true=校验失败直接报错；false=回灌 LLM 让其修正。
    pub strict_schema: bool,
    /// P2-3: 自定义 system prompt 模板（可选）
    /// 如果为 None，使用内置默认模板
    pub system_prompt_template: Option<String>,
    /// P2-D: 审批人 ID（可选）。设置后 YELLOW 工具需经此人审批
    pub approver_id: Option<String>,
    /// PR5: 元进化配置（默认 enabled=false，受控开启）
    pub meta_evolution: crate::meta_evolve::MetaEvolutionConfig,
    /// PR5: 安全配置（含审批门控模式，默认 Auto 免人工审批）
    pub safety: crate::meta_evolve::SafetyConfig,
}

/// 白龙马 A3：Focus Stack → Thread 模型
/// 一个「话题线程（episode）」归档条目。当前焦点任务被切换时，压缩结论后
/// 软隐藏进 Memoria（tags=["focus_conclusion","absorbed:<sid>"]）+ 本地索引，
/// 切回时由 recall 召回结论注入，避免长上下文被旧话题撑爆。
#[derive(Debug, Clone)]
pub struct EpisodeArchive {
    /// 话题稳定键（首条用户消息归一化）
    pub topic_key: String,
    /// 原始首条用户消息（预览）
    pub first_message: String,
    /// LLM 压缩后的结论（一句话到一段）
    pub conclusion: String,
    /// 写入 Memoria 的记忆 id（若写入成功）
    pub memory_id: Option<String>,
    /// 归档时间戳（秒）
    pub archived_at: i64,
}

/// Agent 核心
pub struct AgentCore {
    pub config: AgentConfig,
    pub mcp: McpClient,              // Memoria MCP（主）
    pub mcp_sources: Vec<McpSource>, // 全部 MCP 源（含 Memoria）
    pub llm: LlmClient,
    pub boundary: Arc<Mutex<ComplianceBoundary>>,
    pub harness: Arc<Mutex<HarnessStore>>,
    /// 执行日志（用于 distill）
    pub execution_log: Arc<Mutex<Vec<ExecutionLog>>>,
    /// 收件箱缓存
    inbox_cache: tokio::sync::Mutex<InboxCache>,
    /// 会话管理器
    pub session_manager: SessionManager,
    /// 审计日志记录器
    pub audit_logger: AuditLogger,
    /// 工具路由缓存（P1-3 修复：精确匹配而非 starts_with）
    /// tool_name → MCP 源索引
    tool_route_cache: tokio::sync::Mutex<HashMap<String, usize>>,
    /// 多租户命名空间注册表（P2-C）
    pub namespace_registry: std::sync::Mutex<NamespaceRegistry>,
    /// 审批管理器（P2-D）
    pub approval_manager: ApprovalManager,
    /// P1-1: 控制面 checkpoint 持久化（会话 / 计划 / 审批可续跑）
    pub checkpoint_store: Arc<tokio::sync::Mutex<CheckpointStore>>,
    /// P1-1: 进行中的组合计划（崩溃续跑起点）
    in_progress_plan: Arc<Mutex<Option<crate::composer::ExecutionPlan>>>,
    /// P1-1: 已完成的步骤结果（崩溃后续跑起点）
    in_progress_step_results: Arc<Mutex<HashMap<u32, String>>>,
    /// P1-5: 降级收缩监视器（MCP 源健康 + Kill switch + 模式推导）
    pub degrade: Arc<DegradeMonitor>,
    /// P2-1: 命名空间级配额与成本（tool 轮次 / 日 token 预算 / 并发会话）
    pub quota: Arc<std::sync::Mutex<NsQuotaStore>>,
    /// 白龙马 A3: Focus Stack → Thread 模型 —— 已归档话题（episode）软隐藏索引
    /// key = topic_key；value = 归档元数据。切回时由 recall_episode_for 召回结论注入。
    pub episode_archive: Arc<tokio::sync::Mutex<HashMap<String, EpisodeArchive>>>,
    /// 白龙马 Phase C: 条件式本地资源门控 —— 启动扫描的只读资源快照（ssh/git 元数据）。
    /// 仅当用户消息命中资源规则时由 execute_chat / rephrase_and_confirm 注入 system prompt，
    /// 零常态泄露面、零 prompt 膨胀（见 resources.rs 安全红线）。
    pub local_resources: crate::resources::SharedResourceSnapshot,
    /// 多分身容器（Phase 1）：persona_id → Persona；默认含 "default" 分身
    pub personas: std::sync::Mutex<std::collections::HashMap<String, crate::runtime::self_runtime::Persona>>,
    /// Phase 2：会话 → 分身 绑定（分身级工具白名单接线）
    pub session_personas: std::sync::Mutex<std::collections::HashMap<String, String>>,
    /// Phase 2：分身 tick 调度器注册表（真实 tick 由 AgentCore 驱动，避免循环依赖）
    pub tick_scheduler: crate::scheduler::tick_scheduler::TickScheduler,
    /// PR5: 审批闸门（P-D 门控；默认 Auto 免人工审批，分类逻辑保留）
    pub approval_gate: crate::meta_evolve::ApprovalGate,
    /// PR5: 元进化引擎（L2 闭环；默认 enabled=false）
    pub meta_evolver: crate::meta_evolve::MetaEvolver,
    /// PR5: 机制账本存储（evolution_feedback + meta_prompt），与 meta_evolver 共享
    pub meta_store: std::sync::Arc<tokio::sync::Mutex<crate::meta_evolve::MetaEvolutionStore>>,
}

/// P2-1: 会话级配额守卫（RAII）。离开作用域自动 leave_session，避免并发计数泄漏。
struct SessionQuotaGuard {
    quota: Arc<std::sync::Mutex<NsQuotaStore>>,
    ns: String,
}
impl Drop for SessionQuotaGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.quota.lock() {
            s.leave_session(&self.ns);
        }
    }
}

struct InboxCache {
    data: Option<Vec<serde_json::Value>>,
    expires_at: f64,
}

impl InboxCache {
    fn new() -> Self {
        InboxCache {
            data: None,
            expires_at: 0.0,
        }
    }
    fn is_fresh(&self) -> bool {
        let now = now_secs();
        self.data.is_some() && now < self.expires_at
    }
}

/// Phase 6：圆桌结果
pub struct RoundtableResult {
    /// 各分身立场：(persona_id, stance)
    pub stances: Vec<(String, String)>,
    /// 主席收敛结论
    pub consensus: String,
}

impl AgentCore {
    /// 创建 Agent 核心
    pub fn new(
        config: AgentConfig,
        harness: HarnessStore,
        checkpoint: CheckpointStore,
        local_resources: crate::resources::SharedResourceSnapshot,
    ) -> Self {
        let mcp = McpClient::new(
            &config.memoria_url,
            &config.identity.agent_id,
            &config.identity.badge_token,
        );
        // 构建 MCP 源列表（Memoria 始终为第一个源）
        let mut mcp_sources = vec![McpSource::memoria(mcp.clone())];
        for (name, url, token, stdio_opt, src_ns) in &config.additional_mcp {
            if let Some((cmd, args)) = stdio_opt {
                let client = McpClient::new_stdio(cmd, args);
                mcp_sources.push(McpSource::new(name, client, src_ns.clone()));
            } else {
                let badge = if token.is_empty() {
                    &config.identity.badge_token
                } else {
                    token
                };
                let client = McpClient::new(url, &config.identity.agent_id, badge);
                mcp_sources.push(McpSource::new(name, client, src_ns.clone()));
            }
        }
        // P1-5: 为每个 MCP 源注册健康槽位（memoria 也纳入，便于统一观测）
        let degrade = Arc::new(DegradeMonitor::new());
        for src in &mcp_sources {
            degrade.register_source(&src.name);
        }
        // Kill switch 初始态：环境变量 AGENT_KILL_SWITCH=1/true 时启动即开
        let kill_at_start = matches!(
            std::env::var("AGENT_KILL_SWITCH").ok().as_deref(),
            Some("1") | Some("true") | Some("on")
        );
        if kill_at_start {
            degrade.set_kill_switch(true);
        }
        let llm = LlmClient::new(config.llm.clone());
        let boundary = ComplianceBoundary::new(config.skill_whitelist.clone());
        // 注册 agent 自身到权限链（锁中毒时跳过）
        match boundary.perm_chain.lock() {
            Ok(mut chain) => {
                chain.register(&config.identity.agent_id, None, PermissionLevel::Write);
            }
            Err(_) => tracing::error!("PermissionChain Mutex 中毒，跳过注册"),
        }

        let mcp_for_audit = mcp.clone();

        // PR5: 审批闸门 + 元进化引擎（机制账本落 agent-core 本地 rusqlite）
        let approval_gate = crate::meta_evolve::ApprovalGate::from_safety(
            &config.safety,
            std::env::var("APPROVER").ok().filter(|s| !s.is_empty()),
        );
        let cwd = std::env::current_dir().unwrap_or_default();
        let meta_store = {
            let db_path = cwd.join("meta_evolution.db").to_string_lossy().to_string();
            match crate::meta_evolve::MetaEvolutionStore::open(&db_path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(target: "agent.meta_evolve", "机制账本打开失败，回退内存模式: {}", e);
                    crate::meta_evolve::MetaEvolutionStore::open_memory()
                        .unwrap_or_else(|e2| panic!("meta_evolution 内存库也无法打开: {}", e2))
                }
            }
        };
        let meta_store = std::sync::Arc::new(tokio::sync::Mutex::new(meta_store));
        let meta_evolver = crate::meta_evolve::MetaEvolver::new(
            config.meta_evolution.clone(),
            meta_store.clone(),
            llm.clone(),
            config.memoria_url.clone(),
            config.identity.agent_id.clone(),
        );

        let default_persona = crate::runtime::self_runtime::Persona {
            persona_id: "default".to_string(),
            display_name: "默认分身".to_string(),
            owner_user_id: config.identity.agent_id.clone(),
            workspace_dir: None,
            tool_allowlist: Vec::new(),
            memory_namespace: String::new(),
            badge_token: config.identity.badge_token.clone(),
            ns_full_path: config.identity.ns_full_path.clone(),
            llm: None,
        };
        AgentCore {
            config,
            mcp,
            mcp_sources,
            llm,
            boundary: Arc::new(Mutex::new(boundary)),
            harness: Arc::new(Mutex::new(harness)),
            execution_log: Arc::new(Mutex::new(Vec::new())),
            inbox_cache: tokio::sync::Mutex::new(InboxCache::new()),
            session_manager: SessionManager::new(),
            audit_logger: AuditLogger::new(mcp_for_audit),
            tool_route_cache: tokio::sync::Mutex::new(HashMap::new()),
            namespace_registry: std::sync::Mutex::new(NamespaceRegistry::new()),
            approval_manager: ApprovalManager::new(),
            checkpoint_store: Arc::new(tokio::sync::Mutex::new(checkpoint)),
            in_progress_plan: Arc::new(Mutex::new(None)),
            in_progress_step_results: Arc::new(Mutex::new(HashMap::new())),
            degrade,
            quota: Arc::new(std::sync::Mutex::new(NsQuotaStore::new())),
            episode_archive: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            local_resources,
            personas: std::sync::Mutex::new({
                let mut m = std::collections::HashMap::new();
                m.insert("default".to_string(), default_persona);
                m
            }),
            session_personas: std::sync::Mutex::new(std::collections::HashMap::new()),
            tick_scheduler: crate::scheduler::tick_scheduler::TickScheduler::default(),
            approval_gate,
            meta_evolver,
            meta_store,
        }
    }

    /// 取分身；缺省回退到 "default" 分身，保证旧调用兼容
    pub fn get_persona(&self, id: &str) -> crate::runtime::self_runtime::Persona {
        let map = self.personas.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(p) = map.get(id) {
            return p.clone();
        }
        map.get("default").cloned().unwrap_or_else(|| crate::runtime::self_runtime::Persona {
            persona_id: "default".to_string(),
            display_name: "默认分身".to_string(),
            owner_user_id: self.config.identity.agent_id.clone(),
            workspace_dir: None,
            tool_allowlist: Vec::new(),
            memory_namespace: String::new(),
            badge_token: self.config.identity.badge_token.clone(),
            ns_full_path: self.config.identity.ns_full_path.clone(),
            llm: None,
        })
    }

    /// Phase 1：分身级工具白名单校验。allowlist 为空 = 不限制（沿用 boundary 全局策略）
    pub fn check_persona_tool(&self, persona_id: &str, tool_name: &str) -> Result<(), String> {
        let p = self.get_persona(persona_id);
        if p.tool_allowlist.is_empty() {
            return Ok(());
        }
        if p.tool_allowlist.iter().any(|t| t == tool_name) {
            Ok(())
        } else {
            Err(format!(
                "🛡️ 分身『{}』无权调用工具『{}』（不在其白名单内）",
                persona_id, tool_name
            ))
        }
    }

    /// Phase 2：绑定会话到分身（缺省回退 "default"）
    pub fn bind_session_persona(&self, session_id: &str, persona_id: &str) {
        let mut m = self.session_personas.lock().unwrap_or_else(|p| p.into_inner());
        m.insert(session_id.to_string(), persona_id.to_string());
    }

    /// Phase 2：解析会话所属分身（缺省 "default"）
    pub fn persona_for_session(&self, session_id: &str) -> String {
        let m = self.session_personas.lock().unwrap_or_else(|p| p.into_inner());
        m.get(session_id).cloned().unwrap_or_else(|| "default".to_string())
    }

    /// Phase 2：分身真实 tick —— 用该分身目标驱动一次真实 LLM 调用（仅规划，不执行工具）
    pub async fn run_persona_tick(&self, rt: &crate::runtime::self_runtime::SelfRuntime) -> String {
        let goal = rt.goal_stack.last().cloned().unwrap_or_else(|| "（无目标）".to_string());
        let prompt = format!(
            "[分身 {}] 本轮 tick 目标：{}\n请以一句话简述你下一步会做什么（仅规划，不执行工具）。",
            rt.persona.persona_id, goal
        );
        let msg = crate::llm::Message {
            role: "user".to_string(),
            content: Some(prompt),
            tool_calls: None,
            tool_call_id: None,
        };
        // 优先用分身专属 LLM，否则回退全局 client
        let client = rt.persona.llm.as_ref().unwrap_or(&self.llm);
        match client.chat(&[msg], &[]).await {
            Ok(r) => r.text,
            Err(e) => format!("[{}] tick LLM 调用失败: {}", rt.persona.persona_id, e),
        }
    }

    /// Phase 3：并发遍历已注册分身，对每个非 Sleeping 分身并发跑一次真实 tick（返回 (persona_id, 文本)）
    pub async fn persona_tick_all(&self) -> Vec<(String, String)> {
        // 确保 default 分身始终在场（显式注册的其他分身不影响 default）
        if !self.tick_scheduler.contains("default") {
            let p = self.get_persona("default");
            self.tick_scheduler.register(crate::runtime::self_runtime::SelfRuntime::new(p));
        }
        let rts = self.tick_scheduler.non_sleeping_runtimes();
        let futures = rts.iter().map(|rt| {
            let id = rt.persona.persona_id.clone();
            async move {
                let line = self.run_persona_tick(rt).await;
                (id, line)
            }
        });
        futures::future::join_all(futures).await
    }

    /// Phase 3：运行时创建一个新分身，并注册进 tick 调度器
    pub fn create_persona(
        &self,
        persona_id: &str,
        display_name: &str,
        owner_user_id: &str,
        tool_allowlist: Vec<String>,
        memory_namespace: String,
        llm: Option<LlmConfig>,
    ) -> Result<(), String> {
        if persona_id == "default" {
            return Err("default 分身不可重建".to_string());
        }
        let llm_client = llm.map(LlmClient::new);
        let persona = crate::runtime::self_runtime::Persona {
            persona_id: persona_id.to_string(),
            display_name: display_name.to_string(),
            owner_user_id: owner_user_id.to_string(),
            workspace_dir: None,
            tool_allowlist,
            memory_namespace: memory_namespace.clone(),
            badge_token: self.config.identity.badge_token.clone(),
            ns_full_path: self.config.identity.ns_full_path.clone(),
            llm: llm_client,
        };
        let mut m = self.personas.lock().unwrap_or_else(|p| p.into_inner());
        m.insert(persona_id.to_string(), persona.clone());
        drop(m);
        self.tick_scheduler.register(crate::runtime::self_runtime::SelfRuntime::new(persona));
        Ok(())
    }

    /// Phase 3：列出所有已注册分身
    pub fn list_personas(&self) -> Vec<crate::runtime::self_runtime::Persona> {
        let m = self.personas.lock().unwrap_or_else(|p| p.into_inner());
        m.values().cloned().collect()
    }

    /// Phase 3：删除一个分身（default 不可删）
    pub fn remove_persona(&self, persona_id: &str) -> Result<(), String> {
        if persona_id == "default" {
            return Err("default 分身不可删除".to_string());
        }
        let mut m = self.personas.lock().unwrap_or_else(|p| p.into_inner());
        m.remove(persona_id);
        drop(m);
        self.tick_scheduler.unregister(persona_id);
        Ok(())
    }

    /// Phase 4：给分身压入一个目标（驱动真实 tick）
    pub fn push_persona_goal(&self, persona_id: &str, goal: &str) -> Result<(), String> {
        {
            let m = self.personas.lock().unwrap_or_else(|p| p.into_inner());
            if !m.contains_key(persona_id) {
                return Err(format!("分身『{}』不存在", persona_id));
            }
        }
        self.tick_scheduler.push_goal(persona_id, goal);
        Ok(())
    }

    /// Phase 4：取分身当前目标栈
    pub fn get_persona_goals(&self, persona_id: &str) -> Vec<String> {
        self.tick_scheduler.goals_of(persona_id)
    }

    /// Phase 6：构造 LLM 池 = 全局主 + 所有 fallbacks（failover 不变，仅用于圆桌轮询分配）
    pub fn llm_pool(&self) -> Vec<LlmConfig> {
        let mut pool = vec![self.config.llm.clone()];
        let base = &self.config.llm;
        for fb in &base.fallbacks {
            pool.push(LlmConfig {
                base_url: fb.base_url.clone(),
                model: fb.model.clone(),
                api_key: fb.api_key.clone(),
                chat_path: fb.chat_path.clone(),
                max_tokens: base.max_tokens,
                temperature: base.temperature,
                fallbacks: vec![],
            });
        }
        pool
    }

    /// Phase 6：圆桌 —— 单个分身就议题发表立场（供 run_roundtable / SSE 流式复用）
    pub async fn persona_stance(
        &self,
        p: &crate::runtime::self_runtime::Persona,
        topic: &str,
        index: usize,
        pool: &[LlmConfig],
    ) -> (String, String, String) {
        let (client, provider_label) = match &p.llm {
            Some(c) => (c.clone(), "persona-configured".to_string()),
            None => {
                let cfg = &pool[index % pool.len()];
                (LlmClient::new(cfg.clone()), cfg.model.clone())
            }
        };
        tracing::info!(persona = %p.persona_id, provider = %provider_label, "roundtable: 分配 LLM");
        let sys = format!(
            "你是分身『{}』（{}）。请从你的角色视角独立发表观点，不要附和他人。",
            p.persona_id, p.display_name
        );
        let user = format!("圆桌议题：{}\n请给出你的立场（2-4 句）。", topic);
        let msgs = vec![
            crate::llm::Message { role: "system".to_string(), content: Some(sys), tool_calls: None, tool_call_id: None },
            crate::llm::Message { role: "user".to_string(), content: Some(user), tool_calls: None, tool_call_id: None },
        ];
        // 逐调用硬性超时：避免单个 provider 卡死（如重试退避叠加）拖垮整场圆桌。
        // 超时则该席返回占位立场，圆桌继续收敛，不让一个坏模型阻断其余模型。
        let stance = match tokio::time::timeout(std::time::Duration::from_secs(45), client.chat(&msgs, &[])).await {
            Ok(Ok(r)) => r.text,
            Ok(Err(e)) => format!("(LLM 调用失败: {})", e),
            Err(_) => "(该分身 LLM 调用超时，已跳过其立场)".to_string(),
        };
        (p.persona_id.clone(), stance, provider_label)
    }

    /// Phase 6：主席收敛共识
    pub async fn chair_consensus(
        &self,
        topic: &str,
        stances: &[(String, String)],
        chair_persona: Option<&str>,
    ) -> String {
        let chair_id = chair_persona.unwrap_or("default").to_string();
        let joined = stances
            .iter()
            .map(|(id, s)| format!("【{}】{}", id, s))
            .collect::<Vec<_>>()
            .join("\n");
        let sys_chair = format!("你是圆桌主席（{}）。请综合各方立场，给出一句话共识结论。", chair_id);
        let user_chair = format!("议题：{}\n各方立场：\n{}\n\n请给出共识结论。", topic, joined);
        let chair_msgs = vec![
            crate::llm::Message { role: "system".to_string(), content: Some(sys_chair), tool_calls: None, tool_call_id: None },
            crate::llm::Message { role: "user".to_string(), content: Some(user_chair), tool_calls: None, tool_call_id: None },
        ];
        // 同样加硬性超时，避免主席收敛被全局 LLM 卡死。
        match tokio::time::timeout(std::time::Duration::from_secs(45), self.llm.chat(&chair_msgs, &[])).await {
            Ok(Ok(r)) => r.text,
            Ok(Err(e)) => format!("(主席收敛失败: {})", e),
            Err(_) => "(主席收敛超时)".to_string(),
        }
    }

    /// Phase 6：圆桌 —— 多分身就同一议题发表立场并收敛（收集式，供非流式调用 / tests）
    pub async fn run_roundtable(&self, topic: &str, chair_persona: Option<&str>) -> RoundtableResult {
        let mut personas = self.list_personas();
        personas.sort_by(|a, b| a.persona_id.cmp(&b.persona_id));
        let pool = self.llm_pool();
        let mut stances: Vec<(String, String)> = Vec::new();
        for (i, p) in personas.iter().enumerate() {
            let (id, stance, _prov) = self.persona_stance(p, topic, i, &pool).await;
            stances.push((id, stance));
        }
        let consensus = self.chair_consensus(topic, &stances, chair_persona).await;
        RoundtableResult { stances, consensus }
    }

    /// 从 session_id 解析调用者专属命名空间。
    /// session_id 格式为 `jan/{agent_id}/{user_tag}/{conversation_id}`（PFAiX
    /// 分发版注入 x-user-id/x-user-tag/x-conversation-id 后生成）。
    /// 解析成功后返回 `agent/{agent_id}/user/{agent_id}` —— **身份（agent_id）
    /// 同时用于 user 段**，使记忆归属稳定的登录用户（agent_id=user_id），
    /// 而非随设备变化的 user_tag（install_id）。这样：
    ///   - 登录模式：agent_id=user_id → `agent/{user_id}/user/{user_id}`，记忆跨设备连续；
    ///   - legacy 模式：agent_id=user_tag=install_id → `agent/{install_id}/user/{install_id}`，与原行为一致。
    /// 旧格式或解析失败时回退到 agent 自身 ns，保持向后兼容。
    pub fn caller_ns(&self, session_id: &str) -> String {
        let parts: Vec<&str> = session_id.split('/').collect();
        if parts.len() >= 4 && parts[0] == "jan" {
            let agent_id = parts[1];
            if !agent_id.is_empty() {
                return format!("agent/{}/user/{}", agent_id, agent_id);
            }
        }
        self.config.identity.ns()
    }

    /// 入口：处理用户消息，返回回复
    ///
    /// 集成确认状态机（借鉴 task-workflow）：
    /// - 新任务 → 复述确认（Step 1）→ 执行（Step 2）→ 交付（Step 3）
    /// - 简单查询 → 直接执行
    /// - 已确认会话 → 话题切换检测
    #[tracing::instrument(skip_all, fields(user_id = %user_id, session_id = %session_id))]
    pub async fn chat(
        &self,
        message: &str,
        user_id: &str,
        session_id: &str,
        allowed_ns: &[String],
    ) -> String {
        let confirm_words = [
            "确认",
            "确认添加",
            "确认执行",
            "添加",
            "是",
            "是的",
            "对",
            "执行",
            "确定",
            "可以",
            "好",
            "好的",
            "行",
            "没问题",
            "去吧",
            "查吧",
            "执行吧",
            "同意",
            "继续",
            "就按这个",
        ];
        // 确认词用「包含匹配」而非精确相等：用户常回“对的”“好的，执行”“可以，查吧”
        // 等变体，精确匹配会漏掉导致确认状态机死循环（反复问“方向对吗？”）。
        let is_confirm = |m: &str| confirm_words.iter().any(|w| m.contains(*w));
        let is_cancel = |m: &str| {
            let kws = [
                "取消",
                "算了",
                "不执行",
                "放弃",
                "不要了",
                "不算了",
                "取消计划",
            ];
            kws.iter().any(|w| m.contains(w))
        };
        let trimmed = message.trim();

        // ── P1-1: 崩溃恢复——先从 checkpoint 恢复控制面状态到内存 ──
        self.restore_checkpoint(session_id).await;

        // ── P2-2: 生成本次请求的链路 trace_id（串联 LLM→边界→MCP→结果审计） ──
        let trace_id = new_trace_id();

        // ── P1-5: 降级模式 trace（故障可观测） ──
        tracing::info!(degrade_mode = %self.current_degrade_mode().as_str(), "chat 入口降级模式");

        // ── P2-1: 并发会话配额（RAII 守卫，离开作用域自动 leave_session） ──
        let caller_ns_quota = self.caller_ns(session_id);
        let _quota_guard = match self
            .quota
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .enter_session(&caller_ns_quota)
        {
            Ok(()) => Some(SessionQuotaGuard {
                quota: self.quota.clone(),
                ns: caller_ns_quota.clone(),
            }),
            Err(e) => {
                tracing::warn!("[QUOTA] 命名空间『{}』并发会话超限: {}", caller_ns_quota, e);
                return format!(
                    "⚠️ 命名空间『{}』并发会话已达上限：{}。请稍后重试或合并请求。",
                    caller_ns_quota, e
                );
            }
        };

        // ── 提示词注入检测 ──
        let detector = PromptInjectionDetector::new();
        if let Some(level) = detector.quick_check(trimmed) {
            match level {
                ThreatLevel::High => {
                    tracing::warn!("[INJECTION-HIGH] session={}: {}", session_id, trimmed);
                    let ns = self.caller_ns(session_id);
                    let db_path = self.harness.lock().await.db_path();
                    let reply = "⚠️ 检测到可疑指令，已拒绝执行。\n\n本次请求因安全风险被拦截。";
                    self.session_manager
                        .save_to_history(session_id, &ns, &db_path, message, reply)
                        .await;
                    return reply.to_string();
                }
                ThreatLevel::Medium => {
                    tracing::info!("[INJECTION-MED] session={}: {}", session_id, trimmed);
                    self.checkpoint_awaiting(session_id, message).await;
                    let reply = "⚠️ 检测到不太常规的请求模式。\n\n您确定要执行这个操作吗？请回复\"确认\"继续，或修改您的请求。";
                    return reply.to_string();
                }
                ThreatLevel::Low => {
                    tracing::info!("[INJECTION-LOW] session={}: {}", session_id, trimmed);
                }
            }
        }

        // ── 确认超时检查（5分钟）──
        let timed_out = self.session_manager.check_confirm_timeouts(300).await;
        if timed_out.contains(&session_id.to_string()) {
            let reply = "⏰ 确认已超时，如需继续请重新发送指令。";
            let ns = self.caller_ns(session_id);
            let db_path = self.harness.lock().await.db_path();
            self.session_manager
                .save_to_history(session_id, &ns, &db_path, message, reply)
                .await;
            return reply.to_string();
        }

        // ── 0a. 工具级确认（现有）：pending_actions 中的操作等待确认 ──
        if is_confirm(trimmed) {
            if let Some(action) = self.session_manager.take_pending_action(session_id).await {
                let result = match self
                    .call_tool_routed(&action.tool_name, &self.persona_for_session(session_id), &action.arguments, allowed_ns, &trace_id)
                    .await
                {
                    Ok(text) => text,
                    Err(e) => format!("执行失败: {}", e),
                };
                let desc = action.description.chars().take(120).collect::<String>();
                let result_short = result.chars().take(300).collect::<String>();
                let reply = format!(
                    "✅ 操作已执行成功！\n\n操作内容：{}\n\n{}",
                    desc, result_short
                );
                let ns = self.caller_ns(session_id);
                let db_path = self.harness.lock().await.db_path();
                self.session_manager
                    .save_to_history(session_id, &ns, &db_path, message, &reply)
                    .await;
                return reply;
            }
        }

        // ── 0b. 任务级确认状态机 ──
        let state = self.session_manager.get_state(session_id).await;

        match state {
            // ── 等待用户确认理解 ──
            SessionState::AwaitingConfirmation => {
                // P1-2: 取消计划
                if is_cancel(trimmed) {
                    self.cancel_plan(session_id).await;
                    return "✅ 已取消该计划。如需重新开始，请告诉我新的需求。".to_string();
                }
                if is_confirm(trimmed) {
                    let original = self
                        .session_manager
                        .take_original_message(session_id)
                        .await
                        .unwrap_or_else(|| message.to_string());
                    self.checkpoint_confirmed(session_id).await;
                    return self
                        .execute_chat(&original, user_id, session_id, allowed_ns, &trace_id)
                        .await;
                }
                // P1-2: 计划编辑（当前支持「删除第N步」）
                if let Some(new_plan) = self.try_apply_plan_edit(trimmed).await {
                    *self.in_progress_plan.lock().await = Some(new_plan.clone());
                    self.checkpoint_preview(session_id, &new_plan).await;
                    return self.render_plan_preview(&new_plan).await;
                }
                // 修改/补充 → 保留 AwaitingConfirmation，重新复述
                return self
                    .rephrase_and_confirm(message, user_id, session_id, allowed_ns)
                    .await;
            }

            // ── 已确认，正常执行 ──
            SessionState::Confirmed => {
                // 话题切换检测
                if let Some(task) = self.session_manager.get_original_message(session_id).await {
                    if boundary::TaskConfirmationGate::detect_topic_switch(message, &task) {
                        return self.handle_topic_switch(message, session_id).await;
                    }
                }
                return self
                    .execute_chat(message, user_id, session_id, allowed_ns, &trace_id)
                    .await;
            }

            // ── 新会话 ──
            SessionState::New => {
                if boundary::TaskConfirmationGate::requires_confirmation(message) {
                    self.checkpoint_awaiting(session_id, message).await;
                    return self
                        .rephrase_and_confirm(message, user_id, session_id, allowed_ns)
                        .await;
                }
                // 简单查询 → 直接执行
                self.session_manager
                    .set_state(session_id, SessionState::Confirmed)
                    .await;
                return self
                    .execute_chat(message, user_id, session_id, allowed_ns, &trace_id)
                    .await;
            }
        }
    }

    /// 已确认会话的执行路径（原 chat() 主体 + Step 前缀）
    async fn execute_chat(
        &self,
        message: &str,
        user_id: &str,
        session_id: &str,
        allowed_ns: &[String],
        trace_id: &str,
    ) -> String {
        // ── 0. 组合路由路径：多 Skill 分解 + 按序执行 ──
        if self.config.enable_compositional_routing {
            let tools = self.fetch_tools_filtered(allowed_ns).await;
            if !tools.is_empty() {
                // P1-1: 续跑优先——已有进行中计划则直接复用，不重新分解（崩溃恢复场景）
                let plan_opt = if let Some(p) = self.in_progress_plan.lock().await.clone() {
                    Some(p)
                } else {
                    match crate::composer::decompose(&self.llm, message, &tools).await {
                        Ok(plan) if plan.steps.len() > 1 => Some(plan),
                        _ => None,
                    }
                };
                if let Some(plan) = plan_opt {
                    // 全只读计划（仅 query_/get_/explain_ 等读工具）→ 无需确认，直接执行。
                    // 只有含写/危险步骤的多步计划才走「执行/取消」确认闸，避免对只读咨询凭空制造摩擦。
                    let needs_confirm = Self::plan_requires_confirmation(&plan);
                    // P1-2: 预览优先（非续跑 + 开启 preview + 多步 + 含写/危险步骤）→ 先返回计划，不执行
                    let is_resume = self.in_progress_plan.lock().await.is_some();
                    if self.config.compositional_preview && !is_resume && plan.steps.len() > 1 && needs_confirm {
                        *self.in_progress_plan.lock().await = Some(plan.clone());
                        self.checkpoint_preview(session_id, &plan).await;
                        self.session_manager
                            .set_state(session_id, SessionState::AwaitingConfirmation)
                            .await;
                        self.session_manager
                            .set_original_message(session_id, message)
                            .await;
                        return self.render_plan_preview(&plan).await;
                    }
                    // 执行路径（续跑 / 单步 / 关闭预览）：记录进行中 + 执行
                    *self.in_progress_plan.lock().await = Some(plan.clone());
                    self.checkpoint_executing(
                        session_id,
                        &plan,
                        &self.in_progress_step_results.lock().await.clone(),
                    )
                    .await;
                    let result = self
                        .execute_plan(&plan, session_id, allowed_ns)
                        .await
                        .unwrap_or_else(|e| format!("组合执行失败: {}", e));

                    // 蒸馏闭环：记录组合执行的摘要日志，触发 Harness 蒸馏
                    let is_success = result.starts_with("执行结果") && !result.contains("失败");
                    {
                        let mut log = self.execution_log.lock().await;
                        let query_preview: String = message.chars().take(80).collect();
                        log.push(crate::harness::ExecutionLog {
                            name: format!(
                                "composer_{}",
                                message.chars().take(20).collect::<String>()
                            ),
                            trigger_conditions: serde_json::json!({"query": query_preview}),
                            steps: serde_json::json!(plan
                                .steps
                                .iter()
                                .map(|s| serde_json::json!({
                                    "tool": s.tool,
                                    "args": s.arguments,
                                }))
                                .collect::<Vec<serde_json::Value>>()),
                            verify_rule: String::new(),
                            success: is_success,
                        });
                    }
                    {
                        let logs = self.execution_log.lock().await;
                        let mut harness = self.harness.lock().await;
                        // P2-3：蒸馏触发门槛 —— 需 N=3 次成功组合路由佐证（置信度门槛），
                        // 避免偶发成功被过早蒸馏为模板。
                        let _ = harness.distill_from_logs(&logs, 3);
                    }

                    // P1-1: 组合执行完成 → 终态 checkpoint，清理进行中计划
                    self.checkpoint_terminal(session_id, CheckpointState::Done)
                        .await;
                    *self.in_progress_plan.lock().await = None;
                    self.in_progress_step_results.lock().await.clear();

                    return format!("[Step 2/3: 执行 → Step 3/3: 交付]\n\n{}", result);
                }
                // 单步或分解失败 → 降级到普通 LLM loop（fall through）
                tracing::info!("合成路由降级到普通 LLM（单步或分解失败）");
            }
        }

        // ── 1. 快速路径（Harness 匹配）──
        if let Some(reply) = self.try_harness_match(message, allowed_ns).await {
            return reply;
        }

        // ── 2. 并行获取上下文 ──
        let (inbox_result, mem_result) = tokio::join!(
            self.check_inbox(),
            self.search_memory(message, session_id, allowed_ns),
        );

        // P2-D: 检查审批响应
        self.check_approval_responses().await;
        // 如果有审批通过的请求，立即执行
        if let Some(reply) = self.execute_approved_request(session_id, allowed_ns).await {
            let ns = self.caller_ns(session_id);
            let db_path = self.harness.lock().await.db_path();
            self.session_manager
                .save_to_history(session_id, &ns, &db_path, message, &reply)
                .await;
            return reply;
        }

        let mut knowledge = Vec::new();
        let mut enriched_message = message.to_string();

        if let Ok(Some(inbox_msgs)) = &inbox_result {
            let mut prefix = String::from("你有以下来自其他 Agent 的消息:\n");
            for m in inbox_msgs.iter().take(3) {
                let content = m.get("content").and_then(|c| c.as_str()).unwrap_or("");
                let from = m.get("from").and_then(|f| f.as_str()).unwrap_or("?");
                let preview: String = content.chars().take(200).collect();
                prefix.push_str(&format!(
                    "- [{}] {}\n",
                    from,
                    preview
                ));
            }
            enriched_message = format!("{}\n---\n{}", prefix, message);
        }

        // A1: 记忆召回数（供 prefetch 日志 exposed_tools/recalled_memories 配对观测）
        let recalled = mem_result
            .as_ref()
            .ok()
            .and_then(|(r, _)| r.as_ref())
            .map(|v| v.len())
            .unwrap_or(0);
        tracing::info!(recalled_memories = recalled, "prefetch: 记忆召回");
        if let Ok((Some(results), _ledger)) = &mem_result {
            for item in results.iter().take(3) {
                if let Some(content) = item.get("content").and_then(|c| c.as_str()) {
                    if content.len() > 10 {
                        knowledge.push(content.to_string());
                    }
                }
            }
        }
        // O4：Self-Evolution 挂全部 search_memory→knowledge 路径
        let ledger = mem_result
            .as_ref()
            .ok()
            .map(|(_, l)| l.as_slice())
            .unwrap_or(&[]);
        crate::self_evolution::append_to_knowledge(&mut knowledge, message, ledger);

        // ── 3. 加载历史对话 ──
        let ns = self.caller_ns(session_id);
        let db_path = self.harness.lock().await.db_path();
        let history = self
            .session_manager
            .load_history(session_id, &ns, &db_path)
            .await;

        // ── 4. 构建消息列表 ──
        let mut system_prompt = self.build_system_prompt(&knowledge);
        // 白龙马 Phase C: 条件式本地资源门控（仅消息命中 ssh/git/部署 等规则才注入）
        self.inject_resources_if_relevant(&mut system_prompt, message);
        let mut messages = Vec::new();
        messages.push(Message {
            role: "system".to_string(),
            content: Some(system_prompt),
            tool_calls: None,
            tool_call_id: None,
        });
        for h in history.iter().rev().take(20) {
            messages.push(h.clone());
        }
        messages.push(Message {
            role: "user".to_string(),
            content: Some(enriched_message),
            tool_calls: None,
            tool_call_id: None,
        });

        // ── 5. LLM 调用循环 ──
        let result = self
            .llm_loop(messages, session_id, message, user_id, allowed_ns, trace_id)
            .await;

        // 给结果加 Step 前缀
        format!("[Step 2/3: 执行 → Step 3/3: 交付]\n\n{}", result)
    }

    /// 复述确认：用 LLM 复述用户需求，等待确认
    ///
    /// SAD（Skill-Aware Decomposition）风格增强：
    /// 并行获取记忆 + 可用工具列表，注入到 system prompt 中，
    /// 让 LLM 在复述时就能感知可用能力，对齐措辞。
    async fn rephrase_and_confirm(
        &self,
        message: &str,
        _user_id: &str,
        session_id: &str,
        allowed_ns: &[String],
    ) -> String {
        self.session_manager
            .set_original_message(session_id, message)
            .await;

        // SAD 风格：并行获取上下文（记忆）和可用能力（工具列表）
        let (mem_result, tools) = tokio::join!(
            self.search_memory(message, session_id, allowed_ns),
            self.fetch_tools_filtered(allowed_ns),
        );

        let mut knowledge = Vec::new();
        let mut mem_ledger: Vec<serde_json::Value> = Vec::new();
        if let Ok((Some(results), ledger)) = &mem_result {
            mem_ledger = ledger.clone();
            for item in results.iter().take(3) {
                if let Some(content) = item.get("content").and_then(|c| c.as_str()) {
                    if content.len() > 10 {
                        knowledge.push(content.to_string());
                    }
                }
            }
        }
        // O4：Self-Evolution 挂全部 search_memory→knowledge 路径（复述确认）
        crate::self_evolution::append_to_knowledge(&mut knowledge, message, &mem_ledger);

        // 构建增强版 system prompt
        let mut system_prompt = self.build_system_prompt(&knowledge);

        // 白龙马 Phase C: 条件式本地资源门控（仅消息命中 ssh/git/部署 等规则才注入）
        self.inject_resources_if_relevant(&mut system_prompt, message);

        // SAD 核心：注入可用工具信息，让 LLM 复述时对齐能力
        if !tools.is_empty() {
            system_prompt.push_str("\n\n## 可用工具\n你可以使用以下工具来完成请求。复述时请结合工具来描述你的执行方案：\n");
            for t in tools.iter().take(15) {
                let desc: String = t.function.description.chars().take(100).collect();
                system_prompt.push_str(&format!("- `{}`: {}\n", t.function.name, desc));
            }
            system_prompt.push_str(
                "\n在复述中列出你的执行计划（需要几步、用什么工具），让用户确认方案后再执行。\n",
            );
        }

        let msgs = vec![
            Message {
                role: "system".to_string(),
                content: Some(system_prompt),
                tool_calls: None,
                tool_call_id: None,
            },
            Message {
                role: "user".to_string(),
                content: Some(message.to_string()),
                tool_calls: None,
                tool_call_id: None,
            },
        ];

        // 无工具 LLM 调用 — 只复述，不执行
        let response = match self.llm.chat(&msgs, &[]).await {
            Ok(r) => r,
            Err(e) => return format!("[Step 1/3: 确认理解]\n\n抱歉，理解时遇到问题：{}", e),
        };

        let rephrase = response.text.trim().to_string();
        format!(
            "[Step 1/3: 确认理解]\n\n{}，我理解你的需求是：\n\n{}\n\n方向对吗？",
            self.config.identity.agent_id,
            if rephrase.is_empty() {
                message
            } else {
                &rephrase
            },
        )
    }

    /// 按依赖序执行组合计划（支持并行执行无依赖步骤）
    #[tracing::instrument(skip_all, fields(steps = plan.steps.len()))]
    async fn execute_plan(
        &self,
        plan: &crate::composer::ExecutionPlan,
        session_id: &str,
        allowed_ns: &[String],
    ) -> Result<String, String> {
        use std::collections::HashMap;

        // P1-1: 续跑——从已完成的步骤结果起步（崩溃恢复后 in_progress_step_results 已填充）
        let mut step_results: HashMap<u32, String> =
            self.in_progress_step_results.lock().await.clone();
        let mut step_errors: Vec<String> = Vec::new();
        let mut executed: Vec<u32> = step_results.keys().cloned().collect();
        let total = plan.steps.len();

        while executed.len() < total {
            // 找出本轮可执行的步骤（所有依赖已就绪）
            let ready: Vec<&crate::composer::StepPlan> = plan
                .steps
                .iter()
                .filter(|s| !executed.contains(&s.step_id))
                .filter(|s| s.depends_on.iter().all(|d| executed.contains(d)))
                .collect();

            if ready.is_empty() {
                // 死锁：有步骤未执行但无可就绪的
                for step in &plan.steps {
                    if !executed.contains(&step.step_id) {
                        step_errors.push(format!("Step {} 无法执行（依赖未就绪）", step.step_id));
                    }
                }
                break;
            }

            // 并行执行所有就绪步骤
            let futures: Vec<_> = ready
                .iter()
                .map(|step| {
                    // 解析参数中的依赖占位符（step_N → 第 N 步的实际结果）
                    let mut args = step.arguments.clone();
                    if let Some(obj) = args.as_object_mut() {
                        for val in obj.values_mut() {
                            if let Some(s) = val.as_str() {
                                if let Some(rest) = s.strip_prefix("step_") {
                                    // 解析 step_N[_result] 中的 N
                                    let step_num: u32 = rest
                                        .split(['_', ' '])
                                        .next()
                                        .and_then(|n| n.parse().ok())
                                        .unwrap_or(0);
                                    if step_num > 0 {
                                        if let Some(prev) = step_results.get(&step_num) {
                                            *val = serde_json::Value::String(prev.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // 捕获所需引用
                    let step_id = step.step_id;
                    let tool = step.tool.clone();
                    let desc = step.description.clone();

                    async move { (step_id, tool, desc, args) }
                })
                .collect();

            // 先解析完参数再逐个执行
            let parsed: Vec<_> = futures::future::join_all(futures).await;

            // 并发执行所有就绪步骤
            let exec_futures: Vec<_> = parsed.into_iter().map(|(step_id, tool, desc, args)| {
                let this = &self;
                async move {
                    // 边界检查
                    {
                        let boundary = this.boundary.lock().await;
                        let ns = this.current_ns_paths();
                        let check = boundary.check_tool(
                            &tool, &args,
                            &this.config.identity.agent_id, "user",
                            &this.config.parent_permission, ns.as_deref(),
                        );
                        if !check.allow {
                            this.audit_logger.log_decision(
                                &this.config.identity.agent_id, &tool,
                                &check.reason, false
                            ).await;
                            return (step_id, Err(format!("被安全边界拦截: {}", check.reason)));
                        }
                    }

                    match this.call_tool_routed(&tool, "default", &args, allowed_ns, "").await {
                        Ok(result) => {
                            this.audit_logger.log_tool_call(
                                &this.config.identity.agent_id, &tool, &args, true
                            ).await;
                            // 记录执行日志
                            {
                                let mut log = this.execution_log.lock().await;
                                log.push(crate::harness::ExecutionLog {
                                    name: tool.clone(),
                                    trigger_conditions: serde_json::json!({"composer_step": step_id}),
                                    steps: serde_json::json!([{"tool": tool, "args": args}]),
                                    verify_rule: String::new(),
                                    success: true,
                                });
                            }
                            (step_id, Ok(result))
                        }
                        Err(e) => {
                            tracing::warn!("[Composer] Step {} ({}): {}", step_id, desc, e);
                            (step_id, Err(e))
                        }
                    }
                }
            }).collect();

            // 收集结果
            let results = futures::future::join_all(exec_futures).await;
            for (step_id, result) in results {
                match result {
                    Ok(text) => {
                        step_results.insert(step_id, text);
                    }
                    Err(e) => {
                        step_errors.push(format!("Step {}: {}", step_id, e));
                    }
                }
                executed.push(step_id);
                // P1-1: 每步完成即落盘进度（崩溃可续跑）
                self.persist_plan_progress(session_id).await;
            }
        }

        let success_count = step_results.len();
        let error_count = step_errors.len();
        let mut report = format!("执行结果：{}/{} 步骤成功", success_count, total);

        if error_count > 0 {
            report.push_str(&format!("，{} 步失败\n", error_count));
            for e in &step_errors {
                report.push_str(&format!("- {}\n", e));
            }
        }

        if success_count == total && !step_results.is_empty() {
            if let Some(last_result) = step_results.values().last() {
                if !last_result.is_empty() && last_result.len() < 500 {
                    report.push_str(&format!("\n最终结果：{}", last_result));
                }
            }
        }

        Ok(report)
    }

    // ── P1-1 Checkpoint 控制面辅助方法 ──

    /// 进入待确认态：内存 + checkpoint 双写（含原始消息）
    async fn checkpoint_awaiting(&self, session_id: &str, original_message: &str) {
        self.session_manager
            .set_state(session_id, SessionState::AwaitingConfirmation)
            .await;
        self.session_manager
            .set_original_message(session_id, original_message)
            .await;
        let payload = serde_json::json!({"original_message": original_message});
        let agent_id = self.config.identity.agent_id.clone();
        let _ = self.checkpoint_store.lock().await.save(
            session_id,
            &agent_id,
            CheckpointState::AwaitingConfirmation,
            &payload,
        );
    }

    /// 进入已确认态
    async fn checkpoint_confirmed(&self, session_id: &str) {
        self.session_manager
            .set_state(session_id, SessionState::Confirmed)
            .await;
        let agent_id = self.config.identity.agent_id.clone();
        let _ = self.checkpoint_store.lock().await.save(
            session_id,
            &agent_id,
            CheckpointState::Confirmed,
            &serde_json::json!({}),
        );
    }

    /// 进入计划执行态：记录 plan + 已完成步骤
    async fn checkpoint_executing(
        &self,
        session_id: &str,
        plan: &crate::composer::ExecutionPlan,
        step_results: &HashMap<u32, String>,
    ) {
        let agent_id = self.config.identity.agent_id.clone();
        let payload = serde_json::json!({
            "plan": plan,
            "step_results": step_results,
        });
        let _ = self.checkpoint_store.lock().await.save(
            session_id,
            &agent_id,
            CheckpointState::ExecutingPlan,
            &payload,
        );
    }

    /// 记录待审批：含 approval_id 与工具意图
    async fn checkpoint_pending_approval(
        &self,
        session_id: &str,
        approval_id: &str,
        action: &PendingAction,
    ) {
        let agent_id = self.config.identity.agent_id.clone();
        let payload = serde_json::json!({
            "approval_id": approval_id,
            "pending_action": {
                "tool_name": action.tool_name,
                "arguments": action.arguments,
                "description": action.description,
            }
        });
        let _ = self.checkpoint_store.lock().await.save(
            session_id,
            &agent_id,
            CheckpointState::PendingApproval,
            &payload,
        );
    }

    /// 终态（Done / Failed）：保留 checkpoint 供审计关联
    async fn checkpoint_terminal(&self, session_id: &str, state: CheckpointState) {
        let agent_id = self.config.identity.agent_id.clone();
        let _ = self.checkpoint_store.lock().await.save(
            session_id,
            &agent_id,
            state,
            &serde_json::json!({}),
        );
    }

    /// 把当前进行中的计划进度（plan + 已完成步骤）落盘 checkpoint
    async fn persist_plan_progress(&self, session_id: &str) {
        let plan = self.in_progress_plan.lock().await.clone();
        let sr = self.in_progress_step_results.lock().await.clone();
        if let Some(p) = plan {
            self.checkpoint_executing(session_id, &p, &sr).await;
        }
    }

    /// 从持久化 checkpoint 恢复控制面状态到内存（chat 入口调用）
    async fn restore_checkpoint(&self, session_id: &str) {
        let cp = {
            let store = self.checkpoint_store.lock().await;
            store.load(session_id)
        };
        let cp = match cp {
            Some(c) => c,
            None => return,
        };
        // P2-2: Checkpoint 恢复事件（崩溃续跑可观测）
        let state_str = match cp.state {
            CheckpointState::New => "New",
            CheckpointState::AwaitingConfirmation => "AwaitingConfirmation",
            CheckpointState::Confirmed => "Confirmed",
            CheckpointState::PendingApproval => "PendingApproval",
            CheckpointState::ExecutingPlan => "ExecutingPlan",
            CheckpointState::PlanPreview => "PlanPreview",
            CheckpointState::Done => "Done",
            CheckpointState::Failed => "Failed",
        };
        self.audit_logger
            .checkpoint_resume(&self.config.identity.agent_id, session_id, state_str, "")
            .await;
        match cp.state {
            CheckpointState::AwaitingConfirmation => {
                self.session_manager
                    .set_state(session_id, SessionState::AwaitingConfirmation)
                    .await;
                if let Some(msg) = cp.payload.get("original_message").and_then(|m| m.as_str()) {
                    self.session_manager
                        .set_original_message(session_id, msg)
                        .await;
                }
            }
            CheckpointState::Confirmed => {
                self.session_manager
                    .set_state(session_id, SessionState::Confirmed)
                    .await;
            }
            CheckpointState::PendingApproval => {
                // 恢复待审批意图（审批结果需重新等待，但工具意图保留以便日志关联）
                if let Some(pa) = cp.payload.get("pending_action") {
                    let action = PendingAction {
                        tool_name: pa
                            .get("tool_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        arguments: pa
                            .get("arguments")
                            .cloned()
                            .unwrap_or(serde_json::json!({})),
                        description: pa
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                    };
                    self.session_manager
                        .set_pending_action(session_id, action)
                        .await;
                }
                self.session_manager
                    .set_state(session_id, SessionState::AwaitingConfirmation)
                    .await;
            }
            CheckpointState::ExecutingPlan => {
                // 恢复进行中的计划与已完成步骤，供 execute_plan 续跑
                if let Some(plan_val) = cp.payload.get("plan") {
                    if let Ok(plan) =
                        serde_json::from_value::<crate::composer::ExecutionPlan>(plan_val.clone())
                    {
                        *self.in_progress_plan.lock().await = Some(plan);
                    }
                }
                if let Some(sr) = cp.payload.get("step_results").and_then(|v| v.as_object()) {
                    let mut map = self.in_progress_step_results.lock().await;
                    for (k, v) in sr.iter() {
                        if let (Ok(id), Some(s)) = (k.parse::<u32>(), v.as_str()) {
                            map.insert(id, s.to_string());
                        }
                    }
                }
                // 恢复后下一次 execute_chat 会复用 in_progress_plan 续跑
                self.session_manager
                    .set_state(session_id, SessionState::Confirmed)
                    .await;
            }
            CheckpointState::PlanPreview => {
                // 恢复进行中的计划，等待用户「执行 / 取消 / 修改」
                if let Some(plan_val) = cp.payload.get("plan") {
                    if let Ok(plan) =
                        serde_json::from_value::<crate::composer::ExecutionPlan>(plan_val.clone())
                    {
                        *self.in_progress_plan.lock().await = Some(plan);
                    }
                }
                self.session_manager
                    .set_state(session_id, SessionState::AwaitingConfirmation)
                    .await;
                if let Some(msg) = cp.payload.get("original_message").and_then(|m| m.as_str()) {
                    self.session_manager
                        .set_original_message(session_id, msg)
                        .await;
                }
            }
            CheckpointState::Done | CheckpointState::Failed => {
                // 终态：清空内存待确认（checkpoint 保留供审计）
                self.session_manager.remove_state(session_id).await;
            }
            CheckpointState::New => {}
        }
    }

    // ── P1-2 组合计划 HITL 辅助方法 ──

    /// 计划是否含写/危险步骤（需要用户确认闸）。
    /// 仅当任一步骤的工具不是纯只读（见 `boundary::is_read_only_tool`）时返回 true。
    /// 全只读计划（如「查今日/昨日进厂 + 异常检测」）无需确认，应直接执行。
    fn plan_requires_confirmation(plan: &crate::composer::ExecutionPlan) -> bool {
        plan.steps
            .iter()
            .any(|s| !crate::boundary::is_read_only_tool(&s.tool))
    }

    /// 进入计划预览态：记录 plan 但不执行（等待用户确认）
    async fn checkpoint_preview(&self, session_id: &str, plan: &crate::composer::ExecutionPlan) {
        let agent_id = self.config.identity.agent_id.clone();
        let payload = serde_json::json!({
            "plan": plan,
            "original_message": self.session_manager.get_original_message(session_id).await.unwrap_or_default(),
        });
        let _ = self.checkpoint_store.lock().await.save(
            session_id,
            &agent_id,
            CheckpointState::PlanPreview,
            &payload,
        );
    }

    /// 渲染计划预览（结构化摘要 + 机器可读 JSON）
    async fn render_plan_preview(&self, plan: &crate::composer::ExecutionPlan) -> String {
        let mut s = format!(
            "📋 我规划了以下执行计划（共 {} 步）：\n\n",
            plan.steps.len()
        );
        for step in &plan.steps {
            s.push_str(&format!(
                "{}. {} — 工具 `{}`",
                step.step_id, step.description, step.tool
            ));
            if !step.depends_on.is_empty() {
                s.push_str(&format!("（依赖步骤 {:?}）", step.depends_on));
            }
            s.push('\n');
        }
        s.push_str("\n回复「执行」开始；「取消」放弃；「删除第N步」可调整。\n\n```json\n");
        s.push_str(&serde_json::to_string_pretty(plan).unwrap_or_default());
        s.push_str("\n```");
        s
    }

    /// 取消计划：清理进行中计划 + 审计 + 删除 checkpoint
    async fn cancel_plan(&self, session_id: &str) {
        *self.in_progress_plan.lock().await = None;
        self.in_progress_step_results.lock().await.clear();
        self.session_manager.remove_state(session_id).await;
        let _ = self
            .audit_logger
            .log_decision(
                &self.config.identity.agent_id,
                "plan_cancel",
                "用户取消组合计划",
                false,
            )
            .await;
        let _ = self.checkpoint_store.lock().await.delete(session_id);
    }

    /// 尝试应用计划编辑（当前支持「删除第N步」，并连带移除依赖它的步骤以防悬空）
    async fn try_apply_plan_edit(&self, message: &str) -> Option<crate::composer::ExecutionPlan> {
        let marker = message.find("删除第").or_else(|| message.find("去掉第"))?;
        let rest = &message[marker..];
        let num: u32 = rest
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .next()?
            .to_digit(10)?;
        let mut plan = self.in_progress_plan.lock().await.clone()?;
        plan.steps
            .retain(|s| s.step_id != num && !s.depends_on.contains(&num));
        if plan.steps.is_empty() {
            return None;
        }
        Some(plan)
    }

    /// P1-4: 轻量 JSON Schema 校验——检查 required 字段存在且非 null。
    /// 不引入重依赖，覆盖「参数缺失导致 MCP 调用失败/错位」类问题。
    fn validate_tool_args(
        args: &serde_json::Value,
        schema: &serde_json::Value,
    ) -> Result<(), String> {
        let required = schema.get("required").and_then(|r| r.as_array());
        match required {
            Some(req) => {
                let obj = args
                    .as_object()
                    .ok_or_else(|| "工具参数应为 JSON 对象".to_string())?;
                for r in req {
                    if let Some(name) = r.as_str() {
                        match obj.get(name) {
                            None => return Err(format!("缺少必填参数 '{}'", name)),
                            Some(v) if v.is_null() => {
                                return Err(format!("必填参数 '{}' 为 null", name))
                            }
                            _ => {}
                        }
                    }
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// 话题切换检测：当前任务未完成，检测到话题切换
    async fn handle_topic_switch(&self, message: &str, session_id: &str) -> String {
        let task = self
            .session_manager
            .get_original_message(session_id)
            .await
            .unwrap_or_default();
        let task_preview: String = task.chars().take(80).collect();

        // 白龙马 A3：当前焦点任务被切换 → 把旧话题压缩归档（软隐藏进 Memoria + 本地索引）
        let mut archived_note = String::new();
        if !task.is_empty() {
            if let Some(conclusion) = self.archive_current_episode(session_id, &task).await {
                archived_note = format!("\n\n📦 已把上一个话题归档为记忆（切回时自动召回）：{conclusion}");
            }
        }

        // 白龙马 A3：新消息可能在恢复一个已归档的话题线程 → 召回结论注入
        let mut recall_note = String::new();
        if let Some(recall) = self.recall_episode_for(message).await {
            recall_note = format!("\n\n🔁 检测到这可能是之前归档过的话题，已为你恢复上下文：\n{recall}");
        }

        format!(
            "[Task 管理]\n\n检测到您可能换了话题。当前任务还在处理：{task_preview}{archived_note}{recall_note}\n\n请选择：\n- \"继续\" → 继续当前任务\n- \"暂停\" → 暂停当前任务\n- \"结束\" → 结束当前任务"
        )
    }

    /// 白龙马 A3：把当前焦点话题压缩为结论并归档（软隐藏进 Memoria + 本地索引）。
    /// 返回压缩后的结论文本（用于即时提示）；无历史可归档时返回 None。
    async fn archive_current_episode(&self, session_id: &str, first_message: &str) -> Option<String> {
        // 1. 取本会话历史作为压缩原料
        let history = self.load_history(session_id).await;
        if history.len() < 2 {
            return None;
        }
        // 2. 构造压缩用的原始转录（截断，控制 token 成本）
        let mut transcript = String::new();
        for m in history.iter().take(40) {
            let role = &m.role;
            let content = m.content.clone().unwrap_or_default();
            let line: String = content.chars().take(600).collect();
            if !line.is_empty() {
                transcript.push_str(&format!("[{role}] {line}\n"));
            }
        }
        if transcript.trim().is_empty() {
            return None;
        }
        // 3. LLM 压缩（失败则退回首尾拼接）
        let conclusion = match self.compress_episode(&transcript).await {
            Some(c) if !c.trim().is_empty() => c,
            _ => {
                let head: String = first_message.chars().take(120).collect();
                let tail = history
                    .last()
                    .and_then(|m| m.content.clone())
                    .unwrap_or_default();
                let tail: String = tail.chars().take(200).collect();
                format!("{head} ……（结论）{tail}")
            }
        };

        let topic_key = Self::topic_key_of(first_message);
        let ns = self.caller_ns(session_id);
        let archived_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // 4. 软隐藏写入 Memoria：tags 标记 focus_conclusion + absorbed，搜索时默认不进主召回
        let mut memory_id = None;
        let args = serde_json::json!({
            "content": format!("[episode_conclusion] {}\n\nsession={}", conclusion, session_id),
            "tags": ["focus_conclusion", format!("absorbed:{}", session_id)],
            "category": "episode_conclusion",
            "confidence": 75,
            "namespace": ns,
        });
        if let Ok(resp) = self.mcp.call_json("memory_remember", &args).await {
            memory_id = resp
                .get("memory_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| resp.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()));
            tracing::info!(topic_key = %topic_key, memory_id = ?memory_id, "A3: episode 已归档进 Memoria");
        } else {
            tracing::warn!(topic_key = %topic_key, "A3: episode 写 Memoria 失败（仅本地索引）");
        }

        // 5. 本地索引（切回召回用）
        let entry = EpisodeArchive {
            topic_key: topic_key.clone(),
            first_message: first_message.to_string(),
            conclusion: conclusion.clone(),
            memory_id,
            archived_at,
        };
        self.episode_archive.lock().await.insert(topic_key, entry);

        Some(conclusion)
    }

    /// 白龙马 A3：LLM 把会话转录压缩成一段结论；任何失败返回 None（调用方退回拼接）。
    async fn compress_episode(&self, transcript: &str) -> Option<String> {
        let prompt = format!(
            "你是一个对话压缩器。请把下面的对话转录压缩成一段简洁结论（3-5 句，保留关键决策、结果、待办），\
             不要复述过程，不要加前缀。若信息不足就概括要点。\n\n## 转录\n{}",
            transcript
        );
        let msg = crate::llm::Message {
            role: "user".to_string(),
            content: Some(prompt),
            tool_calls: None,
            tool_call_id: None,
        };
        match self.llm.chat(&[msg], &[]).await {
            Ok(r) if !r.text.trim().is_empty() => Some(r.text.trim().to_string()),
            _ => None,
        }
    }

    /// 白龙马 A3：根据新消息召回匹配的已归档话题结论（Focus Stack 切回）。
    async fn recall_episode_for(&self, message: &str) -> Option<String> {
        let key = Self::topic_key_of(message);
        let guard = self.episode_archive.lock().await;
        guard.get(&key).map(|e| e.conclusion.clone())
    }

    /// 白龙马 A3：话题稳定键 —— 首条用户消息归一化（小写 + 去标点 + 前 24 字符 + 稳定哈希）。
    fn topic_key_of(s: &str) -> String {
        let s = s.to_lowercase();
        let norm: String = s
            .chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace())
            .collect();
        let norm = norm.split_whitespace().collect::<Vec<_>>().join(" ");
        let prefix: String = norm.chars().take(24).collect();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::Hash;
        use std::hash::Hasher;
        norm.hash(&mut hasher);
        let h = hasher.finish();
        if prefix.is_empty() {
            format!("tk_{h:016x}")
        } else {
            format!("{prefix}_{h:016x}")
        }
    }

    /// 从 SessionManager 加载历史对话（按调用者 namespace 隔离）
    #[allow(dead_code)]
    async fn load_history(&self, session_id: &str) -> Vec<Message> {
        let ns = self.caller_ns(session_id);
        let db_path = self.harness.lock().await.db_path();
        self.session_manager
            .load_history(session_id, &ns, &db_path)
            .await
    }

    /// 保存对话到 SessionManager（内存缓存 + SQLite 持久化，按调用者 namespace 隔离）
    async fn save_to_history(&self, session_id: &str, user_msg: &str, assistant_reply: &str) {
        let ns = self.caller_ns(session_id);
        let db_path = self.harness.lock().await.db_path();
        self.session_manager
            .save_to_history(session_id, &ns, &db_path, user_msg, assistant_reply)
            .await;
    }

    /// LLM 调用循环（支持多轮 tool calling）
    // ── A1: 白龙马 ACI 请求前上下文预取（工具子集选择，只选 schema 不调工具）──
    const EXPOSE_TOOL_CAP: usize = 12;

    fn prefetch_tokens(s: &str) -> Vec<String> {
        let s = s.to_lowercase();
        let s: String = s.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace()).collect();
        let mut toks = Vec::new();
        for w in s.split_whitespace() {
            if w.len() >= 2 { toks.push(w.to_string()); }
        }
        let cn: Vec<char> = s.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).collect();
        for w in cn.windows(2) {
            toks.push(w.iter().collect());
        }
        toks
    }

    fn score_tool_relevance(&self, query: &str, name: &str, desc: &str) -> f64 {
        let q = Self::prefetch_tokens(query);
        let t = Self::prefetch_tokens(&format!("{} {}", name, desc));
        if q.is_empty() || t.is_empty() { return 0.0; }
        let hit = q.iter().filter(|w| t.contains(w)).count();
        hit as f64 / (q.len().min(t.len())) as f64
    }

    /// 白龙马 ACI 的 selectTools 等价物：按当前消息(task_context)从全量工具中选 top-K 暴露给 LLM。
    /// 其余工具本轮不进 schema（模型仍可经 find_tool 被动发现，复用现有机制）。
    async fn select_exposed_tools(&self, message: &str, allowed_ns: &[String]) -> Vec<ToolDef> {
        let all = self.fetch_tools_filtered(allowed_ns).await;
        let total = all.len();
        if total <= Self::EXPOSE_TOOL_CAP {
            tracing::info!(exposed_tools = total, total = total, "prefetch: 工具数未超阈值，全量暴露");
            return all;
        }
        let mut scored: Vec<(f64, ToolDef)> = all
            .into_iter()
            .map(|t| {
                let s = self.score_tool_relevance(message, &t.function.name, &t.function.description);
                (s, t)
            })
            .collect();
        let max_score = scored.iter().map(|(s, _)| *s).fold(0.0f64, f64::max);
        if max_score <= 0.0 {
            tracing::info!(exposed_tools = total, total = total, "prefetch: 相关性全 0，退回全量暴露");
            return scored.into_iter().map(|(_, t)| t).collect();
        }
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let top: Vec<ToolDef> = scored.into_iter().take(Self::EXPOSE_TOOL_CAP).map(|(_, t)| t).collect();
        tracing::info!(exposed_tools = top.len(), total = total, "prefetch: 按 task_context 选暴露工具子集");
        top
    }

    /// A2: 白龙马 TICK 心跳 —— 空闲 tick 工作体（silent，不回复用户）
    #[tracing::instrument(skip_all, fields(agent_id = %self.config.identity.agent_id))]
    pub async fn run_idle_tick(&self) {
        tracing::info!("consciousness_tick: 空闲心跳（silent，不回复用户，仅更新内部状态）");
        // Phase B 增强：向 Memoria 发 consolidation 建议 / 主动调用无害只读工具（guarded）
    }

    async fn llm_loop(
        &self,
        mut messages: Vec<Message>,
        session_id: &str,
        raw_message: &str,
        user_id: &str,
        allowed_ns: &[String],
        trace_id: &str,
    ) -> String {
        // 从 Memoria 取可用工具列表（A1: 白龙马 ACI 请求前按 task_context 选暴露子集）
        let tools = self.select_exposed_tools(raw_message, allowed_ns).await;
        // P1-4: 构建工具名 → JSON Schema 映射，用于参数校验
        let tool_schemas: HashMap<String, serde_json::Value> = tools
            .iter()
            .map(|t| (t.function.name.clone(), t.function.parameters.clone()))
            .collect();

        // P1 修复：把真实工具名动态注入 system prompt。
        // build_system_prompt 里写死的 query_sql/query_plate 与真实 MCP 工具
        // (execute_sql/fuzzy_match_plate) 对不上，会导致 LLM 调错或调不存在的工具。
        // 这里以"权威工具清单"覆盖，确保 LLM 使用真实存在的工具名。
        if !tools.is_empty() {
            if let Some(sys_msg) = messages.first_mut() {
                if let Some(ref mut content) = sys_msg.content {
                    let mut extra =
                        String::from("\n\n## 当前真实可用工具（调用时务必使用以下名称）\n");
                    for t in tools.iter().take(20) {
                        let desc: String = t.function.description.chars().take(120).collect();
                        extra.push_str(&format!("- `{}`: {}\n", t.function.name, desc));
                    }
                    extra.push_str("\n注意：以上为系统中真实存在的工具。严禁臆造工具名（如 query_sql/query_plate 并不存在），请直接选用上面列出的工具。\n");
                    content.push_str(&extra);
                }
            }
        }

        // P2-1: 配额命名空间（与 call_tool_routed 保持一致）
        let quota_ns_llm = allowed_ns
            .first()
            .cloned()
            .unwrap_or_else(|| self.caller_ns(session_id));

        for _round in 0..self.config.max_tool_rounds {
            // P2-1: 日 token 预算预估（请求上下文体量），超限硬拒
            let ctx_chars: usize = messages
                .iter()
                .map(|m| m.content.as_ref().map(|c| c.len()).unwrap_or(0))
                .sum();
            let req_est = ((raw_message.len() + ctx_chars) as u64) / 4;
            let budget_check = self
                .quota
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .check_token_budget(&quota_ns_llm, req_est);
            if let Err(e) = budget_check {
                tracing::warn!("[QUOTA] 命名空间『{}』token 预算不足: {}", quota_ns_llm, e);
                self.audit_logger
                    .log_decision(
                        &self.config.identity.agent_id,
                        "<llm>",
                        &format!("QuotaExceeded(token_budget): {}", e),
                        false,
                    )
                    .await;
                return format!(
                    "⚠️ 命名空间『{}』当日 token 预算已用尽：{}。请于次日或联系管理员提升配额。",
                    quota_ns_llm, e
                );
            }
            let response = match self.llm.chat(&messages, &tools).await {
                Ok(r) => r,
                // P1-5：LLM 主/备 Provider 均失败 → 返回「可重试错误」，而非裸崩
                Err(e) => {
                    tracing::warn!("[DEGRADE] LLM 调用失败（已尝试主用+备用 Provider）: {}", e);
                    return "⚠️ LLM 服务暂时不可用（已尝试主用与备用 Provider 均失败）。请稍后重试，或检查网络与 API 密钥配置。".to_string();
                }
            };
            // P2-1: 记录本次 token 消耗（请求 + 响应估算），跨天自动重置
            let resp_est = (response.text.len() as u64) / 4;
            self.quota
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .record_token(&quota_ns_llm, req_est + resp_est);

            // 无工具调用 → LLM 直接回复
            if response.tool_calls.is_empty() {
                let reply = response.text;
                // 保存对话
                let _ = self
                    .mcp
                    .call(
                        "memory_observe",
                        &serde_json::json!({
                            "dialog": raw_message, "role": "user",
                            "source": format!("user:{}", user_id), "session_id": session_id,
                            "namespace": self.caller_ns(session_id),
                        }),
                    )
                    .await;
                let _ = self
                    .mcp
                    .call(
                        "memory_observe",
                        &serde_json::json!({
                            "dialog": &reply, "role": "assistant",
                            "source": &self.config.identity.agent_id, "session_id": session_id,
                            "namespace": self.caller_ns(session_id),
                        }),
                    )
                    .await;
                // 保存到内存缓存
                self.save_to_history(session_id, raw_message, &reply).await;
                return reply;
            }

            // 有工具调用 → 执行工具
            for tc in &response.tool_calls {
                // 边界检查
                let boundary = self.boundary.lock().await;
                let ns = self.current_ns_paths();
                let tool_level = boundary
                    .classifier
                    .lock()
                    .unwrap()
                    .classify(&tc.name)
                    .to_string();
                let check = boundary.check_tool(
                    &tc.name,
                    &tc.arguments,
                    &self.config.identity.agent_id,
                    "user",
                    &self.config.parent_permission,
                    ns.as_deref(),
                );
                drop(boundary);

                // P2-3：boundary 结果写入 span（allow / reason / level 可观测）
                tracing::debug!(
                    tool = %tc.name,
                    allowed = check.allow,
                    level = ?check.level,
                    reason = %check.reason,
                    "llm_tool_boundary"
                );

                if !check.allow {
                    // 审计日志：记录边界/红线拒绝（P2-2 统一事件，带 trace_id 串联）
                    self.audit_logger
                        .boundary_deny(
                            &self.config.identity.agent_id,
                            &tc.name,
                            &check.reason,
                            trace_id,
                            Some(session_id),
                        )
                        .await;

                    // 危险/红线工具：无审批人时直接硬拒绝，不进入 LLM 下一轮
                    let is_dangerous = tool_level == "dangerous";
                    if check.level == Some(BlockLevel::Red) || is_dangerous {
                        if let Some(approver_id) = &self.config.approver_id {
                            let aid = self
                                .approval_manager
                                .create_request(
                                    &tc.name,
                                    &tc.arguments,
                                    &check.reason,
                                    approver_id,
                                    &self.config.identity.agent_id,
                                )
                                .await;
                            let msg = serde_json::json!({
                                "type": "approval_request",
                                "approval_id": aid,
                                "tool_name": tc.name,
                                "description": check.reason,
                                "arguments": tc.arguments,
                                "requester_id": self.config.identity.agent_id,
                                "requester_ns": self.config.identity.ns(),
                            });
                            let _ = self
                                .mcp
                                .call(
                                    "a2a_send",
                                    &serde_json::json!({
                                            "to": approver_id,
                                            "content": msg.to_string(),
                                            "namespace": format!("agent/{}", approver_id),
                                    }),
                                )
                                .await;
                            // P2-2: 审批创建事件（带 trace_id）
                            self.audit_logger
                                .approval_event(
                                    "created",
                                    &self.config.identity.agent_id,
                                    &tc.name,
                                    &check.reason,
                                    trace_id,
                                    Some(session_id),
                                )
                                .await;
                            // P1-1: 记录待审批到 checkpoint（崩溃恢复后审批意图仍可见）
                            let pa = PendingAction {
                                tool_name: tc.name.clone(),
                                arguments: tc.arguments.clone(),
                                description: check.reason.clone(),
                            };
                            self.checkpoint_pending_approval(session_id, &aid, &pa)
                                .await;
                            let reply = format!(
                                "AWAITING_APPROVAL:等待审批人「{}」审批工具「{}」，请稍后",
                                approver_id, tc.name
                            );
                            self.save_to_history(session_id, raw_message, &reply).await;
                            return reply;
                        }
                        let reply = format!(
                            "硬拒绝: 工具「{}」触发{}，未配置审批人，无法执行",
                            tc.name,
                            if check.level == Some(BlockLevel::Red) {
                                "红线"
                            } else {
                                "危险工具策略"
                            }
                        );
                        self.save_to_history(session_id, raw_message, &reply).await;
                        return reply;
                    }

                    // 黄线（未知工具、权限递减等）：走确认流程
                    if let Some(approver_id) = &self.config.approver_id {
                        let aid = self
                            .approval_manager
                            .create_request(
                                &tc.name,
                                &tc.arguments,
                                &check.reason,
                                approver_id,
                                &self.config.identity.agent_id,
                            )
                            .await;
                        let msg = serde_json::json!({
                            "type": "approval_request",
                            "approval_id": aid,
                            "tool_name": tc.name,
                            "description": check.reason,
                            "arguments": tc.arguments,
                            "requester_id": self.config.identity.agent_id,
                            "requester_ns": self.config.identity.ns(),
                        });
                        let _ = self
                            .mcp
                            .call(
                                "a2a_send",
                                &serde_json::json!({
                                    "to": approver_id,
                                    "content": msg.to_string(),
                                    "namespace": format!("agent/{}", approver_id),
                                }),
                            )
                            .await;
                        let reply = format!(
                            "AWAITING_APPROVAL:等待审批人「{}」审批工具「{}」，请稍后",
                            approver_id, tc.name
                        );
                        self.save_to_history(session_id, raw_message, &reply).await;
                        return reply;
                    }
                    let reply = format!(
                        "REQUIRES_REVIEW:{}:工具「{}」需要确认——{}",
                        tc.name, tc.name, check.reason
                    );
                    self.save_to_history(session_id, raw_message, &reply).await;
                    return reply;
                }

                // P1-4: 工具参数 JSON Schema 校验（校验失败不调用 MCP）
                if let Some(schema) = tool_schemas.get(&tc.name) {
                    if let Err(e) = Self::validate_tool_args(&tc.arguments, schema) {
                        if self.config.strict_schema {
                            let reply =
                                format!("工具「{}」参数校验失败: {}。请修正后重试。", tc.name, e);
                            self.save_to_history(session_id, raw_message, &reply).await;
                            return reply;
                        }
                        // 非严格模式：把错误回灌 LLM，让其修正参数后重试（受 max_tool_rounds 限制）
                        tracing::info!(tool = %tc.name, error = %e, "工具参数 schema 校验失败，回灌 LLM 修正");
                        messages.push(Message {
                            role: "user".to_string(),
                            content: Some(format!(
                                "工具 {} 参数错误: {}。请严格按该工具的 JSON Schema（required 字段必填）修正参数后重试。",
                                tc.name, e
                            )),
                            tool_calls: None,
                            tool_call_id: None,
                        });
                        continue;
                    }
                }

                // 通过 MCP 调用工具（按名称路由到正确的源）
                let result = match self
                    .call_tool_routed(&tc.name, &self.persona_for_session(session_id), &tc.arguments, allowed_ns, trace_id)
                    .await
                {
                    Ok(text) => text,
                    Err(e) => format!("执行失败: {}", e),
                };

                // 记录执行日志（供蒸馏）
                {
                    let mut log = self.execution_log.lock().await;
                    log.push(ExecutionLog {
                        name: tc.name.clone(),
                        trigger_conditions: serde_json::json!({"tool": tc.name}),
                        steps: serde_json::json!([{
                            "tool": tc.name,
                            "args": tc.arguments,
                        }]),
                        verify_rule: String::new(),
                        success: !result.starts_with("执行失败"),
                    });
                }

                // 需要确认的操作 → 保存到 pending_actions
                if result.contains("require_confirm") || result.contains("确认") {
                    let action = PendingAction {
                        tool_name: tc.name.clone(),
                        arguments: {
                            let mut args = tc.arguments.clone();
                            if let Some(obj) = args.as_object_mut() {
                                obj.insert("confirmed".to_string(), serde_json::Value::Bool(true));
                            }
                            args
                        },
                        description: format!("{} ({})", tc.name, tc.arguments),
                    };
                    self.session_manager
                        .set_pending_action(session_id, action)
                        .await;
                }

                // 将工具调用 + 结果加入消息列表
                messages.push(Message {
                    role: "assistant".to_string(),
                    content: None,
                    tool_calls: Some(vec![crate::llm::ToolCallJson {
                        id: tc.id.clone(),
                        type_: "function".to_string(),
                        function: crate::llm::ToolFunction {
                            name: tc.name.clone(),
                            arguments: tc.arguments.to_string(),
                        },
                    }]),
                    tool_call_id: None,
                });
                messages.push(Message {
                    role: "tool".to_string(),
                    content: Some(result),
                    tool_calls: None,
                    tool_call_id: Some(tc.id.clone()),
                });
            }
        }

        // 轮数耗尽，最后让 LLM 总结
        messages.push(Message {
            role: "user".to_string(),
            content: Some("请总结你刚才查到的结果，直接回复用户。不要调用工具。".to_string()),
            tool_calls: None,
            tool_call_id: None,
        });

        match self.llm.chat(&messages, &[]).await {
            Ok(r) => {
                let reply = r.text;
                // 保存到内存缓存（工具调用后的总结也需要保存）
                self.save_to_history(session_id, raw_message, &reply).await;
                reply
            }
            Err(e) => format!("LLM 总结失败: {}", e),
        }
    }

    /// 检查 A2A 收件箱（带 30s 缓存）
    async fn check_inbox(&self) -> Result<Option<Vec<serde_json::Value>>, String> {
        let mut cache = self.inbox_cache.lock().await;
        if cache.is_fresh() {
            return Ok(cache.data.clone());
        }

        let result = self
            .mcp
            .call_json(
                "a2a_recv",
                &serde_json::json!({"limit": 5, "namespace": self.config.identity.ns()}),
            )
            .await;

        match result {
            Ok(val) => {
                let msgs = val["messages"].as_array().cloned().unwrap_or_default();
                cache.data = Some(msgs.clone());
                cache.expires_at = now_secs() + 30.0;
                Ok(Some(msgs))
            }
            Err(_) => Ok(None),
        }
    }

    /// 拉取并规范化调用者的 A2A 协作收件箱（按调用者身份，而非服务端自身身份）。
    ///
    /// 与 `check_inbox`（内部审批轮询，固定读服务端身份 ns）不同，本方法以
    /// `caller_agent_id` 为收件人向 Memoria `a2a_recv` 查询 `agent/{caller_agent_id}`
    /// 命名空间下的消息，契合 PFAiX「人各自收件箱」模型。Memoria `a2a_recv` 采用
    /// SelfOnly 策略，调用方只能读自己的收件箱，天然安全。
    ///
    /// 返回已规范化的信封数组（兼容结构化 JSON 信封与旧版 `[subject] body` 文本）。
    pub async fn collab_inbox_raw(
        &self,
        caller_agent_id: &str,
        caller_agent_key: &str,
        limit: u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        let mcp = McpClient::new(&self.config.memoria_url, caller_agent_id, caller_agent_key);
        let val = mcp
            .call_json(
                "a2a_recv",
                &serde_json::json!({
                    "limit": limit,
                    "namespace": format!("agent/{}", caller_agent_id),
                }),
            )
            .await
            .map_err(|e| format!("a2a_recv 失败: {}", e))?;
        let msgs = val["messages"].as_array().cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(msgs.len());
        for m in &msgs {
            out.push(Self::map_a2a_message(m));
        }
        Ok(out)
    }

    /// 将 Memoria 原始 A2A 消息规范化为协作信封。
    /// - 结构化信封：content 为 JSON 且含 `type` 字段，直接取字段。
    /// - 旧版文本：content 形如 `[subject] body`，解析后 type 降级为 `message`。
    fn map_a2a_message(m: &serde_json::Value) -> serde_json::Value {
        let id = m
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let from = m.get("from").and_then(|v| v.as_str()).unwrap_or("");
        let time = m
            .get("time")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let content = m.get("content").and_then(|v| v.as_str()).unwrap_or("");

        let (
            etype,
            subject,
            body,
            from_agent,
            from_ns,
            to_agent,
            scope,
            scope_id,
            workspace_id,
            thread_id,
            payload,
            created_at,
        ) = if let Ok(env) = serde_json::from_str::<serde_json::Value>(content) {
            if env.get("type").is_some() {
                (
                    env.get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("message")
                        .to_string(),
                    env.get("subject")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    env.get("body")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    env.get("from_agent")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| Self::strip_agent_prefix(from)),
                    env.get("from_ns")
                        .and_then(|v| v.as_str())
                        .unwrap_or(from)
                        .to_string(),
                    env.get("to_agent")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    env.get("scope")
                        .and_then(|v| v.as_str())
                        .unwrap_or("agent")
                        .to_string(),
                    env.get("scope_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    env.get("workspace_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    env.get("thread_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    env.get("payload")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                    env.get("created_at")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| time.clone()),
                )
            } else {
                Self::legacy_parts(content, from, &time)
            }
        } else if let Some(rest) = content.strip_prefix('[') {
            // 过渡期：旧 Memoria 可能把 JSON 塞进 `[subject] {envelope}` 的 body
            if let Some(end) = rest.find(']') {
                let body_part = rest[end + 1..].trim_start();
                if let Ok(env) = serde_json::from_str::<serde_json::Value>(body_part) {
                    if env.get("type").is_some() {
                        return Self::map_a2a_message(&serde_json::json!({
                            "id": id,
                            "from": from,
                            "time": time,
                            "content": body_part,
                        }));
                    }
                }
            }
            Self::legacy_parts(content, from, &time)
        } else {
            Self::legacy_parts(content, from, &time)
        };

        serde_json::json!({
            "id": id,
            "type": etype,
            "subject": subject,
            "body": body,
            "from_agent": from_agent,
            "from_ns": from_ns,
            "to_agent": to_agent,
            "scope": scope,
            "scope_id": scope_id,
            "workspace_id": workspace_id,
            "thread_id": thread_id,
            "payload": payload,
            "created_at": created_at,
        })
    }

    /// 代调用者向 `agent/{to_agent}` 收件箱投递一封协作信封。
    ///
    /// 经服务端受信身份 `self.mcp`（即 `dashboard-agent`，在 Memoria 注册为 admin/`*`，
    /// 与现有审批流一致）中继投递。Memoria 的 `a2a_send` NS 门控
    /// 仅放行 admin 角色，故由 agent-core（可信后端）统一中继；真正的可达性策略在
    /// `handle_collab_send` 中按 §3.3 校验，NS 门控仅作纵深防御。
    /// 信封的 `from_agent` / `from_ns` 已填真实调用者，收件人据此识别发送方。
    pub async fn collab_send_raw(
        &self,
        to_agent: &str,
        envelope: &serde_json::Value,
    ) -> Result<String, String> {
        self.mcp
            .call(
                "a2a_send",
                &serde_json::json!({
                    "to": to_agent,
                    // 结构化信封（Memoria 优先存 content）
                    "content": envelope.to_string(),
                    // 兼容旧 Memoria：若仍忽略 content，至少 subject 可读；body 再带一份 JSON
                    "subject": envelope.get("subject").and_then(|v| v.as_str()).unwrap_or(""),
                    "body": envelope.to_string(),
                    "namespace": format!("agent/{}", to_agent),
                }),
            )
            .await
            .map_err(|e| format!("a2a_send 失败: {}", e))
    }

    /// 取同组织已注册 Agent 通讯录（Memoria `agent_list`，需 admin）。
    pub async fn collab_list_peers(&self) -> Result<Vec<serde_json::Value>, String> {
        let admin_key = std::env::var("MEMORIA_ADMIN_KEY").unwrap_or_default();
        let val = self
            .mcp
            .call_json(
                "agent_list",
                &serde_json::json!({ "admin_key": admin_key }),
            )
            .await
            .map_err(|e| format!("agent_list 失败: {}", e))?;
        Ok(val["agents"].as_array().cloned().unwrap_or_default())
    }

    /// 在调用者收件箱中按消息 id 查找一封规范化信封（用于审批响应回写）。
    pub async fn collab_find_message(
        &self,
        caller_agent_id: &str,
        caller_agent_key: &str,
        msg_id: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        let inbox = self
            .collab_inbox_raw(caller_agent_id, caller_agent_key, 200)
            .await?;
        Ok(inbox
            .into_iter()
            .find(|m| m["id"].as_str() == Some(msg_id)))
    }

    /// 解析旧版 `[subject] body` 文本消息为信封各部分（type 降级为 `message`）。
    fn legacy_parts(
        content: &str,
        from: &str,
        time: &str,
    ) -> (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        serde_json::Value,
        String,
    ) {
        let (subject, body) = if let Some(rest) = content.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                (
                    rest[..end].to_string(),
                    rest[end + 1..].trim_start().to_string(),
                )
            } else {
                ("".to_string(), content.to_string())
            }
        } else {
            ("".to_string(), content.to_string())
        };
        (
            "message".to_string(),
            subject,
            body,
            Self::strip_agent_prefix(from),
            from.to_string(),
            "".to_string(),
            "agent".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            serde_json::Value::Null,
            time.to_string(),
        )
    }

    /// 把 `agent:xxx` / `agent/xxx` 形式的来源归一为 agent id。
    fn strip_agent_prefix(from: &str) -> String {
        from.strip_prefix("agent:")
            .or_else(|| from.strip_prefix("agent/"))
            .unwrap_or(from)
            .to_string()
    }

    /// 从 Memoria 拉取会话开场上下文。
    /// 优先 `memory_context`（profile + recall）；失败则降级 `memory_search_v2`。
    /// PFAiX 强制隔离：同时覆盖调用者私有 ns 与 allowed_ns 共享 ns。
    async fn search_memory(
        &self,
        query: &str,
        session_id: &str,
        allowed_ns: &[String],
    ) -> Result<(Option<Vec<serde_json::Value>>, Vec<serde_json::Value>), String> {
        let caller_ns = self.caller_ns(session_id);
        let mut targets = vec![caller_ns];
        for ns in allowed_ns {
            if !targets.contains(ns) {
                targets.push(ns.clone());
            }
        }

        let mut merged: Vec<serde_json::Value> = Vec::new();
        let mut ledger_rows: Vec<serde_json::Value> = Vec::new();
        let mut used_context = false;

        for ns in &targets {
            if merged.len() >= 8 {
                break;
            }
            // P0：优先 memory_context（会话档案 + 轻量 recall）
            let ctx = self
                .mcp
                .call_json(
                    "memory_context",
                    &serde_json::json!({
                        "namespace": ns,
                        "query": query,
                        "recall_k": 3,
                        "include_profile": true,
                    }),
                )
                .await;

            if let Ok(val) = &ctx {
                if val["status"].as_str() == Some("ok") {
                    used_context = true;
                    if let Some(arr) = val["ledger"].as_array() {
                        for row in arr {
                            ledger_rows.push(row.clone());
                        }
                    }
                    if let Some(block) = val["prompt_block"].as_str() {
                        let trimmed = block.trim();
                        if !trimmed.is_empty() && trimmed.len() > 10 {
                            let item = serde_json::json!({
                                "content": trimmed,
                                "source": "memory_context",
                                "namespace": ns,
                            });
                            if !merged.contains(&item) {
                                merged.push(item);
                            }
                        }
                    } else {
                        for key in ["static", "dynamic"] {
                            if let Some(arr) = val["profile"][key].as_array() {
                                for it in arr {
                                    if let Some(c) = it["content"].as_str() {
                                        if c.len() > 10 {
                                            let item = serde_json::json!({
                                                "content": c,
                                                "source": format!("profile_{}", key),
                                                "namespace": ns,
                                            });
                                            if !merged.contains(&item) {
                                                merged.push(item);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(arr) = val["recall"].as_array() {
                            for it in arr {
                                if let Some(c) = it["content"].as_str() {
                                    if c.len() > 10 {
                                        let item = serde_json::json!({
                                            "content": c,
                                            "source": "memory_context_recall",
                                            "namespace": ns,
                                        });
                                        if !merged.contains(&item) {
                                            merged.push(item);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
            }

            // 单 ns context 失败时尝试旧检索
            if used_context {
                continue;
            }
            let result = self
                .mcp
                .call_json(
                    "memory_search_v2",
                    &serde_json::json!({
                        "query": query,
                        "namespace": ns,
                        "max_results": 3,
                        "intent": "WHAT",
                    }),
                )
                .await;
            if let Ok(val) = result {
                if let Some(arr) = val["results"].as_array() {
                    for item in arr.iter().cloned() {
                        if !merged.contains(&item) {
                            merged.push(item);
                        }
                        if merged.len() >= 6 {
                            break;
                        }
                    }
                }
            }
        }

        // 全部 context 失败时兜底旧检索
        if merged.is_empty() {
            for ns in &targets {
                let result = self
                    .mcp
                    .call_json(
                        "memory_search_v2",
                        &serde_json::json!({
                            "query": query,
                            "namespace": ns,
                            "max_results": 3,
                            "intent": "WHAT",
                        }),
                    )
                    .await;
                if let Ok(val) = result {
                    if let Some(arr) = val["results"].as_array() {
                        for item in arr.iter().cloned() {
                            if !merged.contains(&item) {
                                merged.push(item);
                            }
                            if merged.len() >= 6 {
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok((
            if merged.is_empty() {
                None
            } else {
                Some(merged)
            },
            ledger_rows,
        ))
    }

    /// 检查 A2A 收件箱中的审批响应
    /// 扫描收件箱消息，识别 approval_response 类型，记录到 ApprovalManager
    async fn check_approval_responses(&self) {
        let inbox = match self
            .mcp
            .call_json(
                "a2a_recv",
                &serde_json::json!({
                    "limit": 10,
                    "namespace": self.config.identity.ns(),
                }),
            )
            .await
        {
            Ok(val) => val["messages"].as_array().cloned().unwrap_or_default(),
            Err(_) => return,
        };

        for msg in &inbox {
            let content = match msg.get("content").and_then(|c| c.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let parsed: serde_json::Value = match serde_json::from_str(content) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(resp) = ApprovalManager::parse_approval_response(&parsed) {
                self.approval_manager.record_response(resp).await;
            }
        }
    }

    /// 执行审批通过的请求
    /// 检查所有 pending 审批项，如果有已批准的，执行该工具并返回结果
    async fn execute_approved_request(
        &self,
        _session_id: &str,
        allowed_ns: &[String],
    ) -> Option<String> {
        let pending_list = self.approval_manager.list_pending().await;
        for approval in &pending_list {
            if let Some(true) = self
                .approval_manager
                .is_approved(&approval.approval_id)
                .await
            {
                // 审批通过，执行工具
                let result = match self
                    .call_tool_routed(&approval.tool_name, "default", &approval.arguments, allowed_ns, "")
                    .await
                {
                    Ok(text) => text,
                    Err(e) => format!("执行失败: {}", e),
                };
                let desc = approval.description.chars().take(120).collect::<String>();
                let result_short = result.chars().take(300).collect::<String>();
                let reply = format!(
                    "✅ 审批通过！操作已执行。\n\n操作内容：{}\n审批人：{}\n\n{}",
                    desc, approval.approver_id, result_short
                );
                // 审计日志
                self.audit_logger
                    .log_tool_call(
                        &self.config.identity.agent_id,
                        &approval.tool_name,
                        &approval.arguments,
                        true,
                    )
                    .await;
                self.approval_manager.remove(&approval.approval_id).await;
                return Some(reply);
            } else if let Some(false) = self
                .approval_manager
                .is_approved(&approval.approval_id)
                .await
            {
                // 审批被拒绝
                let desc = approval.description.chars().take(120).collect::<String>();
                let reply = format!(
                    "❌ 审批被拒绝。\n\n操作内容：{}\n审批人：{}",
                    desc, approval.approver_id
                );
                self.approval_manager.remove(&approval.approval_id).await;
                return Some(reply);
            }
        }
        None
    }

    /// 查找能处理该工具的 MCP 源
    /// P1-3 修复：优先从 tool_route_cache 精确查找，fallback 到 Memoria 特有工具列表
    pub async fn find_mcp_for_tool(&self, tool_name: &str) -> &McpClient {
        // 1. 先查缓存（关键修复：必须用异步锁 .lock().await，严禁 blocking_lock()，
        //    否则在 tokio runtime 线程内调用会 panic 并直接 drop 请求连接，
        //    表现为前端 "connection failed"）
        {
            let cache = self.tool_route_cache.lock().await;
            if let Some(&idx) = cache.get(tool_name) {
                if idx < self.mcp_sources.len() {
                    return &self.mcp_sources[idx].client;
                }
            }
        }

        // 2. Memoria 特有工具走第一个源
        let memoria_tools = [
            "memory_search",
            "memory_search_v2",
            "memory_remember",
            "memory",
            "memory_observe",
            "memory_profile",
            "memory_context",
            "memory_recall",
            "a2a_send",
            "a2a_recv",
            "register_agent",
            "audit_query",
            "db_stats",
            "skill_market_list_installed",
            "skill_market_search",
            "agent_list",
            "agent_revoke",
        ];
        if memoria_tools.contains(&tool_name) {
            return &self.mcp;
        }

        // 3. 非 memory_ 开头的工具，尝试找第一个非 Memoria 源
        if !tool_name.starts_with("memory_") && !tool_name.starts_with("db_") {
            if self.mcp_sources.len() > 1 {
                return &self.mcp_sources[1].client;
            }
        }

        // 4. fallback 到 Memoria
        &self.mcp
    }

    /// 异步查找 MCP 源（会尝试更新缓存）
    pub async fn find_mcp_for_tool_async(&self, tool_name: &str) -> &McpClient {
        // 先同步检查缓存
        {
            let cache = self.tool_route_cache.lock().await;
            if let Some(&idx) = cache.get(tool_name) {
                if idx < self.mcp_sources.len() {
                    return &self.mcp_sources[idx].client;
                }
            }
        }

        // 缓存未命中 → 查询所有 MCP 源的 tools/list
        for (idx, source) in self.mcp_sources.iter().enumerate() {
            if let Ok(tools) = source.client.list_tools().await {
                let mut cache = self.tool_route_cache.lock().await;
                for (name, _desc, _) in &tools {
                    cache.insert(name.clone(), idx);
                }
                // 同时学习工具分类
                let boundary = self.boundary.lock().await;
                let tool_names_descs: Vec<(String, String)> = tools
                    .iter()
                    .map(|(n, d, _)| (n.clone(), d.clone()))
                    .collect();
                boundary.learn_tools(&tool_names_descs);
                drop(boundary);

                // 检查目标工具是否在此源中
                if tools.iter().any(|(name, _, _)| name == tool_name) {
                    return &source.client;
                }
            }
        }

        // 最终 fallback
        self.find_mcp_for_tool(tool_name).await
    }

    /// 路由到正确的 MCP 源执行工具调用
    /// P0 修复：执行期再次按 allowed_ns 校验工具所属 MCP 源命名空间，
    /// 防止工具发现期被隐藏的工具在调用期被 LLM / prompt 注入点名执行。
    #[tracing::instrument(skip_all, fields(tool_name = %tool_name))]
    pub async fn call_tool_routed(
        &self,
        tool_name: &str,
        persona_id: &str,
        args: &serde_json::Value,
        allowed_ns: &[String],
        trace_id: &str,
    ) -> Result<String, String> {
        // ── Phase 1+2：分身级工具白名单（真实 persona_id 来自会话；缺省 "default"） ──
        if let Err(e) = self.check_persona_tool(persona_id, tool_name) {
            return Err(e);
        }
        // ── P1-5 降级收缩门控（全局 → 源级 → 模式级） ──
        // 1) Kill switch：全局拒绝一切工具调用，仅系统状态查询可用
        if self.degrade.kill_switch_on() {
            tracing::warn!("[DEGRADE] Kill switch 启用，拒绝工具调用: {}", tool_name);
            return Err(
                "🛑 Kill switch 已启用，工具调用已全局禁用，仅系统状态查询可用。".to_string(),
            );
        }

        // ── P2-1 配额门控（命名空间级工具轮次） ──
        // 配额维度取调用者主命名空间（allowed_ns 首个；为空回退 agent 自身 ns）
        let quota_ns = allowed_ns
            .first()
            .cloned()
            .unwrap_or_else(|| self.config.identity.ns());
        // 先把结果绑定到局部变量，确保 MutexGuard 临时量在此语句结束即释放
        // （否则 guard 在 if let 块内跨 .await 存活，违反 Send 约束）
        let quota_check = self
            .quota
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .check_tool_round(&quota_ns);
        if let Err(e) = quota_check {
            tracing::warn!("[QUOTA] 命名空间『{}』工具轮次超限: {}", quota_ns, e);
            self.audit_logger
                .log_decision(
                    &self.config.identity.agent_id,
                    tool_name,
                    &format!("QuotaExceeded(tool_rounds): {}", e),
                    false,
                )
                .await;
            return Err(format!(
                "⚠️ 命名空间『{}』工具调用已达当日轮次上限：{}。请于次日或联系管理员提升配额。",
                quota_ns, e
            ));
        }

        // 解析工具所属 MCP 源
        let idx = self.tool_route_cache.lock().await.get(tool_name).copied();
        let mode = self.current_degrade_mode();
        if let (Some(_idx), Some(source)) = (idx, idx.and_then(|i| self.mcp_sources.get(i))) {
            // 2) 源不健康（连续失败达阈值）：直接拒绝，工具已剔除
            if self.degrade.is_unhealthy(&source.name) {
                tracing::warn!(
                    "[DEGRADE] 源 {} 不健康，拒绝其工具调用: {}",
                    source.name,
                    tool_name
                );
                return Err(format!(
                    "⚠️ 工具来源『{}』当前不可用（已标记 unhealthy），已降级剔除。",
                    source.name
                ));
            }
            // 3) 全部业务 MCP 不可用 → 仅 Memoria 只读 + 纯聊天
            if mode == DegradeMode::MemoriaReadonlyChat && source.name != "memoria" {
                tracing::warn!(
                    "[DEGRADE] MemoriaReadonlyChat 模式，拒绝业务源工具: {} ({})",
                    tool_name,
                    source.name
                );
                return Err(
                    "⚠️ 业务服务已降级（全部不可用），当前仅支持记忆检索与纯聊天，工具调用已暂停。"
                        .to_string(),
                );
            }
            if mode == DegradeMode::MemoriaReadonlyChat && source.name == "memoria" {
                // memoria 仅放行只读工具，避免降级期误写记忆
                let cls = {
                    let b = self.boundary.lock().await;
                    b.classifier
                        .lock()
                        .map(|c| c.classify(tool_name).to_string())
                        .unwrap_or_else(|_| "unknown".to_string())
                };
                if cls != "read" {
                    tracing::warn!(
                        "[DEGRADE] MemoriaReadonlyChat 模式，拒绝非只读记忆工具: {} ({})",
                        tool_name,
                        cls
                    );
                    return Err(format!(
                        "⚠️ 降级模式（仅记忆检索）：工具『{}』非只读，已暂停。",
                        tool_name
                    ));
                }
            }
        }

        let client = self.find_mcp_for_tool_async(tool_name).await;

        // 执行期命名空间门控：根据 tool_route_cache 找到工具所属 MCP 源，
        // 若该源声明了 namespace，则调用者 allowed_ns 必须与之存在包含关系。
        if let Some(&idx) = self.tool_route_cache.lock().await.get(tool_name) {
            if let Some(src_ns) = self
                .mcp_sources
                .get(idx)
                .and_then(|s| s.namespace.as_deref())
            {
                if !allowed_ns.iter().any(|g| Self::ns_covers(g, src_ns)) {
                    return Err(format!(
                        "工具 {} 所属项目 '{}' 不在当前身份授权范围内",
                        tool_name, src_ns
                    ));
                }
            }
        }

        // 实际执行；P2-2：记录 MCP 传输失败（便于按 trace_id 还原调用链）
        let src_name = {
            let c = self.tool_route_cache.lock().await;
            c.get(tool_name)
                .and_then(|&i| self.mcp_sources.get(i))
                .map(|s| s.name.clone())
        };
        // P2.2d：可选 retain 路径 — chat memory_remember 时 LLM 抽取 signal tags
        let mut call_args = args.clone();
        if (tool_name == "memory_remember" || tool_name == "memory")
            && crate::text_signals::llm_retain_signals_enabled()
        {
            if let Some(content) = call_args.get("content").and_then(|c| c.as_str()) {
                if !content.trim().is_empty() {
                    let tags = self.llm_extract_signal_tags_single(content).await;
                    crate::text_signals::enrich_remember_args(&mut call_args, &tags);
                }
            }
        }

        // ── A2 文件级 checkpoint：WRITE/dangerous 工具执行前快照其 path 参数指向的现有文件 ──
        let fc_level = {
            let b = self.boundary.lock().await;
            b.classifier
                .lock()
                .map(|c| c.classify(tool_name).to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        };
        let fc_snapshots: Vec<String> =
            if fc_level == "write" || fc_level == "dangerous" {
                crate::file_checkpoint::snapshot_args(args)
            } else {
                Vec::new()
            };
        if !fc_snapshots.is_empty() {
            tracing::debug!(
                "file_checkpoint: 为 {} 快照 {} 个文件路径，执行失败将自动回滚",
                tool_name,
                fc_snapshots.len()
            );
        }

        // ── PR2：写入前门提取压缩（对标 Mem0；脑子在 agent-core，Memoria 哑存储） ──
        // 在真正写 memoria 之前拦截 memory_remember / memory：用 LLM 把长 raw 拆为 N 原子事实，
        // 原文以 memory_type=raw 存档（parent_id 指向）。失败 / 保真不过 → 降级原样写入。
        if (tool_name == "memory_remember" || tool_name == "memory")
            && crate::memory_extract::agent_memory_extract_enabled()
        {
            if let Some(content) = call_args.get("content").and_then(|c| c.as_str()) {
                if !content.trim().is_empty() {
                    match self
                        .run_memory_extraction(&call_args, content, trace_id)
                        .await
                    {
                        Ok(summary) => {
                            tracing::info!("[PR2] 记忆提取压缩完成: {}", summary);
                            return Ok(summary);
                        }
                        Err(reason) => {
                            tracing::warn!(
                                "[PR2] 记忆提取降级（原样写入）: {} | tool={}",
                                reason,
                                tool_name
                            );
                            // 降级：继续走下方单次原样写入，不阻塞
                        }
                    }
                }
            }
        }

        let result = client.call(tool_name, &call_args).await;
        if let Err(ref e) = result {
            self.audit_logger
                .mcp_retry(
                    &self.config.identity.agent_id,
                    &src_name.unwrap_or_else(|| "memoria".to_string()),
                    tool_name,
                    e,
                    trace_id,
                    None,
                )
                .await;
        }
        // A2 回滚：工具执行失败且此前曾快照 → 自动恢复被改写的文件
        if result.is_err() && !fc_snapshots.is_empty() {
            tracing::warn!(
                "file_checkpoint: {} 执行失败，回滚 {} 个文件快照",
                tool_name,
                fc_snapshots.len()
            );
            crate::file_checkpoint::restore_many(&fc_snapshots);
        }
        result
    }

    /// 获取当前 agent 的命名空间路径列表（用于 boundary check_tool 的 namespaces 参数）
    fn current_ns_paths(&self) -> Option<Vec<String>> {
        self.config.identity.ns_path().map(|p| vec![p.to_string()])
    }

    /// 从 agent_id 解析命名空间并同步到 NamespaceRegistry
    ///
    /// agent_id 格式（来自 handle_register）：{company}_{department}_{name}
    /// 构建层级：Dept(dept_name) → Project(project_name, 可选) → User(user_name, 可选)
    pub fn sync_namespace_from_identity(&self) {
        let agent_id = &self.config.identity.agent_id;
        let ns_full_path = match &self.config.identity.ns_full_path {
            Some(p) => Some(p.clone()),
            None => {
                // 尝试从 agent_id 解析：{company}_{department}_{name}
                let parts: Vec<&str> = agent_id.splitn(3, '_').collect();
                if parts.len() == 3 {
                    let company = parts[0];
                    let department = parts[1];
                    let name = parts[2];
                    let path = format!("/dept/{}/project/{}/user/{}", company, department, name);
                    Some(path)
                } else {
                    None
                }
            }
        };

        if let Some(ref full_path) = ns_full_path {
            // 确保 ns_full_path 被设置
            // 注意：config.identity 不是 pub 可写的，所以我们通过替换来更新
            // 这里只注册到 registry
            let mut reg = match self.namespace_registry.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::error!("namespace_registry Mutex 中毒，跳过命名空间注册");
                    return;
                }
            };
            let parts: Vec<&str> = full_path.trim_start_matches('/').split('/').collect();
            // parts 格式：["dept", "公司名", "project", "部门名", "user", "用户名"]
            if parts.len() >= 2 && parts[0] == "dept" {
                let dept_name = parts[1];
                let _ = reg.register(crate::namespace::Namespace::dept(dept_name), None);
                if parts.len() >= 4 && parts[2] == "project" {
                    let proj_name = parts[3];
                    let dept_path = format!("/dept/{}", dept_name);
                    let _ = reg.register(
                        crate::namespace::Namespace::project(proj_name),
                        Some(&dept_path),
                    );
                    if parts.len() >= 6 && parts[4] == "user" {
                        let user_name = parts[5];
                        let proj_path = format!("/dept/{}/project/{}", dept_name, proj_name);
                        let _ = reg.register(
                            crate::namespace::Namespace::user(user_name),
                            Some(&proj_path),
                        );
                    }
                }
            }
            drop(reg);
        }
    }

    /// 从所有 MCP 源获取工具列表（合并去重）
    /// P1-3 修复：同时更新 tool_route_cache 和 classifier
    /// 无可用 MCP 工具时的兜底工具（query_plate / query_sql），供 fetch_tools 与 fetch_tools_filtered 共用（R9）
    fn fallback_tools() -> Vec<ToolDef> {
        vec![
            ToolDef {
                type_: "function".to_string(),
                function: crate::llm::ToolDefFunction {
                    name: "query_plate".to_string(),
                    description: "查询车牌信息".to_string(),
                    parameters: serde_json::json!({"type": "object", "properties": {"plate": {"type": "string"}}}),
                },
            },
            ToolDef {
                type_: "function".to_string(),
                function: crate::llm::ToolDefFunction {
                    name: "query_sql".to_string(),
                    description: "执行 SQL 查询".to_string(),
                    parameters: serde_json::json!({"type": "object", "properties": {"query": {"type": "string"}}}),
                },
            },
        ]
    }

    // ── P1-5 降级收缩：工具列表健康探测 ──

    /// 业务 MCP 源名列表（除 memoria 外）。
    /// 用于降级模式推导（全部业务源不健康 → MemoriaReadonlyChat）。
    fn business_source_names(&self) -> Vec<String> {
        self.mcp_sources
            .iter()
            .filter(|s| s.name != "memoria")
            .map(|s| s.name.clone())
            .collect()
    }

    /// 当前降级模式（按需推导，不缓存）。
    fn current_degrade_mode(&self) -> DegradeMode {
        self.degrade.current_mode(&self.business_source_names())
    }

    /// 记录某 MCP 源宕机到审计（异步非阻塞）。
    async fn audit_tool_source_down(&self, source: &str, err: &str) {
        self.audit_logger
            .log_identity(
                &self.config.identity.agent_id,
                "mcp_source_down",
                &format!("source={} err={}", source, err),
            )
            .await;
    }

    /// P1-5：带健康探测的工具列表获取。
    ///
    /// - 已 `unhealthy` 的源：先探活一次，成功则恢复并重入，失败则维持剔除。
    /// - 正常源：失败则记录，连续失败达 [`UNHEALTHY_THRESHOLD`] 标记 `unhealthy`
    ///   并审计；无论哪种失败，本次都不并入其工具。
    ///
    /// 返回 `Some(tools)` 表示可用应并入；`None` 表示剔除（调用方 `continue`）。
    async fn list_tools_healthy(
        &self,
        source: &McpSource,
    ) -> Option<Vec<(String, String, serde_json::Value)>> {
        if self.degrade.is_unhealthy(&source.name) {
            // 探活检测恢复
            match source.client.list_tools().await {
                Ok(t) => {
                    self.degrade.record_success(&source.name);
                    tracing::info!(
                        "[DEGRADE] 源 {} 探活成功，已恢复并重新并入工具",
                        source.name
                    );
                    Some(t)
                }
                Err(e) => {
                    self.degrade.record_failure(&source.name, &e);
                    tracing::warn!("[DEGRADE] 源 {} 仍不健康，剔除其工具: {}", source.name, e);
                    None
                }
            }
        } else {
            match source.client.list_tools().await {
                Ok(t) => {
                    self.degrade.record_success(&source.name);
                    Some(t)
                }
                Err(e) => {
                    let became = self.degrade.record_failure(&source.name, &e);
                    if became {
                        tracing::warn!(
                            "[DEGRADE] 源 {} 连续失败达阈值({})，标记 unhealthy 并剔除，审计",
                            source.name,
                            UNHEALTHY_THRESHOLD
                        );
                        self.audit_tool_source_down(&source.name, &e).await;
                    } else {
                        tracing::warn!(
                            "[DEGRADE] 源 {} tools/list 失败(未达阈值 {}): {}",
                            source.name,
                            UNHEALTHY_THRESHOLD,
                            e
                        );
                    }
                    None
                }
            }
        }
    }

    /// 暴露当前降级状态（供管理端点 / 健康检查）。
    pub fn degrade_status(&self) -> serde_json::Value {
        let mode = self.current_degrade_mode();
        let sources: Vec<serde_json::Value> = self
            .degrade
            .health_snapshot()
            .into_iter()
            .map(|(name, unhealthy, failures, last_err)| {
                serde_json::json!({
                    "name": name,
                    "unhealthy": unhealthy,
                    "consecutive_failures": failures,
                    "last_error": last_err,
                })
            })
            .collect();
        serde_json::json!({
            "mode": mode.as_str(),
            "kill_switch": self.degrade.kill_switch_on(),
            "sources": sources,
        })
    }

    /// P1-5：运行时切换 Kill switch（管理端点调用）。
    pub fn set_kill_switch(&self, on: bool) {
        self.degrade.set_kill_switch(on);
    }

    /// P2-1：配额 + 降级联合运行状态（供 `/api/metrics`）。
    pub fn quota_status(&self) -> serde_json::Value {
        let quota = self
            .quota
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .status();
        serde_json::json!({
            "quota": quota,
            "degrade": self.degrade_status(),
        })
    }

    /// P2-1：管理员临时调整某命名空间配额策略（供 `/api/admin/quota` PUT）。
    pub fn set_ns_quota(&self, ns: &str, policy: crate::quota::NsQuotaPolicy) {
        self.quota
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_policy(ns, policy);
    }

    pub async fn fetch_tools(&self) -> Vec<ToolDef> {
        let mut all_tools: Vec<ToolDef> = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for (idx, source) in self.mcp_sources.iter().enumerate() {
            let tools = match self.list_tools_healthy(source).await {
                Some(t) => t,
                None => continue,
            };
            // 更新路由缓存和分类器
            {
                let mut cache = self.tool_route_cache.lock().await;
                let boundary = self.boundary.lock().await;
                let tool_names_descs: Vec<(String, String)> = tools
                    .iter()
                    .map(|(n, d, _)| (n.clone(), d.clone()))
                    .collect();
                for (name, _desc) in &tool_names_descs {
                    cache.insert(name.clone(), idx);
                }
                boundary.learn_tools(&tool_names_descs);
            }

            for (name, desc, params) in tools {
                if seen_names.contains(&name) {
                    continue;
                }
                seen_names.insert(name.clone());
                all_tools.push(ToolDef {
                    type_: "function".to_string(),
                    function: crate::llm::ToolDefFunction {
                        name,
                        description: desc,
                        parameters: params,
                    },
                });
            }
        }

        if all_tools.is_empty() {
            tracing::warn!("所有 MCP 源工具列表为空，使用 fallback");
            return Self::fallback_tools();
        }

        all_tools
    }

    /// 判断授权命名空间 `granted` 是否覆盖目标命名空间 `target`（层级 / 包含匹配）。
    /// 与 memoria `check_ns_access` 语义一致：
    /// - 完全一致；
    /// - target 是 granted 的后代（`granted/` 前缀）；
    /// - granted 是 target 的后代（两者共享同一子树，用于部门级工具对下属项目可见）。
    fn ns_covers(granted: &str, target: &str) -> bool {
        granted == "*"   // 超管通配：allowed_ns 含 "*" 即放行一切
            || granted == target
            || target.starts_with(&format!("{}/", granted))
            || granted.starts_with(&format!("{}/", target))
    }

    /// 仅返回调用者 `allowed_ns` 可见的 MCP 工具（按命名空间门控）。
    ///
    /// 规则：
    /// - 源未声明 `namespace` → 视为全局工具，人人可见；
    /// - 源声明了 `namespace` → 仅当 `allowed_ns` 中存在与其构成包含关系的授权 ns 时可见。
    pub async fn fetch_tools_filtered(&self, allowed_ns: &[String]) -> Vec<ToolDef> {
        let mut all_tools: Vec<ToolDef> = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for (idx, source) in self.mcp_sources.iter().enumerate() {
            // 命名空间门控：无 ns 的源全局可见；有 ns 的源需与 allowed_ns 存在包含关系
            if let Some(src_ns) = &source.namespace {
                let visible = allowed_ns.iter().any(|g| Self::ns_covers(g, src_ns));
                if !visible {
                    continue;
                }
            }
            let tools = match self.list_tools_healthy(source).await {
                Some(t) => t,
                None => continue,
            };
            {
                let mut cache = self.tool_route_cache.lock().await;
                let boundary = self.boundary.lock().await;
                let tool_names_descs: Vec<(String, String)> = tools
                    .iter()
                    .map(|(n, d, _)| (n.clone(), d.clone()))
                    .collect();
                for (name, _desc) in &tool_names_descs {
                    cache.insert(name.clone(), idx);
                }
                boundary.learn_tools(&tool_names_descs);
            }
            for (name, desc, params) in tools {
                if seen_names.contains(&name) {
                    continue;
                }
                seen_names.insert(name.clone());
                all_tools.push(ToolDef {
                    type_: "function".to_string(),
                    function: crate::llm::ToolDefFunction {
                        name,
                        description: desc,
                        parameters: params,
                    },
                });
            }
        }

        // [E2E-DEBUG] 端到端验证：打印 allowed_ns 与最终可见工具集
        let visible: Vec<&str> = all_tools.iter().map(|t| t.function.name.as_str()).collect();
        tracing::info!(allowed_ns = ?allowed_ns, visible_tools = ?visible, "e2e_fetch_tools_filtered");

        if all_tools.is_empty() {
            tracing::warn!("命名空间过滤后无可用 MCP 工具，使用 fallback");
            return Self::fallback_tools();
        }

        all_tools
    }

    /// 快速路径：Harness 模板匹配
    #[tracing::instrument(skip_all, fields(message_len = message.len()))]
    async fn try_harness_match(&self, message: &str, allowed_ns: &[String]) -> Option<String> {
        let context = serde_json::json!({
            "query": message,
            "agent_id": self.config.identity.agent_id,
        });

        let harness = self.harness.lock().await;
        let matches = harness.match_harness(&context, 3).ok()?;

        for m in &matches {
            let score = m.match_score * m.harness.confidence;
            if score < 0.5 {
                continue;
            }

            let steps = m.harness.steps.as_array()?;
            if steps.is_empty() {
                continue;
            }

            tracing::info!(match_score = score, harness = %m.harness.name, "Harness 命中（快速路径）");
            // P2-2: Harness 命中事件
            self.audit_logger
                .harness_hit(&self.config.identity.agent_id, "", &m.harness.name)
                .await;

            // 执行每个步骤（含 boundary 检查）
            let mut all_ok = true;
            for step in steps {
                let tool_name = step["tool"].as_str()?;
                let args = step.get("args").cloned().unwrap_or(serde_json::Value::Null);
                // P2-9: 执行前经过 boundary 检查
                let boundary = self.boundary.lock().await;
                let check = boundary.check_tool(
                    tool_name,
                    &args,
                    &self.config.identity.agent_id,
                    "user",
                    &PermissionLevel::Write,
                    self.current_ns_paths().as_deref(),
                );
                drop(boundary);
                // P2-3：boundary 结果写入 span（allow / reason 可观测）
                tracing::debug!(tool = %tool_name, allowed = check.allow, reason = %check.reason, "harness_step_boundary");
                if !check.allow {
                    tracing::warn!(tool = %tool_name, reason = %check.reason, "Harness 步骤被 boundary 拒绝");
                    all_ok = false;
                    break;
                }
                let result = self
                    .call_tool_routed(tool_name, "default", &args, allowed_ns, "")
                    .await;
                if result.is_err() {
                    all_ok = false;
                    break;
                }
            }

            // 记录使用情况
            let mut h = self.harness.lock().await;
            let _ = h.record_usage(m.harness.id, all_ok);
            drop(h);

            return Some(format!(
                "已执行 {}：{}",
                m.harness.name,
                if all_ok { "成功" } else { "部分失败" }
            ));
        }

        None
    }

    /// 白龙马 Phase C: 条件式本地资源门控
    /// 仅当用户消息命中资源规则、且快照确实存在可注入资源时，把资源块追加到 system prompt。
    /// 同步读 std::sync::Mutex（快照只读、无 await，不在持锁跨 await 风险区）。
    fn inject_resources_if_relevant(&self, system_prompt: &mut String, message: &str) {
        let snap = self
            .local_resources
            .lock()
            .expect("resource snapshot mutex poisoned");
        if let Some(block) = crate::resources::resource_block_for(message, &snap) {
            system_prompt.push_str("\n\n");
            system_prompt.push_str(&block);
            tracing::info!(target: "resources", "条件命中：注入本地资源快照块到 system prompt");
        }
    }

    /// 构建 system prompt
    /// P2-3 修复：支持自定义模板
    fn build_system_prompt(&self, knowledge: &[String]) -> String {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();

        // P2-3: 如果有自定义模板，使用它
        let mut prompt = if let Some(ref template) = self.config.system_prompt_template {
            template
                .replace("{agent}", &self.config.identity.agent_id)
                .replace("{now}", &now)
        } else {
            // 内置默认模板
            format!(
                r#"你是 {agent}，固废智能运营台的 AI 助手，负责帮助运营人员查询数据、排查问题、管理系统。

## 回答风格
- 基于数据，引用来源，不猜测
- 查车牌等简单查询直接秒回，不绕弯
- 遇到问题先查数据再给分析，不要反问"请提供更多信息"
- 能修的直接调工具修，不能修的说明原因
- 修改前向用户确认，确认后直接执行

        ## 工具使用
        你可用的工具由系统按当前身份和命名空间动态提供，完整的真实工具名与描述见对话中
        "当前真实可用工具"清单（每次请求都注入，以该清单为准）。

        调用工具时：
        1. 只能使用清单中列出的真实工具名，严禁臆造（如 query_sql / query_plate 等旧名已不存在）
        2. 直接传递正确的参数，不要猜测参数名；参数必须符合工具的 JSON Schema（required 字段必填、类型正确）
        3. 查询类工具不需要确认，修改/外发类工具需要先确认

## 边界
- ❌ 不能执行 INSERT/UPDATE/DELETE SQL
- ❌ 不能改代码、不能执行系统命令
- ❌ 不能导出数据到外部
- ❌ 不能泄露敏感信息（密码、API Key）
- ✅ 查询类直接执行，不需要确认
- ✅ 改数据前要确认，确认后直接执行

当前时间：{now}
"#,
                agent = self.config.identity.agent_id,
                now = now,
            )
        };

        if !knowledge.is_empty() {
            prompt.push_str("## 记忆档案\n");
            for k in knowledge {
                prompt.push_str(&format!("- {}\n", k));
            }
            prompt.push('\n');
        }

        prompt.push_str(
            "## 故障排查规则\n\
             - 用户说'为什么没变化'时：先查 DB 确认状态，再分析原因，给出结论\n\
             - 遇到问题按链路思考：判断类型→查数据→对比定位→解释原因→给出步骤\n\
             - 能修的直接调工具修，不要只给建议\n\
             - 记住对话中提到过的车牌、日期、公司，不要重复问\n\
             - 做不到的直接说'做不到'并说明原因\n\n\
             ## 数据库结构\n\
             核心表 vehicle_entrance 的字段：\n\
             - id, entrance_date, license_plate, company_name, weight, waste_type\n\
             - entrance_time, status, remark, goods_name\n\n\
             实验数据表 experiment_data 的字段：\n\
             - id, entrance_date, license_plate, company_name\n\
             - test_item（检测项目，如'含水率'）, test_value（数值）, test_unit（单位如'%'）\n\
             - sample_weight（样品重量）, source, remark\n\
             注意：experiment_data 不是每车都有，用户问'含水率'时查此表。\n\n\
             其他核心表：\n\
             - vehicle_whitelist（白名单）: license_plate, company_name, waste_type\n\
             - indicator_history（指标）: indicator_name, indicator_value, data_date\n\
             - sample_records（取样）: serial_no, license_plate, sample_weight, sample_time\n",
        );

        prompt
    }

    /// 洞见发现：拉取最近 7 天数据，LLM 分析模式，存入 Memoria
    pub async fn run_insights(&self, allowed_ns: &[String]) -> String {
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let week_ago = (chrono::Local::now() - chrono::Duration::days(7))
            .format("%Y-%m-%d")
            .to_string();
        let data = self
            .call_tool_routed(
                "query_entrance",
                "default",
                &serde_json::json!({
                    "date_from": week_ago, "date_to": today, "limit": 500,
                }),
                allowed_ns,
                "",
            )
            .await
            .unwrap_or_default();
        let stats = self
            .call_tool_routed(
                "query_monthly_stats",
                "default",
                &serde_json::json!({
                    "year": chrono::Local::now().year(), "month": chrono::Local::now().month(),
                }),
                allowed_ns,
                "",
            )
            .await
            .unwrap_or_default();

        let prompt = format!(
            "你是固废运营数据分析师。分析最近7天入厂数据，找出有意义的模式或异常。\
             没有发现就输出'无异常'。每个发现一句话，最多3个。\n\n## 近7天数据\n{}\n\n## 本月统计\n{}",
            data.chars().take(3000).collect::<String>(),
            stats.chars().take(1000).collect::<String>(),
        );
        let msg = crate::llm::Message {
            role: "system".to_string(),
            content: Some(prompt),
            tool_calls: None,
            tool_call_id: None,
        };
        let reply = match self.llm.chat(&[msg], &[]).await {
            Ok(r) => r.text.trim().to_string(),
            Err(e) => return format!("洞见失败: {}", e),
        };
        if reply.is_empty() || reply == "无异常" {
            return "洞见: 无异常".to_string();
        }
        let _ = self
            .mcp
            .call(
                "memory_remember",
                &serde_json::json!({
                    "content": format!("[洞见] {} | {}~{}", reply, week_ago, today),
                    "tags": ["insight", "auto_discovered"], "confidence": 70,
                }),
            )
            .await;
        format!("洞见: {}", reply)
    }

    /// P2.2d：LLM 批量抽取 text_signals → `signal:*` tags（consolidate retain 路径）。
    async fn llm_extract_signal_tags_batch(&self, texts: &[String]) -> Vec<Vec<String>> {
        if !crate::text_signals::llm_text_signals_enabled() || texts.is_empty() {
            return vec![Vec::new(); texts.len()];
        }
        let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
        let prompt = crate::text_signals::build_extract_prompt(&refs);
        let msg = crate::llm::Message {
            role: "system".to_string(),
            content: Some(prompt),
            tool_calls: None,
            tool_call_id: None,
        };
        match self.llm.chat(&[msg], &[]).await {
            Ok(reply) => {
                let items = crate::text_signals::parse_llm_signal_array(reply.text.trim());
                crate::text_signals::map_llm_signals_by_index(&items, texts.len())
            }
            Err(e) => {
                tracing::warn!("[text_signals] consolidate LLM 抽取失败: {}", e);
                vec![Vec::new(); texts.len()]
            }
        }
    }

    /// P2.2d：单条 retain 路径 LLM 抽取（需 AGENT_TEXT_SIGNALS_LLM_RETAIN=1）。
    async fn llm_extract_signal_tags_single(&self, content: &str) -> Vec<String> {
        if !crate::text_signals::llm_retain_signals_enabled() || content.trim().is_empty() {
            return Vec::new();
        }
        let prompt = crate::text_signals::build_extract_prompt(&[content]);
        let msg = crate::llm::Message {
            role: "system".to_string(),
            content: Some(prompt),
            tool_calls: None,
            tool_call_id: None,
        };
        match self.llm.chat(&[msg], &[]).await {
            Ok(reply) => {
                let items = crate::text_signals::parse_llm_signal_array(reply.text.trim());
                items
                    .first()
                    .map(crate::text_signals::signal_tags_from_llm_item)
                    .unwrap_or_default()
            }
            Err(e) => {
                tracing::warn!("[text_signals] retain LLM 抽取失败: {}", e);
                Vec::new()
            }
        }
    }

    /// PR2：写入前门提取压缩核心逻辑。
    ///
    /// 流程：LLM 抽取原子事实 → 语义保真校验 → 写 raw 父 + N 原子事实（parent_id 回指）。
    /// 任意环节失败返回 Err，由 `call_tool_routed` 降级为单次原样写入（不丢数据）。
    async fn run_memory_extraction(
        &self,
        original_args: &serde_json::Value,
        raw_content: &str,
        trace_id: &str,
    ) -> Result<String, String> {
        // 1. LLM 抽取
        let prompt = crate::memory_extract::build_extract_prompt(raw_content);
        let msg = crate::llm::Message {
            role: "system".to_string(),
            content: Some(prompt),
            tool_calls: None,
            tool_call_id: None,
        };
        let reply = self
            .llm
            .chat(&[msg], &[])
            .await
            .map_err(|e| format!("LLM 提取失败: {e}"))?;
        let ex = crate::memory_extract::parse_extraction(&reply.text)
            .ok_or_else(|| "LLM 返回无法解析为提取结构".to_string())?;

        // 2. 已原子化（单条且等价于原文）→ 无需分解，降级到原样写入，避免重复
        if !crate::memory_extract::should_decompose(&ex, raw_content) {
            return Err("原文已是原子事实，无需分解".to_string());
        }

        // 3. 语义保真校验：关键数字 / 日期不得丢失
        if !crate::memory_extract::fidelity_ok(raw_content, &ex) {
            return Err("语义保真校验不过（关键数字/日期丢失）".to_string());
        }

        // 4. 拿到 memoria client（记忆工具恒定走 self.mcp 源）
        let client = self.find_mcp_for_tool_async("memory_remember").await;

        // 5. 写 raw 父（存档原文，memory_type=raw，降低优先级让检索优先命中原子事实）
        let mut parent_args = original_args.clone();
        if let Some(o) = parent_args.as_object_mut() {
            o.insert("content".to_string(), serde_json::Value::String(raw_content.to_string()));
            o.insert("memory_type".to_string(), serde_json::Value::String("raw".to_string()));
            o.remove("parent_id");
            o.remove("raw_ref");
            // 降低 raw 存档优先级（memoria importance 为整数），让检索优先命中原子事实
            if !o.contains_key("importance") {
                o.insert("importance".to_string(), serde_json::Value::from(1_i64));
            }
            if let Some(actor) = &ex.actor {
                o.insert("actor".to_string(), serde_json::Value::String(actor.clone()));
            }
        }
        let parent_resp = client
            .call("memory_remember", &parent_args)
            .await
            .map_err(|e| format!("raw 父写入失败: {e}"))?;
        let parent_id = crate::memory_extract::extract_id(&parent_resp)
            .ok_or_else(|| "无法解析 raw 父 id".to_string())?;

        // 6. 写每条原子事实（facts + entities + preferences + relations），均挂回 parent
        let mut written = Vec::new();
        let atom_items: Vec<(&String, &str)> = ex
            .facts
            .iter()
            .map(|t| (t, ex.memory_type.as_deref().unwrap_or("declarative")))
            .chain(ex.entities.iter().map(|t| (t, "entity")))
            .chain(ex.preferences.iter().map(|t| (t, "preference")))
            .chain(ex.relations.iter().map(|t| (t, "relation")))
            .collect();

        for (text, mt) in atom_items {
            let mut a = original_args.clone();
            if let Some(o) = a.as_object_mut() {
                o.insert("content".to_string(), serde_json::Value::String(text.clone()));
                o.insert("parent_id".to_string(), serde_json::Value::String(parent_id.clone()));
                o.insert("raw_ref".to_string(), serde_json::Value::String(parent_id.clone()));
                o.insert("memory_type".to_string(), serde_json::Value::String(mt.to_string()));
                if let Some(actor) = &ex.actor {
                    o.insert("actor".to_string(), serde_json::Value::String(actor.clone()));
                }
                // 原子事实略高于默认（memoria importance 为整数），优先于 raw 父被检索
                if !o.contains_key("importance") {
                    o.insert("importance".to_string(), serde_json::Value::from(4_i64));
                }
            }
            if let Ok(r) = client.call("memory_remember", &a).await {
                if let Some(id) = crate::memory_extract::extract_id(&r) {
                    written.push(id);
                }
            }
        }

        let summary = format!(
            "{{\"status\":\"extracted\",\"parent_id\":\"{}\",\"facts\":{},\"entities\":{},\"preferences\":{},\"relations\":{},\"written_ids\":{}}}",
            parent_id,
            ex.facts.len(),
            ex.entities.len(),
            ex.preferences.len(),
            ex.relations.len(),
            serde_json::to_string(&written).unwrap_or_else(|_| "[]".to_string())
        );
        tracing::debug!("[PR2] 提取汇总 trace_id={} : {}", trace_id, summary);
        Ok(summary)
    }

    /// 暗知识层 A2：通用夜间巩固编排器（泛化 run_insights）
    ///
    /// 流程（agent-core 出脑子，memoria 当哑存储）：
    ///   1. dream_state_get 取游标 cursor_ts（该 ns 上次处理到的位置）
    ///   2. memory_fetch_unconsolidated 拉取 cursor 之后的未巩固观察
    ///   3. LLM 从观察中提炼 ≤5 条可复用模式（暗知识）
    ///   4. 每条 pattern 经 memory_remember(category=pattern) 写回 memoria
    ///   5. dream_state_update 推进游标（幂等：重跑不会重复处理同一批）
    ///
    /// 以 admin 身份调用 memoria（系统维护任务，合法跨命名空间读取观察原料）。
    /// ns 隔离：每个 ns 独立游标、独立 pattern 库。
    pub async fn consolidate(&self, ns: &str) -> String {
        // 系统维护任务：以本 Agent 身份 + dashboard badge 跨 ns 读观察（与注册/代理路径一致；
        // 勿用字面 "admin"——Memoria 侧该身份可能过期导致 401）。
        let dash_badge = std::env::var("MEMORIA_DASHBOARD_BADGE")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("MEMORIA_ADMIN_KEY").ok())
            .unwrap_or_default();
        let mem_client = if dash_badge.is_empty() {
            self.mcp.clone()
        } else {
            McpClient::new(
                &self.config.memoria_url,
                &self.config.identity.agent_id,
                &dash_badge,
            )
        };

        // 1. 取游标
        let ds_raw = mem_client
            .call(
                "dream_state_get",
                &serde_json::json!({
                    "phase": "consolidate", "namespace": ns
                }),
            )
            .await
            .unwrap_or_default();
        let cursor_ts = serde_json::from_str::<serde_json::Value>(&ds_raw)
            .ok()
            .and_then(|v| {
                v.get("cursor_ts")
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "1970-01-01T00:00:00".to_string());

        // 2. 拉原料
        let raw = mem_client
            .call(
                "memory_fetch_unconsolidated",
                &serde_json::json!({
                    "since": cursor_ts, "limit": 200, "namespace": ns
                }),
            )
            .await
            .unwrap_or_default();
        let items: Vec<serde_json::Value> = serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.get("items").and_then(|i| i.as_array()).cloned())
            .unwrap_or_default();
        if items.is_empty() {
            return format!("consolidate[{}]: 无新观察（cursor={}）", ns, cursor_ts);
        }

        // 3. LLM 提炼 ≤5 pattern
        let mut obs_lines: Vec<String> = Vec::new();
        let mut max_ts = cursor_ts.clone();
        for it in &items {
            if let Some(c) = it.get("content").and_then(|c| c.as_str()) {
                let c = c.trim();
                if !c.is_empty() {
                    obs_lines.push(c.to_string());
                }
            }
            if let Some(ts) = it.get("created_at").and_then(|t| t.as_str()) {
                if ts > max_ts.as_str() {
                    max_ts = ts.to_string();
                }
            }
        }
        let obs_text = obs_lines.join("\n- ");
        let prompt = format!(
            "你是知识巩固引擎。以下是一批\"观察\"记忆，请从中提炼可复用的高层模式（暗知识）：\
             反复出现的规律、隐含业务约束、用户偏好、运营常识。每条模式用一句话陈述，最多 5 条。\
             若观察里没有可提炼的模式，只输出\"无模式\"。\n\n## 待巩固观察（{} 条，命名空间 {}）\n- {}",
            items.len(), ns, obs_text.chars().take(6000).collect::<String>()
        );
        let msg = crate::llm::Message {
            role: "system".to_string(),
            content: Some(prompt),
            tool_calls: None,
            tool_call_id: None,
        };
        let reply = match self.llm.chat(&[msg], &[]).await {
            Ok(r) => r.text.trim().to_string(),
            Err(e) => return format!("consolidate[{}] LLM 失败: {}", ns, e),
        };
        if reply.is_empty() || reply == "无模式" {
            // 无模式也要推进游标，避免反复扫描同一批
            let _ = mem_client
                .call(
                    "dream_state_update",
                    &serde_json::json!({
                        "phase": "consolidate", "namespace": ns, "cursor_ts": max_ts, "items_out": 0
                    }),
                )
                .await;
            return format!("consolidate[{}]: 无模式（已推进游标 {}）", ns, max_ts);
        }

        // 4. 写回 pattern（≤5）
        let patterns: Vec<&str> = reply
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .take(5)
            .collect();
        let clean_patterns: Vec<String> = patterns
            .iter()
            .map(|p| {
                p.trim_start_matches(|c: char| {
                    c.is_numeric() || c == '.' || c == '-' || c == '、' || c == ' '
                })
                .to_string()
            })
            .collect();

        // P2.2d：consolidate retain 路径 — LLM 抽取 signal tags 并随 memory_remember 持久化
        let signal_tags_by_idx = self
            .llm_extract_signal_tags_batch(&clean_patterns)
            .await;

        let mut written = 0u64;
        for (i, clean) in clean_patterns.iter().enumerate() {
            let mut args = serde_json::json!({
                "content": format!("[pattern] {} | ns={}", clean, ns),
                "tags": ["pattern", "auto_consolidated"],
                "category": "pattern",
                "confidence": 70,
                "namespace": ns
            });
            if let Some(st) = signal_tags_by_idx.get(i) {
                crate::text_signals::enrich_remember_args(&mut args, st);
            }
            let _ = mem_client.call("memory_remember", &args).await;
            written += 1;
        }

        // 5. 推进游标
        let _ = mem_client.call("dream_state_update", &serde_json::json!({
            "phase": "consolidate", "namespace": ns, "cursor_ts": max_ts, "items_out": written
        })).await;

        // 6. B 阶段：NER 实体提取（仅在提炼出 pattern 后才做，避免浪费 LLM 调用）
        if written > 0 {
            let entity_prompt = format!(
                "你负责从以下观察和已提炼模式中识别实体（person/system/tool/concept/org/project/location/event）及关系。\
                 仅输出纯 JSON，不要任何前缀后缀。\
                 若没有实体，输出 {{\"entities\":[],\"edges\":[]}}\n\n## 观察（{} 条）\n- {}\n\n## 已提炼模式\n{}",
                items.len(),
                obs_text.chars().take(3000).collect::<String>(),
                reply.chars().take(1000).collect::<String>(),
            );
            let msg2 = crate::llm::Message {
                role: "system".to_string(),
                content: Some(entity_prompt),
                tool_calls: None,
                tool_call_id: None,
            };
            if let Ok(ner_reply) = self.llm.chat(&[msg2], &[]).await {
                let ner_text = ner_reply.text.trim().to_string();
                // 解析 JSON（尝试直接解析，失败则查找最外层 {}）
                let ner_json: Option<serde_json::Value> =
                    serde_json::from_str(&ner_text).ok().or_else(|| {
                        let start = ner_text.find('{')?;
                        let end = ner_text.rfind('}')?;
                        serde_json::from_str(&ner_text[start..=end]).ok()
                    });
                if let Some(j) = ner_json {
                    let entities = j
                        .get("entities")
                        .and_then(|e| e.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let edges = j
                        .get("edges")
                        .and_then(|e| e.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let mut entity_id_map: std::collections::HashMap<String, String> =
                        std::collections::HashMap::new();
                    for ent in &entities {
                        let name = ent.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let etype = ent.get("type").and_then(|t| t.as_str()).unwrap_or("other");
                        let summary = ent.get("summary").and_then(|s| s.as_str()).unwrap_or("");
                        // 确定性 ID = MD5 前缀 + ns + name
                        // 确定性 ID = 命名空间名小写+实体名小写，去特殊字符
                        let clean_id = |s: &str| -> String {
                            s.to_lowercase()
                                .chars()
                                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                                .take(40)
                                .collect::<String>()
                        };
                        let entity_id = format!("ent:{}_{}", clean_id(ns), clean_id(name));
                        entity_id_map.insert(name.to_string(), entity_id.clone());
                        let _ = mem_client
                            .call(
                                "entity_upsert",
                                &serde_json::json!({
                                    "entity_id": entity_id,
                                    "name": name,
                                    "entity_type": etype,
                                    "summary": summary,
                                    "namespace": ns
                                }),
                            )
                            .await;
                        // 为每条提及该实体的观察记录 mention
                        for item in &items {
                            let content =
                                item.get("content").and_then(|c| c.as_str()).unwrap_or("");
                            let mem_id = item.get("id").and_then(|i| i.as_str()).unwrap_or("");
                            if content.contains(name) {
                                let _ = mem_client.call("entity_add_mention", &serde_json::json!({
                                    "entity_id": entity_id,
                                    "memory_id": mem_id,
                                    "context": content.chars().take(200).collect::<String>(),
                                    "namespace": ns
                                })).await;
                            }
                        }
                        // 将实体摘要同时以 fact 记忆存入（便于搜索召回）
                        if !summary.is_empty() {
                            let _ = mem_client.call("memory_remember", &serde_json::json!({
                                "content": format!("[entity:{}] {} — {}", etype, name, summary),
                                "category": "fact",
                                "tags": ["entity", etype],
                                "namespace": ns
                            })).await;
                        }
                    }
                    let mut edge_count = 0u64;
                    for edge in &edges {
                        let src = edge.get("source").and_then(|s| s.as_str()).unwrap_or("");
                        let tgt = edge.get("target").and_then(|t| t.as_str()).unwrap_or("");
                        let rel = edge
                            .get("relation")
                            .and_then(|r| r.as_str())
                            .unwrap_or("related_to");
                        let evidence = edge.get("evidence").and_then(|e| e.as_str()).unwrap_or("");
                        if let (Some(src_id), Some(tgt_id)) =
                            (entity_id_map.get(src), entity_id_map.get(tgt))
                        {
                            let _ = mem_client
                                .call(
                                    "entity_add_edge",
                                    &serde_json::json!({
                                        "source_entity_id": src_id,
                                        "target_entity_id": tgt_id,
                                        "relation_type": rel,
                                        "evidence": evidence,
                                        "namespace": ns
                                    }),
                                )
                                .await;
                            edge_count += 1;
                        }
                    }
                    // Phase B / M1.3：实体共现回填 — 同条记忆共现的实体对补 related_to 边
                    //（轻量启发式；不上 cross-encoder；冲突仍走 supersede，禁止 DELETE）
                    let mut cooccur_edges = 0u64;
                    let mut mem_to_ents: std::collections::HashMap<String, Vec<String>> =
                        std::collections::HashMap::new();
                    for (ename, eid) in &entity_id_map {
                        for item in &items {
                            let content =
                                item.get("content").and_then(|c| c.as_str()).unwrap_or("");
                            let mem_id =
                                item.get("id").and_then(|i| i.as_str()).unwrap_or("");
                            if !mem_id.is_empty() && content.contains(ename.as_str()) {
                                mem_to_ents
                                    .entry(mem_id.to_string())
                                    .or_default()
                                    .push(eid.clone());
                            }
                        }
                    }
                    for (mem_id, eids) in &mem_to_ents {
                        let mut uniq = eids.clone();
                        uniq.sort();
                        uniq.dedup();
                        for i in 0..uniq.len() {
                            for j in (i + 1)..uniq.len() {
                                let _ = mem_client
                                    .call(
                                        "entity_add_edge",
                                        &serde_json::json!({
                                            "source_entity_id": uniq[i],
                                            "target_entity_id": uniq[j],
                                            "relation_type": "related_to",
                                            "evidence": format!("cooccur in memory {}", mem_id),
                                            "namespace": ns
                                        }),
                                    )
                                    .await;
                                cooccur_edges += 1;
                            }
                        }
                    }
                    if !entities.is_empty() {
                        tracing::info!(
                            "consolidate[{}] NER: {} entities, {} edges, {} cooccur",
                            ns,
                            entities.len(),
                            edge_count,
                            cooccur_edges
                        );
                    }
                }
            }
        }

        // 7. PR4 Phase A：演化决策 — 为尚未演化的观察记忆合成 evolved_context（结合已提炼 pattern）
        //    批处理 + 分批（每批 ≤80 条）限制 LLM 输出体积，避免逐条演化写风暴；
        //    经 MCP memory_evolve 落库（Memoria 哑存储，守 H1/H2）。绝不进 call_tool_routed 热路径。
        if written > 0 && crate::memory_evolve::agent_memory_evolve_enabled() {
            let evo_items: Vec<(String, String)> = items
                .iter()
                .filter_map(|it| {
                    let id = it.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                    let content =
                        it.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();
                    if id.is_empty() || content.is_empty() {
                        None
                    } else {
                        Some((id, content))
                    }
                })
                .collect();
            if !evo_items.is_empty() {
                let model = self.config.llm.model.clone();
                let patterns_txt = reply.chars().take(1500).collect::<String>();
                // PR5：演化提示词动态化（默认回退 DEFAULT_EVOLVE_PROMPT，元进化 rollout 后读动态版）
                let base_prompt = self.meta_evolver.current_prompt().await;
                let mut evolved = 0u64;
                for chunk in evo_items.chunks(80) {
                    let evo_prompt = format!(
                        "{}\n\n## 已提炼模式\n{}\n\n## 待演化观察（{} 条）\n{}",
                        base_prompt,
                        patterns_txt,
                        chunk.len(),
                        chunk
                            .iter()
                            .map(|(id, c)| {
                                format!("{}: {}", id, c.chars().take(300).collect::<String>())
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    );
                    let msg3 = crate::llm::Message {
                        role: "system".to_string(),
                        content: Some(evo_prompt),
                        tool_calls: None,
                        tool_call_id: None,
                    };
                    if let Ok(evo_reply) = self.llm.chat(&[msg3], &[]).await {
                        let pairs = crate::memory_evolve::parse_evolution_array(&evo_reply.text);
                        for (eid, ectx) in pairs {
                            // 仅演化本批次内的 id（防御 LLM 编造 id 跨批）
                            if chunk.iter().any(|(id, _)| id == &eid) {
                                // PR5 P-D 门控：高风险演化（supersede/override 或高危工具）需过闸。
                                // 当前 change_type=context_update 不触发；保留以应未来路径。Auto 模式直接放行。
                                if self.approval_gate.is_high_risk("memory_evolve", Some("context_update")) {
                                    if let Err(rej) = self.approval_gate.check("memory_evolve", Some("context_update")) {
                                        tracing::warn!(target: "agent.evolve", "演化被门控拒绝: {}", rej);
                                        continue;
                                    }
                                }
                                let _ = mem_client
                                    .call(
                                        "memory_evolve",
                                        &serde_json::json!({
                                            "target_id": eid,
                                            "namespace": ns,
                                            "evolved_context": ectx,
                                            "model": model,
                                            "change_type": "context_update"
                                        }),
                                    )
                                    .await;
                                evolved += 1;
                            }
                        }
                    }
                }
                if evolved > 0 {
                    tracing::info!(
                        "consolidate[{}] PR4 演化: {} 条记忆写入 evolved_context",
                        ns,
                        evolved
                    );
                }
            }
        }

        format!(
            "consolidate[{}]: 从 {} 条观察提炼 {} 条 pattern（cursor→{}）",
            ns,
            items.len(),
            written,
            max_ts
        )
    }

    /// PR5：手动触发一轮元进化（L2 闭环）。受 `meta_evolution.enabled` 开关保护。
    pub async fn run_meta_evolution(&self, ns: &str) -> serde_json::Value {
        if !self.config.meta_evolution.enabled {
            return serde_json::json!({
                "status": "skipped",
                "reason": "meta_evolution.enabled=false（受控开启，需在 agent.toml 显式开启）"
            });
        }
        // 与 consolidate 一致的 dash_badge 取权逻辑（以本 Agent 身份 + dashboard badge 跨 ns 读）
        let dash_badge = std::env::var("MEMORIA_DASHBOARD_BADGE")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("MEMORIA_ADMIN_KEY").ok())
            .unwrap_or_default();
        let mem_client = if dash_badge.is_empty() {
            self.mcp.clone()
        } else {
            McpClient::new(
                &self.config.memoria_url,
                &self.config.identity.agent_id,
                &dash_badge,
            )
        };
        let res = self.meta_evolver.run_once(&mem_client, ns).await;
        res.to_json()
    }

    /// PR5：元进化状态（供 /api/meta-evolution/status）
    pub async fn meta_evolution_status(&self) -> serde_json::Value {
        let enabled = self.config.meta_evolution.enabled;
        let hash = self.meta_evolver.current_prompt_hash().await;
        let store = self.meta_store.lock().await;
        let latest = store.latest_feedback();
        let count = store.feedback_count();
        drop(store);
        let last_run_at = self.meta_evolver.last_run_at_secs().await;
        serde_json::json!({
            "enabled": enabled,
            "approval_mode": self.config.safety.approval_mode.as_str(),
            "current_prompt_hash": hash,
            "feedback_count": count,
            "last_run_at": last_run_at,
            "last_feedback": latest,
            "config": {
                "window_days": self.config.meta_evolution.window_days,
                "min_samples": self.config.meta_evolution.min_samples,
                "improve_threshold": self.config.meta_evolution.improve_threshold,
                "max_rollback_rate": self.config.meta_evolution.max_rollback_rate,
                "cooldown_hours": self.config.meta_evolution.cooldown_hours,
            }
        })
    }
}

fn now_secs() -> f64 {
    harness::now_secs()
}
