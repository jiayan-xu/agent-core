//! Agent 核心 — chat 循环 + 工具执行

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::audit::AuditLogger;
use crate::boundary::{self, ComplianceBoundary, PermissionLevel};
use crate::harness::{self, ExecutionLog, HarnessStore};
use crate::llm::{LlmClient, LlmConfig, Message, ToolDef};
use crate::mcp_client::{McpClient, McpSource};
use crate::session::{PendingAction, SessionManager, SessionState};
use crate::namespace::NamespaceRegistry;
use crate::approval::ApprovalManager;
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
    /// 可选 MCP 源（名称 + URL + 令牌 + 可选的 stdio (命令, 参数)），
    /// 例 HTTP:  [("dashboard", "http://127.0.0.1:8000", "", None)]
    /// 例 stdio: [("dashboard", "", "", Some(("python".into(), ["-m","mcp_server"].map(String::from).to_vec())))]
    pub additional_mcp: Vec<(String, String, String, Option<(String, Vec<String>)>)>,
    pub skill_whitelist: Option<Vec<String>>,
    pub max_tool_rounds: u32,
    pub parent_permission: PermissionLevel,
    /// 启用组合路由（多 Skill 分解 + 按序执行）
    pub enable_compositional_routing: bool,
    /// P2-3: 自定义 system prompt 模板（可选）
    /// 如果为 None，使用内置默认模板
    pub system_prompt_template: Option<String>,
    /// P2-D: 审批人 ID（可选）。设置后 YELLOW 工具需经此人审批
    pub approver_id: Option<String>,
}

/// Agent 核心
pub struct AgentCore {
    pub config: AgentConfig,
    pub mcp: McpClient,  // Memoria MCP（主）
    pub mcp_sources: Vec<McpSource>,  // 全部 MCP 源（含 Memoria）
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
}

struct InboxCache {
    data: Option<Vec<serde_json::Value>>,
    expires_at: f64,
}

impl InboxCache {
    fn new() -> Self {
        InboxCache { data: None, expires_at: 0.0 }
    }
    fn is_fresh(&self) -> bool {
        let now = now_secs();
        self.data.is_some() && now < self.expires_at
    }
}

impl AgentCore {
    /// 创建 Agent 核心
    pub fn new(config: AgentConfig, harness: HarnessStore) -> Self {
        let mcp = McpClient::new(&config.memoria_url, &config.identity.agent_id, &config.identity.badge_token);
        // 构建 MCP 源列表（Memoria 始终为第一个源）
        let mut mcp_sources = vec![McpSource::memoria(mcp.clone())];
        for (name, url, token, stdio_opt) in &config.additional_mcp {
            if let Some((cmd, args)) = stdio_opt {
                let client = McpClient::new_stdio(cmd, args);
                mcp_sources.push(McpSource::new(name, client));
            } else {
                let badge = if token.is_empty() { &config.identity.badge_token } else { token };
                let client = McpClient::new(url, &config.identity.agent_id, badge);
                mcp_sources.push(McpSource::new(name, client));
            }
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
        }
    }

    /// 入口：处理用户消息，返回回复
    ///
    /// 集成确认状态机（借鉴 task-workflow）：
    /// - 新任务 → 复述确认（Step 1）→ 执行（Step 2）→ 交付（Step 3）
    /// - 简单查询 → 直接执行
    /// - 已确认会话 → 话题切换检测
    pub async fn chat(&self, message: &str, user_id: &str, session_id: &str) -> String {
        let confirm_words = ["确认", "确认添加", "确认执行", "添加", "是", "是的", "对", "执行", "确定", "可以"];
        let trimmed = message.trim();

        // ── 0a. 工具级确认（现有）：pending_actions 中的操作等待确认 ──
        if confirm_words.contains(&trimmed) {
            if let Some(action) = self.session_manager.take_pending_action(session_id).await {
                let result = match self.call_tool_routed(&action.tool_name, &action.arguments).await {
                    Ok(text) => text,
                    Err(e) => format!("执行失败: {}", e),
                };
                let desc = action.description.chars().take(120).collect::<String>();
                let result_short = result.chars().take(300).collect::<String>();
                let reply = format!("✅ 操作已执行成功！\n\n操作内容：{}\n\n{}", desc, result_short);
                let ns = self.config.identity.ns();
                let db_path = self.harness.lock().await.db_path();
                self.session_manager.save_to_history(session_id, &ns, &db_path, message, &reply).await;
                return reply;
            }
        }

        // ── 0b. 任务级确认状态机 ──
        let state = self.session_manager.get_state(session_id).await;

        match state {
            // ── 等待用户确认理解 ──
            SessionState::AwaitingConfirmation => {
                if confirm_words.contains(&trimmed) {
                    let original = self.session_manager.take_original_message(session_id).await
                        .unwrap_or_else(|| message.to_string());
                    self.session_manager.set_state(session_id, SessionState::Confirmed).await;
                    return self.execute_chat(&original, user_id, session_id).await;
                }
                // 修改/补充 → 保留 AwaitingConfirmation，重新复述
                return self.rephrase_and_confirm(message, user_id, session_id).await;
            }

            // ── 已确认，正常执行 ──
            SessionState::Confirmed => {
                // 话题切换检测
                if let Some(task) = self.session_manager.get_original_message(session_id).await {
                    if boundary::TaskConfirmationGate::detect_topic_switch(message, &task) {
                        return self.handle_topic_switch(message, session_id).await;
                    }
                }
                return self.execute_chat(message, user_id, session_id).await;
            }

            // ── 新会话 ──
            SessionState::New => {
                if boundary::TaskConfirmationGate::requires_confirmation(message) {
                    self.session_manager.set_state(session_id, SessionState::AwaitingConfirmation).await;
                    return self.rephrase_and_confirm(message, user_id, session_id).await;
                }
                // 简单查询 → 直接执行
                self.session_manager.set_state(session_id, SessionState::Confirmed).await;
                return self.execute_chat(message, user_id, session_id).await;
            }
        }
    }

    /// 已确认会话的执行路径（原 chat() 主体 + Step 前缀）
    async fn execute_chat(&self, message: &str, user_id: &str, session_id: &str) -> String {
        // ── 0. 组合路由路径：多 Skill 分解 + 按序执行 ──
        if self.config.enable_compositional_routing {
            let tools = self.fetch_tools().await;
            if !tools.is_empty() {
                match crate::composer::decompose(&self.llm, message, &tools).await {
                    Ok(plan) if plan.steps.len() > 1 => {
                        let result = self.execute_plan(&plan, session_id).await
                            .unwrap_or_else(|e| format!("组合执行失败: {}", e));

                        // 蒸馏闭环：记录组合执行的摘要日志，触发 Harness 蒸馏
                        let is_success = result.starts_with("执行结果") && !result.contains("失败");
                        {
                            let mut log = self.execution_log.lock().await;
                            // 用消息中的关键词作为 trigger_conditions（供后续 Harness 匹配）
                            let query_preview: String = message.chars().take(80).collect();
                            log.push(crate::harness::ExecutionLog {
                                name: format!("composer_{}", message.chars().take(20).collect::<String>()),
                                trigger_conditions: serde_json::json!({"query": query_preview}),
                                steps: serde_json::json!(plan.steps.iter().map(|s| serde_json::json!({
                                    "tool": s.tool,
                                    "args": s.arguments,
                                })).collect::<Vec<serde_json::Value>>()),
                                verify_rule: String::new(),
                                success: is_success,
                            });
                        }
                        // 从积累的执行日志中蒸馏新模板
                        {
                            let logs = self.execution_log.lock().await;
                            let mut harness = self.harness.lock().await;
                            let _ = harness.distill_from_logs(&logs, 2);
                        }

                        return format!("[Step 2/3: 执行 → Step 3/3: 交付]\n\n{}", result);
                    }
                    _ => {
                        tracing::info!("合成路由降级到普通 LLM（单步或分解失败）");
                    } // 单步或失败 → 降级到普通 LLM loop
                }
            }
        }

        // ── 1. 快速路径（Harness 匹配）──
        if let Some(reply) = self.try_harness_match(message).await {
            return reply;
        }

        // ── 2. 并行获取上下文 ──
        let (inbox_result, mem_result) = tokio::join!(
            self.check_inbox(),
            self.search_memory(message),
        );

        // P2-D: 检查审批响应
        self.check_approval_responses().await;
        // 如果有审批通过的请求，立即执行
        if let Some(reply) = self.execute_approved_request(session_id).await {
            let ns = self.config.identity.ns();
            let db_path = self.harness.lock().await.db_path();
            self.session_manager.save_to_history(session_id, &ns, &db_path, message, &reply).await;
            return reply;
        }

        let mut knowledge = Vec::new();
        let mut enriched_message = message.to_string();

        if let Ok(Some(inbox_msgs)) = &inbox_result {
            let mut prefix = String::from("你有以下来自其他 Agent 的消息:\n");
            for m in inbox_msgs.iter().take(3) {
                let content = m.get("content").and_then(|c| c.as_str()).unwrap_or("");
                let from = m.get("from").and_then(|f| f.as_str()).unwrap_or("?");
                prefix.push_str(&format!("- [{}] {}\n", from, &content[..content.len().min(200)]));
            }
            enriched_message = format!("{}\n---\n{}", prefix, message);
        }

        if let Ok(Some(results)) = &mem_result {
            for item in results.iter().take(3) {
                if let Some(content) = item.get("content").and_then(|c| c.as_str()) {
                    if content.len() > 10 {
                        knowledge.push(content.to_string());
                    }
                }
            }
        }

        // ── 3. 加载历史对话 ──
        let ns = self.config.identity.ns();
        let db_path = self.harness.lock().await.db_path();
        let history = self.session_manager.load_history(session_id, &ns, &db_path).await;

        // ── 4. 构建消息列表 ──
        let system_prompt = self.build_system_prompt(&knowledge);
        let mut messages = Vec::new();
        messages.push(Message { role: "system".to_string(), content: Some(system_prompt), tool_calls: None, tool_call_id: None });
        for h in history.iter().rev().take(20) {
            messages.push(h.clone());
        }
        messages.push(Message { role: "user".to_string(), content: Some(enriched_message), tool_calls: None, tool_call_id: None });

        // ── 5. LLM 调用循环 ──
        let result = self.llm_loop(messages, session_id, message, user_id).await;

        // 给结果加 Step 前缀
        format!("[Step 2/3: 执行 → Step 3/3: 交付]\n\n{}", result)
    }

    /// 复述确认：用 LLM 复述用户需求，等待确认
    ///
    /// SAD（Skill-Aware Decomposition）风格增强：
    /// 并行获取记忆 + 可用工具列表，注入到 system prompt 中，
    /// 让 LLM 在复述时就能感知可用能力，对齐措辞。
    async fn rephrase_and_confirm(&self, message: &str, _user_id: &str, session_id: &str) -> String {
        self.session_manager.set_original_message(session_id, message).await;

        // SAD 风格：并行获取上下文（记忆）和可用能力（工具列表）
        let (mem_result, tools) = tokio::join!(
            self.search_memory(message),
            self.fetch_tools(),
        );

        let mut knowledge = Vec::new();
        if let Ok(Some(results)) = &mem_result {
            for item in results.iter().take(3) {
                if let Some(content) = item.get("content").and_then(|c| c.as_str()) {
                    if content.len() > 10 {
                        knowledge.push(content.to_string());
                    }
                }
            }
        }

        // 构建增强版 system prompt
        let mut system_prompt = self.build_system_prompt(&knowledge);

        // SAD 核心：注入可用工具信息，让 LLM 复述时对齐能力
        if !tools.is_empty() {
            system_prompt.push_str("\n\n## 可用工具\n你可以使用以下工具来完成请求。复述时请结合工具来描述你的执行方案：\n");
            for t in tools.iter().take(15) {
                let desc: String = t.function.description.chars().take(100).collect();
                system_prompt.push_str(&format!("- `{}`: {}\n", t.function.name, desc));
            }
            system_prompt.push_str("\n在复述中列出你的执行计划（需要几步、用什么工具），让用户确认方案后再执行。\n");
        }

        let msgs = vec![
            Message { role: "system".to_string(), content: Some(system_prompt), tool_calls: None, tool_call_id: None },
            Message { role: "user".to_string(), content: Some(message.to_string()), tool_calls: None, tool_call_id: None },
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
            if rephrase.is_empty() { message } else { &rephrase },
        )
    }

    /// 按依赖序执行组合计划（支持并行执行无依赖步骤）
    async fn execute_plan(&self, plan: &crate::composer::ExecutionPlan, _session_id: &str) -> Result<String, String> {
        use std::collections::HashMap;

        let mut step_results: HashMap<u32, String> = HashMap::new();
        let mut step_errors: Vec<String> = Vec::new();
        let mut executed: Vec<u32> = Vec::new();
        let total = plan.steps.len();

        while executed.len() < total {
            // 找出本轮可执行的步骤（所有依赖已就绪）
            let ready: Vec<&crate::composer::StepPlan> = plan.steps.iter()
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
            let futures: Vec<_> = ready.iter().map(|step| {
                // 解析参数中的依赖占位符（step_N → 第 N 步的实际结果）
                let mut args = step.arguments.clone();
                if let Some(obj) = args.as_object_mut() {
                    for val in obj.values_mut() {
                        if let Some(s) = val.as_str() {
                            if let Some(rest) = s.strip_prefix("step_") {
                                // 解析 step_N[_result] 中的 N
                                let step_num: u32 = rest.split(['_', ' ']).next()
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

                async move {
                    (step_id, tool, desc, args)
                }
            }).collect();

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

                    match this.call_tool_routed(&tool, &args).await {
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

    /// 话题切换检测：当前任务未完成，检测到话题切换
    async fn handle_topic_switch(&self, _message: &str, session_id: &str) -> String {
        let task = self.session_manager.get_original_message(session_id).await.unwrap_or_default();
        let task_preview: String = task.chars().take(80).collect();
        format!(
            "[Task 管理]\n\n检测到您可能换了话题。当前任务还在处理：{task_preview}\n\n请选择：\n- \"继续\" → 继续当前任务\n- \"暂停\" → 暂停当前任务\n- \"结束\" → 结束当前任务"
        )
    }

    /// 从 SessionManager 加载历史对话
    #[allow(dead_code)]
    async fn load_history(&self, session_id: &str) -> Vec<Message> {
        let ns = self.config.identity.ns();
        let db_path = self.harness.lock().await.db_path();
        self.session_manager.load_history(session_id, &ns, &db_path).await
    }

    /// 保存对话到 SessionManager（内存缓存 + SQLite 持久化）
    async fn save_to_history(&self, session_id: &str, user_msg: &str, assistant_reply: &str) {
        let ns = self.config.identity.ns();
        let db_path = self.harness.lock().await.db_path();
        self.session_manager.save_to_history(session_id, &ns, &db_path, user_msg, assistant_reply).await;
    }

    /// LLM 调用循环（支持多轮 tool calling）
    async fn llm_loop(
        &self,
        mut messages: Vec<Message>,
        session_id: &str,
        raw_message: &str,
        user_id: &str,
    ) -> String {
        // 从 Memoria 取可用工具列表
        let tools = self.fetch_tools().await;

        for _round in 0..self.config.max_tool_rounds {
            let response = match self.llm.chat(&messages, &tools).await {
                Ok(r) => r,
                Err(e) => return format!("LLM 调用失败: {}", e),
            };

            // 无工具调用 → LLM 直接回复
            if response.tool_calls.is_empty() {
                let reply = response.text;
                // 保存对话
                let _ = self.mcp.call("memory_observe", &serde_json::json!({
                    "dialog": raw_message, "role": "user",
                    "source": format!("user:{}", user_id), "session_id": session_id,
                    "namespace": self.config.identity.ns(),
                })).await;
                let _ = self.mcp.call("memory_observe", &serde_json::json!({
                    "dialog": &reply, "role": "assistant",
                    "source": &self.config.identity.agent_id, "session_id": session_id,
                    "namespace": self.config.identity.ns(),
                })).await;
                // 保存到内存缓存
                self.save_to_history(session_id, raw_message, &reply).await;
                return reply;
            }

            // 有工具调用 → 执行工具
            for tc in &response.tool_calls {
                // 边界检查
                let boundary = self.boundary.lock().await;
                let ns = self.current_ns_paths();
                let check = boundary.check_tool(
                    &tc.name, &tc.arguments,
                    &self.config.identity.agent_id, "user",
                    &self.config.parent_permission, ns.as_deref(),
                );
                drop(boundary);

                if !check.allow {
                    // 审计日志：记录拒绝决策
                    self.audit_logger.log_decision(
                        &self.config.identity.agent_id, &tc.name,
                        &check.reason, false
                    ).await;
                    // REQUIRES_REVIEW：黄线 → 触发确认流程
                    if check.level == Some(crate::boundary::BlockLevel::Yellow) {
                        // P2-D: 如果有审批人，走外部审批流程
                        if let Some(approver_id) = &self.config.approver_id {
                            let aid = self.approval_manager.create_request(
                                &tc.name,
                                &tc.arguments,
                                &check.reason,
                                approver_id,
                                &self.config.identity.agent_id,
                            ).await;
                            // 通过 A2A 发送审批请求
                            let msg = serde_json::json!({
                                "type": "approval_request",
                                "approval_id": aid,
                                "tool_name": tc.name,
                                "description": check.reason,
                                "arguments": tc.arguments,
                                "requester_id": self.config.identity.agent_id,
                                "requester_ns": self.config.identity.ns(),
                            });
                            let _ = self.mcp.call("a2a_send", &serde_json::json!({
                                "to": approver_id,
                                "content": msg.to_string(),
                                "namespace": format!("agent/{}", approver_id),
                            })).await;
                            let reply = format!("AWAITING_APPROVAL:等待审批人「{}」审批工具「{}」，请稍后",
                                           approver_id, tc.name);
                            self.save_to_history(session_id, raw_message, &reply).await;
                            return reply;
                        }
                        // 无审批人：原有的 REQUIRES_REVIEW 流程
                        let reply = format!("REQUIRES_REVIEW:{}:工具「{}」需要确认——{}",
                                       tc.name, tc.name, check.reason);
                        self.save_to_history(session_id, raw_message, &reply).await;
                        return reply;
                    }
                    // 红线 → 直接拒绝
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
                        content: Some(format!("错误: {}", check.reason)),
                        tool_calls: None,
                        tool_call_id: Some(tc.id.clone()),
                    });
                    continue;
                }

                // 通过 MCP 调用工具（按名称路由到正确的源）
                let result = match self
                    .call_tool_routed(&tc.name, &tc.arguments)
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
                    self.session_manager.set_pending_action(session_id, action).await;
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

    /// 从 Memoria 搜索记忆
    async fn search_memory(&self, query: &str) -> Result<Option<Vec<serde_json::Value>>, String> {
        let result = self
            .mcp
            .call_json(
                "memory_search_v2",
                &serde_json::json!({
                    "query": query,
                    "namespace": self.config.identity.ns(),
                    "max_results": 3,
                    "intent": "WHAT",
                }),
            )
            .await;

        match result {
            Ok(val) => Ok(val["results"].as_array().cloned()),
            Err(_) => Ok(None),
        }
    }

    /// 检查 A2A 收件箱中的审批响应
    /// 扫描收件箱消息，识别 approval_response 类型，记录到 ApprovalManager
    async fn check_approval_responses(&self) {
        let inbox = match self.mcp.call_json("a2a_recv", &serde_json::json!({
            "limit": 10,
            "namespace": self.config.identity.ns(),
        })).await {
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
    async fn execute_approved_request(&self, _session_id: &str) -> Option<String> {
        let pending_list = self.approval_manager.list_pending().await;
        for approval in &pending_list {
            if let Some(true) = self.approval_manager.is_approved(&approval.approval_id).await {
                // 审批通过，执行工具
                let result = match self.call_tool_routed(&approval.tool_name, &approval.arguments).await {
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
                self.audit_logger.log_tool_call(
                    &self.config.identity.agent_id,
                    &approval.tool_name,
                    &approval.arguments,
                    true,
                ).await;
                self.approval_manager.remove(&approval.approval_id).await;
                return Some(reply);
            } else if let Some(false) = self.approval_manager.is_approved(&approval.approval_id).await {
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
    pub fn find_mcp_for_tool(&self, tool_name: &str) -> &McpClient {
        // 1. 先查缓存
        {
            let cache = self.tool_route_cache.blocking_lock();
            if let Some(&idx) = cache.get(tool_name) {
                if idx < self.mcp_sources.len() {
                    return &self.mcp_sources[idx].client;
                }
            }
        }

        // 2. Memoria 特有工具走第一个源
        let memoria_tools = [
            "memory_search", "memory_search_v2", "memory_remember",
            "memory_observe", "a2a_send", "a2a_recv", "register_agent",
            "audit_query", "db_stats", "skill_market_list_installed",
            "skill_market_search", "agent_list", "agent_revoke",
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
                let tool_names_descs: Vec<(String, String)> = tools.iter().map(|(n, d, _)| (n.clone(), d.clone())).collect();
                boundary.learn_tools(&tool_names_descs);
                drop(boundary);

                // 检查目标工具是否在此源中
                if tools.iter().any(|(name, _, _)| name == tool_name) {
                    return &source.client;
                }
            }
        }

        // 最终 fallback
        self.find_mcp_for_tool(tool_name)
    }

    /// 路由到正确的 MCP 源执行工具调用
    pub async fn call_tool_routed(&self, tool_name: &str, args: &serde_json::Value) -> Result<String, String> {
        let client = self.find_mcp_for_tool_async(tool_name).await;
        client.call(tool_name, args).await
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
                let _ = reg.register(
                    crate::namespace::Namespace::dept(dept_name),
                    None,
                );
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
    pub async fn fetch_tools(&self) -> Vec<ToolDef> {
        let mut all_tools: Vec<ToolDef> = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for (idx, source) in self.mcp_sources.iter().enumerate() {
            match source.client.list_tools().await {
                Ok(tools) => {
                    // 更新路由缓存和分类器
                    {
                        let mut cache = self.tool_route_cache.lock().await;
                        let boundary = self.boundary.lock().await;
                        let tool_names_descs: Vec<(String, String)> = tools.iter().map(|(n, d, _)| (n.clone(), d.clone())).collect();
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
                Err(e) => {
                    tracing::warn!("{} tools/list 失败: {}", source.name, e);
                }
            }
        }

        if all_tools.is_empty() {
            tracing::warn!("所有 MCP 源工具列表为空，使用 fallback");
            return vec![
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
            ];
        }

        all_tools
    }

    /// 快速路径：Harness 模板匹配
    async fn try_harness_match(&self, message: &str) -> Option<String> {
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

            tracing::info!("Harness 命中: {} (score={:.2})", m.harness.name, score);

            // 执行每个步骤（含 boundary 检查）
            let mut all_ok = true;
            for step in steps {
                let tool_name = step["tool"].as_str()?;
                let args = step.get("args").cloned().unwrap_or(serde_json::Value::Null);
                // P2-9: 执行前经过 boundary 检查
                let boundary = self.boundary.lock().await;
                let check = boundary.check_tool(tool_name, &args, &self.config.identity.agent_id, "user", &PermissionLevel::Write, self.current_ns_paths().as_deref());
                drop(boundary);
                if !check.allow {
                    tracing::warn!("Harness 步骤 {} 被 boundary 拒绝: {}", tool_name, check.reason);
                    all_ok = false;
                    break;
                }
                let result = self.call_tool_routed(tool_name, &args).await;
                if result.is_err() {
                    all_ok = false;
                    break;
                }
            }

            // 记录使用情况
            let mut h = self.harness.lock().await;
            let _ = h.record_usage(m.harness.id, all_ok);
            drop(h);

            return Some(format!("已执行 {}：{}", m.harness.name, if all_ok { "成功" } else { "部分失败" }));
        }

        None
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
你有以下可用的工具（由系统自动提供）：
- query_plate：查车牌对应的企业信息
- query_sql：执行 SQL 查询（只允许 SELECT）
- manage_whitelist：管理白名单
- fill_excel_log：填写入厂日志
- 以及其他系统提供的工具

调用工具时：
1. 直接传递正确的参数，不要猜测参数名
2. query_sql 的 SQL 必须是合法的 SQLite SELECT 语句
3. 查询类工具不需要确认，修改类工具需要先确认

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
            prompt.push_str("## 相关知识（来自记忆系统）\n");
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
             - sample_records（取样）: serial_no, license_plate, sample_weight, sample_time\n"
        );

        prompt
    }
}

fn now_secs() -> f64 {
    harness::now_secs()
}
