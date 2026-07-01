//! Agent 核心 — chat 循环 + 工具执行

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use crate::boundary::{self, ComplianceBoundary, PermissionLevel, ToolCheck};
use crate::harness::{ExecutionLog, HarnessStore};
use crate::llm::{LlmClient, LlmConfig, Message, ToolCall, ToolDef};
use crate::mcp_client::{McpClient, McpSource};
use std::collections::HashMap;

/// 待确认操作
struct PendingAction {
    tool_name: String,
    arguments: serde_json::Value,
    description: String,
}

/// Agent 身份
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub namespace: String,
    pub badge_token: String,
}

impl AgentIdentity {
    pub fn ns(&self) -> String {
        format!("agent/{}", self.agent_id)
    }
}

/// Agent 配置
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub identity: AgentIdentity,
    pub llm: LlmConfig,
    pub memoria_url: String,
    /// 可选 MCP 源（名称 + URL + 令牌），例：[("dashboard", "http://127.0.0.1:8000", "")]
    pub additional_mcp: Vec<(String, String, String)>,
    pub skill_whitelist: Option<Vec<String>>,
    pub max_tool_rounds: u32,
    pub parent_permission: PermissionLevel,
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
    /// 多轮会话历史缓存（session_id → messages）
    session_history: tokio::sync::Mutex<HashMap<String, Vec<Message>>>,
    /// 待确认操作（session_id → pending action）
    pending_actions: tokio::sync::Mutex<HashMap<String, PendingAction>>,
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
        for (name, url, token) in &config.additional_mcp {
            let badge = if token.is_empty() { &config.identity.badge_token } else { token };
            let client = McpClient::new(url, &config.identity.agent_id, badge);
            mcp_sources.push(McpSource::new(name, client));
        }
        let llm = LlmClient::new(config.llm.clone());
        let boundary = ComplianceBoundary::new(config.skill_whitelist.clone());
        // 注册 agent 自身到权限链
        boundary.perm_chain.lock().unwrap().register(
            &config.identity.agent_id,
            None,
            PermissionLevel::Write,
        );

        AgentCore {
            config,
            mcp,
            mcp_sources,
            llm,
            boundary: Arc::new(Mutex::new(boundary)),
            harness: Arc::new(Mutex::new(harness)),
            execution_log: Arc::new(Mutex::new(Vec::new())),
            inbox_cache: tokio::sync::Mutex::new(InboxCache::new()),
            session_history: tokio::sync::Mutex::new(HashMap::new()),
            pending_actions: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 入口：处理用户消息，返回回复
    pub async fn chat(&self, message: &str, user_id: &str, session_id: &str) -> String {
        // ── 0. 确认关键词 → 执行待确认操作 ──
        let confirm_words = ["确认", "确认添加", "确认执行", "添加", "是", "是的", "对", "执行", "确定", "可以"];
        let trimmed = message.trim();
        if confirm_words.contains(&trimmed) {
            let mut pending = self.pending_actions.lock().await;
            if let Some(action) = pending.remove(session_id) {
                drop(pending);
                let result = match self.call_tool_routed(&action.tool_name, &action.arguments).await {
                    Ok(text) => text,
                    Err(e) => format!("执行失败: {}", e),
                };
                let desc = action.description.chars().take(120).collect::<String>();
                let result_short = result.chars().take(300).collect::<String>();
                let reply = format!("✅ 操作已执行成功！\n\n操作内容：{}\n\n{}", desc, result_short);
                self.save_to_history(session_id, message, &reply).await;
                return reply;
            }
            drop(pending);
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

        let mut knowledge = Vec::new();
        let mut enriched_message = message.to_string();

        // 收件箱消息拼接到用户消息前
        if let Ok(Some(inbox_msgs)) = &inbox_result {
            let mut prefix = String::from("你有以下来自其他 Agent 的消息:\n");
            for m in inbox_msgs.iter().take(3) {
                let content = m.get("content").and_then(|c| c.as_str()).unwrap_or("");
                let from = m.get("from").and_then(|f| f.as_str()).unwrap_or("?");
                prefix.push_str(&format!("- [{}] {}\n", from, &content[..content.len().min(200)]));
            }
            enriched_message = format!("{}\n---\n{}", prefix, message);
        }

        // 记忆搜索结果
        if let Ok(Some(results)) = &mem_result {
            for item in results.iter().take(3) {
                if let Some(content) = item.get("content").and_then(|c| c.as_str()) {
                    if content.len() > 10 {
                        knowledge.push(content.to_string());
                    }
                }
            }
        }

        // ── 3. 加载历史对话（多轮记忆）──
        let history = self.load_history(session_id).await;

        // ── 4. 构建消息列表 ──
        let system_prompt = self.build_system_prompt(&knowledge);
        let mut messages = Vec::new();
        // system prompt 始终在最前
        messages.push(Message { role: "system".to_string(), content: Some(system_prompt), tool_calls: None, tool_call_id: None });
        // 历史消息（最近的 10 轮）
        for h in history.iter().rev().take(20) {
            messages.push(h.clone());
        }
        // 当前用户消息
        messages.push(Message { role: "user".to_string(), content: Some(enriched_message), tool_calls: None, tool_call_id: None });

        // ── 5. LLM 调用循环 ──
        self.llm_loop(messages, session_id, message, user_id).await
    }

    /// 从内存缓存 + SQLite 加载历史对话
    async fn load_history(&self, session_id: &str) -> Vec<Message> {
        // 先从内存缓存
        let cache = self.session_history.lock().await;
        if let Some(msgs) = cache.get(session_id) {
            if !msgs.is_empty() {
                return msgs.clone();
            }
        }
        drop(cache);

        // 内存没有 → 从 SQLite 恢复
        let ns = self.config.identity.ns();
        let harness = self.harness.clone();
        let db_path = harness.lock().await.db_path();

        if db_path.is_empty() {
            return Vec::new();
        }

        let sid = session_id.to_string();
        let msgs = tokio::task::spawn_blocking(move || {
            let mut result = Vec::new();
            if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT role, content FROM chat_history WHERE session_id=?1 AND namespace=?2 ORDER BY id DESC LIMIT 20"
                ) {
                    if let Ok(rows) = stmt.query_map(rusqlite::params![sid, ns], |row| {
                        let role: String = row.get(0)?;
                        let content: String = row.get(1)?;
                        Ok((role, content))
                    }) {
                        for row in rows.flatten() {
                            result.push(Message {
                                role: row.0,
                                content: Some(row.1),
                                tool_calls: None,
                                tool_call_id: None,
                            });
                        }
                    }
                }
            }
            result.reverse();
            result
        }).await.unwrap_or_default();

        // 写回内存缓存
        if !msgs.is_empty() {
            let mut cache = self.session_history.lock().await;
            cache.insert(session_id.to_string(), msgs.clone());
        }

        msgs
    }

    /// 保存对话到内存缓存 + SQLite 持久化
    async fn save_to_history(&self, session_id: &str, user_msg: &str, assistant_reply: &str) {
        // 内存缓存
        let mut cache = self.session_history.lock().await;
        let history = cache.entry(session_id.to_string()).or_insert_with(Vec::new);
        // 只保留最近 10 轮（20 条消息）
        if history.len() > 20 {
            history.drain(0..history.len() - 20);
        }
        history.push(Message {
            role: "user".to_string(),
            content: Some(user_msg.to_string()),
            tool_calls: None,
            tool_call_id: None,
        });
        history.push(Message {
            role: "assistant".to_string(),
            content: Some(assistant_reply.to_string()),
            tool_calls: None,
            tool_call_id: None,
        });
        drop(cache);

        // SQLite 持久化（通过 harness 的 DB）
        let ns = self.config.identity.ns();
        let db_path = self.harness.clone().lock().await.db_path();
        let sid = session_id.to_string();
        let u_msg = user_msg.to_string();
        let a_msg = assistant_reply.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                conn.execute(
                    "INSERT INTO chat_history (session_id, namespace, role, content, created_at) VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                    rusqlite::params![sid, ns, "user", u_msg],
                ).ok();
                conn.execute(
                    "INSERT INTO chat_history (session_id, namespace, role, content, created_at) VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                    rusqlite::params![sid, ns, "assistant", a_msg],
                ).ok();
            }
        }).await;
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

        for round in 0..self.config.max_tool_rounds {
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
                let check = boundary.check_tool(
                    &tc.name, &tc.arguments,
                    &self.config.identity.agent_id, "user",
                    &self.config.parent_permission, None,
                );
                drop(boundary);

                if !check.allow {
                    // REQUIRES_REVIEW：黄线 → 触发确认流程
                    if check.level == Some(crate::boundary::BlockLevel::Yellow) {
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
                    let mut pending = self.pending_actions.lock().await;
                    pending.insert(session_id.to_string(), PendingAction {
                        tool_name: tc.name.clone(),
                        arguments: {
                            let mut args = tc.arguments.clone();
                            if let Some(obj) = args.as_object_mut() {
                                obj.insert("confirmed".to_string(), serde_json::Value::Bool(true));
                            }
                            args
                        },
                        description: format!("{} ({})", tc.name, tc.arguments),
                    });
                    drop(pending);
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

    /// 查找能处理该工具的 MCP 源
    /// 按工具名在 mcp_sources 中查找对应的 MCP 客户端
    pub fn find_mcp_for_tool(&self, tool_name: &str) -> &McpClient {
        // Memoria 特有工具走第一个源
        let memoria_tools = [
            "memory_search", "memory_search_v2", "memory_remember",
            "memory_observe", "a2a_send", "a2a_recv", "register_agent",
            "audit_query", "db_stats", "skill_market_list_installed",
            "skill_market_search", "agent_list", "agent_revoke",
        ];
        if memoria_tools.contains(&tool_name) {
            return &self.mcp;
        }
        // 在其他 MCP 源中查找（简化版：按源名前缀匹配）
        // 生产环境应缓存每个源的 tools/list 结果做精确匹配
        for source in &self.mcp_sources[1..] {
            if tool_name.starts_with(&source.name) {
                return &source.client;
            }
        }
        // 非 memory_ 开头的工具，尝试找第一个非 Memoria 源
        if !tool_name.starts_with("memory_") && !tool_name.starts_with("db_") {
            for source in &self.mcp_sources[1..] {
                return &source.client;
            }
        }
        &self.mcp
    }

    /// 路由到正确的 MCP 源执行工具调用
    pub async fn call_tool_routed(&self, tool_name: &str, args: &serde_json::Value) -> Result<String, String> {
        let client = self.find_mcp_for_tool(tool_name);
        client.call(tool_name, args).await
    }

    /// 从所有 MCP 源获取工具列表（合并去重）
    pub async fn fetch_tools(&self) -> Vec<ToolDef> {
        let mut all_tools: Vec<ToolDef> = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for source in &self.mcp_sources {
            match source.client.list_tools().await {
                Ok(tools) => {
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

            // 执行每个步骤
            let mut all_ok = true;
            for step in steps {
                let tool_name = step["tool"].as_str()?;
                let args = step.get("args").cloned().unwrap_or(serde_json::Value::Null);
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
    fn build_system_prompt(&self, knowledge: &[String]) -> String {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
        let mut prompt = format!(
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
        );

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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
