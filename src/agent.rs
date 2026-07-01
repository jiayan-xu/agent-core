//! Agent 核心 — chat 循环 + 工具执行

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use crate::boundary::{self, ComplianceBoundary, PermissionLevel, ToolCheck};
use crate::harness::{ExecutionLog, HarnessStore};
use crate::llm::{LlmClient, LlmConfig, Message, ToolCall, ToolDef};
use crate::mcp_client::McpClient;

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
    pub skill_whitelist: Option<Vec<String>>,
    pub max_tool_rounds: u32,
    pub parent_permission: PermissionLevel,
}

/// Agent 核心
pub struct AgentCore {
    pub config: AgentConfig,
    pub mcp: McpClient,
    pub llm: LlmClient,
    pub boundary: Arc<Mutex<ComplianceBoundary>>,
    pub harness: Arc<Mutex<HarnessStore>>,
    /// 执行日志（用于 distill）
    pub execution_log: Arc<Mutex<Vec<ExecutionLog>>>,
    /// 收件箱缓存
    inbox_cache: tokio::sync::Mutex<InboxCache>,
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
            llm,
            boundary: Arc::new(Mutex::new(boundary)),
            harness: Arc::new(Mutex::new(harness)),
            execution_log: Arc::new(Mutex::new(Vec::new())),
            inbox_cache: tokio::sync::Mutex::new(InboxCache::new()),
        }
    }

    /// 入口：处理用户消息，返回回复
    pub async fn chat(&self, message: &str, user_id: &str, session_id: &str) -> String {
        // ── 1. 并行获取上下文 ──
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

        // ── 2. 快速路径（Harness 匹配） ──
        if let Some(reply) = self.try_harness_match(message).await {
            return reply;
        }

        // ── 3. 构建消息列表 ──
        let system_prompt = self.build_system_prompt(&knowledge);
        let messages = vec![
            Message { role: "system".to_string(), content: Some(system_prompt), tool_calls: None, tool_call_id: None },
            Message { role: "user".to_string(), content: Some(enriched_message), tool_calls: None, tool_call_id: None },
        ];

        // ── 4. LLM 调用循环 ──
        self.llm_loop(messages, session_id, message, user_id).await
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

                // 通过 MCP 调用工具
                let result = match self
                    .mcp
                    .call(&tc.name, &tc.arguments)
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
            Ok(r) => r.text,
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

    /// 从 Memoria 获取工具列表
    pub async fn fetch_tools(&self) -> Vec<ToolDef> {
        // 从 Memoria Skill Market 获取已安装的工具列表
        match self
            .mcp
            .call_json(
                "skill_market_list_installed",
                &serde_json::json!({"agent_id": self.config.identity.agent_id}),
            )
            .await
        {
            Ok(data) => {
                let skills = data["skills"].as_array().cloned().unwrap_or_default();
                if skills.is_empty() {
                    tracing::warn!("Skill Market 返回空列表，使用 fallback");
                } else {
                    return skills
                        .iter()
                        .filter_map(|s| {
                            let name = s["name"].as_str()?;
                            let desc = s
                                .get("description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("");
                            Some(ToolDef {
                                type_: "function".to_string(),
                                function: crate::llm::ToolDefFunction {
                                    name: name.to_string(),
                                    description: desc.to_string(),
                                    parameters: s
                                        .get("parameters")
                                        .cloned()
                                        .unwrap_or(serde_json::json!({
                                            "type": "object",
                                            "properties": {}
                                        })),
                                },
                            })
                        })
                        .collect();
                }
            }
            Err(e) => {
                tracing::warn!("fetch_tools 调用失败: {}，使用 fallback", e);
            }
        }

        // fallback: 硬编码 2 个基础工具
        vec![
            ToolDef {
                type_: "function".to_string(),
                function: crate::llm::ToolDefFunction {
                    name: "query_plate".to_string(),
                    description: "查询车牌信息".to_string(),
                    parameters: serde_json::json!({
                        "type": "object",
                        "properties": {"plate": {"type": "string"}},
                    }),
                },
            },
            ToolDef {
                type_: "function".to_string(),
                function: crate::llm::ToolDefFunction {
                    name: "query_sql".to_string(),
                    description: "执行 SQL 查询".to_string(),
                    parameters: serde_json::json!({
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                    }),
                },
            },
        ]
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
                let result = self.mcp.call(tool_name, &args).await;
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
        let mut prompt = format!("你是 {}, 一个 AI 助手。\n\n", self.config.identity.agent_id);
        if !knowledge.is_empty() {
            prompt.push_str("相关知识：\n");
            for k in knowledge {
                prompt.push_str(&format!("- {}\n", k));
            }
        }
        prompt
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
