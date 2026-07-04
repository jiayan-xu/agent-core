//! LLM 客户端 — 兼容 DeepSeek / OpenAI API（支持流式）

use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use tokio::sync::mpsc;

/// SSE 流式事件
#[derive(Debug, Clone, Serialize)]
pub enum SseEvent {
    #[serde(rename = "thinking")]
    ThinkingEvt { content: String },
    #[serde(rename = "text")]
    TextEvt { content: String },
    #[serde(rename = "tool_call")]
    ToolCallEvt { name: String, arguments: serde_json::Value, id: String },
    #[serde(rename = "tool_result")]
    ToolResultEvt { name: String, result: String },
    #[serde(rename = "done")]
    DoneEvt,
    #[serde(rename = "error")]
    ErrorEvt { message: String },
}

/// LLM 配置
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    pub max_tokens: u32,
    pub temperature: f64,
    /// 备用 Provider（failover 用）
    pub fallbacks: Vec<(String, String, String)>, // (base_url, model, api_key)
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            base_url: "https://api.deepseek.com".to_string(),
            model: "deepseek-chat".to_string(),
            api_key: String::new(),
            max_tokens: 4096,
            temperature: 0.0,
            fallbacks: Vec::new(),
        }
    }
}

/// LLM 响应中的工具调用
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// LLM 响应
#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
}

/// LLM 消息
#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolCallJson {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub function: ToolFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolFunction {
    pub name: String,
    pub arguments: String,
}

/// 工具定义（供 LLM 的 tools 参数）
#[derive(Debug, Clone, Serialize)]
pub struct ToolDef {
    #[serde(rename = "type")]
    pub type_: String,
    pub function: ToolDefFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolDefFunction {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// LLM 客户端
pub struct LlmClient {
    client: Client,
    config: LlmConfig,
}

impl LlmClient {
    pub fn new(config: LlmConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest Client::build");
        LlmClient { client, config }
    }

    /// 发送聊天请求，返回响应（带重试 + failover）
    pub async fn chat(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
    ) -> Result<LlmResponse, String> {
        // 主 Provider + 备用 Provider 列表
        let mut providers = Vec::new();
        providers.push((self.config.base_url.clone(), self.config.model.clone(), self.config.api_key.clone()));
        for fb in &self.config.fallbacks {
            providers.push(fb.clone());
        }

        let mut last_error = String::new();

        for (idx, (base_url, model, api_key)) in providers.iter().enumerate() {
            let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));

            let mut body = serde_json::json!({
                "model": model,
                "messages": messages,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            });

            if !tools.is_empty() {
                body["tools"] = serde_json::to_value(tools).map_err(|e| format!("tools json: {}", e))?;
            }

            // 3 次重试：0s, 1s, 2s 退避
            let max_retries = if idx == 0 { 3 } else { 1 }; // 主 Provider 重试 3 次，备用只试 1 次
            for attempt in 0..max_retries {
                let resp_result = self
                    .client
                    .post(&url)
                    .json(&body)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .send()
                    .await;

                match resp_result {
                    Ok(resp) => {
                        let status = resp.status();
                        if !status.is_success() {
                            let err_body = resp.text().await.unwrap_or_default();
                            let msg = format!("HTTP {}: {}", status.as_u16(), err_body.chars().take(200).collect::<String>());
                            if attempt < max_retries - 1 {
                                tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                                continue;
                            }
                            last_error = msg;
                            break;
                        }

                        let data: serde_json::Value = resp.json().await.map_err(|e| format!("LLM json: {}", e))?;

                        let choice = data["choices"][0]
                            .as_object()
                            .ok_or("LLM returned no choices")?
                            .clone();

                        let message = choice["message"]
                            .as_object()
                            .ok_or("LLM returned no message")?;

                        let text = message
                            .get("content")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();

                        let tool_calls = message
                            .get("tool_calls")
                            .and_then(|tc| tc.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|tc| {
                                        let id = tc["id"].as_str()?.to_string();
                                        let name = tc["function"]["name"].as_str()?.to_string();
                                        let args_str = tc["function"]["arguments"].as_str()?;
                                        let arguments: serde_json::Value =
                                            serde_json::from_str(args_str).ok()?;
                                        Some(ToolCall { id, name, arguments })
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();

                        // 备用 Provider 调用成功时记录日志
                        if idx > 0 {
                            tracing::warn!("LLM failover: 主 Provider 失败，切到 {} {}", base_url, model);
                        }

                        return Ok(LlmResponse { text, tool_calls });
                    }
                    Err(e) => {
                        let msg = format!("连接失败: {}", e);
                        if attempt < max_retries - 1 {
                            tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                            continue;
                        }
                        last_error = msg;
                    }
                }
            }
        }

        Err(format!("LLM 所有 Provider 均失败，最后错误: {}", last_error))
    }

    /// 流式聊天（SSE 事件通过 sender 发送）
    /// P2-6 修复：添加 failover 支持
    pub async fn chat_stream(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        sender: mpsc::UnboundedSender<SseEvent>,
    ) -> Result<(), String> {
        // P2-6: 主 Provider 失败时尝试备用 Provider
        let mut providers = Vec::new();
        providers.push((self.config.base_url.clone(), self.config.model.clone(), self.config.api_key.clone()));
        for fb in &self.config.fallbacks {
            providers.push(fb.clone());
        }

        let mut last_error = String::new();

        for (idx, (base_url, model, api_key)) in providers.iter().enumerate() {
            match self.chat_stream_single(base_url, model, api_key, messages, tools, &sender).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if idx == 0 {
                        tracing::warn!("流式主 Provider 失败，尝试 failover: {}", e);
                    }
                    last_error = e;
                    // 发送错误事件让前端知道在重试
                    if idx < providers.len() - 1 {
                        let _ = sender.send(SseEvent::ThinkingEvt {
                            content: format!("⚠️ 连接失败，正在切换到备用服务器..."),
                        });
                    }
                }
            }
        }

        let _ = sender.send(SseEvent::ErrorEvt { message: last_error.clone() });
        Err(last_error)
    }

    /// 单个 Provider 的流式聊天
    async fn chat_stream_single(
        &self,
        base_url: &str,
        model: &str,
        api_key: &str,
        messages: &[Message],
        tools: &[ToolDef],
        sender: &mpsc::UnboundedSender<SseEvent>,
    ) -> Result<(), String> {
        let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));

        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": true,
        });

        if !tools.is_empty() {
            body["tools"] = serde_json::to_value(tools).map_err(|e| format!("tools json: {}", e))?;
        }

        // DeepSeek 专用：禁用 thinking 输出（避免中文乱码）
        body["extra_body"] = serde_json::json!({"thinking": {"type": "disabled"}});

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| format!("stream request: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!("HTTP {}: {}", status.as_u16(), err_body.chars().take(200).collect::<String>()));
        }

        use futures::StreamExt;
        let mut stream = resp.bytes_stream();
        let _tool_call_buf: Option<String> = None;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| format!("stream read: {}", e))?;
            let text = String::from_utf8_lossy(&chunk);

            for line in text.lines() {
                if !line.starts_with("data: ") {
                    continue;
                }
                let data = &line[6..];
                if data == "[DONE]" {
                    let _ = sender.send(SseEvent::DoneEvt);
                    return Ok(());
                }

                if let Ok(val) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(choices) = val["choices"].as_array() {
                        if choices.is_empty() { continue; }
                        let delta = &choices[0]["delta"];

                        // thinking
                        if let Some(tc) = delta.get("reasoning_content").and_then(|c| c.as_str()) {
                            if !tc.is_empty() {
                                let _ = sender.send(SseEvent::ThinkingEvt { content: tc.to_string() });
                            }
                        }

                        // text
                        if let Some(tc) = delta.get("content").and_then(|c| c.as_str()) {
                            if !tc.is_empty() {
                                let _ = sender.send(SseEvent::TextEvt { content: tc.to_string() });
                            }
                        }

                        // tool_calls
                        if let Some(tcs) = delta.get("tool_calls").and_then(|tc| tc.as_array()) {
                            for tc in tcs {
                                let id = tc["id"].as_str().unwrap_or("").to_string();
                                let name = tc["function"]["name"].as_str().unwrap_or("").to_string();
                                let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
                                if let Ok(args) = serde_json::from_str(args_str) {
                                    let _ = sender.send(SseEvent::ToolCallEvt {
                                        name, arguments: args, id,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let _ = sender.send(SseEvent::DoneEvt);
        Ok(())
    }
}
