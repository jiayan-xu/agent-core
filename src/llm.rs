//! LLM 客户端 — 兼容 DeepSeek / OpenAI API

use std::time::Duration;

use reqwest::Client;
use serde::Serialize;

/// LLM 配置
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    pub max_tokens: u32,
    pub temperature: f64,
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            base_url: "https://api.deepseek.com".to_string(),
            model: "deepseek-chat".to_string(),
            api_key: String::new(),
            max_tokens: 4096,
            temperature: 0.0,
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

    /// 发送聊天请求，返回响应
    pub async fn chat(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
    ) -> Result<LlmResponse, String> {
        let url = format!("{}/v1/chat/completions", self.config.base_url.trim_end_matches('/'));

        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        });

        if !tools.is_empty() {
            body["tools"] = serde_json::to_value(tools).map_err(|e| format!("tools json: {}", e))?;
        }

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await
            .map_err(|e| format!("LLM request: {}", e))?;

        let data: serde_json::Value = resp.json().await.map_err(|e| format!("LLM json: {}", e))?;

        // 提取首个 choice
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

        Ok(LlmResponse { text, tool_calls })
    }
}
