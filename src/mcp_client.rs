//! MCP 客户端 — 连接 Memoria 的工具调用接口
//!
//! 复用 HTTP 连接池，支持自动重试。

use std::time::Duration;

use reqwest::Client;

/// MCP 调用结果
#[derive(Debug, Clone)]
pub struct McpResult {
    /// 工具返回的原始文本
    pub text: String,
}

use serde::{Serialize, Deserialize};
/// MCP 客户端
#[derive(Clone)]
pub struct McpClient {
    client: Client,
    base_url: String,
    agent_id: String,
    badge_token: String,
}

impl McpClient {
    /// 创建新的 MCP 客户端
    pub fn new(base_url: &str, agent_id: &str, badge_token: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(4) // 连接池
            .build()
            .expect("reqwest Client::build");
        McpClient {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_id: agent_id.to_string(),
            badge_token: badge_token.to_string(),
        }
    }

    /// 调用 MCP 工具（带重试）
    pub async fn call(&self, tool: &str, args: &serde_json::Value) -> Result<String, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": args,
            }
        });

        let url = format!("{}/mcp", self.base_url);

        // 3 次重试：0s, 1s, 2s 退避
        for attempt in 0..3 {
            let result = self
                .client
                .post(&url)
                .json(&body)
                .header("X-Agent-Id", &self.agent_id)
                .header("X-Agent-Key", &self.badge_token)
                .send()
                .await;

            match result {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        if attempt < 2 {
                            tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                            continue;
                        }
                        return Err(format!("HTTP {}", resp.status()));
                    }
                    let data: serde_json::Value = resp.json().await.map_err(|e| format!("json: {}", e))?;
                    // 提取 result.content[0].text
                    let text = data["result"]["content"][0]["text"]
                        .as_str()
                        .ok_or_else(|| "empty MCP response".to_string())?
                        .to_string();
                    return Ok(text);
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                        continue;
                    }
                    return Err(format!("MCP call failed after 3 retries: {}", e));
                }
            }
        }

        Err("unreachable".to_string())
    }

    /// 获取 MCP 源的工具列表（含完整参数 schema）
    pub async fn list_tools(&self) -> Result<Vec<(String, String, serde_json::Value)>, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });
        let url = format!("{}/mcp", self.base_url);
        let resp = self.client.post(&url)
            .json(&body)
            .header("X-Agent-Id", &self.agent_id)
            .header("X-Agent-Key", &self.badge_token)
            .send().await
            .map_err(|e| format!("tools/list: {}", e))?;
        let data: serde_json::Value = resp.json().await
            .map_err(|e| format!("tools/list JSON: {}", e))?;
        let tools = data["result"]["tools"].as_array()
            .ok_or("tools/list 返回格式异常")?;
        let mut result = Vec::new();
        for t in tools {
            if let Some(func) = t.get("function") {
                let name = func.get("name")
                    .and_then(|n| n.as_str()).unwrap_or("?").to_string();
                let desc = func.get("description")
                    .and_then(|d| d.as_str()).unwrap_or("").to_string();
                let params = func.get("parameters")
                    .cloned()
                    .unwrap_or(serde_json::json!({"type": "object", "properties": {}}));
                result.push((name, desc, params));
            }
        }
        Ok(result)
    }

    /// 调用并解析为 JSON Value
    pub async fn call_json(&self, tool: &str, args: &serde_json::Value) -> Result<serde_json::Value, String> {
        let text = self.call(tool, args).await?;
        serde_json::from_str(&text).map_err(|e| format!("parse result: {}", e))
    }
}

/// MCP 源：命名 + 客户端
#[derive(Clone)]
pub struct McpSource {
    pub name: String,
    pub client: McpClient,
}

impl McpSource {
    pub fn new(name: &str, client: McpClient) -> Self {
        McpSource { name: name.to_string(), client }
    }

    pub fn memoria(client: McpClient) -> Self {
        McpSource { name: "memoria".to_string(), client }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = McpClient::new("http://127.0.0.1:9003", "test-agent", "test-token");
        assert_eq!(client.base_url, "http://127.0.0.1:9003");
        assert_eq!(client.agent_id, "test-agent");
    }

    #[test]
    fn test_url_trim() {
        let client = McpClient::new("http://127.0.0.1:9003/", "a", "b");
        assert_eq!(client.base_url, "http://127.0.0.1:9003");
    }
}
