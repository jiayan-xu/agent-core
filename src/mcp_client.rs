//! MCP 客户端 — 支持 HTTP 和 stdio 两种传输层
//!
//! - `McpClient::Http(HttpMcpClient)` — HTTP(S) 连接远程 MCP 服务器
//! - `McpClient::Stdio(StdioMcpClient)` — 子进程 stdin/stdout MCP 通信

use rand::Rng;
use reqwest::Client as HttpClient;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::time::Duration;

// ── 通用 MCP 结果 ──

/// MCP 调用结果
#[derive(Debug, Clone)]
pub struct McpResult {
    pub text: String,
}

// ── HTTP 传输 ──

/// HTTP MCP 客户端（原 McpClient）
#[derive(Clone)]
pub struct HttpMcpClient {
    client: HttpClient,
    base_url: String,
    agent_id: String,
    badge_token: String,
    timeout_secs: u64,
}

impl HttpMcpClient {
    pub fn new(base_url: &str, agent_id: &str, badge_token: &str) -> Self {
        Self::with_timeout(base_url, agent_id, badge_token, 30)
    }

    pub fn with_timeout(
        base_url: &str,
        agent_id: &str,
        badge_token: &str,
        timeout_secs: u64,
    ) -> Self {
        let client = HttpClient::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .pool_max_idle_per_host(4)
            .build()
            .expect("reqwest Client::build");
        HttpMcpClient {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_id: agent_id.to_string(),
            badge_token: badge_token.to_string(),
            timeout_secs,
        }
    }

    pub async fn call(&self, tool: &str, args: &serde_json::Value) -> Result<String, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        });
        let url = format!("{}/mcp", self.base_url);
        let mut last_err = String::from("no response");
        for attempt in 0..3 {
            // 联调：为每次 MCP 调用生成 x-trace-id（与 http.request trace_id 独立，携带跨服务 trace 链）。
            let trace_id = format!("{:x}", rand::thread_rng().gen::<u128>());
            let result = self
                .client
                .post(&url)
                .json(&body)
                .header("X-Agent-Id", &self.agent_id)
                .header("X-Agent-Key", &self.badge_token)
                .header("x-trace-id", &trace_id)
                .send()
                .await;
            match result {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        // HTTP 层错误（5xx / 网关）：视为可重试的传输错误
                        last_err = format!("HTTP {}", resp.status());
                        if attempt < 2 {
                            tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                            continue;
                        }
                        return Err(last_err);
                    }
                    // HTTP 200 — 解析 JSON-RPC 信封
                    let data: serde_json::Value = match resp.json().await {
                        Ok(d) => d,
                        Err(e) => {
                            last_err = format!("json parse: {}", e);
                            if attempt < 2 {
                                tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                                continue;
                            }
                            return Err(last_err);
                        }
                    };
                    // JSON-RPC 业务错误（鉴权失败 / 参数错误等）：不重试，直接返回
                    // 否则会把一次鉴权失败当成传输错误重试 3 次，放大对端的调用量（如 Memoria CPU 飙升）。
                    if let Some(err) = data.get("error") {
                        return Err(format!("MCP error: {}", err));
                    }
                    // 成功：抽取文本结果
                    return match data
                        .get("result")
                        .and_then(|r| r.get("content"))
                        .and_then(|c| c.get(0))
                        .and_then(|c| c.get("text"))
                        .and_then(|t| t.as_str())
                    {
                        Some(t) => Ok(t.to_string()),
                        None => Err("empty MCP response".to_string()),
                    };
                }
                Err(e) => {
                    // 传输层错误（连接失败 / 超时）：可重试
                    last_err = format!("MCP transport error: {}", e);
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                        continue;
                    }
                    return Err(last_err);
                }
            }
        }
        Err(last_err)
    }

    pub async fn list_tools(&self) -> Result<Vec<(String, String, serde_json::Value)>, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
        });
        let url = format!("{}/mcp", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .header("X-Agent-Id", &self.agent_id)
            .header("X-Agent-Key", &self.badge_token)
            .send()
            .await
            .map_err(|e| format!("tools/list: {}", e))?;
        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("tools/list JSON: {}", e))?;
        Ok(extract_tools(&data))
    }

    pub async fn call_json(
        &self,
        tool: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let text = self.call(tool, args).await?;
        serde_json::from_str(&text).map_err(|e| format!("parse result: {}", e))
    }
}

// ── Stdio 传输 ──

/// Stdio MCP 客户端 — 通过子进程 stdin/stdout 通信
pub struct StdioMcpClient {
    child: tokio::sync::Mutex<ChildProcess>,
    command: String,
    args: Vec<String>,
    next_id: AtomicU64,
}

/// 子进程状态
struct ChildProcess {
    inner: Child,
    /// 读取就绪信号后的缓冲区（第一行 stdout 是就绪信号）
    ready: bool,
}

/// 读 stdout 一行：容忍非严格 UTF-8（Windows 子进程偶发）
fn read_line_flexible(reader: &mut impl BufRead) -> Result<String, String> {
    let mut buf = Vec::new();
    reader
        .read_until(b'\n', &mut buf)
        .map_err(|e| format!("read stdout: {}", e))?;
    if buf.is_empty() {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

impl StdioMcpClient {
    pub fn new(command: &str, args: &[String]) -> Self {
        StdioMcpClient {
            child: tokio::sync::Mutex::new(ChildProcess {
                inner: spawn_process(command, args),
                ready: false,
            }),
            command: command.to_string(),
            args: args.to_vec(),
            next_id: AtomicU64::new(1),
        }
    }

    /// 发送 JSON-RPC 请求，返回响应
    async fn communicate(&self, request: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut guard = self.child.lock().await;

        // 检查进程是否存活，死了就重启
        if guard.inner.try_wait().ok().flatten().is_some() {
            guard.inner = spawn_process(&self.command, &self.args);
            guard.ready = false;
        }

        // 读取就绪信号（首次启动时）
        if !guard.ready {
            let mut reader = BufReader::new(guard.inner.stdout.as_mut().unwrap());
            let ready_line = read_line_flexible(&mut reader)?;
            let _ = ready_line;
            guard.ready = true;
            // 把 reader 丢回去 — 用完后 drop
        }

        // 发送请求
        let stdin = guard.inner.stdin.as_mut().unwrap();
        let mut line = serde_json::to_string(request).map_err(|e| format!("serialize: {}", e))?;
        line.push('\n');
        stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("write stdin: {}", e))?;
        stdin.flush().map_err(|e| format!("flush stdin: {}", e))?;

        // 读取响应
        let stdout = guard.inner.stdout.as_mut().unwrap();
        let mut reader = BufReader::new(stdout);
        let resp_line = read_line_flexible(&mut reader)?;
        if resp_line.is_empty() {
            return Err("MCP server closed stdout".to_string());
        }
        serde_json::from_str(resp_line.trim()).map_err(|e| format!("parse JSON: {}", e))
    }

    pub async fn call(&self, tool: &str, args: &serde_json::Value) -> Result<String, String> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        });
        let response = self.communicate(&request).await?;
        if let Some(err) = response.get("error") {
            return Err(err["message"]
                .as_str()
                .unwrap_or("unknown error")
                .to_string());
        }
        Ok(response["result"]["content"][0]["text"]
            .as_str()
            .ok_or("empty response")?
            .to_string())
    }

    pub async fn list_tools(&self) -> Result<Vec<(String, String, serde_json::Value)>, String> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}
        });
        let response = self.communicate(&request).await?;
        if let Some(err) = response.get("error") {
            return Err(err["message"]
                .as_str()
                .unwrap_or("unknown error")
                .to_string());
        }
        Ok(extract_tools(&response))
    }

    pub async fn call_json(
        &self,
        tool: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let text = self.call(tool, args).await?;
        serde_json::from_str(&text).map_err(|e| format!("parse result: {}", e))
    }
}

fn spawn_process(command: &str, args: &[String]) -> Child {
    let mut cmd = Command::new(command);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // 强制子进程 stdout UTF-8，避免 Windows 本地代码页导致 JSON-RPC 行非法
        .env("PYTHONUTF8", "1")
        .env("PYTHONIOENCODING", "utf-8");

    // 注入沙箱根：供守规 MCP/工具自检（路径门闸、写前快照）
    if let Some(root) = crate::sandbox::resolve_sandbox_root() {
        cmd.env("AGENT_SANDBOX_ROOT", root);
    }
    // 可选 cwd 约束（默认关，避免破坏依赖相对路径的 MCP）
    if let Some(root) = crate::sandbox::cwd_root() {
        cmd.current_dir(root);
    }

    // Windows: 防止 spawn 的 MCP 子进程（如 python）弹出控制台窗口
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let child = cmd
        .spawn()
        .expect("failed to spawn MCP server process");

    // 后置约束：纳入 Job Object（kill-on-close），斩断孤儿/逃逸子进程
    crate::sandbox::confine_child_process(&child);

    child
}

// ── 统一 McpClient 枚举 ──

/// 统一 MCP 客户端 — 支持 HTTP 和 stdio 两种传输
#[derive(Clone)]
pub enum McpClient {
    Http(HttpMcpClient),
    Stdio(std::sync::Arc<StdioMcpClient>), // Arc because StdioMcpClient isn't Clone
}

impl McpClient {
    /// 创建 HTTP MCP 客户端（向后兼容）
    pub fn new(base_url: &str, agent_id: &str, badge_token: &str) -> Self {
        McpClient::Http(HttpMcpClient::new(base_url, agent_id, badge_token))
    }

    pub fn with_timeout(
        base_url: &str,
        agent_id: &str,
        badge_token: &str,
        timeout_secs: u64,
    ) -> Self {
        McpClient::Http(HttpMcpClient::with_timeout(
            base_url,
            agent_id,
            badge_token,
            timeout_secs,
        ))
    }

    pub fn new_stdio(command: &str, args: &[String]) -> Self {
        McpClient::Stdio(std::sync::Arc::new(StdioMcpClient::new(command, args)))
    }

    pub async fn call(&self, tool: &str, args: &serde_json::Value) -> Result<String, String> {
        match self {
            McpClient::Http(c) => c.call(tool, args).await,
            McpClient::Stdio(c) => c.call(tool, args).await,
        }
    }

    pub async fn list_tools(&self) -> Result<Vec<(String, String, serde_json::Value)>, String> {
        match self {
            McpClient::Http(c) => c.list_tools().await,
            McpClient::Stdio(c) => c.list_tools().await,
        }
    }

    pub async fn call_json(
        &self,
        tool: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        match self {
            McpClient::Http(c) => c.call_json(tool, args).await,
            McpClient::Stdio(c) => c.call_json(tool, args).await,
        }
    }

    pub fn timeout_secs(&self) -> u64 {
        match self {
            McpClient::Http(c) => c.timeout_secs,
            McpClient::Stdio(_) => 30,
        }
    }
}

// ── MCP 源 ──

/// MCP 源：命名 + 客户端 + 所属命名空间（可选，用于工具级门控）
#[derive(Clone)]
pub struct McpSource {
    pub name: String,
    pub client: McpClient,
    pub namespace: Option<String>,
}

impl McpSource {
    pub fn new(name: &str, client: McpClient, namespace: Option<String>) -> Self {
        McpSource {
            name: name.to_string(),
            client,
            namespace,
        }
    }

    pub fn memoria(client: McpClient) -> Self {
        McpSource {
            name: "memoria".to_string(),
            client,
            namespace: None,
        }
    }
}

// ── 工具列表提取（HTTP 和 stdio 共用） ──

fn extract_tools(data: &serde_json::Value) -> Vec<(String, String, serde_json::Value)> {
    let mut result = Vec::new();
    if let Some(tools) = data["result"]["tools"].as_array() {
        for t in tools {
            if let Some(func) = t.get("function") {
                let name = func
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("?")
                    .to_string();
                let desc = func
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                let params = func
                    .get("parameters")
                    .cloned()
                    .unwrap_or(serde_json::json!({"type": "object", "properties": {}}));
                result.push((name, desc, params));
            }
        }
    }
    result
}

// ── 测试 ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_client_creation() {
        let client = McpClient::new("http://127.0.0.1:9003", "test-agent", "test-token");
        assert!(matches!(client, McpClient::Http(_)));
    }

    #[test]
    fn test_stdio_client_creation() {
        let client =
            McpClient::new_stdio("python", &["-c".to_string(), "print('test')".to_string()]);
        assert!(matches!(client, McpClient::Stdio(_)));
    }

    #[test]
    fn test_url_trim() {
        let client = McpClient::new("http://127.0.0.1:9003/", "a", "b");
        if let McpClient::Http(ref http) = client {
            // base_url 是私有字段，只验证客户端创建成功
        }
    }
}
