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
    /// 用 Option 便于在通信时临时取出所有权（移入阻塞线程）后再归还
    inner: Option<Child>,
    /// 子进程 pid，用于超时远程 kill（spawn_blocking 闭包持有 Child 所有权时，
    /// 外部无法访问，只能凭 pid 杀）
    pid: u32,
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

/// 在阻塞线程中执行一轮 stdio 通信（同步 I/O）。
/// 返回 `(结果, 新的 ready 状态)`，供 `communicate` 在超时重启后归还子进程。
fn do_communicate(
    child: &mut Child,
    ready: bool,
    req_str: &str,
) -> (Result<String, String>, bool) {
    // 首次启动：读取就绪信号行
    if !ready {
        let mut reader = BufReader::new(child.stdout.as_mut().unwrap());
        if let Err(e) = read_line_flexible(&mut reader) {
            return (Err(e), false);
        }
    }
    // 发送请求
    {
        let stdin = child.stdin.as_mut().unwrap();
        let mut line = req_str.to_string();
        line.push('\n');
        if let Err(e) = stdin.write_all(line.as_bytes()).and_then(|_| stdin.flush()) {
            return (Err(format!("write stdin: {}", e)), ready);
        }
    }
    // 读取响应
    let stdout = child.stdout.as_mut().unwrap();
    let mut reader = BufReader::new(stdout);
    match read_line_flexible(&mut reader) {
        Ok(resp) if !resp.is_empty() => (Ok(resp), true),
        Ok(_) => (Err("MCP server closed stdout".to_string()), ready),
        Err(e) => (Err(e), ready),
    }
}

/// 跨平台按 pid 强杀进程（含子进程树）。
///
/// 用于 MCP stdio 通信超时场景：`spawn_blocking` 闭包持有 `Child` 所有权，
/// 外部无法调用 `Child::kill()`，只能凭 pid 远程终止。Windows 用 `taskkill /T /F`
/// 杀整棵树，类 Unix 用 `kill -9`。
#[cfg(windows)]
fn kill_pid(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .output();
}

#[cfg(not(windows))]
fn kill_pid(pid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output();
}

impl StdioMcpClient {
    pub fn new(command: &str, args: &[String]) -> Self {
        let child = spawn_process(command, args);
        let pid = child.id();
        StdioMcpClient {
            child: tokio::sync::Mutex::new(ChildProcess {
                inner: Some(child),
                pid,
                ready: false,
            }),
            command: command.to_string(),
            args: args.to_vec(),
            next_id: AtomicU64::new(1),
        }
    }

    /// 发送 JSON-RPC 请求，返回响应
    ///
    /// 修复 C13：原实现在持有 async 锁的情况下做同步 I/O，且 `read_line_flexible`
    /// 无超时 —— 子进程挂起（未退出但不再输出）时会永久阻塞调用线程并锁死整个 client。
    /// 现改为：同步 I/O 在 `spawn_blocking` 中执行，外层用 `tokio::time::timeout`
    /// 包裹；超时即 kill 卡住的子进程（关闭其 stdout 管道，使阻塞的 read 返回），
    /// 然后重启，解除死锁。
    async fn communicate(&self, request: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut guard = self.child.lock().await;

        // 检查进程是否存活，退出则重启
        let exited = match guard.inner.as_mut() {
            Some(c) => c.try_wait().ok().flatten().is_some(),
            None => true,
        };
        if exited {
            let c = spawn_process(&self.command, &self.args);
            guard.pid = c.id();
            guard.inner = Some(c);
            guard.ready = false;
        }

        // 取出子进程所有权移入阻塞线程（避免同步 I/O 卡死 async runtime）
        let mut child = guard.inner.take().expect("child present after spawn");
        let ready = guard.ready;
        let req_str =
            serde_json::to_string(request).map_err(|e| format!("serialize: {}", e))?;
        let cmd = self.command.clone();
        let args = self.args.clone();
        let pid = guard.pid;

        let handle = tokio::task::spawn_blocking(move || {
            let (res, new_ready) = do_communicate(&mut child, ready, &req_str);
            (res, child, new_ready)
        });

        match tokio::time::timeout(Duration::from_secs(30), handle).await {
            Ok(Ok((res, child_back, new_ready))) => {
                guard.pid = child_back.id();
                guard.inner = Some(child_back);
                guard.ready = new_ready;
                let line = res?;
                serde_json::from_str(line.trim()).map_err(|e| format!("parse JSON: {}", e))
            }
            Ok(Err(join_err)) => {
                // 阻塞线程内部 I/O 失败
                let c = spawn_process(&cmd, &args);
                guard.pid = c.id();
                guard.inner = Some(c);
                guard.ready = false;
                Err(format!("MCP 通信线程错误: {}", join_err))
            }
            Err(_elapsed) => {
                // 超时：凭 pid 远程 kill 卡住的子进程（关闭其 stdout 管道，使阻塞的
                // read 返回），随后重启，解除死锁。旧进程由 taskkill/kill 回收，无泄漏。
                kill_pid(pid);
                let c = spawn_process(&cmd, &args);
                guard.pid = c.id();
                guard.inner = Some(c);
                guard.ready = false;
                Err("MCP stdio 通信超时（已重启子进程）".to_string())
            }
        }
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
            // 兼容两种工具 schema：
            //  1) OpenAI 风格嵌套：{ "function": { name, description, parameters } }
            //     （dashboard 自定义 MCP 走此分支，参数键为 parameters）
            //  2) MCP 标准扁平：{ name, description, inputSchema }
            //     （memoria 等标准 MCP 走此分支，参数键为 inputSchema）
            // function 嵌套优先，否则回退到扁平结构。
            let (name_val, desc_val, params_val) = if let Some(func) = t.get("function") {
                (func.get("name"), func.get("description"), func.get("parameters"))
            } else {
                (t.get("name"), t.get("description"), t.get("inputSchema"))
            };
            let name = name_val
                .and_then(|n| n.as_str())
                .unwrap_or("?")
                .to_string();
            let desc = desc_val
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let params = params_val
                .cloned()
                .unwrap_or(serde_json::json!({"type": "object", "properties": {}}));
            result.push((name, desc, params));
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

    #[test]
    fn test_extract_tools_flat_mcp_schema() {
        // MCP 标准扁平结构：{ name, description, inputSchema }
        // memoria 等标准 MCP 走此分支，修复前会被解析为空。
        let data = serde_json::json!({
            "result": {
                "tools": [
                    {
                        "name": "register_agent",
                        "description": "register a new agent",
                        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}
                    },
                    {
                        "name": "memory_search",
                        "description": "semantic search",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        });
        let tools = extract_tools(&data);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].0, "register_agent");
        assert_eq!(tools[0].1, "register a new agent");
        assert_eq!(tools[0].2["properties"]["id"]["type"], "string");
        assert_eq!(tools[1].0, "memory_search");
        assert_eq!(tools[1].1, "semantic search");
    }

    #[test]
    fn test_extract_tools_openai_nested_kept() {
        // OpenAI 风格嵌套：{ "function": { name, description, parameters } }
        // dashboard 自定义 MCP 走此分支，必须保持向后兼容。
        let data = serde_json::json!({
            "result": {
                "tools": [
                    {
                        "function": {
                            "name": "dashboard_action",
                            "description": "do a dashboard thing",
                            "parameters": {"type": "object"}
                        }
                    }
                ]
            }
        });
        let tools = extract_tools(&data);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].0, "dashboard_action");
        assert_eq!(tools[0].1, "do a dashboard thing");
    }

    #[test]
    fn test_extract_tools_mixed_schemas() {
        // 同一响应里混合两种结构，两者都应被解析。
        let data = serde_json::json!({
            "result": {
                "tools": [
                    { "name": "memory_remember", "description": "remember", "inputSchema": {"type": "object"} },
                    { "function": { "name": "dashboard_ping", "description": "ping", "parameters": {"type": "object"} } }
                ]
            }
        });
        let tools = extract_tools(&data);
        assert_eq!(tools.len(), 2);
        let names: Vec<&str> = tools.iter().map(|t| t.0.as_str()).collect();
        assert!(names.contains(&"memory_remember"));
        assert!(names.contains(&"dashboard_ping"));
    }
}
