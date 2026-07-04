//! 审计日志模块
//!
//! 将 agent-core 内部的决策、工具调用、身份变更等事件记录到 Memoria 的 audit_log 表。
//! Memoria 的 audit_log 表已分离到独立 audit.db，不占用记忆数据库的锁。
//!
//! 审计日志是异步非阻塞的——写入失败不影响主流程。

use crate::mcp_client::McpClient;

/// 审计事件分类
#[derive(Debug, Clone, Copy)]
pub enum AuditEventType {
    /// 策略决策（check_tool 结果）
    PolicyDecision,
    /// 身份变更（注册/调岗）
    IdentityChange,
    /// 工具调用（composer execute_plan）
    ToolInvocation,
}

impl AuditEventType {
    fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::PolicyDecision => "policy_decision",
            AuditEventType::IdentityChange => "identity_change",
            AuditEventType::ToolInvocation => "tool_invocation",
        }
    }
}

/// 审计日志记录器
pub struct AuditLogger {
    mcp: McpClient,
}

impl AuditLogger {
    /// 创建审计日志记录器
    ///
    /// 复用 agent-core 已有的 MCP 连接（指向 Memoria）。
    pub fn new(mcp: McpClient) -> Self {
        AuditLogger { mcp }
    }

    /// 记录一条策略决策审计
    ///
    /// 在 check_tool 返回前调用，记录谁请求了什么工具、结果是允许还是拒绝。
    pub async fn log_decision(&self, agent_id: &str, tool: &str, params: &str, allowed: bool) {
        let payload = serde_json::json!({
            "agent_id": agent_id,
            "tool": format!("{}/{}", AuditEventType::PolicyDecision.as_str(), tool),
            "params": params,
            "allowed": allowed,
        });
        // 非阻塞写入，失败忽略
        // Memoria MCP 已自动记录 audit_log，此调用为冗余主动写入
        let _ = self.mcp.call("memory_observe", &payload).await;
    }

    /// 记录身份变更审计
    ///
    /// 注册、调岗、角色变更时调用。
    pub async fn log_identity(&self, agent_id: &str, action: &str, detail: &str) {
        let payload = serde_json::json!({
            "agent_id": agent_id,
            "tool": format!("{}/{}", AuditEventType::IdentityChange.as_str(), action),
            "params": detail,
            "allowed": true,
        });
        let _ = self.mcp.call("memory_observe", &payload).await;
    }

    /// 记录工具调用审计
    ///
    /// composer execute_plan 每步执行前后调用。
    pub async fn log_tool_call(&self, agent_id: &str, tool: &str, args: &serde_json::Value, allowed: bool) {
        // 只记录参数摘要，不传敏感字段
        let summary = summarize_args(args);
        let payload = serde_json::json!({
            "agent_id": agent_id,
            "tool": format!("{}/{}", AuditEventType::ToolInvocation.as_str(), tool),
            "params": summary,
            "allowed": allowed,
        });
        let _ = self.mcp.call("memory_observe", &payload).await;
    }
}

/// 参数摘要：限制长度 + 排除敏感字段
fn summarize_args(args: &serde_json::Value) -> String {
    const MAX_LEN: usize = 200;
    const SENSITIVE_KEYS: &[&str] = &["admin_key", "api_key", "badge_token", "token", "password", "secret"];

    match args {
        serde_json::Value::Object(map) => {
            let mut clean = serde_json::Map::new();
            for (k, v) in map.iter() {
                if SENSITIVE_KEYS.contains(&k.as_str()) {
                    clean.insert(k.clone(), serde_json::Value::String("***".to_string()));
                } else {
                    clean.insert(k.clone(), v.clone());
                }
            }
            let s = serde_json::to_string(&clean).unwrap_or_default();
            if s.len() > MAX_LEN {
                format!("{}…", &s[..MAX_LEN])
            } else {
                s
            }
        }
        _ => {
            let s = args.to_string();
            if s.len() > MAX_LEN {
                format!("{}…", &s[..MAX_LEN])
            } else {
                s
            }
        }
    }
}
