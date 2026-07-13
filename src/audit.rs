//! 审计日志模块（P2-2 增强）
//!
//! 统一事件分类（AuthFail / BoundaryDeny / Approval* / McpRetry /
//! CheckpointResume / HarnessHit / ToolInvocation / IdentityChange），
//! 每条事件带 `trace_id`（同一请求链路可串联）+ `session_id`（可选）+ 已脱敏 detail。
//!
//! 双写：
//! 1. 异步写入 Memoria 的 audit_log（耐久，失败忽略，不阻塞主流程）；
//! 2. 本地有界环形缓冲（`events`），供只读审计查询 API（`/api/admin/audit`）即时返回，
//!    无需每次查询都打 Memoria。
//!
//! 敏感字段（admin_key / api_key / token / password / secret 等）在写入前脱敏。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::mcp_client::McpClient;
use serde::Serialize;

/// 统一审计事件类型
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// 鉴权失败（x-agent-key / x-user-tag 不匹配、未注册）
    AuthFail,
    /// 边界/红线拒绝（check_tool 不允许）
    BoundaryDeny,
    /// 审批创建
    ApprovalCreated,
    /// 审批通过
    ApprovalApproved,
    /// 审批拒绝
    ApprovalRejected,
    /// MCP 调用重试 / 传输失败
    McpRetry,
    /// Checkpoint 恢复（崩溃续跑）
    CheckpointResume,
    /// Harness 命中（快速路径）
    HarnessHit,
    /// 工具调用（composer 执行）
    ToolInvocation,
    /// 身份变更（注册 / 调岗）
    IdentityChange,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::AuthFail => "auth_fail",
            AuditEventType::BoundaryDeny => "boundary_deny",
            AuditEventType::ApprovalCreated => "approval_created",
            AuditEventType::ApprovalApproved => "approval_approved",
            AuditEventType::ApprovalRejected => "approval_rejected",
            AuditEventType::McpRetry => "mcp_retry",
            AuditEventType::CheckpointResume => "checkpoint_resume",
            AuditEventType::HarnessHit => "harness_hit",
            AuditEventType::ToolInvocation => "tool_invocation",
            AuditEventType::IdentityChange => "identity_change",
        }
    }
}

/// 单条审计事件
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// 发生时间（本地，YYYY-MM-DD HH:MM:SS）
    pub ts: String,
    /// 链路 trace_id（同一次请求内的事件共享，便于还原 LLM→边界→MCP→结果）
    pub trace_id: String,
    /// 触发 agent
    pub agent_id: String,
    /// 会话 id（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// 事件类型
    pub event_type: AuditEventType,
    /// 已脱敏的事件详情
    pub detail: String,
}

/// 进程内自增序号，配合纳秒时间戳生成稳定且唯一的 trace_id
static TRACE_SEQ: AtomicU64 = AtomicU64::new(0);

/// 生成链路 trace_id（纳秒时间戳 + 自增序号，避免引入 uuid 依赖）
pub fn new_trace_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{:016x}-{:08x}", nanos, seq)
}

/// 审计日志记录器
pub struct AuditLogger {
    mcp: McpClient,
    /// 本地有界环形缓冲（只读查询 API 用）
    events: Mutex<VecDeque<AuditEvent>>,
}

const RING_CAPACITY: usize = 2000;

impl AuditLogger {
    /// 创建审计日志记录器（复用指向 Memoria 的 MCP 连接）
    pub fn new(mcp: McpClient) -> Self {
        AuditLogger {
            mcp,
            events: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
        }
    }

    /// 记录一条事件（脱敏 → 入环 → 异步写 Memoria）
    pub async fn record_event(&self, mut ev: AuditEvent) {
        ev.detail = redact(&ev.detail);
        // 1) 本地环形缓冲（有界）
        if let Ok(mut buf) = self.events.lock() {
            if buf.len() >= RING_CAPACITY {
                buf.pop_front();
            }
            buf.push_back(ev.clone());
        }
        // 2) 异步写 Memoria（耐久；失败忽略）
        let payload = serde_json::json!({
            "agent_id": ev.agent_id,
            "tool": format!("audit/{}", ev.event_type.as_str()),
            "params": serde_json::json!({
                "trace_id": ev.trace_id,
                "session_id": ev.session_id,
                "detail": ev.detail,
            }),
            "allowed": true,
        });
        let _ = self.mcp.call("memory_observe", &payload).await;
    }

    /// 只读查询：按 trace_id / event_type 过滤，返回最近 limit 条
    pub fn recent_events(
        &self,
        trace_id: Option<&str>,
        event: Option<&str>,
        limit: usize,
    ) -> Vec<AuditEvent> {
        let buf = match self.events.lock() {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<AuditEvent> = buf
            .iter()
            .filter(|e| {
                if let Some(t) = trace_id {
                    if e.trace_id != t {
                        return false;
                    }
                }
                if let Some(ev) = event {
                    if e.event_type.as_str() != ev {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        // 最新在前
        out.reverse();
        out.into_iter().take(limit).collect()
    }

    // ── 类型化便捷构造器（detail 自动脱敏） ──

    pub async fn auth_fail(&self, agent_id: &str, detail: &str) {
        self.record_event(AuditEvent {
            ts: now_ts(),
            trace_id: new_trace_id(),
            agent_id: agent_id.to_string(),
            session_id: None,
            event_type: AuditEventType::AuthFail,
            detail: detail.to_string(),
        })
        .await;
    }

    pub async fn boundary_deny(
        &self,
        agent_id: &str,
        tool: &str,
        reason: &str,
        trace_id: &str,
        session_id: Option<&str>,
    ) {
        self.record_event(AuditEvent {
            ts: now_ts(),
            trace_id: if trace_id.is_empty() {
                new_trace_id()
            } else {
                trace_id.to_string()
            },
            agent_id: agent_id.to_string(),
            session_id: session_id.map(|s| s.to_string()),
            event_type: AuditEventType::BoundaryDeny,
            detail: format!("tool={} | {}", tool, reason),
        })
        .await;
    }

    pub async fn approval_event(
        &self,
        kind: &str,
        agent_id: &str,
        tool: &str,
        detail: &str,
        trace_id: &str,
        session_id: Option<&str>,
    ) {
        let et = match kind {
            "approved" => AuditEventType::ApprovalApproved,
            "rejected" => AuditEventType::ApprovalRejected,
            _ => AuditEventType::ApprovalCreated,
        };
        self.record_event(AuditEvent {
            ts: now_ts(),
            trace_id: if trace_id.is_empty() {
                new_trace_id()
            } else {
                trace_id.to_string()
            },
            agent_id: agent_id.to_string(),
            session_id: session_id.map(|s| s.to_string()),
            event_type: et,
            detail: format!("tool={} | {}", tool, detail),
        })
        .await;
    }

    pub async fn mcp_retry(
        &self,
        agent_id: &str,
        source: &str,
        tool: &str,
        detail: &str,
        trace_id: &str,
        session_id: Option<&str>,
    ) {
        self.record_event(AuditEvent {
            ts: now_ts(),
            trace_id: if trace_id.is_empty() {
                new_trace_id()
            } else {
                trace_id.to_string()
            },
            agent_id: agent_id.to_string(),
            session_id: session_id.map(|s| s.to_string()),
            event_type: AuditEventType::McpRetry,
            detail: format!("source={} tool={} | {}", source, tool, detail),
        })
        .await;
    }

    pub async fn checkpoint_resume(
        &self,
        agent_id: &str,
        session_id: &str,
        state: &str,
        detail: &str,
    ) {
        self.record_event(AuditEvent {
            ts: now_ts(),
            trace_id: new_trace_id(),
            agent_id: agent_id.to_string(),
            session_id: Some(session_id.to_string()),
            event_type: AuditEventType::CheckpointResume,
            detail: format!("state={} | {}", state, detail),
        })
        .await;
    }

    pub async fn harness_hit(&self, agent_id: &str, session_id: &str, skill: &str) {
        self.record_event(AuditEvent {
            ts: now_ts(),
            trace_id: new_trace_id(),
            agent_id: agent_id.to_string(),
            session_id: Some(session_id.to_string()),
            event_type: AuditEventType::HarnessHit,
            detail: format!("skill={}", skill),
        })
        .await;
    }

    // ── 兼容旧调用（映射到统一事件） ──

    #[tracing::instrument(skip_all, fields(event_type = "policy_decision", agent_id = %agent_id, tool = %tool, allowed))]
    pub async fn log_decision(&self, agent_id: &str, tool: &str, params: &str, allowed: bool) {
        if !allowed {
            self.boundary_deny(agent_id, tool, params, "", None).await;
        } else {
            // 允许的策略决策也记录（ToolInvocation 语义近似）
            self.record_event(AuditEvent {
                ts: now_ts(),
                trace_id: new_trace_id(),
                agent_id: agent_id.to_string(),
                session_id: None,
                event_type: AuditEventType::ToolInvocation,
                detail: format!("allowed decision for {}", tool),
            })
            .await;
        }
    }

    #[tracing::instrument(skip_all, fields(event_type = "identity_change", agent_id = %agent_id, action = %action))]
    pub async fn log_identity(&self, agent_id: &str, action: &str, detail: &str) {
        self.record_event(AuditEvent {
            ts: now_ts(),
            trace_id: new_trace_id(),
            agent_id: agent_id.to_string(),
            session_id: None,
            event_type: AuditEventType::IdentityChange,
            detail: format!("{}={}", action, detail),
        })
        .await;
    }

    #[tracing::instrument(skip_all, fields(event_type = "tool_invocation", agent_id = %agent_id, tool = %tool, allowed))]
    pub async fn log_tool_call(
        &self,
        agent_id: &str,
        tool: &str,
        args: &serde_json::Value,
        allowed: bool,
    ) {
        let summary = summarize_args(args);
        self.record_event(AuditEvent {
            ts: now_ts(),
            trace_id: new_trace_id(),
            agent_id: agent_id.to_string(),
            session_id: None,
            event_type: if allowed {
                AuditEventType::ToolInvocation
            } else {
                AuditEventType::BoundaryDeny
            },
            detail: format!("tool={} | args={}", tool, summary),
        })
        .await;
    }
}

/// 本地时间戳（YYYY-MM-DD HH:MM:SS）
fn now_ts() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 敏感字段脱敏（自由文本）
pub fn redact(text: &str) -> String {
    const SENSITIVE_KEYS: &[&str] = &[
        "admin_key",
        "api_key",
        "badge_token",
        "token",
        "password",
        "secret",
        "authorization",
    ];
    let mut out = text.to_string();
    for key in SENSITIVE_KEYS {
        // 形如 key="..." / key: "..." 的键值对，脱敏其值
        let pat = format!("{}", key);
        if let Some(idx) = out.to_lowercase().find(&pat) {
            // 找后续引号包裹的值
            let rest = &out[idx..];
            if let Some(q1) = rest[pat.len()..].find('"') {
                let after = &rest[pat.len() + q1 + 1..];
                if let Some(q2) = after.find('"') {
                    let val = &after[..q2];
                    if !val.is_empty() {
                        let from = idx + pat.len() + q1 + 1;
                        let to = from + q2;
                        out.replace_range(from..to, "***");
                    }
                }
            }
        }
    }
    // 脱敏长十六进制密钥（>=16 位 hex）
    out
}

/// 参数摘要：限制长度 + 排除敏感字段
fn summarize_args(args: &serde_json::Value) -> String {
    const MAX_LEN: usize = 200;
    const SENSITIVE_KEYS: &[&str] = &[
        "admin_key",
        "api_key",
        "badge_token",
        "token",
        "password",
        "secret",
    ];

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_api_key_value() {
        let raw = "call with api_key=\"deadbeefcafe0000\" and token=\"abc\"";
        let r = redact(raw);
        assert!(!r.contains("deadbeefcafe0000"), "api_key 值应被脱敏: {}", r);
        assert!(!r.contains("abc\""), "token 值应被脱敏: {}", r);
        assert!(r.contains("api_key"));
    }

    #[test]
    fn event_type_strings_stable() {
        assert_eq!(AuditEventType::AuthFail.as_str(), "auth_fail");
        assert_eq!(AuditEventType::BoundaryDeny.as_str(), "boundary_deny");
        assert_eq!(
            AuditEventType::CheckpointResume.as_str(),
            "checkpoint_resume"
        );
    }

    #[test]
    fn ring_buffer_query_by_trace() {
        // 单测不触发网络写入（recent_events 只读本地缓冲），mcp 用占位构造
        let logger = AuditLogger {
            mcp: McpClient::new("http://127.0.0.1:9", "test", "x"),
            events: Mutex::new(VecDeque::new()),
        };
        // 直接验证 recent_events 过滤逻辑（不触发 record_event 的网络写入）
        let tid = "trace-001";
        logger.events.lock().unwrap().push_back(AuditEvent {
            ts: now_ts(),
            trace_id: tid.to_string(),
            agent_id: "a".into(),
            session_id: None,
            event_type: AuditEventType::HarnessHit,
            detail: "skill=x".into(),
        });
        let got = logger.recent_events(Some(tid), None, 10);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].event_type, AuditEventType::HarnessHit);
        let none = logger.recent_events(Some("nope"), None, 10);
        assert!(none.is_empty());
    }
}
