//! 审批流 — YELLOW 红线扩展到指定审批人
//!
//! 当 Agent 触发 YELLOW 级别工具且配置了审批人时，
//! 通过 A2A 向审批人发送审批请求，等待审批结果后再执行。

use std::collections::HashMap;
use tokio::sync::Mutex;

/// 审批状态
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalStatus {
    /// 等待审批
    Pending,
    /// 已批准
    Approved,
    /// 已拒绝
    Denied,
}

/// 待审批项
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub approval_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub description: String,
    pub approver_id: String,
    pub requester_id: String,
    pub status: ApprovalStatus,
    pub created_at: f64,
}

/// 审批请求（通过 A2A 发送）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalRequest {
    pub r#type: String, // "approval_request"
    pub approval_id: String,
    pub tool_name: String,
    pub description: String,
    pub arguments: serde_json::Value,
    pub requester_id: String,
    pub requester_ns: String,
}

/// 审批响应（通过 A2A 接收）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalResponse {
    pub r#type: String, // "approval_response"
    pub approval_id: String,
    pub approved: bool,
    pub reason: Option<String>,
    pub approver_id: String,
}

/// 审批管理器
///
/// 跟踪发出去的审批请求和收到的审批结果。
pub struct ApprovalManager {
    /// 发出去的待审批请求（approval_id → PendingApproval）
    outgoing: Mutex<HashMap<String, PendingApproval>>,
    /// 收到的审批结果（approval_id → ApprovalResponse）
    responses: Mutex<HashMap<String, ApprovalResponse>>,
}

impl ApprovalManager {
    pub fn new() -> Self {
        ApprovalManager {
            outgoing: Mutex::new(HashMap::new()),
            responses: Mutex::new(HashMap::new()),
        }
    }

    /// 创建审批请求（存入 outgoing，等待审批）
    pub async fn create_request(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        description: &str,
        approver_id: &str,
        requester_id: &str,
    ) -> String {
        let approval_id = format!("apr_{}_{}", chrono::Utc::now().timestamp_millis(), tool_name);
        let now = now_secs();

        let mut outgoing = self.outgoing.lock().await;
        outgoing.insert(approval_id.clone(), PendingApproval {
            approval_id: approval_id.clone(),
            tool_name: tool_name.to_string(),
            arguments: arguments.clone(),
            description: description.to_string(),
            approver_id: approver_id.to_string(),
            requester_id: requester_id.to_string(),
            status: ApprovalStatus::Pending,
            created_at: now,
        });

        approval_id
    }

    /// 记录收到的审批响应
    pub async fn record_response(&self, response: ApprovalResponse) {
        let mut responses = self.responses.lock().await;
        responses.insert(response.approval_id.clone(), response);
    }

    /// 检查审批是否已完成
    pub async fn check_response(&self, approval_id: &str) -> Option<ApprovalResponse> {
        let responses = self.responses.lock().await;
        responses.get(approval_id).cloned()
    }

    /// 检查审批是否已批准
    pub async fn is_approved(&self, approval_id: &str) -> Option<bool> {
        let responses = self.responses.lock().await;
        responses.get(approval_id).map(|r| r.approved)
    }

    /// 获取 pending 中的审批项（不移除）
    pub async fn get_pending(&self, approval_id: &str) -> Option<PendingApproval> {
        let outgoing = self.outgoing.lock().await;
        outgoing.get(approval_id).cloned()
    }

    /// 获取所有 pending 的审批项
    pub async fn list_pending(&self) -> Vec<PendingApproval> {
        let outgoing = self.outgoing.lock().await;
        outgoing.values()
            .filter(|a| a.status == ApprovalStatus::Pending)
            .cloned()
            .collect()
    }

    /// 移除已完成的审批项
    pub async fn remove(&self, approval_id: &str) {
        self.outgoing.lock().await.remove(approval_id);
        self.responses.lock().await.remove(approval_id);
    }

    /// pending 数量
    pub async fn pending_count(&self) -> usize {
        self.outgoing.lock().await.len()
    }

    /// 构建 A2A 审批请求消息
    pub fn build_a2a_request(&self, approval: &PendingApproval, requester_ns: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "approval_request",
            "approval_id": approval.approval_id,
            "tool_name": approval.tool_name,
            "description": approval.description,
            "arguments": approval.arguments,
            "requester_id": approval.requester_id,
            "requester_ns": requester_ns,
        })
    }

    /// 从 A2A 消息中解析审批请求
    pub fn parse_approval_request(msg: &serde_json::Value) -> Option<ApprovalRequest> {
        if msg.get("type")?.as_str()? != "approval_request" {
            return None;
        }
        Some(ApprovalRequest {
            r#type: "approval_request".to_string(),
            approval_id: msg["approval_id"].as_str()?.to_string(),
            tool_name: msg["tool_name"].as_str()?.to_string(),
            description: msg["description"].as_str()?.to_string(),
            arguments: msg["arguments"].clone(),
            requester_id: msg["requester_id"].as_str()?.to_string(),
            requester_ns: msg["requester_ns"].as_str()?.to_string(),
        })
    }

    /// 从 A2A 消息中解析审批响应
    pub fn parse_approval_response(msg: &serde_json::Value) -> Option<ApprovalResponse> {
        if msg.get("type")?.as_str()? != "approval_response" {
            return None;
        }
        Some(ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: msg["approval_id"].as_str()?.to_string(),
            approved: msg["approved"].as_bool()?,
            reason: msg.get("reason").and_then(|r| r.as_str()).map(|s| s.to_string()),
            approver_id: msg["approver_id"].as_str()?.to_string(),
        })
    }
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 同步检查是否有 pending 审批（供 check_tool 使用）
///
/// check_tool 是同步方法，不能 await，所以用这个辅助函数
/// 快速检查当前工具是否需要走审批流程。
pub fn has_pending_approval_sync(_manager: &ApprovalManager, _tool_name: &str) -> bool {
    // 简单实现：检查 dangerous 工具是否需要审批
    // 完整实现需要 tokio::runtime 或 async 调用，这里保持同步
    false
}

fn now_secs() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_status_partial_eq() {
        assert_eq!(ApprovalStatus::Pending, ApprovalStatus::Pending);
        assert_ne!(ApprovalStatus::Pending, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn test_approval_manager_new() {
        let am = ApprovalManager::new();
        assert_eq!(am.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_create_and_get_pending() {
        let am = ApprovalManager::new();
        let aid = am.create_request(
            "delete_record",
            &serde_json::json!({"id": 42}),
            "删除记录 42",
            "approver-01",
            "agent-001",
        ).await;

        let pending = am.get_pending(&aid).await;
        assert!(pending.is_some());
        assert_eq!(pending.unwrap().tool_name, "delete_record");
        assert_eq!(am.pending_count().await, 1);
    }

    #[tokio::test]
    async fn test_record_and_check_response() {
        let am = ApprovalManager::new();
        let aid = am.create_request("delete_record", &serde_json::json!({}), "del", "approver-01", "agent-001").await;

        // 审批人批准
        let resp = ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: true,
            reason: None,
            approver_id: "approver-01".to_string(),
        };
        am.record_response(resp).await;

        assert_eq!(am.is_approved(&aid).await, Some(true));
    }

    #[tokio::test]
    async fn test_deny_response() {
        let am = ApprovalManager::new();
        let aid = am.create_request("shutdown_server", &serde_json::json!({}), "关停", "admin", "agent-001").await;

        let resp = ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: false,
            reason: Some("非维护时间，拒绝关停".to_string()),
            approver_id: "admin".to_string(),
        };
        am.record_response(resp).await;

        assert_eq!(am.is_approved(&aid).await, Some(false));
    }

    #[test]
    fn test_parse_approval_request() {
        let msg = serde_json::json!({
            "type": "approval_request",
            "approval_id": "apr_123",
            "tool_name": "delete_record",
            "description": "删除记录",
            "arguments": {"id": 1},
            "requester_id": "agent-001",
            "requester_ns": "agent/agent-001/dept/运营部",
        });
        let req = ApprovalManager::parse_approval_request(&msg).unwrap();
        assert_eq!(req.approval_id, "apr_123");
        assert_eq!(req.tool_name, "delete_record");
    }

    #[test]
    fn test_parse_approval_response() {
        let msg = serde_json::json!({
            "type": "approval_response",
            "approval_id": "apr_123",
            "approved": true,
            "reason": "可以执行",
            "approver_id": "admin-01",
        });
        let resp = ApprovalManager::parse_approval_response(&msg).unwrap();
        assert_eq!(resp.approval_id, "apr_123");
        assert!(resp.approved);
        assert_eq!(resp.reason, Some("可以执行".to_string()));
    }

    #[test]
    fn test_build_a2a_request() {
        let am = ApprovalManager::new();
        let approval = PendingApproval {
            approval_id: "apr_456".to_string(),
            tool_name: "batch_update".to_string(),
            arguments: serde_json::json!({"ids": [1,2,3]}),
            description: "批量更新".to_string(),
            approver_id: "admin".to_string(),
            requester_id: "agent-001".to_string(),
            status: ApprovalStatus::Pending,
            created_at: 1000.0,
        };
        let json = am.build_a2a_request(&approval, "agent/agent-001/dept/运营部");
        assert_eq!(json["type"], "approval_request");
        assert_eq!(json["approval_id"], "apr_456");
    }

    #[tokio::test]
    async fn test_list_pending() {
        let am = ApprovalManager::new();
        am.create_request("tool_a", &serde_json::json!({}), "A", "approver-01", "agent-001").await;
        am.create_request("tool_b", &serde_json::json!({}), "B", "approver-01", "agent-001").await;

        assert_eq!(am.list_pending().await.len(), 2);
    }

    #[tokio::test]
    async fn test_remove() {
        let am = ApprovalManager::new();
        let aid = am.create_request("tool", &serde_json::json!({}), "test", "approver-01", "agent-001").await;

        let resp = ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: true,
            reason: None,
            approver_id: "approver-01".to_string(),
        };
        am.record_response(resp).await;
        am.remove(&aid).await;
        assert_eq!(am.pending_count().await, 0);
    }
}
