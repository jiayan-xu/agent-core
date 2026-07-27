//! 审批流 — YELLOW 红线扩展到指定审批人
//!
//! 当 Agent 触发 YELLOW 级别工具且配置了审批人时，
//! 通过 A2A 向审批人发送审批请求，等待审批结果后再执行。

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;

/// C1b: 审批态记忆 TTL（秒）
/// - 已批准：默认 1h（非 24h，避免长时间挂起的批准被遗忘，过期需重批）
/// - 已否决：短 TTL 60s（防重复问，过期回到黄线）
/// - pending：24h（主要靠 resolve 时清除，TTL 兜底防泄漏）
const APPROVED_TTL: f64 = 3600.0;
const REJECTED_TTL: f64 = 60.0;
const PENDING_TTL: f64 = 86400.0;

/// 审批状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    /// 等待审批
    Pending,
    /// 已批准
    Approved,
    /// 已拒绝
    Denied,
}

/// 待审批项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub approval_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub description: String,
    pub approver_id: String,
    pub requester_id: String,
    pub status: ApprovalStatus,
    pub created_at: f64,
    /// Phase A (OpenClaw crestidan 吸收): 操作的规范化指纹。
    /// 由 host 在创建请求时计算，审批响应必须回显同一指纹，
    /// 否则视为「操作被偷换」而拒绝（防模型自我批准 / 审批-执行错位）。
    pub operation_hash: String,
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
    /// Phase A: 审批人必须回显创建时的操作指纹；与 PendingApproval.operation_hash 不一致即拒绝。
    pub operation_hash: String,
}

/// 审批管理器
///
/// 跟踪发出去的审批请求和收到的审批结果。
/// L2：支持 JSON 文件持久化（store_path），使人工审批跨 agent-core 重启不丢。
pub struct ApprovalManager {
    /// 发出去的待审批请求（approval_id → PendingApproval）
    outgoing: Mutex<HashMap<String, PendingApproval>>,
    /// 收到的审批结果（approval_id → ApprovalResponse）
    responses: Mutex<HashMap<String, ApprovalResponse>>,
    /// 持久化路径（None = 仅内存，不落盘）
    store_path: Option<std::path::PathBuf>,
    /// C1b: 审批态内存记忆（同步可读，供 check_tool 快查，绕过 async Mutex）。
    /// key 形如 `pending:{tool}@{agent}` / `approved:{tool}@{agent}@{op_hash}` / `rejected:{tool}@{agent}`
    /// value = 过期时间戳（unix secs）；TTL 过期由查询时惰性清除。不落盘（短生命周期）。
    memory: StdMutex<HashMap<String, f64>>,
}

impl ApprovalManager {
    /// 内存模式（测试 / 无持久化需求）
    pub fn new() -> Self {
        Self::new_with_store(None)
    }

    /// 带持久化的审批管理器：启动即从 store_path 反序列化恢复 pending / responses，
    /// 使人工审批跨 agent-core 重启不丢（用户可能重启后才回到审批台点批准）。
    pub fn new_with_store(store_path: Option<std::path::PathBuf>) -> Self {
        let mut outgoing: HashMap<String, PendingApproval> = HashMap::new();
        let mut responses: HashMap<String, ApprovalResponse> = HashMap::new();
        if let Some(path) = &store_path {
            if let Ok(s) = std::fs::read_to_string(path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                    if let Some(arr) = v.get("outgoing").and_then(|x| x.as_array()) {
                        for item in arr {
                            if let Ok(p) = serde_json::from_value::<PendingApproval>(item.clone()) {
                                outgoing.insert(p.approval_id.clone(), p);
                            }
                        }
                    }
                    if let Some(arr) = v.get("responses").and_then(|x| x.as_array()) {
                        for item in arr {
                            if let Ok(r) = serde_json::from_value::<ApprovalResponse>(item.clone()) {
                                responses.insert(r.approval_id.clone(), r);
                            }
                        }
                    }
                }
            }
        }
        ApprovalManager {
            outgoing: Mutex::new(outgoing),
            responses: Mutex::new(responses),
            store_path,
            memory: StdMutex::new(HashMap::new()),
        }
    }

    /// 原子落盘：先写 .tmp 再 rename。序列化在持锁块内完成（Value 拥有数据，离开块即释放锁）。
    async fn persist(&self) {
        if let Some(path) = &self.store_path {
            let payload = {
                let outgoing = self.outgoing.lock().await;
                let responses = self.responses.lock().await;
                serde_json::json!({
                    "outgoing": outgoing.values().collect::<Vec<_>>(),
                    "responses": responses.values().collect::<Vec<_>>(),
                })
            };
            if let Ok(s) = serde_json::to_string_pretty(&payload) {
                let tmp = path.with_extension("tmp");
                if std::fs::write(&tmp, &s).is_ok() {
                    let _ = std::fs::rename(&tmp, path);
                }
            }
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
        // C1b 防重复建单：同 tool+requester 已有 pending → 复用既有 id，不重复造单。
        if crate::approval::is_pending_sync(self, tool_name, requester_id) {
            let outgoing = self.outgoing.lock().await;
            for (id, p) in outgoing.iter() {
                if p.tool_name == tool_name
                    && p.requester_id == requester_id
                    && p.status == ApprovalStatus::Pending
                {
                    return id.clone();
                }
            }
        }

        let approval_id = format!(
            "apr_{}_{}",
            chrono::Utc::now().timestamp_millis(),
            tool_name
        );
        let now = now_secs();
        // Phase A: host 计算操作指纹（防后续审批-执行错位 / 模型自我批准）
        let operation_hash = compute_operation_hash(tool_name, arguments);

        let mut outgoing = self.outgoing.lock().await;
        outgoing.insert(
            approval_id.clone(),
            PendingApproval {
                approval_id: approval_id.clone(),
                tool_name: tool_name.to_string(),
                arguments: arguments.clone(),
                description: description.to_string(),
                approver_id: approver_id.to_string(),
                requester_id: requester_id.to_string(),
                status: ApprovalStatus::Pending,
                created_at: now,
                operation_hash,
            },
        );
        drop(outgoing);
        // C1b: 记录 pending 记忆（供 is_pending_sync 防重复建单）
        if let Ok(mut mem) = self.memory.lock() {
            mem.insert(
                format!("pending:{}@{}", tool_name, requester_id),
                now + PENDING_TTL,
            );
        }
        self.persist().await;

        approval_id
    }

    /// 记录收到的审批响应
    ///
    /// C1c: 兜底校验 `operation_hash` 防偷换（defense-in-depth）。
    /// 即便 HTTP 台（main.rs:2916）与 A2A 中继（main.rs:2803）已校验，
    /// 任何调用方到此仍拦一道错配；错配或 pending 不存在则拒绝插入。
    /// C1b: 写入后同步更新审批态记忆（approved 含 op_hash / rejected 短 TTL）。
    pub async fn record_response(&self, response: ApprovalResponse) {
        let approved = response.approved;
        let approval_id = response.approval_id.clone();

        // 兜底校验 operation_hash（防偷换/越权写入）
        let pending_opt = self.get_pending(&approval_id).await;
        match pending_opt {
            Some(p) => {
                if p.operation_hash != response.operation_hash {
                    tracing::warn!(
                        "[APPROVAL] record_response hash 不匹配，拒绝 {}",
                        approval_id
                    );
                    return;
                }
            }
            None => {
                tracing::warn!("[APPROVAL] record_response 找不到 pending {}", approval_id);
                return;
            }
        }

        let mut responses = self.responses.lock().await;
        responses.insert(approval_id.clone(), response);
        drop(responses);

        // C1b: 更新审批态记忆
        if let Some(p) = self.get_pending(&approval_id).await {
            if let Ok(mut mem) = self.memory.lock() {
                let now = now_secs();
                // 移除 pending 标记（已 resolve）
                mem.remove(&format!("pending:{}@{}", p.tool_name, p.requester_id));
                if approved {
                    mem.insert(
                        format!(
                            "approved:{}@{}@{}",
                            p.tool_name, p.requester_id, p.operation_hash
                        ),
                        now + APPROVED_TTL,
                    );
                } else {
                    mem.insert(
                        format!("rejected:{}@{}", p.tool_name, p.requester_id),
                        now + REJECTED_TTL,
                    );
                }
            }
        }
        self.persist().await;
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

    /// 获取所有 pending 的审批项（已收到响应/已决定的不列出，避免审批台重复处理）
    pub async fn list_pending(&self) -> Vec<PendingApproval> {
        let outgoing = self.outgoing.lock().await;
        let responses = self.responses.lock().await;
        outgoing
            .values()
            .filter(|a| {
                a.status == ApprovalStatus::Pending && !responses.contains_key(&a.approval_id)
            })
            .cloned()
            .collect()
    }

    /// P0 修复：返回「pending 仍在 + 已收到 approved 响应」的项——执行侧应消费的就绪集。
    /// 与 `list_pending`（排除任何 response）互补：list_pending 给审批台看，本函数给执行侧用。
    /// 原 `execute_approved_request` 走 `list_pending` + `is_approved` 形成死路（list_pending 已排除有 response 的项，
    /// 故 is_approved 永为 None → 批准后执行路径恒空）。本函数修复该断路。
    pub async fn list_approved_ready(&self) -> Vec<PendingApproval> {
        let outgoing = self.outgoing.lock().await;
        let responses = self.responses.lock().await;
        outgoing
            .values()
            .filter(|a| {
                a.status == ApprovalStatus::Pending
                    && responses.get(&a.approval_id).map(|r| r.approved) == Some(true)
            })
            .cloned()
            .collect()
    }

    /// 移除已完成的审批项
    pub async fn remove(&self, approval_id: &str) {
        self.outgoing.lock().await.remove(approval_id);
        self.responses.lock().await.remove(approval_id);
        self.persist().await;
    }

    /// pending 数量
    pub async fn pending_count(&self) -> usize {
        self.outgoing.lock().await.len()
    }

    /// 构建 A2A 审批请求消息
    pub fn build_a2a_request(
        &self,
        approval: &PendingApproval,
        requester_ns: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "type": "approval_request",
            "approval_id": approval.approval_id,
            "tool_name": approval.tool_name,
            "description": approval.description,
            "arguments": approval.arguments,
            "requester_id": approval.requester_id,
            "requester_ns": requester_ns,
            "operation_hash": approval.operation_hash,
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
            reason: msg
                .get("reason")
                .and_then(|r| r.as_str())
                .map(|s| s.to_string()),
            approver_id: msg["approver_id"].as_str()?.to_string(),
            operation_hash: msg["operation_hash"].as_str()?.to_string(),
        })
    }
}

/// Phase A (OpenClaw crestidan 吸收): 计算操作的规范化指纹。
///
/// 取 `{tool, args}` 的规范化 JSON 串的 sha256。审批创建时由 host 计算并随请求下发的指纹，
/// 审批响应必须回显同一指纹；不一致即视为「操作被偷换」（防模型自我批准 / 审批-执行错位）。
pub(crate) fn compute_operation_hash(tool_name: &str, arguments: &serde_json::Value) -> String {
    let canonical = serde_json::json!({ "tool": tool_name, "args": arguments });
    let s = serde_json::to_string(&canonical).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self::new()
    }
}

/// C1b: 同步读取审批态记忆——是否已批准（精确 op_hash，TTL 1h）。
/// 供 check_tool 决定是否跳过黄线（已批准=放行；未批准/已否决/无记录=仍走黄线/红闸）。
/// 用 std Mutex 支撑的 `memory` 字段做同步快查（check_tool 是同步方法，不能 await）。
pub fn is_approved_sync(
    manager: &ApprovalManager,
    tool_name: &str,
    args: &serde_json::Value,
    agent_id: &str,
) -> bool {
    let op_hash = compute_operation_hash(tool_name, args);
    if let Ok(mut mem) = manager.memory.lock() {
        let now = now_secs();
        mem.retain(|_, exp| *exp > now); // 惰性清除过期项
        mem.contains_key(&format!("approved:{}@{}@{}", tool_name, agent_id, op_hash))
    } else {
        false
    }
}

/// C1b: 同步读取——是否已被否决（短 TTL 60s）。命中→check_tool 直接红闸。
pub fn is_rejected_sync(manager: &ApprovalManager, tool_name: &str, agent_id: &str) -> bool {
    if let Ok(mut mem) = manager.memory.lock() {
        let now = now_secs();
        mem.retain(|_, exp| *exp > now);
        mem.contains_key(&format!("rejected:{}@{}", tool_name, agent_id))
    } else {
        false
    }
}

/// C1b: 同步读取——是否已有 pending（防重复建单）。
pub fn is_pending_sync(manager: &ApprovalManager, tool_name: &str, agent_id: &str) -> bool {
    if let Ok(mem) = manager.memory.lock() {
        mem.contains_key(&format!("pending:{}@{}", tool_name, agent_id))
    } else {
        false
    }
}

fn now_secs() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
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
        let aid = am
            .create_request(
                "delete_record",
                &serde_json::json!({"id": 42}),
                "删除记录 42",
                "approver-01",
                "agent-001",
            )
            .await;

        let pending = am.get_pending(&aid).await;
        assert!(pending.is_some());
        assert_eq!(pending.unwrap().tool_name, "delete_record");
        assert_eq!(am.pending_count().await, 1);
    }

    #[tokio::test]
    async fn test_record_and_check_response() {
        let am = ApprovalManager::new();
        let aid = am
            .create_request(
                "delete_record",
                &serde_json::json!({}),
                "del",
                "approver-01",
                "agent-001",
            )
            .await;
        // 用 pending 真实 operation_hash 回显（C1c 校验要求一致）
        let pending_hash = am.get_pending(&aid).await.unwrap().operation_hash;

        // 审批人批准
        let resp = ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: true,
            reason: None,
            approver_id: "approver-01".to_string(),
            operation_hash: pending_hash,
        };
        am.record_response(resp).await;

        assert_eq!(am.is_approved(&aid).await, Some(true));
    }

    #[tokio::test]
    async fn test_deny_response() {
        let am = ApprovalManager::new();
        let aid = am
            .create_request(
                "shutdown_server",
                &serde_json::json!({}),
                "关停",
                "admin",
                "agent-001",
            )
            .await;
        let pending_hash = am.get_pending(&aid).await.unwrap().operation_hash;

        let resp = ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: false,
            reason: Some("非维护时间，拒绝关停".to_string()),
            approver_id: "admin".to_string(),
            operation_hash: pending_hash,
        };
        am.record_response(resp).await;

        assert_eq!(am.is_approved(&aid).await, Some(false));
    }

    // ── C1 回归 / 新测试 ──

    /// P0 死路修复：list_approved_ready 能命中已批准项（原 list_pending + is_approved 恒空）
    #[tokio::test]
    async fn test_list_approved_ready() {
        let am = ApprovalManager::new();
        let aid = am
            .create_request(
                "delete_record",
                &serde_json::json!({"id": 1}),
                "del",
                "approver-01",
                "agent-001",
            )
            .await;
        let pending_hash = am.get_pending(&aid).await.unwrap().operation_hash;
        // 审批台视角：list_pending 仍可见（尚无 response）
        assert_eq!(am.list_pending().await.len(), 1);
        // 执行侧视角：list_approved_ready 此时为空（未批准）
        assert_eq!(am.list_approved_ready().await.len(), 0);

        am.record_response(ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: true,
            reason: None,
            approver_id: "approver-01".to_string(),
            operation_hash: pending_hash,
        })
        .await;
        // 批准后：审批台不再列出（list_pending 排除有 response 的），执行侧就绪
        assert_eq!(am.list_pending().await.len(), 0);
        assert_eq!(am.list_approved_ready().await.len(), 1);
    }

    /// C1c：record_response 对 operation_hash 错配应拒绝（不写入 approved）
    #[tokio::test]
    async fn test_record_response_hash_mismatch_rejected() {
        let am = ApprovalManager::new();
        let aid = am
            .create_request(
                "delete_record",
                &serde_json::json!({}),
                "del",
                "approver-01",
                "agent-001",
            )
            .await;
        am.record_response(ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: true,
            reason: None,
            approver_id: "approver-01".to_string(),
            operation_hash: "wrong_hash".to_string(),
        })
        .await;
        // 错配 → 不标记 approved
        assert_eq!(am.is_approved(&aid).await, None);
        assert_eq!(am.list_approved_ready().await.len(), 0);
    }

    /// C1b：批准后「换 args」不能复用批准（approved 指纹含 op_hash）
    #[tokio::test]
    async fn test_approved_args_isolation() {
        let am = ApprovalManager::new();
        // 批准 delete_record(args=A)
        let aid_a = am
            .create_request(
                "delete_record",
                &serde_json::json!({"id": 1}),
                "del A",
                "approver-01",
                "agent-001",
            )
            .await;
        let hash_a = am.get_pending(&aid_a).await.unwrap().operation_hash;
        am.record_response(ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid_a.clone(),
            approved: true,
            reason: None,
            approver_id: "approver-01".to_string(),
            operation_hash: hash_a,
        })
        .await;

        // args=A 已批准
        assert!(is_approved_sync(&am, "delete_record", &serde_json::json!({"id": 1}), "agent-001"));
        // args=B（不同 hash）未批准 → 仍走黄线
        assert!(!is_approved_sync(&am, "delete_record", &serde_json::json!({"id": 2}), "agent-001"));
    }

    /// C1b：rejected 记忆（短 TTL）生效
    #[tokio::test]
    async fn test_rejected_memory() {
        let am = ApprovalManager::new();
        let aid = am
            .create_request(
                "delete_record",
                &serde_json::json!({}),
                "del",
                "approver-01",
                "agent-001",
            )
            .await;
        let hash = am.get_pending(&aid).await.unwrap().operation_hash;
        am.record_response(ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: false,
            reason: Some("拒绝".to_string()),
            approver_id: "approver-01".to_string(),
            operation_hash: hash,
        })
        .await;
        assert!(is_rejected_sync(&am, "delete_record", "agent-001"));
        assert!(!is_approved_sync(&am, "delete_record", &serde_json::json!({}), "agent-001"));
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
            "operation_hash": "apr_123",
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
            operation_hash: "op_hash_456".to_string(),
        };
        let json = am.build_a2a_request(&approval, "agent/agent-001/dept/运营部");
        assert_eq!(json["type"], "approval_request");
        assert_eq!(json["approval_id"], "apr_456");
    }

    #[tokio::test]
    async fn test_list_pending() {
        let am = ApprovalManager::new();
        am.create_request(
            "tool_a",
            &serde_json::json!({}),
            "A",
            "approver-01",
            "agent-001",
        )
        .await;
        am.create_request(
            "tool_b",
            &serde_json::json!({}),
            "B",
            "approver-01",
            "agent-001",
        )
        .await;

        assert_eq!(am.list_pending().await.len(), 2);
    }

    #[tokio::test]
    async fn test_remove() {
        let am = ApprovalManager::new();
        let aid = am
            .create_request(
                "tool",
                &serde_json::json!({}),
                "test",
                "approver-01",
                "agent-001",
            )
            .await;

        let resp = ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: true,
            reason: None,
            approver_id: "approver-01".to_string(),
            operation_hash: "op_hash_test".to_string(),
        };
        am.record_response(resp).await;
        am.remove(&aid).await;
        assert_eq!(am.pending_count().await, 0);
    }
}
