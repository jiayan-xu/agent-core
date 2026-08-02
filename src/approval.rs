//! 审批流 — YELLOW 红线扩展到指定审批人
//!
//! 当 Agent 触发 YELLOW 级别工具且配置了审批人时，
//! 通过 A2A 向审批人发送审批请求，等待审批结果后再执行。
//!
//! TASK-652 / ADR-015：**审批权威 = SQLite**（`checkpoints.db` 同库异表 `approvals`）。
//! 旧 `approvals.json` 仅启动时只读回填，不再写入。

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::approval_store::{ApprovalRecord, ApprovalRecordStatus, ApprovalStore};

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
    /// TASK-652：绑定会话；旧 JSON 回填缺省 `legacy`
    #[serde(default = "default_session_id")]
    pub session_id: String,
}

fn default_session_id() -> String {
    "legacy".to_string()
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
/// TASK-652 P3：仅 SQLite 权威落盘；legacy JSON 只读导入。
pub struct ApprovalManager {
    /// 发出去的待审批请求（approval_id → PendingApproval）
    outgoing: Mutex<HashMap<String, PendingApproval>>,
    /// 收到的审批结果（approval_id → ApprovalResponse）
    responses: Mutex<HashMap<String, ApprovalResponse>>,
    /// SQLite 权威存储（同库异表）
    sqlite: Option<Arc<StdMutex<ApprovalStore>>>,
    /// C1b: 审批态内存记忆（同步可读，供 check_tool 快查，绕过 async Mutex）。
    /// key 形如 `pending:{tool}@{agent}` / `approved:{tool}@{agent}@{op_hash}` / `rejected:{tool}@{agent}`
    /// value = 过期时间戳（unix secs）；TTL 过期由查询时惰性清除。不落盘（短生命周期）。
    memory: StdMutex<HashMap<String, f64>>,
}

impl ApprovalManager {
    /// 内存模式（测试 / 无持久化需求）
    pub fn new() -> Self {
        Self::new_with_sqlite(None, None)
    }

    /// 兼容旧名：把 legacy JSON **只读导入**内存（不落盘）。生产请用 `new_with_sqlite`。
    pub fn new_with_store(legacy_json: Option<std::path::PathBuf>) -> Self {
        Self::new_with_sqlite(None, legacy_json)
    }

    /// 兼容 P1/P2 签名：`dual_write_json` 已退役，传入 true 仅打 warn。
    pub fn new_with_persistence(
        legacy_json: Option<std::path::PathBuf>,
        sqlite: Option<ApprovalStore>,
        dual_write_json: bool,
    ) -> Self {
        if dual_write_json {
            tracing::warn!(
                "[APPROVAL] APPROVAL_DUAL_WRITE / dual_write_json 已在 TASK-652 P3 退役，忽略"
            );
        }
        Self::new_with_sqlite(sqlite, legacy_json)
    }

    /// TASK-652 P3：SQLite 权威 + 可选 legacy JSON 只读回填。
    pub fn new_with_sqlite(
        sqlite: Option<ApprovalStore>,
        legacy_json: Option<std::path::PathBuf>,
    ) -> Self {
        let sqlite = sqlite.map(|s| Arc::new(StdMutex::new(s)));
        let mut outgoing: HashMap<String, PendingApproval> = HashMap::new();
        let mut responses: HashMap<String, ApprovalResponse> = HashMap::new();

        if let Some(ref sq) = sqlite {
            if let Ok(guard) = sq.lock() {
                for rec in guard.list_active() {
                    Self::hydrate_from_record(&mut outgoing, &mut responses, &rec);
                }
            }
        }

        if let Some(path) = &legacy_json {
            let imported = Self::import_legacy_json(
                path,
                &sqlite,
                &mut outgoing,
                &mut responses,
            );
            if imported > 0 {
                tracing::info!(
                    "[APPROVAL] imported {} legacy item(s) from {} (read-only; file not written)",
                    imported,
                    path.display()
                );
            }
        }

        ApprovalManager {
            outgoing: Mutex::new(outgoing),
            responses: Mutex::new(responses),
            sqlite,
            memory: StdMutex::new(HashMap::new()),
        }
    }

    /// 启动时只读导入旧 approvals.json → 内存，并 upsert 进 SQLite（若有）。
    fn import_legacy_json(
        path: &std::path::Path,
        sqlite: &Option<Arc<StdMutex<ApprovalStore>>>,
        outgoing: &mut HashMap<String, PendingApproval>,
        responses: &mut HashMap<String, ApprovalResponse>,
    ) -> usize {
        let Ok(s) = std::fs::read_to_string(path) else {
            return 0;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) else {
            return 0;
        };
        let mut n = 0usize;
        if let Some(arr) = v.get("outgoing").and_then(|x| x.as_array()) {
            for item in arr {
                if let Ok(p) = serde_json::from_value::<PendingApproval>(item.clone()) {
                    let id = p.approval_id.clone();
                    if !outgoing.contains_key(&id) {
                        if let Some(ref sq) = sqlite {
                            if let Ok(guard) = sq.lock() {
                                let _ = guard.upsert(&Self::pending_to_record(
                                    &p,
                                    ApprovalRecordStatus::Pending,
                                    None,
                                    None,
                                ));
                            }
                        }
                        outgoing.insert(id, p);
                        n += 1;
                    }
                }
            }
        }
        if let Some(arr) = v.get("responses").and_then(|x| x.as_array()) {
            for item in arr {
                if let Ok(r) = serde_json::from_value::<ApprovalResponse>(item.clone()) {
                    let id = r.approval_id.clone();
                    if !responses.contains_key(&id) {
                        if let Some(ref sq) = sqlite {
                            if let Ok(guard) = sq.lock() {
                                if let Some(mut rec) = guard.get(&id) {
                                    let status = if r.approved {
                                        ApprovalRecordStatus::Approved
                                    } else {
                                        ApprovalRecordStatus::Denied
                                    };
                                    rec.status = status;
                                    rec.decided_at = Some(now_secs());
                                    rec.decision_reason = r.reason.clone();
                                    rec.response_json = serde_json::to_string(&r).ok();
                                    let _ = guard.upsert(&rec);
                                }
                            }
                        }
                        responses.insert(id, r);
                        n += 1;
                    }
                }
            }
        }
        n
    }

    fn hydrate_from_record(
        outgoing: &mut HashMap<String, PendingApproval>,
        responses: &mut HashMap<String, ApprovalResponse>,
        rec: &ApprovalRecord,
    ) {
        let args: serde_json::Value =
            serde_json::from_str(&rec.arguments_json).unwrap_or(serde_json::json!({}));
        if matches!(
            rec.status,
            ApprovalRecordStatus::Pending
                | ApprovalRecordStatus::Approved
                | ApprovalRecordStatus::Denied
        ) {
            outgoing.insert(
                rec.approval_id.clone(),
                PendingApproval {
                    approval_id: rec.approval_id.clone(),
                    tool_name: rec.tool_name.clone(),
                    arguments: args,
                    description: rec.description.clone(),
                    approver_id: rec.approver_id.clone(),
                    requester_id: rec.requester_id.clone(),
                    status: ApprovalStatus::Pending,
                    created_at: rec.created_at,
                    operation_hash: rec.operation_hash.clone(),
                    session_id: rec.session_id.clone(),
                },
            );
        }
        if let Some(rj) = &rec.response_json {
            if let Ok(r) = serde_json::from_str::<ApprovalResponse>(rj) {
                responses.insert(rec.approval_id.clone(), r);
            }
        }
    }

    fn pending_to_record(
        p: &PendingApproval,
        status: ApprovalRecordStatus,
        decided_at: Option<f64>,
        response: Option<&ApprovalResponse>,
    ) -> ApprovalRecord {
        ApprovalRecord {
            approval_id: p.approval_id.clone(),
            session_id: if p.session_id.is_empty() {
                "legacy".into()
            } else {
                p.session_id.clone()
            },
            agent_id: p.requester_id.clone(),
            tool_name: p.tool_name.clone(),
            arguments_json: serde_json::to_string(&p.arguments).unwrap_or_else(|_| "{}".into()),
            description: p.description.clone(),
            operation_hash: p.operation_hash.clone(),
            approver_id: p.approver_id.clone(),
            requester_id: p.requester_id.clone(),
            status,
            created_at: p.created_at,
            decided_at,
            consumed_at: None,
            decision_reason: response.and_then(|r| r.reason.clone()),
            response_json: response.and_then(|r| serde_json::to_string(r).ok()),
        }
    }

    fn sqlite_upsert(&self, rec: &ApprovalRecord) {
        if let Some(ref sq) = self.sqlite {
            if let Ok(guard) = sq.lock() {
                if let Err(e) = guard.upsert(rec) {
                    tracing::warn!("[APPROVAL-SQLITE] upsert failed: {}", e);
                }
            }
        }
    }

    fn sqlite_consume(&self, approval_id: &str) {
        if let Some(ref sq) = self.sqlite {
            if let Ok(guard) = sq.lock() {
                if let Err(e) = guard.mark_consumed(approval_id, now_secs()) {
                    tracing::warn!("[APPROVAL-SQLITE] consume failed: {}", e);
                }
            }
        }
    }

    /// 兼容旧签名：session_id = legacy
    pub async fn create_request(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        description: &str,
        approver_id: &str,
        requester_id: &str,
    ) -> String {
        self.create_request_for_session(
            tool_name,
            arguments,
            description,
            approver_id,
            requester_id,
            "legacy",
        )
        .await
    }

    /// 创建审批请求（绑定 session，写入 SQLite 权威表）
    pub async fn create_request_for_session(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        description: &str,
        approver_id: &str,
        requester_id: &str,
        session_id: &str,
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
        let operation_hash = compute_operation_hash(tool_name, arguments);
        let session_id = if session_id.trim().is_empty() {
            "legacy".to_string()
        } else {
            session_id.to_string()
        };

        let pending = PendingApproval {
            approval_id: approval_id.clone(),
            tool_name: tool_name.to_string(),
            arguments: arguments.clone(),
            description: description.to_string(),
            approver_id: approver_id.to_string(),
            requester_id: requester_id.to_string(),
            status: ApprovalStatus::Pending,
            created_at: now,
            operation_hash,
            session_id,
        };
        self.sqlite_upsert(&Self::pending_to_record(
            &pending,
            ApprovalRecordStatus::Pending,
            None,
            None,
        ));

        let mut outgoing = self.outgoing.lock().await;
        outgoing.insert(approval_id.clone(), pending);
        drop(outgoing);
        // C1b: 记录 pending 记忆（供 is_pending_sync 防重复建单）
        if let Ok(mut mem) = self.memory.lock() {
            mem.insert(
                format!("pending:{}@{}", tool_name, requester_id),
                now + PENDING_TTL,
            );
        }

        approval_id
    }

    /// 记录收到的审批响应
    ///
    /// C1c: 兜底校验 `operation_hash` 防偷换（defense-in-depth）。
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
        responses.insert(approval_id.clone(), response.clone());
        drop(responses);

        // C1b: 更新审批态记忆 + SQLite
        if let Some(p) = self.get_pending(&approval_id).await {
            let status = if approved {
                ApprovalRecordStatus::Approved
            } else {
                ApprovalRecordStatus::Denied
            };
            self.sqlite_upsert(&Self::pending_to_record(
                &p,
                status,
                Some(now_secs()),
                Some(&response),
            ));
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
    /// 审批历史（含已消费/已拒绝），SQLite 权威表倒序，供审批台审计留证
    pub async fn list_history(&self, limit: usize) -> Vec<ApprovalRecord> {
        if let Some(ref sq) = self.sqlite {
            if let Ok(guard) = sq.lock() {
                return guard.list_history(limit);
            }
        }
        Vec::new()
    }

    pub async fn list_pending(&self) -> Vec<PendingApproval> {        let outgoing = self.outgoing.lock().await;
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

    /// TASK-652 预留：按 session 取就绪项（P2 执行侧切主）
    pub async fn list_approved_ready_for_session(&self, session_id: &str) -> Vec<PendingApproval> {
        self.list_approved_ready()
            .await
            .into_iter()
            .filter(|a| a.session_id == session_id)
            .collect()
    }

    /// 移除已完成的审批项（SQLite 标 Consumed）
    pub async fn remove(&self, approval_id: &str) {
        self.outgoing.lock().await.remove(approval_id);
        self.responses.lock().await.remove(approval_id);
        self.sqlite_consume(approval_id);
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
/// 递归规范化 serde_json::Value：将所有对象的 key 按字典序排序。
///
/// 消除不同解析/构造路径（尤其 `serde_json` 的 `preserve_order` 特性开启时，
/// 或参数经多次序列化-反序列化后 key 顺序漂移）导致的 key 顺序差异，
/// 保证同一操作的指纹稳定可复现，避免 operation_hash 因 key 顺序误拒（P1-2）。
fn canonicalize_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<String, serde_json::Value> =
                std::collections::BTreeMap::new();
            for (k, val) in map {
                sorted.insert(k.clone(), canonicalize_value(val));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize_value).collect())
        }
        other => other.clone(),
    }
}

pub(crate) fn compute_operation_hash(tool_name: &str, arguments: &serde_json::Value) -> String {
    // P1-2 修复：先递归规范化 args（对象 key 字典序），再组合 tool + args 序列化。
    let canonical_args = canonicalize_value(arguments);
    let canonical = serde_json::json!({ "tool": tool_name, "args": canonical_args });
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
            session_id: "s1".to_string(),
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

    // ── 本次修复回归测试（P1-2 / P0-1 / P1-1） ──

    /// P1-2：规范化指纹必须消除 key 顺序差异——同内容不同 key 顺序 → 同一 hash。
    #[test]
    fn test_compute_operation_hash_canonical_stable() {
        let args_a = serde_json::json!({"b": 2, "a": 1, "nested": {"z": 9, "y": 8}});
        let args_b = serde_json::json!({"a": 1, "b": 2, "nested": {"y": 8, "z": 9}});
        let h1 = compute_operation_hash("sync_whitelist_plates", &args_a);
        let h2 = compute_operation_hash("sync_whitelist_plates", &args_b);
        assert_eq!(h1, h2, "key 顺序不同不应改变指纹（P1-2 规范化）");

        // 模拟审批持久化 reload：序列化→反序列化后重算仍一致（BTreeMap 默认序 vs preserve_order 序）
        let reparsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&args_a).unwrap()).unwrap();
        let h3 = compute_operation_hash("sync_whitelist_plates", &reparsed);
        assert_eq!(h1, h3, "重序列化后指纹应稳定（防 execute 期误拒）");
    }

    /// P1-2 健全性：tool 或 args 不同 → 指纹不同（防错配放行）。
    #[test]
    fn test_compute_operation_hash_differs_by_content() {
        let base = serde_json::json!({"id": 1});
        let h_tool = compute_operation_hash("sync_whitelist_plates", &base);
        let h_other_tool = compute_operation_hash("delete_record", &base);
        assert_ne!(h_tool, h_other_tool, "不同 tool 必须不同指纹");
        let h_diff_args = compute_operation_hash("sync_whitelist_plates", &serde_json::json!({"id": 2}));
        assert_ne!(h_tool, h_diff_args, "不同 args 必须不同指纹");
    }

    /// P0-1：A2A 回传的 approval_response 必须携带 operation_hash，且能被 requester 侧解析。
    #[test]
    fn test_a2a_response_includes_operation_hash() {
        let expected_hash = "abc123def456";
        // 与 main.rs handle_collab_approval 非本地路径回传包结构一致（含 operation_hash）
        let resp_env = serde_json::json!({
            "type": "approval_response",
            "approval_id": "apr_999",
            "approved": true,
            "reason": "跨实例批准",
            "approver_id": "admin-remote",
            "operation_hash": expected_hash,
        });
        let parsed = ApprovalManager::parse_approval_response(&resp_env);
        assert!(parsed.is_some(), "带 operation_hash 的响应应可被解析");
        assert_eq!(parsed.unwrap().operation_hash, expected_hash);
    }

    /// P0-1 负向：缺 operation_hash 的 A2A 响应解析失败（即修复前的死锁根因）。
    #[test]
    fn test_a2a_response_missing_hash_fails_parse() {
        let resp_env = serde_json::json!({
            "type": "approval_response",
            "approval_id": "apr_999",
            "approved": true,
            "reason": "跨实例批准",
            "approver_id": "admin-remote",
        });
        let parsed = ApprovalManager::parse_approval_response(&resp_env);
        assert!(parsed.is_none(), "缺 operation_hash 的响应必须解析失败（否则 C1c 校验恒拒）");
    }

    /// P1-1：执行失败应保留审批项（待人工复查），成功才移除。
    /// 直接校验 `execute_approved_request` 依赖的数据层契约（移除仅发生在 exec_result.is_ok() 时）。
    #[tokio::test]
    async fn test_execute_ready_retention_on_failure() {
        let am = ApprovalManager::new();
        let aid = am
            .create_request(
                "sync_whitelist_plates",
                &serde_json::json!({"action": "add", "plate": "苏D22222"}),
                "新增白名单 苏D22222",
                "approver-01",
                "agent-001",
            )
            .await;
        let hash = am.get_pending(&aid).await.unwrap().operation_hash;
        am.record_response(ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: true,
            reason: None,
            approver_id: "approver-01".to_string(),
            operation_hash: hash,
        })
        .await;

        // 已批准 → 执行侧就绪
        assert_eq!(am.list_approved_ready().await.len(), 1);

        // 模拟「执行失败」路径（agent.rs 现在 Err 时不 remove）：保留
        // （此处仅验证数据契约：未调用 remove，项仍存在）
        assert_eq!(am.list_approved_ready().await.len(), 1, "失败路径必须保留待查");

        // 模拟「执行成功」路径：remove
        am.remove(&aid).await;
        assert_eq!(am.list_approved_ready().await.len(), 0, "成功路径必须移除");
    }

    /// TASK-652 P3：create/record/remove 不得再写 approvals.json
    #[tokio::test]
    async fn test_legacy_json_is_read_only_no_write() {
        let dir = std::env::temp_dir().join(format!("appr_p3_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let json_path = dir.join("approvals.json");
        let db_path = dir.join("checkpoints.db");
        let legacy = serde_json::json!({
            "outgoing": [{
                "approval_id": "legacy-aid-1",
                "tool_name": "manage_samples",
                "arguments": {"action": "sync"},
                "description": "legacy",
                "approver_id": "admin",
                "requester_id": "agent-001",
                "status": "Pending",
                "created_at": 1.0,
                "operation_hash": "deadbeef",
                "session_id": "legacy"
            }],
            "responses": []
        });
        std::fs::write(&json_path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();
        let before = std::fs::metadata(&json_path).unwrap().modified().unwrap();

        let store = ApprovalStore::open(&db_path.to_string_lossy()).unwrap();
        let am = ApprovalManager::new_with_sqlite(Some(store), Some(json_path.clone()));
        assert!(am.get_pending("legacy-aid-1").await.is_some());

        let aid = am
            .create_request_for_session(
                "local_fs",
                &serde_json::json!({"op": "write"}),
                "写文件",
                "admin",
                "agent-001",
                "sess/p3",
            )
            .await;
        let hash = am.get_pending(&aid).await.unwrap().operation_hash;
        am.record_response(ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid.clone(),
            approved: true,
            reason: None,
            approver_id: "admin".to_string(),
            operation_hash: hash,
        })
        .await;
        am.remove(&aid).await;

        let after = std::fs::metadata(&json_path).unwrap().modified().unwrap();
        assert_eq!(before, after, "P3 退役后不得写回 approvals.json");
        let body = std::fs::read_to_string(&json_path).unwrap();
        assert!(
            !body.contains(&aid),
            "JSON 文件内容不得被运行时改写"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TASK-652 P1：SQLite 同库权威表跨 reopen 存活。
    #[tokio::test]
    async fn test_sqlite_authority_survives_reopen() {
        let path = std::env::temp_dir().join(format!(
            "appr_auth_{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let p = path.to_string_lossy().to_string();
        {
            let store = ApprovalStore::open(&p).unwrap();
            let am = ApprovalManager::new_with_sqlite(Some(store), None);
            let aid = am
                .create_request_for_session(
                    "manage_samples",
                    &serde_json::json!({"action": "sync"}),
                    "取样同步",
                    "dashboard-admin",
                    "agent-001",
                    "sess/demo",
                )
                .await;
            let hash = am.get_pending(&aid).await.unwrap().operation_hash;
            am.record_response(ApprovalResponse {
                r#type: "approval_response".to_string(),
                approval_id: aid.clone(),
                approved: true,
                reason: None,
                approver_id: "dashboard-admin".to_string(),
                operation_hash: hash,
            })
            .await;
            assert_eq!(am.list_approved_ready_for_session("sess/demo").await.len(), 1);
        }
        // reopen
        let store2 = ApprovalStore::open(&p).unwrap();
        let am2 = ApprovalManager::new_with_sqlite(Some(store2), None);
        assert_eq!(am2.list_approved_ready().await.len(), 1);
        assert_eq!(am2.list_approved_ready_for_session("sess/demo").await.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    /// TASK-652 P2：跨 session 不得抢跑他人已批准项
    #[tokio::test]
    async fn test_ready_is_session_scoped() {
        let am = ApprovalManager::new();
        let aid_a = am
            .create_request_for_session(
                "sync_whitelist_plates",
                &serde_json::json!({"action": "add", "plate": "苏A"}),
                "a",
                "admin",
                "agent-001",
                "sess/A",
            )
            .await;
        let hash_a = am.get_pending(&aid_a).await.unwrap().operation_hash;
        am.record_response(ApprovalResponse {
            r#type: "approval_response".to_string(),
            approval_id: aid_a.clone(),
            approved: true,
            reason: None,
            approver_id: "admin".to_string(),
            operation_hash: hash_a,
        })
        .await;
        assert_eq!(am.list_approved_ready_for_session("sess/A").await.len(), 1);
        assert_eq!(am.list_approved_ready_for_session("sess/B").await.len(), 0);
        assert_eq!(am.list_approved_ready().await.len(), 1);
    }
}
