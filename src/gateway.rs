//! R1 工具执行网关（ADR-016 §2，v1.4 拍板后实施）——Phase 1。
//!
//! 无头工具执行接口：外部 caller（L1 槽位引擎 dsh / 其他 agent）提交工具调用，
//! 网关执行 `鉴权(auth_middleware) → 工具分级 → 边界 → 审批判定 → 执行 → 审计`，
//! 不经过任何 LLM。三态响应：`200 executed` / `202 pending_approval` / `4xx|5xx`。
//!
//! Phase 1 范围（本文件）：
//! - 执行注册表（内存态；`gateway_executions` SQLite 持久化与批准后自动执行队列属 Phase 2）
//! - 幂等键/防环链（X-Execution-Chain）为 Phase 2；本阶段网关不产生嵌套调用
//!
//! 安全语义：
//! - `GATEWAY_ENABLED=0`（默认）时接口返回 404（等价路由不存在，回滚零成本）
//! - `GATEWAY_ALLOW_WRITE=0`（默认）时 write 级工具 403；dangerous 永远走审批
//! - 危险/红线工具：`human_approval` 关闭时 403（无审批人 = 硬拒绝，不开洞）
//! - 审批身份隔离（D6）：批准只能经 dashboard 审批台（既有 HTTP 回执路径），
//!   网关自身不提供 respond 能力

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;

use serde_json::json;

/// 执行项状态机（ADR-016 §4）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayStatus {
    Executing,
    Executed,
    AwaitingApproval,
    Denied,
    Failed,
}

impl GatewayStatus {
    fn as_str(&self) -> &'static str {
        match self {
            GatewayStatus::Executing => "executing",
            GatewayStatus::Executed => "executed",
            GatewayStatus::AwaitingApproval => "pending_approval",
            GatewayStatus::Denied => "denied",
            GatewayStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayExecution {
    pub execution_id: String,
    pub caller_agent_id: String,
    pub tool_name: String,
    pub status: GatewayStatus,
    pub approval_id: Option<String>,
    pub operation_hash: Option<String>,
    pub trace_id: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 全局执行注册表（Phase 1 内存态；TTL 清理由 Phase 2 持久化一并处理）
pub static EXECUTIONS: StdMutex<Option<HashMap<String, GatewayExecution>>> =
    StdMutex::new(None);

pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn record_execution(exec: GatewayExecution) {
    let mut guard = EXECUTIONS.lock().unwrap_or_else(|p| p.into_inner());
    guard
        .get_or_insert_with(HashMap::new)
        .insert(exec.execution_id.clone(), exec);
    // Phase 1 简单防膨胀：保留最近 1024 条
    let map = guard.as_mut().unwrap();
    if map.len() > 1024 {
        let mut ids: Vec<(String, i64)> = map
            .iter()
            .map(|(k, v)| (k.clone(), v.created_at))
            .collect();
        ids.sort_by_key(|(_, t)| *t);
        let drop_n = map.len() - 1024;
        for (k, _) in ids.into_iter().take(drop_n) {
            map.remove(&k);
        }
    }
}

pub fn get_execution(id: &str) -> Option<GatewayExecution> {
    let guard = EXECUTIONS.lock().unwrap_or_else(|p| p.into_inner());
    guard.as_ref()?.get(id).cloned()
}

pub fn update_status(id: &str, status: GatewayStatus, result: Option<String>, error: Option<String>) {
    let mut guard = EXECUTIONS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(map) = guard.as_mut() {
        if let Some(e) = map.get_mut(id) {
            e.status = status;
            e.result = result;
            e.error = error;
            e.updated_at = now_secs();
        }
    }
}

pub fn execution_to_json(e: &GatewayExecution) -> serde_json::Value {
    json!({
        "status": e.status.as_str(),
        "execution_id": e.execution_id,
        "approval_id": e.approval_id,
        "result": e.result,
        "error": e.error,
        "trace_id": e.trace_id,
        "created_at": e.created_at,
        "updated_at": e.updated_at,
    })
}

pub fn gateway_enabled() -> bool {
    std::env::var("GATEWAY_ENABLED")
        .map(|v| v == "1")
        .unwrap_or(false)
}

pub fn gateway_allow_write() -> bool {
    std::env::var("GATEWAY_ALLOW_WRITE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// 生成执行 id：`ex_<毫秒>_<短随机>`
pub fn new_execution_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!(
        "ex_{}_{}",
        chrono::Utc::now().timestamp_millis(),
        rng.gen::<u32>()
    )
}

pub fn new_trace_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("gw_{:x}", rng.gen::<u64>())
}
