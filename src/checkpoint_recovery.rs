//! Checkpoint 恢复核心（审计无关），可独立单测 / e2e 集成测试。
//!
//! `AgentCore::restore_checkpoint` 把「计数 + 内存重建」核心抽离到本模块的 free fn，
//! 使 e2e 测试无需构造完整 `AgentCore`（及其 `AuditLogger` 所需的 Memoria 网络）。
//! 审计日志（checkpoint_resume 写 Memoria）仍由 `AgentCore::restore_checkpoint` 负责，
//! 本模块只返回命中的 `CheckpointState`（None = 无 checkpoint，调用方跳过审计）。
//!
//! 这样「进程重启后真实续跑」可被纯内存集成测试覆盖，零生产污染、零网络依赖。

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::checkpoint::{CheckpointState, CheckpointStore};
use crate::composer::{ExecutionPlan, StepPlan};
use crate::metrics::MetricsRegistry;
use crate::session::{PendingAction, SessionManager, SessionState};

/// 审计无关的 checkpoint 恢复核心。
///
/// 从 `checkpoint_store` 读盘 → 非 New 状态计数恢复 → 按状态重建内存
/// （session_manager 状态 / in_progress_plan / in_progress_step_results）→ 成功计数。
/// 与 `AgentCore::restore_checkpoint` 走同一恢复路径，只是不含 Memoria 审计写。
///
/// 返回命中的 `CheckpointState`：`None` 表示无 checkpoint（调用方应跳过审计）；
/// `Some(state)` 表示命中（含 New 状态），调用方据此审计。
pub async fn apply_checkpoint_recovery(
    session_id: &str,
    store: &Arc<Mutex<CheckpointStore>>,
    metrics: &MetricsRegistry,
    session_manager: &SessionManager,
    in_progress_plan: &Arc<Mutex<Option<ExecutionPlan>>>,
    in_progress_step_results: &Arc<Mutex<HashMap<u32, String>>>,
) -> Option<CheckpointState> {
    let cp = {
        let guard = store.lock().await;
        guard.load(session_id)
    };
    let cp = match cp {
        Some(c) => c,
        None => return None,
    };
    let state_str = cp.state.as_str();
    // 战略罗盘「可观测」：崩溃/重启后续跑恢复计数（仅当存在非 New 控制面状态）
    if cp.state != CheckpointState::New {
        metrics.inc_checkpoint_recovery();
        metrics.inc_checkpoint_recovery_by_state(state_str);
    }
    let mut recovered_ok = true;
    match cp.state {
        CheckpointState::AwaitingConfirmation => {
            session_manager
                .set_state(session_id, SessionState::AwaitingConfirmation)
                .await;
            if let Some(msg) = cp.payload.get("original_message").and_then(|m| m.as_str()) {
                session_manager.set_original_message(session_id, msg).await;
            }
        }
        CheckpointState::Confirmed => {
            session_manager
                .set_state(session_id, SessionState::Confirmed)
                .await;
        }
        CheckpointState::PendingApproval => {
            // 恢复待审批意图（审批结果需重新等待，但工具意图保留以便日志关联）
            if let Some(pa) = cp.payload.get("pending_action") {
                let action = PendingAction {
                    tool_name: pa
                        .get("tool_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    arguments: pa.get("arguments").cloned().unwrap_or(serde_json::json!({})),
                    description: pa
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                };
                session_manager.set_pending_action(session_id, action).await;
            }
            session_manager
                .set_state(session_id, SessionState::AwaitingConfirmation)
                .await;
        }
        CheckpointState::ExecutingPlan => {
            // 恢复进行中的计划与已完成步骤，供 execute_plan 续跑
            let mut plan_ok = true;
            if let Some(plan_val) = cp.payload.get("plan") {
                match serde_json::from_value::<ExecutionPlan>(plan_val.clone()) {
                    Ok(plan) => {
                        *in_progress_plan.lock().await = Some(plan);
                    }
                    Err(_) => {
                        plan_ok = false;
                    }
                }
            } else {
                plan_ok = false;
            }
            if let Some(sr) = cp.payload.get("step_results").and_then(|v| v.as_object()) {
                let mut map = in_progress_step_results.lock().await;
                for (k, v) in sr.iter() {
                    if let (Ok(id), Some(s)) = (k.parse::<u32>(), v.as_str()) {
                        map.insert(id, s.to_string());
                    }
                }
            }
            // 恢复后下一次 execute_chat 会复用 in_progress_plan 续跑
            session_manager.set_state(session_id, SessionState::Confirmed).await;
            if !plan_ok {
                recovered_ok = false;
            }
        }
        CheckpointState::PlanPreview => {
            // 恢复进行中的计划，等待用户「执行 / 取消 / 修改」
            let mut plan_ok = true;
            if let Some(plan_val) = cp.payload.get("plan") {
                match serde_json::from_value::<ExecutionPlan>(plan_val.clone()) {
                    Ok(plan) => {
                        *in_progress_plan.lock().await = Some(plan);
                    }
                    Err(_) => {
                        plan_ok = false;
                    }
                }
            } else {
                plan_ok = false;
            }
            session_manager
                .set_state(session_id, SessionState::AwaitingConfirmation)
                .await;
            if let Some(msg) = cp.payload.get("original_message").and_then(|m| m.as_str()) {
                session_manager.set_original_message(session_id, msg).await;
            }
            if !plan_ok {
                recovered_ok = false;
            }
        }
        CheckpointState::Done | CheckpointState::Failed => {
            // 终态：清空内存待确认（checkpoint 保留供审计）
            session_manager.remove_state(session_id).await;
        }
        CheckpointState::New => {}
    }
    // 战略罗盘「可观测」：仅当非 New 且续跑重建成功，恢复成功 +1
    if cp.state != CheckpointState::New && recovered_ok {
        metrics.inc_checkpoint_recovery_success();
    }
    Some(cp.state)
}

// ══════════════════════════════════════════════════════
// e2e 集成测试（纯内存，真实持久化 + 真实恢复核心，零网络）
// ══════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 战略罗盘「持久执行深化」e2e 实证：真实写盘 ExecutingPlan checkpoint ->
    /// drop 旧 store + 同路径 reopen（模拟进程重启）-> 调真实 `apply_checkpoint_recovery`
    /// -> 断言恢复计数四字段齐全 + in_progress_plan / step_results 真实重建。
    #[tokio::test]
    async fn test_e2e_restore_executing_plan_after_reopen() {
        let path = std::env::temp_dir().join(format!("ckpt_e2e_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // 「进程 1」：持久化一个进行中的多步计划 checkpoint
        let plan = ExecutionPlan {
            steps: vec![
                StepPlan {
                    step_id: 1,
                    description: "查询".into(),
                    tool: "db_query".into(),
                    arguments: serde_json::json!({}),
                    depends_on: vec![],
                },
                StepPlan {
                    step_id: 2,
                    description: "汇总".into(),
                    tool: "summarize".into(),
                    arguments: serde_json::json!({}),
                    depends_on: vec![1],
                },
            ],
        };
        let mut sr = HashMap::new();
        sr.insert(1u32, "ok".to_string());
        {
            let store = CheckpointStore::open(path.to_str().unwrap()).unwrap();
            let payload = serde_json::json!({ "plan": plan, "step_results": sr });
            store
                .save("exec1", "agent1", CheckpointState::ExecutingPlan, &payload)
                .unwrap();
        }

        // 「进程重启」：重新打开同一文件（store1 已 drop，模拟崩溃后重开）
        let store2 = Arc::new(Mutex::new(
            CheckpointStore::open(path.to_str().unwrap()).unwrap(),
        ));
        let metrics = MetricsRegistry::new();
        let session_manager = SessionManager::new();
        let in_progress_plan = Arc::new(Mutex::new(None::<ExecutionPlan>));
        let in_progress_step_results = Arc::new(Mutex::new(HashMap::<u32, String>::new()));

        // 调真实恢复核心（与生产 chat 入口同一条路径）
        let st = apply_checkpoint_recovery(
            "exec1",
            &store2,
            &metrics,
            &session_manager,
            &in_progress_plan,
            &in_progress_step_results,
        )
        .await
        .expect("checkpoint must exist after reopen");
        assert_eq!(st, CheckpointState::ExecutingPlan);

        // 恢复计数：attempts=1, success=1, success_rate=1.0, by_state{ExecutingPlan:1}
        let snap = metrics.snapshot(serde_json::json!({}), serde_json::json!({}));
        let cr = &snap["checkpoint_recovery"];
        assert_eq!(cr["attempts"].as_u64(), Some(1), "recovery attempt must be 1");
        assert_eq!(cr["success"].as_u64(), Some(1), "recovery success must be 1");
        assert_eq!(
            cr["success_rate"].as_f64(),
            Some(1.0),
            "recovery success_rate must be 1.0"
        );
        assert_eq!(
            cr["by_state"]["ExecutingPlan"].as_u64(),
            Some(1),
            "by_state must bucket ExecutingPlan=1"
        );

        // 内存重建：in_progress_plan 与 step_results 必须存活（可续跑）
        let restored_plan = in_progress_plan.lock().await;
        let restored_plan = restored_plan.as_ref().expect("plan must be rebuilt");
        assert_eq!(restored_plan.steps.len(), 2);
        assert_eq!(restored_plan.steps[0].tool, "db_query");
        assert_eq!(restored_plan.steps[1].step_id, 2);
        let restored_sr = in_progress_step_results.lock().await;
        assert_eq!(
            restored_sr.get(&1).map(|s| s.as_str()),
            Some("ok"),
            "step 1 result must survive restart"
        );
        // 恢复后 session 状态应为 Confirmed（供 execute_chat 续跑）
        assert_eq!(
            session_manager.get_state("exec1").await,
            SessionState::Confirmed
        );

        let _ = std::fs::remove_file(&path);
    }

    /// 覆盖 AwaitingConfirmation 分支：恢复 original_message + 状态重建 + 计数按状态分桶。
    #[tokio::test]
    async fn test_e2e_restore_awaiting_confirmation_rebuilds_message() {
        let path = std::env::temp_dir().join(format!("ckpt_e2e_ac_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        {
            let store = CheckpointStore::open(path.to_str().unwrap()).unwrap();
            let payload = serde_json::json!({ "original_message": "帮我查昨天的进厂数据" });
            store
                .save(
                    "s_ac",
                    "agent1",
                    CheckpointState::AwaitingConfirmation,
                    &payload,
                )
                .unwrap();
        }

        let store2 = Arc::new(Mutex::new(
            CheckpointStore::open(path.to_str().unwrap()).unwrap(),
        ));
        let metrics = MetricsRegistry::new();
        let session_manager = SessionManager::new();
        let in_progress_plan = Arc::new(Mutex::new(None::<ExecutionPlan>));
        let in_progress_step_results = Arc::new(Mutex::new(HashMap::<u32, String>::new()));

        let st = apply_checkpoint_recovery(
            "s_ac",
            &store2,
            &metrics,
            &session_manager,
            &in_progress_plan,
            &in_progress_step_results,
        )
        .await
        .expect("checkpoint must exist");
        assert_eq!(st, CheckpointState::AwaitingConfirmation);

        let snap = metrics.snapshot(serde_json::json!({}), serde_json::json!({}));
        let cr = &snap["checkpoint_recovery"];
        assert_eq!(cr["attempts"].as_u64(), Some(1));
        assert_eq!(cr["success"].as_u64(), Some(1));
        assert_eq!(cr["by_state"]["AwaitingConfirmation"].as_u64(), Some(1));

        // original_message 必须重建
        assert_eq!(
            session_manager.get_original_message("s_ac").await,
            Some("帮我查昨天的进厂数据".to_string())
        );
        assert_eq!(
            session_manager.get_state("s_ac").await,
            SessionState::AwaitingConfirmation
        );

        let _ = std::fs::remove_file(&path);
    }

    /// New 状态 / 不存在：不计入恢复（与生产计数语义一致）。
    #[tokio::test]
    async fn test_e2e_restore_new_or_missing_does_not_count() {
        let path = std::env::temp_dir().join(format!("ckpt_e2e_new_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let store = CheckpointStore::open(path.to_str().unwrap()).unwrap();
            store
                .save("s_new", "a", CheckpointState::New, &serde_json::json!({}))
                .unwrap();
        }
        let store2 = Arc::new(Mutex::new(
            CheckpointStore::open(path.to_str().unwrap()).unwrap(),
        ));
        let metrics = MetricsRegistry::new();
        let session_manager = SessionManager::new();
        let in_progress_plan = Arc::new(Mutex::new(None::<ExecutionPlan>));
        let in_progress_step_results = Arc::new(Mutex::new(HashMap::<u32, String>::new()));

        let st = apply_checkpoint_recovery(
            "s_new",
            &store2,
            &metrics,
            &session_manager,
            &in_progress_plan,
            &in_progress_step_results,
        )
        .await
        .expect("New-state checkpoint exists");
        assert_eq!(st, CheckpointState::New);

        // 不存在的 session：返回 None，无审计、无计数
        let none_st = apply_checkpoint_recovery(
            "does_not_exist",
            &store2,
            &metrics,
            &session_manager,
            &in_progress_plan,
            &in_progress_step_results,
        )
        .await;
        assert!(none_st.is_none(), "missing checkpoint => None");

        let snap = metrics.snapshot(serde_json::json!({}), serde_json::json!({}));
        let cr = &snap["checkpoint_recovery"];
        assert_eq!(cr["attempts"].as_u64(), Some(0), "New/missing must not count");
        assert_eq!(cr["success"].as_u64(), Some(0));

        let _ = std::fs::remove_file(&path);
    }
}
