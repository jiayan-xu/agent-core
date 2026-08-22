//! R1 网关 HTTP handler（`/api/tool/execute`，受保护路由）。
//! 管线：鉴权(中间件) → 分级 → GATEWAY_ALLOW_WRITE 门 → 边界 → 危险判定(审批/拒绝)
//! → call_tool_routed 执行 → 三态响应。不经过任何 LLM（ADR-016 决策 1）。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::AuthContext;
use agent_core::boundary::BlockLevel;
use agent_core::gateway::{
    execution_to_json, gateway_allow_write, gateway_enabled, get_execution, new_execution_id,
    new_trace_id, record_execution, update_status, GatewayExecution, GatewayStatus,
};
use crate::state::AppState;

#[derive(Deserialize)]
pub(crate) struct ToolExecuteBody {
    pub tool: String,
    pub arguments: serde_json::Value,
    pub persona_id: Option<String>,
    pub session_id: Option<String>,
    pub trace_id: Option<String>,
    #[allow(dead_code)]
    pub idempotency_key: Option<String>,
}

fn err_json(status: StatusCode, code: &str, message: &str) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

pub(crate) async fn handle_tool_execute(
    State(st): State<Arc<AppState>>,
    axum::Extension(auth): axum::Extension<AuthContext>,
    Json(body): Json<ToolExecuteBody>,
) -> axum::response::Response {
    if !gateway_enabled() {
        return err_json(StatusCode::NOT_FOUND, "gateway-disabled", "GATEWAY_ENABLED=0");
    }
    let agent = {
        let guard = st.agent.lock().await;
        match guard.clone() {
            Some(a) => a,
            None => {
                return err_json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "agent-not-ready",
                    "agent 未就绪",
                )
            }
        }
    };

    if body.tool.trim().is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid-params", "tool 不能为空");
    }
    let persona = body.persona_id.clone().unwrap_or_else(|| "default".into());
    let session_id = body
        .session_id
        .clone()
        .unwrap_or_else(|| format!("gateway/{}", auth.agent_id));
    let trace_id = body.trace_id.clone().unwrap_or_else(new_trace_id);
    let execution_id = new_execution_id();

    // ── 工具分级（与 chat 循环同源：classifier.classify）──
    let tool_level = {
        let boundary = agent.boundary.lock().await;
        let level = boundary
            .classifier
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .classify(&body.tool)
            .to_string();
        level
    };

    // ── GATEWAY_ALLOW_WRITE 门（默认仅只读）──
    if tool_level == "write" && !gateway_allow_write() {
        return err_json(
            StatusCode::FORBIDDEN,
            "write-disabled",
            "GATEWAY_ALLOW_WRITE=0：网关当前仅放行只读工具",
        );
    }

    // ── 外部调用方权限底座：网关 caller 不在进程内权限链上（链只注册了 agent-core 自身），
    // 按灰度开关授予 Read/Write 底座后再生效（幂等；审批/红线不受影响）──
    {
        let boundary = agent.boundary.lock().await;
        let floor = if tool_level == "write" && gateway_allow_write() {
            agent_core::boundary::PermissionLevel::Write
        } else {
            agent_core::boundary::PermissionLevel::Read
        };
        let registered = match boundary.perm_chain.lock() {
            Ok(mut chain) => {
                chain.register(&auth.agent_id, None, floor);
                true
            }
            Err(_) => false,
        };
        drop(boundary);
        let _ = registered;
    }

    // ── 边界检查（按本次调用实际触碰的命名空间，而非调用方全量授权域）──
    // 2026-08-22 修复：此前传 auth.allowed_ns（经 dept_ops 增强后必 >1 个），
    // check_cross_ns 只要 >1 就拒——外部调用方任何工具都触发「跨 N 命名空间
    // 聚合需审批」→ 网关对外部调用方完全不可用。对齐 chat 循环语义
    // （current_ns_paths = 本次调用生效的 ns）：取 arguments.namespace；
    // 无该参数的工具不存在跨域信号，授权层已把关，传 None 放行。
    let check = {
        let boundary = agent.boundary.lock().await;
        let mut ns: Vec<String> = Vec::new();
        for key in ["namespace", "ns"] {
            if let Some(v) = body.arguments.get(key).and_then(|v| v.as_str()) {
                ns.extend(
                    v.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty()),
                );
            }
        }
        ns.sort();
        ns.dedup();
        boundary.check_tool(
            &body.tool,
            &body.arguments,
            &auth.agent_id,
            "user",
            &agent.config.parent_permission,
            if ns.is_empty() { None } else { Some(ns.as_slice()) },
        )
    };
    if !check.allow {
        return err_json(
            StatusCode::FORBIDDEN,
            "boundary-rejected",
            &format!("边界拒绝：{}", check.reason),
        );
    }

    // ── 危险判定（dangerous 分级或红线）：进入人工审批，绝不直接执行 ──
    let is_dangerous = tool_level == "dangerous";
    if is_dangerous || check.level == Some(BlockLevel::Red) {
        if !agent.config.human_approval {
            return err_json(
                StatusCode::FORBIDDEN,
                "no-approver",
                "危险工具且未启用人工审批通道（human_approval=false），硬拒绝",
            );
        }
        let approval_id = agent
            .approval_manager
            .create_request_for_session(
                &body.tool,
                &body.arguments,
                &format!("[gateway:{}] {}", auth.agent_id, check.reason),
                "dashboard-admin", // D6：批准只在 dashboard 审批台，网关不自批
                &auth.agent_id,
                &session_id,
            )
            .await;
        let operation_hash = agent
            .approval_manager
            .get_pending(&approval_id)
            .await
            .map(|p| p.operation_hash);
        record_execution(GatewayExecution {
            execution_id: execution_id.clone(),
            caller_agent_id: auth.agent_id.clone(),
            tool_name: body.tool.clone(),
            status: GatewayStatus::AwaitingApproval,
            approval_id: Some(approval_id.clone()),
            operation_hash: operation_hash.clone(),
            trace_id: trace_id.clone(),
            result: None,
            error: None,
            created_at: chrono::Utc::now().timestamp(),
            updated_at: chrono::Utc::now().timestamp(),
        });
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": "pending_approval",
                "execution_id": execution_id,
                "approval_id": approval_id,
                "operation_hash": operation_hash,
                "approver": "dashboard-admin",
                "poll": { "path": format!("/api/tool/execute/{}", execution_id), "after_ms": 2000 },
                "trace_id": trace_id,
            })),
        )
            .into_response();
    }

    // ── 只读/普通写：直接执行（call_tool_routed 内部含配额/killswitch/审计）──
    record_execution(GatewayExecution {
        execution_id: execution_id.clone(),
        caller_agent_id: auth.agent_id.clone(),
        tool_name: body.tool.clone(),
        status: GatewayStatus::Executing,
        approval_id: None,
        operation_hash: None,
        trace_id: trace_id.clone(),
        result: None,
        error: None,
        created_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    });
    let ns = auth.allowed_ns.clone();
    match agent
        .call_tool_routed(&body.tool, &persona, &body.arguments, &ns, &trace_id)
        .await
    {
        Ok(result) => {
            update_status(
                &execution_id,
                GatewayStatus::Executed,
                Some(result.clone()),
                None,
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "executed",
                    "execution_id": execution_id,
                    "tool": body.tool,
                    "result": result,
                    "trace_id": trace_id,
                })),
            )
                .into_response()
        }
        Err(e) => {
            update_status(
                &execution_id,
                GatewayStatus::Failed,
                None,
                Some(e.clone()),
            );
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "status": "failed",
                    "execution_id": execution_id,
                    "error": e,
                    "trace_id": trace_id,
                })),
            )
                .into_response()
        }
    }
}

pub(crate) async fn handle_tool_execute_get(
    Path(execution_id): Path<String>,
) -> axum::response::Response {
    if !gateway_enabled() {
        return err_json(StatusCode::NOT_FOUND, "gateway-disabled", "GATEWAY_ENABLED=0");
    }
    match get_execution(&execution_id) {
        Some(e) => (StatusCode::OK, Json(execution_to_json(&e))).into_response(),
        None => err_json(StatusCode::NOT_FOUND, "not-found", "执行不存在或已过期"),
    }
}
