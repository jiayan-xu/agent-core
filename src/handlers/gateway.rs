//! R1 网关 HTTP handler（`/api/tool/execute`，受保护路由）。
//! 管线：鉴权(中间件) → 分级 → GATEWAY_ALLOW_WRITE 门 → 边界 → 危险判定(审批/拒绝)
//! → call_tool_routed 执行 → 三态响应。
//! ADR-016（2026-09-03 修订）：执行路径仍无 LLM；仅审批分级允许一次可配置的
//! 廉价 judge 调用（[gateway_approval] mode=llm_auto），fail-safe 落人工，全程审计。

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
    // C1a 地板兜底（2026-09-03 补）：manage_whitelist 同在 write/dangerous 两静态集，
    // classify 顺序返回 write，GATEWAY_ALLOW_WRITE=0 下被写门 403，dangerous floor
    // （HARD_DANGEROUS 精确集，check_tool 内黄线之源）在网关层漏判——按 C1a 注释
    // "危险工具无论分类器如何都进黄线"的意图，在分级处显式升级。
    let tool_level = {
        let boundary = agent.boundary.lock().await;
        let level = if boundary.is_dangerous_floor(&body.tool) {
            "dangerous".to_string()
        } else {
            boundary
                .classifier
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .classify(&body.tool)
                .to_string()
        };
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
    //
    // 2026-08-22 安全修复（D2-b 内测发现泄漏）：网关执行身份为 admin（"*"），
    // 若不校验「请求的 ns ⊆ 调用方授权域」，任何调用方可借网关 admin 身份
    // 读任意他人命名空间（实测 dsh-slot 越权读 d2b-user-a 成功）。故先做
    // 包含校验（与 memoria check_ns_access 同规则：相等/双向前缀），再走
    // 跨域聚合计数审批。
    let mut ns: Vec<String> = Vec::new();
    let check = {
        let boundary = agent.boundary.lock().await;
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
        // ① 越权校验：请求的每个 ns 必须被调用方授权域覆盖
        for n in &ns {
            let covered = auth.allowed_ns.iter().any(|g| {
                g == "*" || g == n || n.starts_with(&format!("{g}/")) || g.starts_with(&format!("{n}/"))
            });
            if !covered {
                return err_json(
                    StatusCode::FORBIDDEN,
                    "namespace-not-authorized",
                    &format!(
                        "边界拒绝：命名空间 '{}' 不在调用方 '{}' 授权范围内",
                        n, auth.agent_id
                    ),
                );
            }
        }
        boundary.check_tool(
            &body.tool,
            &body.arguments,
            &auth.agent_id,
            "user",
            &agent.config.parent_permission,
            if ns.is_empty() { None } else { Some(ns.as_slice()) },
        )
    };
    // ── 「需审批」类边界拒绝 → 转 202 审批流（对齐 chat 循环 AWAITING_APPROVAL）──
    // 2026-08-22 R2：boundary 的审批守卫（如 manage_whitelist「需要审批，请等待
    // 审批人确认」）以 allow=false + reason 携带审批意图返回，此前被 403 短路，
    // 网关的审批全链路永远走不到。凡 reason 含「审批」即转 202 创建审批请求。
    let needs_approval = !check.allow && check.reason.contains("审批");
    // 分级审批：judge 拒绝/quota 满时把理由带进审批单（见下方 llm_auto 分支）
    let mut check_reason_auto = String::new();
    // llm_auto 模式下的只读动作旁路：manage_whitelist query / dry_run 预览属读操作，
    // 整工具在 dangerous 集导致查询也被拦进审批（judge 白烧 + 配额白扣 + before_state
    // 抓取失败）。仅 llm_auto 生效——human_all 模式行为保持零变化。
    let llm_auto_readonly_bypass = agent.config.gateway_approval.llm_auto_enabled()
        && {
            let policy = agent_core::gateway_approval::AutoPolicy::from_config(
                &agent.config.gateway_approval,
            );
            policy.in_auto_zone(&body.tool)
        }
        && (body
            .arguments
            .get("dry_run")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || body.tool.eq_ignore_ascii_case("manage_whitelist")
                && body
                    .arguments
                    .get("action")
                    .and_then(|a| a.as_str())
                    .map(|a| a.eq_ignore_ascii_case("query"))
                    .unwrap_or(false));
    if !check.allow && !needs_approval {
        return err_json(
            StatusCode::FORBIDDEN,
            "boundary-rejected",
            &format!("边界拒绝：{}", check.reason),
        );
    }

    // ── 危险判定（dangerous 分级或红线）：进入人工审批，绝不直接执行 ──
    let is_dangerous = tool_level == "dangerous";
    if (is_dangerous || check.level == Some(BlockLevel::Red) || needs_approval)
        && !llm_auto_readonly_bypass
    {
        // ── 分级审批（2026-09-03）：T1 自动区 LLM judge；Red/硬人工名单永远人工 ──
        // judge 失败/超时/超 quota → fail-safe 落人工（理由附审批单）。
        if check.level != Some(BlockLevel::Red)
            && agent.config.gateway_approval.llm_auto_enabled()
        {
            let policy = agent_core::gateway_approval::AutoPolicy::from_config(
                &agent.config.gateway_approval,
            );
            let quota_used = agent
                .approval_manager
                .sqlite_store()
                .and_then(|s| s.lock().ok())
                .map(|s| s.count_auto_today(&auth.agent_id))
                .unwrap_or(u32::MAX);
            let quota_ok = quota_used < agent.config.gateway_approval.daily_quota;
            if policy.in_auto_zone(&body.tool) {
                if quota_ok {
                    // judge 选型：[gateway_approval].judge > 主 [llm] 第一个
                    // fallback（快模型）> 主 provider。分类任务要快，思考型主模型易超时。
                    let judge_override = agent
                        .config
                        .gateway_approval
                        .judge
                        .clone()
                        .or_else(|| agent.config.llm.fallbacks.first().cloned());
                    let verdict = agent_core::gateway_approval::judge_risk_with(
                        &agent.llm,
                        judge_override.as_ref(),
                        &body.tool,
                        &body.arguments,
                        agent.config.gateway_approval.judge_timeout_ms,
                    )
                    .await;
                    if verdict.auto {
                        return execute_auto_approved(
                            agent.clone(),
                            auth.agent_id.clone(),
                            body.tool.clone(),
                            body.arguments.clone(),
                            ns.clone(),
                            auth.allowed_ns.clone(),
                            session_id.clone(),
                            execution_id.clone(),
                            trace_id.clone(),
                            verdict,
                        )
                        .await;
                    }
                    check_reason_auto = format!(
                        "{} | LLM判定转人工: {}",
                        check.reason, verdict.reason
                    );
                } else {
                    check_reason_auto = format!(
                        "{} | 每日自动批准配额已满({}/{}),转人工",
                        check.reason, quota_used, agent.config.gateway_approval.daily_quota
                    );
                }
            }
        }

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
                &if check_reason_auto.is_empty() {
                    format!("[gateway:{}] {}", auth.agent_id, check.reason)
                } else {
                    format!("[gateway:{}] {}", auth.agent_id, check_reason_auto)
                },
                "dashboard-admin", // D6：批准只在 dashboard 审批台，网关不自批
                &auth.agent_id,
                &session_id,
                // R2：批准后按调用方授权域恢复执行——参数带 ns 用之；
                // 无 ns 参数的工具（如 manage_whitelist）传调用方全量授权域，
                // 空列表会被源级门控以「不在授权范围」拒绝
                Some(if ns.is_empty() { auth.allowed_ns.clone() } else { ns.clone() }),
                Some(execution_id.clone()), // R2：批准后回写网关执行终态
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

// ── 分级审批辅助（2026-09-03）────────────────────────────────────────────

/// T1 工具改前状态抓取（撤销依据）。首批 manage_whitelist 行级；其余 None。
async fn capture_before_state(
    agent: &Arc<agent_core::agent::AgentCore>,
    tool: &str,
    args: &serde_json::Value,
    allowed_ns: &[String],
) -> Option<serde_json::Value> {
    if tool != "manage_whitelist" {
        return None;
    }
    let plate = args.get("plate")?.as_str()?.to_string();
    // confirmed=true 过受控写红线（boundary 对 manage_whitelist 全动作黄线，query 也拦）
    let q = serde_json::json!({"action": "query", "plate": plate, "confirmed": true});
    // allowed_ns 不能为空：源级门控拒空授权域（网关 R2 同坑）
    let res = agent
        .call_tool_routed(tool, "default", &q, allowed_ns, "")
        .await
        .ok()?;
    let text = res;
    // manage_whitelist query 返回 JSON 文本（dashboard skill 包装）
    let v: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let in_list = v.get("in_whitelist").and_then(|x| x.as_bool()).unwrap_or(false);
    Some(serde_json::json!({
        "found": in_list,
        "company": v.get("company").and_then(|x| x.as_str()).unwrap_or(""),
        "waste_type": v.get("waste_type").and_then(|x| x.as_str()).unwrap_or(""),
        "raw": v,
    }))
}

/// 自动批准执行路径：权威表记录（AutoApproved + before_state + judge 元数据）
/// → 注入 confirmed=true 执行 → 审计 → 200（带 undo 路径）。
#[allow(clippy::too_many_arguments)]
async fn execute_auto_approved(
    agent: Arc<agent_core::agent::AgentCore>,
    caller: String,
    tool: String,
    arguments: serde_json::Value,
    ns: Vec<String>,
    allowed_ns: Vec<String>,
    session_id: String,
    execution_id: String,
    trace_id: String,
    verdict: agent_core::gateway_approval::RiskVerdict,
) -> axum::response::Response {
    let t_auto = std::time::Instant::now();
    let approval_id = format!("auto_{}_{}", chrono::Utc::now().timestamp_millis(), tool);
    let before_state = capture_before_state(&agent, &tool, &arguments, &allowed_ns).await;
    let before_json = before_state.as_ref().map(|b| b.to_string());
    let judge_meta = serde_json::json!({
        "model": verdict.model, "judge_ms": verdict.elapsed_ms,
    })
    .to_string();
    if let Some(store) = agent.approval_manager.sqlite_store() {
        if let Ok(g) = store.lock() {
            let _ = g.insert_auto_approval(
                &approval_id,
                &session_id,
                &caller,
                &tool,
                &serde_json::to_string(&arguments).unwrap_or_default(),
                &verdict.reason,
                &judge_meta,
                before_json.as_deref(),
            );
        }
    }
    agent
        .audit_logger
        .record_event(agent_core::audit::AuditEvent {
            ts: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            trace_id: agent_core::audit::new_trace_id(),
            agent_id: caller.clone(),
            session_id: None,
            event_type: agent_core::audit::AuditEventType::AutoApproval,
            detail: format!(
                "[auto-approve] {} reason={} model={} judge_ms={} args={}",
                tool,
                verdict.reason,
                verdict.model,
                verdict.elapsed_ms,
                serde_json::to_string(&arguments).unwrap_or_default().chars().take(300).collect::<String>()
            ),
        })
        .await;
    record_execution(GatewayExecution {
        execution_id: execution_id.clone(),
        caller_agent_id: caller.clone(),
        tool_name: tool.clone(),
        status: GatewayStatus::Executing,
        approval_id: Some(approval_id.clone()),
        operation_hash: None,
        trace_id: trace_id.clone(),
        result: None,
        error: None,
        created_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    });
    // 与审批恢复执行同语义：confirmed 注入（受控写红线）
    let mut exec_args = arguments.clone();
    if let Some(obj) = exec_args.as_object_mut() {
        obj.insert("confirmed".to_string(), serde_json::json!(true));
    }
    let exec_ns: Vec<String> = if ns.is_empty() { allowed_ns } else { ns };
    let result = agent
        .call_tool_routed(&tool, "default", &exec_args, &exec_ns, "")
        .await;
    match &result {
        Ok(text) => {
            if let Some(store) = agent.approval_manager.sqlite_store() {
                if let Ok(g) = store.lock() {
                    let _ = g.set_auto_response(
                        &approval_id,
                        &text.chars().take(4000).collect::<String>(),
                    );
                }
            }
            agent_core::gateway::update_status(
                &execution_id,
                GatewayStatus::Executed,
                Some(text.clone()),
                None,
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "executed",
                    "auto_approved": true,
                    "approval_id": approval_id,
                    "risk_reason": verdict.reason,
                    "judge_model": verdict.model,
                    "undo": { "path": format!("/api/tool/auto-writes/{}/undo", approval_id) },
                    "result": text,
                    "execution_id": execution_id,
                    "trace_id": trace_id,
                    "elapsed_ms": t_auto.elapsed().as_millis() as u64,
                })),
            )
                .into_response()
        }
        Err(e) => {
            agent_core::gateway::update_status(
                &execution_id,
                GatewayStatus::Failed,
                None,
                Some(e.clone()),
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": "failed",
                    "auto_approved": true,
                    "approval_id": approval_id,
                    "error": e,
                    "execution_id": execution_id,
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/tool/auto-writes?limit=50 —— 近期自动批准记录（含改前状态/撤销标记）
pub(crate) async fn handle_auto_writes_list(
    State(st): State<Arc<crate::state::AppState>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let agent = {
        let guard = st.agent.lock().await;
        match guard.clone() {
            Some(a) => a,
            None => return err_json(StatusCode::SERVICE_UNAVAILABLE, "agent-not-ready", "agent 未就绪"),
        }
    };
    let limit = q
        .get("limit")
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(50)
        .min(200);
    let rows = agent
        .approval_manager
        .sqlite_store()
        .and_then(|s| s.lock().ok())
        .map(|s| s.list_auto_approvals(limit))
        .unwrap_or_default();
    Json(serde_json::json!({"count": rows.len(), "items": rows})).into_response()
}

/// POST /api/tool/auto-writes/{id}/undo —— 一键撤销（人发起的纠正动作，直接执行+审计）
pub(crate) async fn handle_auto_write_undo(
    State(st): State<Arc<crate::state::AppState>>,
    axum::Extension(auth): axum::Extension<crate::auth::AuthContext>,
    Path(approval_id): Path<String>,
) -> axum::response::Response {
    let agent = {
        let guard = st.agent.lock().await;
        match guard.clone() {
            Some(a) => a,
            None => return err_json(StatusCode::SERVICE_UNAVAILABLE, "agent-not-ready", "agent 未就绪"),
        }
    };
    let rec = agent
        .approval_manager
        .sqlite_store()
        .and_then(|s| s.lock().ok())
        .and_then(|s| s.get_auto_approval(&approval_id));
    let Some(rec) = rec else {
        return err_json(StatusCode::NOT_FOUND, "not-found", "自动批准记录不存在");
    };
    if rec.get("undone_by").and_then(|x| x.as_str()).is_some() {
        return err_json(StatusCode::CONFLICT, "already-undone", "该操作已被撤销过");
    }
    let tool = rec.get("tool_name").and_then(|x| x.as_str()).unwrap_or("");
    let args = rec.get("arguments").cloned().unwrap_or(serde_json::Value::Null);
    let before = rec.get("before_state");
    let undo_args = agent_core::gateway_approval::build_undo_for(tool, &args, before);
    let Some(undo_args) = undo_args else {
        return err_json(
            StatusCode::BAD_REQUEST,
            "not-undoable",
            "该工具/操作暂不支持自动撤销（无改前快照或无逆操作）",
        );
    };
    // 标记撤销（原子：重复点击第二次会 409）
    if let Some(store) = agent.approval_manager.sqlite_store() {
        if let Ok(g) = store.lock() {
            if let Err(e) = g.mark_undone(&approval_id, &format!("undo-ref:{}", approval_id)) {
                return err_json(StatusCode::CONFLICT, "already-undone", &e);
            }
        }
    }
    // 撤销是人工发起的纠正：直接执行（undo 参数已带 confirmed），全程审计
    let result = agent
        .call_tool_routed(tool, "default", &undo_args, &auth.allowed_ns.clone(), "")
        .await;
    agent
        .audit_logger
        .record_event(agent_core::audit::AuditEvent {
            ts: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            trace_id: agent_core::audit::new_trace_id(),
            agent_id: auth.agent_id.clone(),
            session_id: None,
            event_type: agent_core::audit::AuditEventType::UndoExecuted,
            detail: format!(
                "[undo] auto={} tool={} args={}",
                approval_id,
                tool,
                serde_json::to_string(&undo_args).unwrap_or_default().chars().take(300).collect::<String>()
            ),
        })
        .await;
    match result {
        Ok(text) => Json(serde_json::json!({
            "ok": true, "undone": approval_id, "undo_args": undo_args, "result": text
        }))
        .into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, "undo-failed", &e),
    }
}
