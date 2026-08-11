//! 会议 handler（从 src/main.rs 拆出，P5 重构）。
//!
//! 承载：会议 CRUD / 消息 / 结束 / SSE 流 / 心跳 / 在线表清扫 / 通道回收。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event as SseEvent, Sse};
use axum::response::IntoResponse;
use axum::Json;
use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;

use agent_core::agent::{AgentCore, EventKind, MeetingEvent};

use crate::auth::authenticate;
use crate::handlers::approval::is_admin;
use crate::state::AppState;

pub(crate) async fn handle_meetings_list(
    headers: axum::http::HeaderMap,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let g = st.agent.lock().await;
    let Some(ref agent) = *g else {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
    };
    let list = agent.list_meetings(&caller, admin, &caller_ns);
    // scope 会议的可见性已在 AgentCore::list_meetings 内权威判定（public within scope）
    let items: Vec<serde_json::Value> = list
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id,
                "topic": m.topic,
                "owner_user_id": m.owner_user_id,
                "participant_personas": m.participant_personas,
                "is_private": m.is_private,
                "created_at": m.created_at,
                "status": m.status,
                "consensus": m.consensus,
                "scope": m.scope,
                "participant_agents": m.participant_agents,
                "messages": m.messages,
                "phase": m.phase,
            })
        })
        .collect();
    Json(serde_json::json!({ "meetings": items })).into_response()
}

/// Phase 6 增强：删除圆桌会议（私有仅拥有者 / admin 可删）
pub(crate) async fn handle_meeting_delete(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    // 【reviewer round-17 #8 反枚举】删除前先做可见性门禁（与 message/end/SSE/心跳同一
    // meeting_visible 判定）：会议不存在与无权统一返回 403「无权访问该会议」，避免通过 DELETE
    // 的错误串差异探测私有会议 ID 是否存在（remove_meeting 内部此前区分「无权删除该会议」/
    // 「会议不存在」，会暴露存在性）。可见即可删（配 remove_meeting 的 owner/admin 校验）。
    // 【round-24 #3】agent 未就绪（meeting_visible 返回 None）→ 503 而非 403，避免未就绪被
    // 误报成鉴权失败。
    match meeting_visible(&st, &id, &caller, &caller_ns, admin).await {
        None => return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "服务尚未就绪").into_response(),
        Some(false) => return (axum::http::StatusCode::FORBIDDEN, "无权访问该会议").into_response(),
        Some(true) => {}
    }
    // 在 agent 锁短作用域完成删除判定，随即释放全局锁，避免 presence 清理 / 实时广播
    // 在持全局锁期间 await 而拉长全局锁持有时长、并引入脆弱的锁顺序（reviewer round-10 F1）。
    // presence / 广播均在 agent 锁释放后进行，无 agent→presence 嵌套。
    let agent_arc = {
        let g = st.agent.lock().await;
        let Some(ref agent) = *g else {
            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
        };
        let agent_arc = agent.clone();
        match agent.remove_meeting(&id, &caller, admin) {
            Ok(()) => agent_arc,
            // 门禁已把「不存在 / 无权」挡在 403，此处仅剩合法删除的内部错误（如竞态），
            // 仍以统一错误返回，不泄露存在性。
            Err(e) => {
                return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
                    .into_response()
            }
        }
    };
    // 【reviewer round-25 #8 security·low】门禁已把「不存在/无权」挡在 403，此处错误串仅剩
    // remove_meeting 的防御性返回（竞态窗口内被并发删除 / 权限变化），且已统一为中立串
    // 「无权访问该会议」（round-25 #2），不会再经此回显会议存在性。客户端见到的任何错误
    // 都是同一中立串，无法借 DELETE 探测私有 ID。
    // 【reviewer round-25 #3 performance·medium】**先广播、后后台持久化**（与 handle_meeting_message
    // round-22 #1 同一「实时优先 + 先广播后持久化」原则）：persist_meetings_for 内部是 spawn_blocking
    // 全文件序列化 + fsync，且被 persist_lock 串行化——并发写多会议时磁盘延迟会排队，若 await 它
    // 再广播 Ended，订阅端就被累积的磁盘延迟挡住，会议已删除却迟迟收不到终止信号。持久化是
    // best-effort（失败仅 error 日志、删除已在内存生效、后续 save 不会再带上它），故：
    //   1) presence 清理 + Ended 广播移到最前（订阅端立即收到终止信号，实时性不受磁盘影响）；
    //   2) 再 spawn 后台持久化（best-effort，spawn_blocking 迁移到阻塞线程池，不占 tokio worker）。
    // 全局 st.agent 锁已释放：presence 清理与实时广播均在锁外进行。
    st.meeting_presence.lock().await.remove(&id);
    // Step3 实时同步：广播终止事件。会议已被删除，get_meeting 之后恒为 None，
    // 若不广播，订阅端拿不到任何终止信号 → 本地状态永久陈旧、SSE 任务空转到客户端断开为止。
    broadcast_meeting_event(
        &st,
        &id,
        EventKind::Ended,
        serde_json::json!({ "deleted": true, "terminal": true, "status": "done", "phase": "done" }),
    )
    .await;
    // 后台持久化（best-effort，不阻塞实时广播与响应）：remove_meeting 已不再内部落盘（round-17 #3），
    // 此处 spawn 后台任务落盘，避免同步全量写盘挡在广播/响应关键路径。save_meetings 内部仍持轻量
    // persist_lock 串行化，保进程崩溃不把已删除会议重新写回。
    let pa = agent_arc.clone();
    let pid = id.clone();
    tokio::spawn(async move {
        persist_meetings_for(&pa, |e| {
            tracing::error!(error = %e, meeting = %pid, "handle_meeting_delete: 会议已删除但落盘失败（可能进程崩溃后残留，请排查磁盘）");
        }).await;
    });
    Json(serde_json::json!({"ok": true, "removed": id})).into_response()
}

/// Phase 6 增强 (Step2)：真人 A2A 参会——向会议发言。
/// body: { "from": agent_id, "content": "..." }
/// 记录发言后，将该消息 A2A 投递到会议其余 participant_agents 的收件箱。
pub(crate) async fn handle_meeting_message(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // 发言资格判定需 admin 身份；在获取全局 agent 锁之前算好，避免持锁期间 await。
    let admin = is_admin(&headers, &st).await;
    // 【round-14 #5 安全对齐】发言前先做可见性门禁（与 SSE 订阅 / 心跳同一判定 meeting_visible，
    // 含 scope 成员）：(a) 让可订阅会议的 scope 成员也能发言，读写权限一致；(b) 会议不存在与
    // 无权统一返回 403「无权访问」，避免通过区分「会议不存在」/「发言者非邀请」错误串探测私有
    // 会议 ID 是否存在（add_meeting_message 的鉴权错误不再暴露）。可见即可评，与政策一致。
    // 【round-24 #3】agent 未就绪（None）→ 503 而非 403。
    match meeting_visible(&st, &id, &caller, &caller_ns, admin).await {
        None => return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "服务尚未就绪").into_response(),
        Some(false) => return (axum::http::StatusCode::FORBIDDEN, "无权访问该会议").into_response(),
        Some(true) => {}
    }
    let v = match body {
        Some(Json(v)) => v,
        None => return (axum::http::StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    // 安全：发言身份强制绑定到已认证的 caller，忽略请求体中的 `from` 伪造。
    // 否则任意认证用户可伪装成受邀参与者 (participant_agents)，强制把状态机推进到
    // discussing，干扰圆桌收敛（见 round-9 F3）。
    // 【reviewer round-26 #3 security·medium】授权身份与显示字段在 add_meeting_message 签名层
    // 分离：授权以 caller（已认证主体）判定，sender 仅作 msg.from 显示字段。此处 sender=caller
    // （两者同源），不变式由签名强制而非注释约束。
    let sender = caller.clone();
    let content = match v.get("content").and_then(|x| x.as_str()) {
        Some(c) if !c.trim().is_empty() => c.to_string(),
        _ => return (axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "content required"}))).into_response(),
    };
    // 在 agent 锁短作用域内完成「记录发言 + 收集投递目标 + 读取状态」，随即释放全局锁，
    // 避免后续 A2A 网络投递（collab_send_raw）与实时广播（broadcast 通道锁）在持全局锁期间
    // await 而拉长全局 agent 锁持有时长、并引入脆弱的 agent→presence/agent→meeting_tx 锁顺序
    // （reviewer round-10 F1）。collab_send_raw 需 agent 引用，故克隆 Arc 在锁外调用。
    let (msg, targets, agent_arc) = {
        let g = st.agent.lock().await;
        let Some(ref agent) = *g else {
            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
        };
        let agent_arc = agent.clone();
        let msg = match agent.add_meeting_message(&id, &caller, &sender, &caller_ns, "human", &content, admin) {
            Ok(m) => m,
            Err(e) => {
                return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
                    .into_response()
            }
        };
        let targets: Vec<String> = agent
            .meeting_agent_participants(&id)
            .into_iter()
            .filter(|a| *a != sender)
            .collect();
        (msg, targets, agent_arc)
    };
    // 全局 st.agent 锁已释放。先广播增量 Message 实时事件，再后台持久化、再 A2A 投递。
    // 【reviewer round-20 #4 + round-21 re-review #1 performance·medium】实时广播必须放在
    // persist await **之前**：persist_meetings_for 内部是 spawn_blocking 全文件序列化 + fsync，
    // 且被 persist_lock 串行化——并发写多会议时磁盘延迟会排队，若 await 它再广播，订阅端就被
    // 累积的磁盘延迟挡住（部分抵消 round-20 #4 让广播脱离关键路径的目标）。持久化是 best-effort
    // （失败仅 error 日志、消息已在内存、后续 save 会带上它），故：
    //   1) 先广播 Message（订阅端立即收到，实时性不受磁盘/对端影响）；
    //   2) 再 spawn 后台持久化（best-effort，也被 spawn_blocking 迁移到阻塞线程池，不占 tokio worker）；
    //   3) 最后 A2A 串行投递（只影响 HTTP 响应的 delivered 计数）。
    // 这也让 round-20 #4 注释「Message 必在任何后续 ended/state 之前落广播」真正成立：today 若
    // persist 在广播前、并发 end/delete 的（无 fsync gating 的）persist 先完成，会先广播 ended
    // 再让本 handler 广播 Message——状态倒退。广播移到最前则本 handler 的 Message 必先落。
    // 广播**增量**（仅新发言 + 状态字段）：不再序列化完整 Meeting（round-13），避免 O(n²)。
    // 仅在会议仍存在时广播：add_meeting_message 成功后到此处读状态之间若被并发删除，
    // meeting_state 返回 None，不应伪造 status:"running" 广播针对已不存在会议的消息。
    // TOCTOU（reviewer round-13 #5）：此处用 agent_arc 重读会议状态作为广播的唯一来源。
    // 【round-14 #2】绝不可用回退到锁内旧状态：`meeting_state` 返回 None 仅当会议已被并发删除；
    // 会议已消失则直接丢弃广播（不复活 ESM 的陈旧 running 状态）。
    if let Some((status, phase, _, _)) = agent_arc.meeting_state(&id) {
        broadcast_meeting_event(
            &st,
            &id,
            EventKind::Message,
            serde_json::json!({ "message": msg, "status": status, "phase": phase }),
        ).await;
    }
    // 后台持久化（best-effort，不阻塞实时广播）：add_meeting_message 已不再内部落盘（round-14 #4），
    // 此处 spawn 后台任务落盘，避免同步全量写盘挡在广播/A2A 关键路径。save_meetings 内部仍持
    // 轻量 persist_lock 串行化，保进程崩溃不丢已确认发言。
    // 【round-15 #3】落盘失败以 **error 级**日志记录「已确认但未持久化」的发言（含会议 id），
    // 使审计域可发现；但不因此拒绝已成功的发言请求（客户端已确认，内存状态已生效，仅持久化失败）。
    // 【round-17 #5】persist_meetings_for 用 spawn_blocking 迁移写盘到阻塞线程池，避免同步 fsync
    // 阻塞 tokio worker。
    let pa = agent_arc.clone();
    let pid = id.clone();
    tokio::spawn(async move {
        persist_meetings_for(&pa, |e| {
            tracing::error!(error = %e, meeting = %pid, "handle_meeting_message: 发言已确认但落盘失败（可能进程崩溃丢失，请排查磁盘）");
        }).await;
    });
    let mut delivered = 0usize;
    // 【reviewer round-17 #9 性能】A2A 投递加每目标超时：`collab_send_raw` 每对端最多重试
    // 3 次 × 30s reqwest 超时（mcp_client.rs timeout_secs=30），单个不可达对端可把串行循环
    // 阻塞 ~90s。用短超时（5s）把慢对端从实时路径隔离：超时按未送达处理（不抛出、不阻塞
    // 其余对端）。广播已在上方提前发出，此处循环只影响 HTTP 响应的 delivered 计数。
    for t in &targets {
        let envelope = serde_json::json!({
            "type": "meeting",
            "subject": format!("会议 {}：{} 发言", id, sender),
            "meeting": id,
            "from": sender,
            "content": content,
            "kind": "human-message",
        });
        let ok_delivered =
            tokio::time::timeout(Duration::from_secs(5), agent_arc.collab_send_raw(t, &envelope))
                .await
                .map_or(false, |r| r.is_ok());
        if ok_delivered {
            delivered += 1;
        }
    }
    Json(serde_json::json!({"ok": true, "delivered": delivered, "targets": targets.len()})).into_response()
}

/// Phase 6 增强 (Step2)：结束会议并回填共识。
/// body: { "requested_by": "<owner>", "consensus": "..." }
/// consensus 可选，缺省用 caller 的 ""。
pub(crate) async fn handle_meeting_end(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    // 【round-15 #1 反枚举】结束会议前先做可见性门禁（与 message/SSE/心跳同一 meeting_visible
    // 判定）：会议不存在与无权统一返回 403「无权访问该会议」，避免通过 /end 的错误串差异探测
    // 私有会议 ID 是否存在（end_meeting 内部的错误串也已统一）。
    // 【round-24 #3】agent 未就绪（None）→ 503 而非 403。
    match meeting_visible(&st, &id, &caller, &caller_ns, admin).await {
        None => return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "服务尚未就绪").into_response(),
        Some(false) => return (axum::http::StatusCode::FORBIDDEN, "无权访问该会议").into_response(),
        Some(true) => {}
    }
    let v = match body {
        Some(Json(v)) => v,
        None => serde_json::json!({}),
    };
    // 安全：结束会议的「请求者」强制绑定到已认证的 caller，忽略请求体中的 `requested_by` 伪造。
    // 否则任意认证用户可把 requested_by 设成 owner 以绕过 `end_meeting` 的 ownership 校验（越权结束会议）。
    let requested_by = caller.clone();
    let consensus = v.get("consensus").and_then(|x| x.as_str()).unwrap_or("").to_string();
    // 在 agent 锁短作用域完成终态跃迁判定，随即释放全局锁，避免 presence 清理 / 实时广播
    // 在持全局锁期间 await 而拉长全局锁持有时长、并引入脆弱的锁顺序（reviewer round-10 F1）。
    // presence / 广播均在 agent 锁释放后进行，无 agent→presence 嵌套。
    let (transitioned, agent_arc) = {
        let g = st.agent.lock().await;
        let Some(ref agent) = *g else {
            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
        };
        let agent_arc = agent.clone();
        match agent.end_meeting(&id, &consensus, &requested_by, admin) {
            Ok(b) => (b, agent_arc),
            Err(e) => {
                return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
                    .into_response()
            }
        }
    };
    // 全局 st.agent 锁已释放。end_meeting 已不再内部落盘（round-15 #2），此处须在锁外持久化，
    // 避免把同步 fsync 写盘拖进持 st.agent 全局锁的临界区。仅当实际发生终态跃迁才写盘
    // （已终态幂等返回时状态未变，无需写盘）。
    // 【reviewer round-25 #4 performance·medium】**先广播、后后台持久化**（与 handle_meeting_message
    // round-22 #1 / handle_meeting_delete round-25 #3 同一「实时优先 + 先广播后持久化」原则）：
    // persist_meetings_for 内部是 spawn_blocking 全文件序列化 + fsync，且被 persist_lock 串行化——
    // 若 await 它再广播 Ended，磁盘慢时订阅端滞留非终态 + /end 响应被延迟。故把 presence 清理 +
    // Ended 广播移到最前，持久化 spawn 后台执行（best-effort，失败仅 error 日志、内存终态已生效、
    // 后续 save 会带上它）。
    // 以下 presence 清理与广播均在锁外进行。
    match transitioned {
        true => {
            // 实际发生终态跃迁：清理在线态并广播 ended 事件（增量，不含完整消息历史）
            st.meeting_presence.lock().await.remove(&id);
            broadcast_meeting_event(
                &st,
                &id,
                EventKind::Ended,
                serde_json::json!({
                    "status": "done",
                    "phase": "done",
                    "terminal": true,
                    "consensus": consensus,
                }),
            ).await;
            // 后台持久化（best-effort，不阻塞实时广播与响应）：仅终态跃迁后才 spawn 落盘。
            let pa = agent_arc.clone();
            let pid = id.clone();
            tokio::spawn(async move {
                persist_meetings_for(&pa, |e| {
                    tracing::error!(error = %e, meeting = %pid, "handle_meeting_end: 会议已结束但共识落盘失败（可能进程崩溃丢失，请排查磁盘）");
                }).await;
            });
            Json(serde_json::json!({"ok": true, "ended": id})).into_response()
        }
        false => {
            // 已终态（幂等）：不重复广播 ended，避免订阅端收到两次 ended 事件 / 共识分歧。
            // 仍清理在线态（幂等安全），但不下发 ended。
            st.meeting_presence.lock().await.remove(&id);
            Json(serde_json::json!({"ok": true, "ended": id, "already_terminal": true})).into_response()
        }
    }
}

/// 会议持久化的异步入口：把 `save_meetings()`（同步 full-file 序列化 + fsync）迁移到
/// tokio **阻塞线程池**（spawn_blocking），避免同步磁盘 IO 阻塞 tokio worker 线程
/// （head-of-line blocking，reviewer round-17 #5 / #6）。
///
/// 调用点（handle_meeting_message / end / delete）都已在持 st.agent 全局锁的临界区**之外**
/// 调用本函数，因此写盘不会拉长全局锁持有时间；spawn_blocking 再进一步把 fsync 从当前
/// worker 线程挪走，保证单次会议的慢磁盘不会拖慢所有 tokio 任务。
///
/// 落盘失败时调用 `on_err`（error 级日志，援引会议 id 上下文，「已确认但未持久化」可审计）。
/// 返回 `()`：持久化是 best-effort，失败不拒绝已成功的业务请求（内存状态已生效，仅持久化
/// 失败）。`save_meetings` 内部仍持轻量 persist_lock 串行化，保进程崩溃不丢已确认状态。
pub(crate) async fn persist_meetings_for<F>(agent_arc: &Arc<AgentCore>, on_err: F)
where
    F: FnOnce(String),
{
    let a = agent_arc.clone();
    match tokio::task::spawn_blocking(move || a.save_meetings()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => on_err(e),
        Err(e) => on_err(format!("spawn_blocking 任务失败: {e}")),
    }
}

/// Step3：向会议实时广播通道推送一条事件。
///
/// payload 由调用方决定粒度：
/// - `Message` / `Ended`：**增量**（新发言 + status/phase，或终止状态），O(1)；
/// - `Snapshot`：完整 Meeting JSON，仅用于初始订阅与 Lagged 重同步。
///
/// 仅向**已存在**的会议通道广播：通道在订阅时按需创建，无订阅者时不创建孤儿通道
/// （否则无接收者的通道会永久留在 map 中），避免内存无限增长。迟到的订阅者会收到包含
/// 最新状态（含 ended）的初始快照，无需重放历史事件。
pub(crate) async fn broadcast_meeting_event(
    st: &Arc<AppState>,
    id: &str,
    kind: EventKind,
    payload: serde_json::Value,
) {
    let sender = {
        let map = st.meeting_tx.lock().await;
        map.get(id).cloned()
    };
    if let Some(sender) = sender {
        let _ = sender.send(MeetingEvent {
            meeting_id: id.to_string(),
            kind,
            payload,
            at: chrono::Utc::now().to_rfc3339(),
        });
    }
}

/// Step3：SSE 任务结束时清理该会议的 broadcast 通道（若无存活接收者），避免每会议通道无限积累。
pub(crate) async fn cleanup_meeting_channel(st: &Arc<AppState>, id: &str) {
    let mut map = st.meeting_tx.lock().await;
    if let Some(tx) = map.get(id) {
        // 调用点：本函数总在 spawned 任务内、rx 仍存活时执行，receiver_count() 至少为 1。
        // 用 `<= 1` 判定（即仅剩本任务这一接收者）才能正确回收，否则 Sender 永不释放 → 泄漏。
        if tx.receiver_count() <= 1 {
            map.remove(id);
        }
    }
}

/// Step3：周期回收无接收者的会议 broadcast 通道（兜底清理）。
///
/// `cleanup_meeting_channel` 在 SSE 任务结束时调用，但当多个订阅者**同时**退出时存在竞态窗口：
/// 每个任务调用 cleanup 时自身 `rx` 仍存活、`receiver_count()` 可能都 `> 1`，于是谁都不删，
/// 留下一个 0 接收者的 `Sender` 永久泄漏。本后台任务每 60s 扫描一次，移除 `receiver_count()==0`
/// 的通道，作为确定性的兜底，杜绝无界泄漏。
pub(crate) fn spawn_meeting_channel_sweeper(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            let mut map = st.meeting_tx.lock().await;
            let stale: Vec<String> = map
                .iter()
                .filter(|(_, tx)| tx.receiver_count() == 0)
                .map(|(id, _)| id.clone())
                .collect();
            for id in stale {
                map.remove(&id);
            }
        }
    });
}

/// Step3：会议在线表兜底清理 —— 周期性移除「会议已不存在」或「已终态但仍存在」的孤儿 presence 条目。
///
/// 心跳 handler（handle_meeting_heartbeat）为降低全局 agent 锁持有时长，分两步执行：
/// 先在 agent 锁内做「可见性 + 终态」判定并释放，再在 presence 锁内写入在线态。若并发的
/// delete/end 在两步之间 remove 掉该会议，心跳会用 `or_default()` 为已删除会议重建孤儿 presence
/// 条目；此后心跳对该会议恒返回 403（不可见）、SSE 任务也已退出，无人再裁剪该键，造成无界泄漏。
/// 此外，纯 AI 圆桌经 `handle_panel_discuss` 收敛为终态（status=done）后会议仍保留在 `meetings` 中，
/// 原 `is_none()` 谓词匹配不到，其 presence 条目同样会泄漏。
/// 本后台任务每 60s 扫描一次，对「会议不存在」或「已终态」的 id 直接 remove，作为确定性兜底。
///
/// 锁顺序：agent → presence（先取 agent 锁判定会议是否存在，再取 presence 锁删除），
/// 与 delete/end、心跳 handler 的锁顺序一致，无死锁风险（无任何路径反向 presence→agent 取锁）。
pub(crate) fn spawn_meeting_presence_sweeper(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            // 锁序（修复 reviewer round-10 F2）：
            // ① 仅持 presence 锁收集全部 id（不碰 agent），随即释放；
            // ② 逐个持 agent 锁做 O(1) 的会议存在性判定（agent 锁短持、且不在 presence 锁内）；
            // ③ 仅对确认缺失的 id 持 presence 锁删除（短临界区）。
            // 全程不「持 agent 锁内取 presence」，与心跳 / end / delete 的「agent 释放后取 presence」
            // 方向一致，无死锁；且不再周期性同时持全局 agent + presence 锁全表扫描，消除全局停顿。
            let ids: Vec<String> = {
                let p = st.meeting_presence.lock().await;
                p.keys().cloned().collect()
            };
            if ids.is_empty() {
                continue;
            }
            // 【reviewer round-24 #1 bug·medium】sweeper 除清理「会议缺失/终态」的 presence 外，
            // 还要回收「内层全 stale」的键：非终态会议（如 awaiting_humans）若客户端只通过
            // /heartbeat 保活、不常开 SSE 流（或流已关闭），内层 map 在 15s 保留后清空，但**外层
            // 键会一直存活**——跨大量长期会议会无界增长。故对每个键检查：会议缺失 / 已终态 /
            // 内层全部条目已超过 15s 保留（无人心跳）→ 回收该键。注意非终态会议若仍有活跃心跳
            // 不应被误清（内层有 fresh 条目），仅全 stale 才回收。
            // 先取「内层全 stale」的 id 集合（仅 presence 锁，O(内层)）；再与缺失/终态判定合并。
            // 【reviewer round-25 #6 performance·low】用 HashSet 而非 Vec.contains：下方 O(ids) 循环
            // 内做成员测试，Vec 是 O(n²)（每个都线性扫），HashSet 摊还 O(1)。
            let mut stale_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
            {
                let p = st.meeting_presence.lock().await;
                for (id, inner) in p.iter() {
                    let all_stale = inner.values().all(|h| h.elapsed().as_secs() >= 15);
                    if all_stale {
                        stale_ids.insert(id.clone());
                    }
                }
            }
            // 【round-14 #3 性能】单次取全局 agent 锁批量判定全部 id（而非逐个获取 N 次全局锁），
            // 消除每 60s 对 N 个 presence 条目做 N 次全局锁获取的周期性序列化争用。判定逻辑：
            // 会议不存在 或 已终态（status=done / phase=Done / 含 phase_raw 未知 phase）→ true。
            let should_clear: Vec<bool> = {
                let g = st.agent.lock().await;
                g.as_ref()
                    .map(|a| a.meetings_need_presence_clear(&ids))
                    .unwrap_or_else(|| vec![true; ids.len()])
            };
            // to_remove: (id, force_clear)。force_clear=true 表示该会议已被 agent 判定为缺失/终态
            // （删除无条件安全）；force_clear=false 表示仅因「内层全 stale」入选，须在最终锁内复核。
            let mut to_remove: Vec<(String, bool)> = Vec::new();
            for (id, clear) in ids.iter().zip(should_clear.iter()) {
                if *clear {
                    to_remove.push((id.clone(), true));
                } else if stale_ids.contains(id) {
                    to_remove.push((id.clone(), false));
                }
            }
            if !to_remove.is_empty() {
                let mut p = st.meeting_presence.lock().await;
                for (id, force) in &to_remove {
                    if *force {
                        // 会议缺失/终态：删除无条件安全（心跳对缺失/终态会议恒 403，不会重建）。
                        p.remove(id);
                    } else if let Some(inner) = p.get(id) {
                        // 【reviewer round-25 #5 bug·medium】消除 check-then-act 竞态：stale_ids 判定在
                        // 上方**另一把锁**内完成，从判定到此处 remove 之间，并发心跳可能已把该条目刷新为
                        // fresh（15s 窗口内），若仍按陈旧判定删除，会误删刚上报的在线态（客户端认为在线、
                        // 服务器却已把它清掉）。故在**同一把锁**内复核该条目仍全 stale 才 remove——
                        // 刚被心跳刷新的条目此处判定非 stale，跳过删除，避免丢失最新在线态。
                        if inner.values().all(|h| h.elapsed().as_secs() >= 15) {
                            p.remove(id);
                        }
                    }
                }
            }
        }
    });
}

/// Step3：会议可见性判定的**取锁便捷包装**（供 SSE 订阅使用）。
///
/// 判定规则的唯一实现在 `AgentCore::meeting_visible`（owner / admin / scope 成员 /
/// 公开 / participant_agents 成员），SSE 订阅与心跳 handler 共用同一份规则，不会各写一份而漂移。
/// 注意：**仅 SSE 订阅**通过本包装取锁调用；心跳 handler 为保持 `agent → presence` 锁顺序、
/// 降低全局 agent 锁持有时长，**主动分两步**执行——先在 agent 锁内做「可见性 + 终态」判定并
/// 释放锁，再在 presence 锁内写在线态（见 `handle_meeting_heartbeat`）。两条路径共享
/// `AgentCore::meeting_visible` 这一权威判定，但取锁策略各自独立，勿混淆。
///
/// 会议不存在/无权时返回 `Some(false)`；**agent 尚未就绪（st.agent 为 None）返回 `None`**。
/// 调用方须将 `None` 映射为 503「服务未就绪」，而非 403「无权」——否则服务启动期所有会议
/// 端点（message/end/delete/stream）会把未就绪误报成鉴权失败，误导客户端与健康监控
/// （reviewer round-24 #3 bug·low）。
pub(crate) async fn meeting_visible(
    st: &Arc<AppState>,
    id: &str,
    caller: &str,
    caller_ns: &[String],
    admin: bool,
) -> Option<bool> {
    let g = st.agent.lock().await;
    match &*g {
        Some(agent) => agent.meeting_visible(id, caller, caller_ns, admin),
        None => None,
    }
}

/// Step3：实时同步 —— SSE 订阅某会议的实时事件流。
/// 事件类型：snapshot（初始快照）/ message / state / ended（会议状态变更）/ presence（在线列表）。
pub(crate) async fn handle_meeting_stream(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    // 可见性校验：owner / admin / scope 成员 / 公开会议 可订阅（与心跳共用同一判定）
    // 【round-24 #3】agent 未就绪（None）→ 503 而非 403。
    match meeting_visible(&st, &id, &caller, &caller_ns, admin).await {
        None => return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "服务尚未就绪").into_response(),
        Some(false) => return (axum::http::StatusCode::FORBIDDEN, "无权订阅该会议").into_response(),
        Some(true) => {}
    }

    // Step3 顺序关键：先克隆快照，再订阅**该会议**专属通道，订阅后立刻复核会议是否
    // 在「克隆→订阅」窗口内发生变化（如并发发言）；若变化则重新克隆，使快照包含该事件，
    // 避免该事件既在快照中又被 rx 重放导致前端重复应用（subscribe/snapshot 竞态修复）。
    // 【reviewer round-25 #7 performance·low】克隆快照**移出全局 agent 锁**：全局 `st.agent`
    // 锁只守卫 `Option<Arc<AgentCore>>` 槽位，一旦取到 `Arc`，其内部方法各自用 `self.meetings`
    // 的内部锁保护数据（与 handle_meeting_message/end/delete 的 `agent.clone()` 后锁外调用同一
    // 模式）。此前在 `st.agent` 锁内 clone 完整 Meeting（O(会议大小)），大会议 / 多订阅者会在
    // 全局锁临界区内做全量深拷贝，阻塞所有 agent 操作。改为短锁取 `agent_arc` 后立即释放，
    // get_meeting / meeting_state 全在锁外进行（内部 meetings 锁仍串行化单次访问）。
    let id2 = id.clone();
    let agent_arc = {
        let g = st.agent.lock().await;
        // 门禁 meeting_visible 已确认 Some(true)；此处再取一次以防「门禁→取句柄」窗口内
        // agent 从就绪变未就绪（实际启动期设置后不再变化，防御性处理）。None → 503。
        match &*g {
            Some(a) => a.clone(),
            None => return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "服务尚未就绪").into_response(),
        }
    };
    // 锁外克隆初始快照与轻量状态（内部 meetings 锁串行化，不驻留全局锁）。
    let mut snap = agent_arc.get_meeting(&id2);
    let mut rx = {
            let mut map = st.meeting_tx.lock().await;
            map.entry(id2.clone())
                .or_insert_with(|| broadcast::channel(256).0)
                .subscribe()
        };
    // 复核窗口：用 meeting_state()（仅取 status/phase/发言数/终态标记，不克隆整会）判断快照是否过期，
    // 仅在确实变化时再克隆完整会议用于序列化，避免每次订阅都做全量 clone 占用全局 agent 锁、
    // 拖慢大会议的所有 agent 操作（发言 / A2A / 生命周期 handler）。
    let state = agent_arc.meeting_state(&id2);
    // 终态快照：status != running / phase == Done / 含 phase_raw 的未知 phase 都表示会议已结束。
    // 终态判定统一委托给 agent_core::agent::Meeting::is_terminal()（reviewer round-19 #1）——
    // 它覆盖 phase_raw 未知 phase 的保守判定，是 status/phase/phase_raw 的单一来源，避免各
    // handler 各写一份 `s == "done" || p == Some(Done)`，新增终态时漏改导致分歧。meeting_state
    // 直接返回该布尔值，避免调用方用 is_terminal_state(&s, p) 重建而漏掉 phase_raw。
    let terminal = state.as_ref().map_or(true, |(_, _, _, term)| *term);
    match state {
        Some((status, phase, count, _)) => {
            let changed = match &snap {
                Some(s) => s.messages.len() != count || s.status != status || s.phase != phase,
                None => true,
            };
            if changed {
                // 仅在确实变化时克隆完整会议（用于快照序列化），避免每次订阅全量 clone。
                // 在 agent_arc 上调用（锁外，内部 meetings 锁串行化），不驻留全局 agent 锁。
                // 【reviewer round-17 #7 bug·medium】无条件赋值（含 None）：
                // 若 get_meeting 返回 None（复核窗口内被并发删除），snap 必须置 None，
                // 与下方 `state == None` 分支一致地走 ended(deleted) 终止路径，而不是保留
                // 陈旧的（非终态 running）快照——否则会用过期 status 发「running + terminal:true」
                // 的矛盾 ended payload，且丢失 deleted 标记。
                snap = agent_arc.get_meeting(&id2);
            }
        }
        None => {
            // 复核窗口内会议已被删除：标记 snap 为 None，稍后发 ended(deleted) 并终止。
            snap = None;
        }
    }
    // 服务端去重指纹：快照中已有发言的 (from,at)。每个订阅连接构建一次（O(消息数)），
    // 订阅窗口（克隆→订阅）内落地的发言会同时出现在快照与 rx 缓冲，非终态时跳过转发，
    // 避免客户端重复应用（此前依赖前端去重）。本领域（固废监管圆桌）会议发言数有界且较小，
    // 每连接线性内存开销可接受；集合随订阅任务结束而释放，不会跨会议累积。
    let mut snap_msg_keys: HashSet<(String, String)> = snap
        .as_ref()
        .map(|m| m.messages.iter().map(|msg| (msg.from.clone(), msg.at.clone())).collect())
        .unwrap_or_default();
    let (tx, rx_out) = tokio::sync::mpsc::channel::<Result<SseEvent, Infallible>>(64);
    let st2 = st.clone();
    // 把 agent_arc 克隆进流任务，供 Lagged 重同步锁外克隆（避免每 60s 持全局 agent 锁）。
    let agent_arc2 = agent_arc.clone();
    tokio::spawn(async move {
        // 初始快照：克隆已在上方锁外完成，此处仅序列化并发送。
        if let Some(m) = snap {
            // 序列化失败不应静默下发空快照（会污染客户端会议状态）；记录诊断并终止流。
            let data = match serde_json::to_string(&m) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(meeting = %id2, "snapshot 序列化失败: {e}");
                    cleanup_meeting_channel(&st2, &id2).await;
                    return;
                }
            };
            if tx
                .try_send(Ok(SseEvent::default().event("snapshot").data(data)))
                .is_err()
            {
                cleanup_meeting_channel(&st2, &id2).await;
                return;
            }
            if terminal {
                // 快照已是终态（status != running 或 phase == Done）：无后续事件，
                // 立即发 ended 并终止流，避免客户端持有永不关闭的 zombie 连接。
                // 携带 status/phase（来自快照会议），统一 ended payload 契约。
                let ended_payload = serde_json::json!({
                    "status": m.status, "phase": m.phase, "terminal": true,
                });
                let _ = tx.try_send(Ok(SseEvent::default().event("ended").data(
                    ended_payload.to_string(),
                )));
                cleanup_meeting_channel(&st2, &id2).await;
                return;
            }
        } else {
            // 复核窗口内会议已被删除：立即发 ended(deleted) 终止，不留 zombie 流。
            let _ = tx.try_send(Ok(SseEvent::default().event("ended").data(
                serde_json::json!({ "deleted": true, "terminal": true }).to_string(),
            )));
            cleanup_meeting_channel(&st2, &id2).await;
            return;
        }
        // 心跳保活 + 在线表推送（每 5s）
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    // 在线表裁剪与「无存活则删除会议键」在**同一次锁**内完成，
                    // 消除 check-then-act 竞态：否则并发心跳可能在两次加锁之间插入新条目，
                    // 被本次 remove 误删，导致在线表丢失刚上报的心跳、复活刚被清理的状态。
                    let online: Vec<String> = {
                        let mut map = st2.meeting_presence.lock().await;
                        let online: Vec<String> = map
                            .get(&id2)
                            .map(|p| {
                                p.iter()
                                    .filter(|(_, t)| t.elapsed().as_secs() < 15)
                                    .map(|(k, _)| k.clone())
                                    .collect()
                            })
                            .unwrap_or_default();
                        if online.is_empty() {
                            map.remove(&id2);
                        }
                        online
                    };
                    // 非关键心跳事件：客户端断开(Closed)才结束任务；慢客户端缓冲写满(Full)直接丢弃，不断流
                    if !send_meeting_event(
                        &tx,
                        SseEvent::default()
                            .event("presence")
                            .data(serde_json::json!({ "online": online }).to_string()),
                        false,
                    )
                    .await
                    { break; }
                    // SSE 注释行心跳：axum 以 ':' 前缀发出，客户端忽略，不产生伪 message 事件
                    if !send_meeting_event(&tx, SseEvent::default().comment("ping"), false).await { break; }
                }
                msg = rx.recv() => {
                    match msg {
                        Ok(ev) if ev.meeting_id == id2 => {
                            // 会议终止（ended / 删除）事件转发后立即结束推送任务并关闭 SSE 流，
                            // 避免任务、mpsc 通道、broadcast 接收端随服务器生命周期无限常驻（资源泄漏）。
                            let ended = ev.kind == EventKind::Ended;
                            // 服务端去重：订阅窗口内落地、已随快照下发的发言，跳过转发，
                            // 避免客户端收到两次（此前仅依赖前端 (from,at) 去重）。
                            if ev.kind == EventKind::Message {
                                if let Some(inner) = ev.payload.get("message") {
                                    let key = (
                                        inner.get("from").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        inner.get("at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    );
                                    if snap_msg_keys.contains(&key) {
                                        continue;
                                    }
                                    // 记录已转发发言指纹，保证去重集与实际下发一致；
                                    // (from,at) 因 RFC3339 含亚秒精度实际唯一，碰撞在实践中不可能。
                                    snap_msg_keys.insert(key);
                                    // 内存护栏：去重集只增不删会在长连接 × 订阅数下线性膨胀。
                                    // 超阈值即清空（正常发言经 broadcast 单次发布不会重复下发，
                                    // Lagged 路径会基于快照重建集合，见 round-9 F6）。
                                    if snap_msg_keys.len() > 4096 {
                                        snap_msg_keys.clear();
                                    }
                                }
                            }
                            // 关键实时事件：区分 Closed(断开→结束) 与 Full(慢客户端→背压 2s，避免重连风暴)
                            if !send_meeting_event(
                                &tx,
                                SseEvent::default()
                                    .event(ev.kind.as_str())
                                    .data(ev.payload.to_string()),
                                true,
                            )
                            .await
                            { break; }
                            if ended { break; }
                        }
                        Ok(_) => {}
                        // 客户端落后超过缓冲：重新发送完整快照以重同步，避免静默丢事件
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // 同初始快照：克隆在 agent_arc 上做（锁外，内部 meetings 锁串行化）；
                            // 此前在 st2.agent 全局锁内克隆，Lagged 高频时反复驻留全局锁。
                            let m = agent_arc2.get_meeting(&id2);
                            match m {
                                Some(m) => {
                                    let s = match serde_json::to_string(&m) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!(meeting = %id2, "Lagged 重同步快照序列化失败: {e}");
                                            break;
                                        }
                                    };
                                    // 重同步快照可能包含订阅窗口之后的发言，刷新去重指纹，
                                    // 避免这些发言被后续 rx 再次下发导致客户端重复应用。
                                    snap_msg_keys = m
                                        .messages
                                        .iter()
                                        .map(|msg| (msg.from.clone(), msg.at.clone()))
                                        .collect();
                                    if tx.try_send(Ok(SseEvent::default().event("snapshot").data(s))).is_err() { break; }
                                    // Lagged 重同步后判定终态：Ended 可能被本次 Lagged 吞掉，
                                    // 若会议已结束/删除则补发 ended 并终止，避免 zombie 流。
                                    if m.is_terminal() {
                                        let _ = tx.try_send(Ok(SseEvent::default().event("ended").data(
                                            serde_json::json!({
                                                "status": m.status, "phase": m.phase, "terminal": true,
                                            }).to_string(),
                                        )));
                                        // 【round-15 #4】此处不再重复调 cleanup_meeting_channel：
                                        // break 后的 post-loop 会统一清理同一通道（receiver_count()
                                        // 在本任务 drop 其 rx 前恒 >0，分支内清理无效果且与 post-loop
                                        // 重复取锁）。仅在 break 后由 post-loop 做一次清理即可。
                                        break;
                                    }
                                }
                                None => {
                                    // 会议已被删除：不再重同步，转发终止避免永久阻塞 rx.recv()
                                    let _ = tx.try_send(Ok(SseEvent::default().event("ended").data(
                                        serde_json::json!({ "deleted": true, "terminal": true }).to_string(),
                                    )));
                                    break;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
        // 不再下发无契约的裸 `done` 事件：流的结束由连接关闭 / 终态 `ended` 事件表达，
        // 一个空 payload 的 `done` 无 SSE 契约、客户端不应依赖（见 ocr-review finding #8）。
        cleanup_meeting_channel(&st2, &id2).await;
    });
    let mut resp = Sse::new(ReceiverStream::new(rx_out)).into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    resp.headers_mut().insert(
        "x-accel-buffering",
        axum::http::HeaderValue::from_static("no"),
    );
    resp
}

/// Step3：SSE 背压助手——区分客户端真正断开(Closed)与慢客户端缓冲写满(Full)。
///
/// - `Closed` → 返回 `false`，调用方 `break` 结束任务，避免僵尸流；
/// - `Full`   → 非关键事件(心跳/ping)直接丢弃、关键事件(发言/快照)带超时 `await` 施加背压，
///   避免浏览器节流导致缓冲写满时直接拆流、客户端无限重连风暴（见 ocr-review finding #7）。
///
/// `tx` 为会议 SSE 的 mpsc 发送端；`ev` 为待下发事件；`critical` 标记是否为关键实时事件。
pub(crate) async fn send_meeting_event(
    tx: &tokio::sync::mpsc::Sender<Result<SseEvent, Infallible>>,
    ev: SseEvent,
    critical: bool,
) -> bool {
    match tx.try_send(Ok::<_, Infallible>(ev)) {
        Ok(()) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        Err(tokio::sync::mpsc::error::TrySendError::Full(inner)) => {
            if !critical {
                return true; // 非关键事件满则丢弃，不断流
            }
            // inner 即本次未能入队的原始值 Result<SseEvent, Infallible>，
            // Infallible 不可构造，故必为 Ok(SseEvent)。背压：带超时 await send。
            // （reviewer round-21 #3 maintainability·low：仅匹配 Ok(e) 即对 Result<T, Infallible>
            // 穷尽——Infallible 无法构造，Err 分支是不可达死代码，已移除。）
            let ev = match inner {
                Ok(e) => e,
            };
            // 区分内层结果：外层 Ok 仅代表「send 调用已返回」，不代表客户端仍在线。
            // - Ok(Ok(()))：真正下发成功；
            // - Ok(Err(_))：接收端已 drop（客户端断开），应立即结束任务、避免僵尸流；
            // - Err(_)：2s 超时（慢客户端背压），关键事件在窗口内仍未下发，按失败处理，
            //   与「Closed→立即结束避免僵尸流」契约一致，避免拖长数秒（见 ocr-review finding #9）。
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tx.send(Ok::<_, Infallible>(ev)),
            )
            .await
            {
                Ok(Ok(())) => true,
                Ok(Err(_)) => false,
                Err(_) => false,
            }
        }
    }
}

/// Step3：实时同步 —— 心跳保活。记录调用者在该会议的在线状态，返回当前在线列表。
pub(crate) async fn handle_meeting_heartbeat(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(st): State<Arc<AppState>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    // 降低全局 agent 锁持有时长：可见性校验 + 终态判定在 agent 锁内完成（O(1)，仅判可见+终态，
    // 不触碰磁盘、不碰 presence），随即释放 agent 锁；在线态写入单独在 presence 锁内完成。
    // 两步拆分存在 check-then-act 竞态：并发 delete/end 可能在两步之间 remove 掉该会议，使后续
    // 心跳用 or_default() 为已删除会议重建孤儿 presence 条目。该竞态由 spawn_meeting_presence_sweeper
    // （每 60s 兜底清理「会议已不存在」的孤儿条目）兜底，杜绝无界泄漏，故此处无需在 presence 锁内
    // 反向回查 agent（会破坏 agent→presence 锁顺序、引发死锁）。锁顺序始终保持 agent → presence。
    // 会议不存在时同样按「无权」返回，避免任意认证用户借错误码探测会议 ID 是否存在。
    // 【round-24 #3】agent 未就绪（g 为 None）→ 503 而非 403。
    let (ready, visible, terminal) = {
        let g = st.agent.lock().await;
        let agent_opt = g.as_ref();
        let ready = agent_opt.is_some();
        let visible = agent_opt
            .map(|a| a.meeting_visible(&id, &caller, &caller_ns, admin).unwrap_or(false))
            .unwrap_or(false);
        let terminal = agent_opt
            .map_or(true, |a| a.meeting_state(&id).map_or(true, |(_, _, _, term)| term));
        (ready, visible, terminal)
    };
    if !ready {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "服务尚未就绪").into_response();
    }
    if !visible {
        return (axum::http::StatusCode::FORBIDDEN, "无权访问该会议").into_response();
    }
    // 终态会议（status=done / phase=Done）不再接受心跳：直接清在线态并返回空在线表，
    // 避免 or_default() 重建孤儿 presence 条目导致该键无界泄漏。
    if terminal {
        st.meeting_presence.lock().await.remove(&id);
        return Json(serde_json::json!({ "ok": true, "online": [] })).into_response();
    }
    // 仅持 presence 锁完成「写在线态 + 读在线列表」（agent 锁已释放，无跨会议争用）。
    // 写与读合并在**同一次** presence 锁内，避免重复加锁造成的自死锁（tokio Mutex 不可重入）。
    // 并发 delete/end 在两次心跳之间发生会瞬时写入孤儿 presence，但 delete/end 自身已
    // remove(&id) 清理，且 entry 按 15s 裁剪，不会无界泄漏。
    let online: Vec<String> = {
        let mut map = st.meeting_presence.lock().await;
        let entry = map.entry(id.clone()).or_default();
        entry.retain(|_, t| t.elapsed().as_secs() < 15);
        entry.insert(caller.clone(), std::time::Instant::now());
        map.get(&id)
            .map(|p| {
                p.iter()
                    .filter(|(_, t)| t.elapsed().as_secs() < 15)
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    Json(serde_json::json!({ "ok": true, "online": online })).into_response()
}


