//! 对话 handler（从 src/main.rs 拆出，P6 重构）。
//!
//! 承载：chat / chat_stream / sessions / session load-delete / v1 chat。
//! 纯搬移 + `pub(crate)` 可见性，零行为变更。

use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::response::sse::{Event as SseEvent, Sse};
use axum::response::IntoResponse;
use axum::Json;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::auth::AuthContext;
use crate::caller_ns_covers;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct ChatRequest {
    message: String,
    #[serde(default = "default_sid")]
    session_id: String,
}
pub(crate) fn default_sid() -> String {
    "default".to_string()
}
#[derive(Debug, Serialize)]
pub(crate) struct ChatResponse {
    reply: String,
    session_id: String,
}
#[derive(Debug, Deserialize)]
pub(crate) struct SetupRequest {
    pub(crate) agent_id: String,
    pub(crate) api_key: String,
    #[serde(default)]
    pub(crate) server: String,
}
#[derive(Debug, Serialize)]
pub(crate) struct SetupResponse {
    pub(crate) ok: bool,
    pub(crate) error: Option<String>,
}

pub(crate) async fn handle_chat(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<ChatRequest>,
) -> axum::response::Response {
    // A2: 白龙马 TICK 心跳 —— 用户消息到达，抢占在途空闲 tick
    if let Some(ref c) = *st.consciousness.lock().await {
        c.interrupt();
    }
    // 解串行：克隆 Arc 后立即释放全局锁，chat() 在锁外并发执行
    let agent = {
        let g = st.agent.lock().await;
        g.as_ref().map(|a| a.clone())
    };
    if let Some(agent) = agent {
        let start = std::time::Instant::now();
        let reply = agent
            .chat(
                &req.message,
                &ctx.agent_id,
                &req.session_id,
                &ctx.allowed_ns,
                None,
            )
            .await;
        st.metrics
            .record_latency(start.elapsed().as_secs_f64() * 1000.0);
        Json(ChatResponse {
            reply,
            session_id: req.session_id,
        })
        .into_response()
    } else {
        Json(ChatResponse {
            reply: "请先在设置页面配置 API 密钥。".to_string(),
            session_id: req.session_id,
        })
        .into_response()
    }
}

/// SSE 流式聊天（包装 chat() 结果，分块推送）
pub(crate) async fn handle_chat_stream(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    axum::extract::Query(params): axum::extract::Query<ChatRequest>,
) -> axum::response::Response {
    let (tx, rx): (
        tokio::sync::mpsc::UnboundedSender<Result<SseEvent, Infallible>>,
        tokio::sync::mpsc::UnboundedReceiver<Result<SseEvent, Infallible>>,
    ) = tokio::sync::mpsc::unbounded_channel();

    // A2: 白龙马 TICK 心跳 —— 用户消息到达，抢占在途空闲 tick
    if let Some(ref c) = *st.consciousness.lock().await {
        c.interrupt();
    }
    let agent_guard = st.agent.lock().await;
    let has_agent = agent_guard.is_some();
    drop(agent_guard);

    if has_agent {
        let st_clone = st.clone();
        let msg = params.message.clone();
        let sid = params.session_id.clone();
        let agent_id = ctx.agent_id.clone();
        let allowed_ns = ctx.allowed_ns.clone();
        tokio::spawn(async move {
            // 解串行：克隆 Arc 后释放锁，chat() 并发执行
            let agent = {
                let g = st_clone.agent.lock().await;
                g.as_ref().map(|a| a.clone())
            };
            if let Some(agent) = agent {
                let start = std::time::Instant::now();
                let reply = agent.chat(&msg, &agent_id, &sid, &allowed_ns, None).await;
                st_clone
                    .metrics
                    .record_latency(start.elapsed().as_secs_f64() * 1000.0);
                let chars: Vec<char> = reply.chars().collect();
                let mut i = 0;
                while i < chars.len() {
                    let end = (i + 3).min(chars.len());
                    let chunk: String = chars[i..end].iter().collect();
                    let _ = tx.send(Ok(SseEvent::default().data(chunk).event("text")));
                    i = end;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            let _ = tx.send(Ok(SseEvent::default().data("").event("done")));
        });
    } else {
        let _ = tx.send(Ok(SseEvent::default()
            .data("请先在设置页面配置 API 密钥。")
            .event("text")));
        let _ = tx.send(Ok(SseEvent::default().data("").event("done")));
    }

    Sse::new(UnboundedReceiverStream::new(rx)).into_response()
}

/// 获取会话列表
pub(crate) async fn handle_sessions(
    State(_st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
) -> Json<serde_json::Value> {
    let allowed_ns = ctx.allowed_ns.clone();
    let db_path = std::env::current_dir()
        .unwrap_or_default()
        .join("harness.db")
        .to_string_lossy()
        .to_string();

    let sessions = tokio::task::spawn_blocking(move || {
        let mut result = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT session_id, namespace, role, content, created_at FROM chat_history WHERE id IN (
                    SELECT MIN(id) FROM chat_history GROUP BY session_id
                ) AND role = 'user' ORDER BY id DESC LIMIT 50",
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    let sid: String = row.get(0)?;
                    let ns: String = row.get(1)?;
                    let content: String = row.get(2)?;
                    let created: String = row.get(3)?;
                    Ok((sid, ns, content, created))
                }) {
                    for row in rows.flatten() {
                        // C2 修复：仅返回调用方命名空间覆盖的会话，防跨 agent 泄露
                        if !caller_ns_covers(&allowed_ns, &row.1) {
                            continue;
                        }
                        let summary = row.2.chars().take(40).collect::<String>();
                        result.push(serde_json::json!({
                            "session_id": row.0,
                            "summary": summary,
                            "created_at": row.3,
                        }));
                    }
                }
            }
        }
        result
    })
    .await
    .unwrap_or_default();

    Json(serde_json::json!({"sessions": sessions}))
}

/// 协作收件箱（A2A）：拉取调用者身份下的规范化信封，支持 type/scope 过滤与未读计数。
/// 读操作，沿用 authenticate 中间件（x-agent-id / x-agent-key）。
/// 解析转发给 Memoria 的有效调用者密钥。
///
/// PFAiX legacy 模式仅发 `x-user-tag`（随机安装ID），不携带 `x-agent-key`；
/// 若此处直接读 `x-agent-key` 头会得到空串，导致 Memoria `a2a_recv` 返回 -32001
/// （协作收件箱 502）。三级兜底：
///   1) `auth_cache` 中 `authenticate` 已校验/注册的 badge（legacy 自动注册 / 登录态自愈写入）；
///   2) 请求头 `x-agent-key`（登录态正常携带，且 `authenticate` 已据此成功鉴权）；
///   3) 兜底：以 admin 身份确保该 agent 在 Memoria 注册并取回 badge，再缓存复用。
/// 这样无论 `authenticate` 的注册 badge 是否成功落入 cache，调用方都能拿到可鉴权的密钥。
pub(crate) async fn handle_session_load(
    State(_st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let allowed_ns = ctx.allowed_ns.clone();
    let db_path = {
        std::env::current_dir()
            .unwrap_or_default()
            .join("harness.db")
            .to_string_lossy()
            .to_string()
    };

    let sid = id.clone();
    let messages = tokio::task::spawn_blocking(move || {
        let mut result = Vec::new();
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            // C2 修复：校验会话归属，仅当调用方命名空间覆盖该会话时才返回
            let owned = {
                let mut flag = false;
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT DISTINCT namespace FROM chat_history WHERE session_id=?1",
                ) {
                    if let Ok(rows) = stmt.query_map(rusqlite::params![&sid], |row| {
                        row.get::<_, String>(0)
                    }) {
                        flag = rows.flatten().any(|ns| caller_ns_covers(&allowed_ns, &ns));
                    }
                }
                flag
            };
            if !owned {
                return result;
            }
            if let Ok(mut stmt) = conn.prepare(
                "SELECT role, content, created_at FROM chat_history WHERE session_id=?1 ORDER BY id ASC"
            ) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![&sid], |row| {
                    let role: String = row.get(0)?;
                    let content: String = row.get(1)?;
                    let created: String = row.get(2)?;
                    Ok((role, content, created))
                }) {
                    for row in rows.flatten() {
                        result.push(serde_json::json!({
                            "role": row.0,
                            "content": row.1,
                            "time": row.2,
                        }));
                    }
                }
            }
        }
        result
    }).await.unwrap_or_default();

    Json(serde_json::json!({"messages": messages, "session_id": id}))
}

/// 删除指定会话
pub(crate) async fn handle_session_delete(
    Extension(ctx): Extension<AuthContext>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let allowed_ns = ctx.allowed_ns.clone();
    let db_path = std::env::current_dir()
        .unwrap_or_default()
        .join("harness.db")
        .to_string_lossy()
        .to_string();
    let sid = id.clone();

    let deleted = tokio::task::spawn_blocking(move || {
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            // C2 修复：校验会话归属，仅当调用方命名空间覆盖该会话时才允许删除
            let owned = {
                let mut flag = false;
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT DISTINCT namespace FROM chat_history WHERE session_id=?1",
                ) {
                    if let Ok(rows) = stmt.query_map(rusqlite::params![&sid], |row| {
                        row.get::<_, String>(0)
                    }) {
                        flag = rows.flatten().any(|ns| caller_ns_covers(&allowed_ns, &ns));
                    }
                }
                flag
            };
            if !owned {
                return 0;
            }
            if let Ok(cnt) = conn.execute(
                "DELETE FROM chat_history WHERE session_id=?1",
                rusqlite::params![&sid],
            ) {
                return cnt;
            }
        }
        0
    })
    .await
    .unwrap_or(0);

    Json(serde_json::json!({"deleted": deleted, "session_id": id}))
}

/// OpenAI 兼容聊天补全请求（JAN / 第三方客户端）
#[derive(Debug, Deserialize)]
pub(crate) struct V1ChatRequest {
    model: Option<String>,
    messages: Vec<V1Message>,
    #[allow(dead_code)]
    stream: Option<bool>,
}

/// OpenAI content 可能是 string，也可能是 [{type,text}, ...] 多段
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum V1Content {
    Text(String),
    Parts(Vec<V1ContentPart>),
}

#[derive(Debug, Deserialize)]
pub(crate) struct V1ContentPart {
    #[serde(default)]
    text: Option<String>,
}

impl V1Content {
    fn as_text(&self) -> String {
        match self {
            V1Content::Text(s) => s.clone(),
            V1Content::Parts(parts) => parts
                .iter()
                .filter_map(|p| p.text.as_ref())
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct V1Message {
    #[allow(dead_code)]
    role: String,
    content: Option<V1Content>,
}

pub(crate) async fn handle_v1_chat(
    State(st): State<Arc<AppState>>,
    Extension(ctx): Extension<AuthContext>,
    headers: axum::http::HeaderMap,
    Json(req): Json<V1ChatRequest>,
) -> axum::response::Response {
    // A2: 白龙马 TICK 心跳 —— 用户消息到达，抢占在途空闲 tick
    if let Some(ref c) = *st.consciousness.lock().await {
        c.interrupt();
    }
    let agent_guard = st.agent.lock().await;
    // PFAiX 强制上下文隔离：每个安装实例 + 每个对话独立 session（提到 if 外，stream 分支共用）。
    // x-user-tag 是壳首次启动生成的随机 install_id；x-conversation-id 是壳内当前对话 id。
    let user_tag = headers
        .get("x-user-tag")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());
    let conversation_id = headers
        .get("x-conversation-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());
    let session_id = format!("jan/{}/{}/{}", ctx.agent_id, user_tag, conversation_id);
    if session_id.len() > 128
        || !session_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_')
    {
        return axum::response::Json(serde_json::json!({
            "error": "invalid session_id"
        }))
        .into_response();
    }
    // 折叠 OpenAI messages 提到 if 外（stream 分支需要 user_text/external_history）
    let pairs: Vec<(String, String)> = req
        .messages
        .iter()
        .filter_map(|m| {
            m.content
                .as_ref()
                .map(|c| (m.role.clone(), c.as_text()))
        })
        .collect();
    let folded = agent_core::v1_compat::fold_v1_messages(&pairs);
    let user_text = folded.user_message;
    let external_history = if folded.history.is_empty() {
        None
    } else {
        Some(folded.history)
    };
    let reply = if let Some(ref agent) = *agent_guard {
        // 输入校验：消息长度限制 32KB，消息数限制 100
        if req.messages.len() > 100 {
            return axum::response::Json(serde_json::json!({
                "error": "too many messages"
            }))
            .into_response();
        }
        // P2-6：stream=true 时跳过预生成（reply 由 stream 分支真流式产出，避免重复 LLM 调用）
        if req.stream.unwrap_or(false) {
            String::new()
        } else if user_text.trim().is_empty() {
            "请输入消息".to_string()
        } else {
            if !folded.system_ctx.is_empty() {
                tracing::info!(
                    system_chars = folded.system_ctx.chars().count(),
                    "v1_chat: folded client system into user message"
                );
            }
            agent
                .chat(
                    &user_text,
                    &ctx.agent_id,
                    &session_id,
                    &ctx.allowed_ns,
                    external_history.clone(),
                )
                .await
        }
    } else {
        "Agent 未就绪".to_string()
    };
    drop(agent_guard);

    // PFAiX SSE 兼容：stream=true 时返回 text/event-stream
    if req.stream.unwrap_or(false) {
        let model = req.model.unwrap_or_else(|| "agent-core".to_string());
        let id = "chatcmpl-agent".to_string();
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (tx, rx): (
            tokio::sync::mpsc::UnboundedSender<Result<SseEvent, Infallible>>,
            tokio::sync::mpsc::UnboundedReceiver<Result<SseEvent, Infallible>>,
        ) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            // role 起始事件
            let _ = tx.send(Ok(SseEvent::default().data(
                serde_json::json!({
                    "id": &id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": &model,
                    "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
                })
                .to_string(),
            )));
            // 空消息校验（与非 stream 路径一致，防空消息跑完整 agent 管线）
            if user_text.trim().is_empty() {
                let _ = tx.send(Ok(SseEvent::default().data(
                    serde_json::json!({
                        "id": &id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": &model,
                        "choices": [{"index": 0, "delta": {"content": "请输入消息"}, "finish_reason": null}]
                    })
                    .to_string(),
                )));
                let _ = tx.send(Ok(SseEvent::default().data(
                    serde_json::json!({
                        "id": &id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": &model,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                    })
                    .to_string(),
                )));
                let _ = tx.send(Ok(SseEvent::default().data("[DONE]")));
                return;
            }
            // P2-6 真流式：快速通道命中 → provider 流式逐 chunk（首 token 秒出）；
            // 未命中/失败 → agent.chat_stream 内部降级伪流式（完整生成后分块推）。
            let agent = {
                let g = st.agent.lock().await;
                g.as_ref().map(|a| a.clone())
            };
            if let Some(agent) = agent {
                // llm 事件 → chat.completion.chunk 格式的转发层
                let (tx_llm, mut rx_llm): (
                    tokio::sync::mpsc::UnboundedSender<agent_core::llm::SseEvent>,
                    tokio::sync::mpsc::UnboundedReceiver<agent_core::llm::SseEvent>,
                ) = tokio::sync::mpsc::unbounded_channel();
                let tx_fwd = tx.clone();
                let fwd_id = id.clone(); // id/model 已被外层 async move 捕获，转发 task 用 clone
                let fwd_model = model.clone();
                // 转发 task：llm 事件 → chat.completion.chunk。ErrorEvt 不立即转发
                // （延迟到主流程决定：补推全文时混推 error 会语义混乱）；统计已推 TextEvt 数。
                let fwd = tokio::spawn(async move {
                    let mut errored = false;
                    let mut pushed: usize = 0;
                    let mut err_msg: Option<String> = None;
                    while let Some(ev) = rx_llm.recv().await {
                        let out: Option<String> = match ev {
                            agent_core::llm::SseEvent::TextEvt { content } => {
                                pushed += 1;
                                Some(
                                    serde_json::json!({
                                        "id": &fwd_id,
                                        "object": "chat.completion.chunk",
                                        "created": created,
                                        "model": &fwd_model,
                                        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
                                    })
                                    .to_string(),
                                )
                            }
                            agent_core::llm::SseEvent::ThinkingEvt { content } => Some(
                                serde_json::json!({
                                    "id": &fwd_id,
                                    "object": "chat.completion.chunk",
                                    "created": created,
                                    "model": &fwd_model,
                                    "choices": [{"index": 0, "delta": {"reasoning_content": content}, "finish_reason": null}]
                                })
                                .to_string(),
                            ),
                            agent_core::llm::SseEvent::ErrorEvt { message } => {
                                errored = true;
                                err_msg = Some(message);
                                None // 延迟转发，避免与补推全文混推
                            }
                            agent_core::llm::SseEvent::DoneEvt | _ => None,
                        };
                        if let Some(data) = out {
                            let _ = tx_fwd.send(Ok(SseEvent::default().data(data)));
                        }
                    }
                    (errored, Some(pushed), err_msg)
                });
                let full = agent
                    .chat_stream(&user_text, &ctx.agent_id, &session_id, &ctx.allowed_ns, external_history.clone(), &tx_llm)
                    .await;
                // 关闭 tx_llm 并等待转发 task flush 完（防 finish 截断最后内容）
                drop(tx_llm);
                let (stream_errored, pushed, _err_msg) = match fwd.await {
                    Ok(r) => r,
                    Err(je) => {
                        // 转发 task panic/abort：pushed 未知（None）→ 保守视为已推（不补推防重复）
                        tracing::warn!(err = %je, "SSE 转发 task 异常结束");
                        (true, None, Some("SSE 转发任务异常".to_string()))
                    }
                };
                // pushed: Option<usize>（None=未知）；已推与否 = pushed.map_or(true, |p| p>0)
                let pushed_any = pushed.map_or(true, |p| p > 0);
                if stream_errored && pushed_any {
                    // 中途失败（已推部分内容）：error 事件（可区分失败/成功；中性措辞覆盖
                    // 认证/限流/连接/内部异常等所有来源）+ 内容提示不完整 + stop
                    let _ = tx.send(Ok(SseEvent::default()
                        .event("error")
                        .data("流式响应异常，本次回复可能不完整")));
                    let _ = tx.send(Ok(SseEvent::default().data(
                        serde_json::json!({
                            "id": &id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": &model,
                            "choices": [{"index": 0, "delta": {"content": "\n\n⚠️ 流式响应异常，本次回复可能不完整。请重试。"}, "finish_reason": null}]
                        })
                        .to_string(),
                    )));
                    let _ = tx.send(Ok(SseEvent::default().data(
                        serde_json::json!({
                            "id": &id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": &model,
                            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                        })
                        .to_string(),
                    )));
                } else if !pushed_any {
                    // 未推任何内容（首包失败/流式未命中/正常 fallback）→ 伪流式补推 llm_loop
                    // 的完整结果（真实降级答案，诚实呈现——即使 full 是错误文本也如实展示）
                    let mut chars = full.chars();
                    loop {
                        let mut chunk = String::new();
                        for _ in 0..3 {
                            match chars.next() {
                                Some(c) => chunk.push(c),
                                None => break,
                            }
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        let data = serde_json::json!({
                            "id": &id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": &model,
                            "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": null}]
                        })
                        .to_string();
                        if tx.send(Ok(SseEvent::default().data(data))).is_err() {
                            break; // 客户端断开立即退出
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    // 首包失败：补推内容后标注降级（error 事件，可区分、不伪装成功）
                    if stream_errored {
                        let _ = tx.send(Ok(SseEvent::default()
                            .event("error")
                            .data("流式响应异常，已切换普通模式返回。")));
                    }
                    let _ = tx.send(Ok(SseEvent::default().data(
                        serde_json::json!({
                            "id": &id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": &model,
                            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                        })
                        .to_string(),
                    )));
                } else {
                    // 真流式成功（已推完整内容）→ 仅终态 finish:stop
                    let _ = tx.send(Ok(SseEvent::default().data(
                        serde_json::json!({
                            "id": &id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": &model,
                            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                        })
                        .to_string(),
                    )));
                }
            } else {
                let _ = tx.send(Ok(SseEvent::default().data(
                    serde_json::json!({
                        "id": &id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": &model,
                        "choices": [{"index": 0, "delta": {"content": "Agent 未就绪"}, "finish_reason": null}]
                    })
                    .to_string(),
                )));
                // Agent 未就绪分支也发终态 finish_reason（客户端依赖 finish 终结）
                let _ = tx.send(Ok(SseEvent::default().data(
                    serde_json::json!({
                        "id": &id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": &model,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                    })
                    .to_string(),
                )));
            }
            // [DONE]
            let _ = tx.send(Ok(SseEvent::default().data("[DONE]")));
        });
        return Sse::new(UnboundedReceiverStream::new(rx)).into_response();
    }

    axum::response::Json(serde_json::json!({
        "id": "chatcmpl-agent",
        "object": "chat.completion",
        "created": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        "model": req.model.unwrap_or_else(|| "agent-core".to_string()),
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": reply,
            },
            "finish_reason": "stop",
        }],
    })).into_response()
}