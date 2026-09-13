//! 群聊型会议新增 handler（2026-09-12 方案 §3.1–3.3）：
//! 创建房间（不开桌）/ 点名分身发言 / 消息 @ 提及解析触发。
//!
//! 与 handle_panel_discuss（圆桌直播）的关系：
//!   roundtable = 建会 + 逐席 LLM + 共识 + 终态（自动化流程，/api/roundtable 兼容保留）
//!   群聊       = 建会（不开桌）+ 真人/分身消息时间线 + 显式结束/共识（end mode 拆分见 meetings.rs）
//!
//! 共享基础设施（meeting_visible / broadcast_meeting_event / persist_meetings_for）
//! 全部复用 meetings.rs，零重复。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use agent_core::agent::EventKind;

use crate::auth::authenticate;
use crate::handlers::approval::is_admin;
use crate::handlers::meetings::{broadcast_meeting_event, meeting_visible, persist_meetings_for};
use crate::state::AppState;

/// 防刷限流（方案 §7）：同一会议同一分身 10s 内只应答一次（@ 提及与手动点名共用）。
/// 进程内状态即可：agent-core 单实例，会议本身也是内存态。
const ASK_COOLDOWN: Duration = Duration::from_secs(10);

fn ask_cooldown_ok(meeting_id: &str, persona_id: &str) -> bool {
    static MAP: std::sync::OnceLock<std::sync::Mutex<HashMap<(String, String), Instant>>> =
        std::sync::OnceLock::new();
    let mut map = MAP
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    // 顺手清理过期项，防止长跑进程表无限增长
    map.retain(|_, t| now.duration_since(*t) < ASK_COOLDOWN * 64);
    let key = (meeting_id.to_string(), persona_id.to_string());
    if let Some(t) = map.get(&key) {
        if now.duration_since(*t) < ASK_COOLDOWN {
            return false;
        }
    }
    map.insert(key, now);
    true
}

/// ═══ §3.1 新增：创建房间（不自动开桌） ═══
///
/// 复用 handle_panel_discuss 的鉴权/scope/分身筛选/建会逻辑，
/// 但不启动圆桌 SSE 任务——只建房间、持久化、返回 meeting JSON。
pub(crate) async fn handle_meetings_create(
    headers: axum::http::HeaderMap,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    let v = match body {
        Some(Json(v)) => v,
        None => return (StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let topic = match v.get("topic").and_then(|x| x.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return (StatusCode::BAD_REQUEST, "topic required").into_response(),
    };
    // 与圆桌同默认：缺省私有（仅拥有者 / admin 可见），显式 visibility=public 才公开
    let is_private = !(v
        .get("visibility")
        .and_then(|x| x.as_str())
        .map(|s| s == "public")
        .unwrap_or(false));
    let scope: Option<String> = v
        .get("scope")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    // 发起者只能创建自己所属 scope 的会议（与 handle_panel_discuss 同一防越权判定）
    if let Some(ref sc) = scope {
        if !admin && !agent_core::agent::scope_matches_caller(sc, &caller_ns) {
            return (
                StatusCode::FORBIDDEN,
                format!("无权发起该 scope 的会议：{}", sc),
            )
                .into_response();
        }
    }
    let participant_agents: Vec<String> = v
        .get("participants")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let selected_ids: Option<Vec<String>> = v
        .get("personas")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .filter(|a| !a.is_empty());

    // 单一锁临界区：算参与者 → 建会（不开桌）→ 取快照序列化，随即释放全局锁。
    let meeting_json = {
        let g = st.agent.lock().await;
        let Some(ref agent) = *g else {
            return (StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪").into_response();
        };
        let mut personas = agent.list_personas_scoped(scope.as_deref());
        personas.sort_by(|a, b| a.persona_id.cmp(&b.persona_id));
        if let Some(ids) = &selected_ids {
            personas.retain(|p| ids.contains(&p.persona_id));
        }
        let participants: Vec<String> = personas.iter().map(|p| p.persona_id.clone()).collect();
        let id = agent.create_meeting(
            &topic,
            &caller,
            participants,
            participant_agents,
            is_private,
            scope,
        );
        match agent.get_meeting(&id) {
            Some(m) => serde_json::to_value(&m).unwrap_or_else(|_| serde_json::json!({ "id": id })),
            None => serde_json::json!({ "id": id }),
        }
    };
    let meeting_id = meeting_json
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    // 落盘（锁外，best-effort：与 roundtable 建会同款后台持久化）
    let persist_arc = {
        let g = st.agent.lock().await;
        g.as_ref().map(|a| a.clone())
    };
    if let Some(arc) = persist_arc {
        let _ = persist_meetings_for(&arc, |e| {
            tracing::error!(error = %e, meeting = %meeting_id,
                "meetings_create: 房间已创建但落盘失败（可能进程崩溃丢失，请排查磁盘）");
        })
        .await;
    }

    Json(serde_json::json!({ "meeting": meeting_json })).into_response()
}

/// ═══ §3.2 新增：点名分身发言（房间内 / @ 提及共用核心流程） ║══
///
/// 流程：会议存在且 running → 找分身（scope 过滤）→ 防刷限流 →
/// persona_stance（LLM，全程不持全局锁）→ add_meeting_message（锁内短临界区）→
/// 广播增量 Message 事件（与 handle_meeting_message 相同载荷形状）→ 后台落盘。
///
/// 返回 Ok(该分身发言的 JSON)；Err((状态码, 错误串))。
pub(crate) async fn ask_persona_flow(
    st: &Arc<AppState>,
    meeting_id: &str,
    persona_id: &str,
    prompt: &str,
    caller: &str,
    caller_ns: &[String],
    admin: bool,
) -> Result<serde_json::Value, (StatusCode, String)> {
    // Step1 锁内：取 agent arc + 会议快照（status/scope/topic），随即释放全局锁。
    // LLM 调用绝不能在持全局锁期间进行（与 roundtable SSE 任务同一纪律）。
    let (agent_arc, scope, topic, running) = {
        let g = st.agent.lock().await;
        let Some(ref agent) = *g else {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪".to_string()));
        };
        match agent.get_meeting(meeting_id) {
            None => return Err((StatusCode::NOT_FOUND, "会议不存在".to_string())),
            Some(m) => (agent.clone(), m.scope.clone(), m.topic.clone(), m.status == "running"),
        }
    };
    if !running {
        return Err((StatusCode::BAD_REQUEST, "会议已结束，不能点名".to_string()));
    }

    // Step2 找分身（锁外：list_personas_scoped 只走内部 personas 锁）。
    // 排序与圆桌一致（persona_id 升序），保证 LLM 池分配下标可复现。
    let mut personas = agent_arc.list_personas_scoped(scope.as_deref());
    personas.sort_by(|a, b| a.persona_id.cmp(&b.persona_id));
    let (idx, persona) = match personas.iter().enumerate().find(|(_, p)| p.persona_id == persona_id)
    {
        Some((i, p)) => (i, p.clone()),
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("分身 {} 不存在（或不在该会议 scope 内）", persona_id),
            ))
        }
    };

    // Step3 防刷限流（方案 §7）
    if !ask_cooldown_ok(meeting_id, persona_id) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            format!("分身 {} 刚刚应答过，请稍候再点名", persona_id),
        ));
    }

    // Step4 LLM 拿立场卡（锁外）。persona_stance 内部自带 JSON 输出约束，
    // 返回 (persona_id, StanceCard, provider)；card.raw 是模型原文（可回溯）。
    let pool = agent_arc.llm_pool();
    if pool.is_empty() && persona.llm.is_none() {
        // persona_stance 对无专属 LLM 的分身按 pool 下标取模分配，空池会 panic——提前拦成业务错误
        return Err((StatusCode::SERVICE_UNAVAILABLE, "未配置任何 LLM，分身无法发言".to_string()));
    }
    let llm_topic = if prompt.trim().is_empty() {
        topic.clone()
    } else {
        format!("{}\n补充提问：{}", topic, prompt.trim())
    };
    let (_pid, card, provider) = agent_arc.persona_stance(&persona, &llm_topic, idx, &pool).await;

    // Step5 锁内短临界区写入会议（add_meeting_message 内部再校验
    // is_authorized + 终态守卫，竞态窗口内会议被删/已结束会在这里被挡下）。
    let msg = {
        let g = st.agent.lock().await;
        let Some(ref agent) = *g else {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "agent 尚未就绪".to_string()));
        };
        agent
            .add_meeting_message(meeting_id, caller, &persona.persona_id, caller_ns, "ai", &card.raw, admin)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?
    };

    // Step6 广播增量 Message（载荷形状与 handle_meeting_message 完全一致，前端零特判）。
    // TOCTOU 同款处理：会议被并发删除则 meeting_state=None，直接丢弃广播。
    if let Some((status, phase, _, _)) = agent_arc.meeting_state(meeting_id) {
        broadcast_meeting_event(
            st,
            meeting_id,
            EventKind::Message,
            serde_json::json!({ "message": msg, "status": status, "phase": phase }),
        )
        .await;
    }

    // Step7 后台落盘（best-effort，先广播后持久化——与全部会议写路径同一原则）。
    let pa = agent_arc.clone();
    let mid = meeting_id.to_string();
    tokio::spawn(async move {
        persist_meetings_for(&pa, |e| {
            tracing::error!(error = %e, meeting = %mid,
                "ask_persona_flow: 分身发言已确认但落盘失败（可能进程崩溃丢失，请排查磁盘）");
        })
        .await;
    });

    Ok(serde_json::json!({
        "message": msg,
        "persona_id": persona.persona_id,
        "display_name": persona.display_name,
        "provider": provider,
        "stance_card": card,
    }))
}

/// HTTP handler：POST /api/meetings/{id}/ask（「请 TA 表态」按钮）。
pub(crate) async fn handle_meeting_ask(
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    State(st): State<Arc<AppState>>,
    body: Option<Json<serde_json::Value>>,
) -> axum::response::Response {
    let (caller, caller_ns) = match authenticate(&headers, &st).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let admin = is_admin(&headers, &st).await;
    // 可见性门禁（与 message/end/SSE/心跳同一判定，反枚举策略一致）
    match meeting_visible(&st, &id, &caller, &caller_ns, admin).await {
        None => return (StatusCode::SERVICE_UNAVAILABLE, "服务尚未就绪").into_response(),
        Some(false) => return (StatusCode::FORBIDDEN, "无权访问该会议").into_response(),
        Some(true) => {}
    }
    let v = match body {
        Some(Json(v)) => v,
        None => return (StatusCode::BAD_REQUEST, "missing body").into_response(),
    };
    let persona_id = match v.get("persona_id").and_then(|x| x.as_str()) {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return (StatusCode::BAD_REQUEST, "persona_id required").into_response(),
    };
    let prompt = v
        .get("prompt")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    match ask_persona_flow(&st, &id, &persona_id, &prompt, &caller, &caller_ns, admin).await {
        Ok(v) => Json(v).into_response(),
        Err((code, msg)) => (code, Json(serde_json::json!({ "error": msg }))).into_response(),
    }
}

/// ═══ §3.3 消息 @ 提及解析：提取 @persona_id 或 @显示名 ═══
///
/// 返回命中的 persona_id 列表（按分身出现顺序去重）。显示名匹配做最长优先：
/// 存在「运营总监」/「运营总监助理」这类前缀包含关系时，长名优先命中。
pub(crate) fn parse_mentions(
    content: &str,
    personas: &[agent_core::runtime::self_runtime::Persona],
) -> Vec<String> {
    let mut sorted: Vec<&agent_core::runtime::self_runtime::Persona> = personas.iter().collect();
    // 标签越长越优先（persona_id 与 display_name 分别比较）
    sorted.sort_by(|a, b| {
        let la = a.persona_id.chars().count().max(a.display_name.chars().count());
        let lb = b.persona_id.chars().count().max(b.display_name.chars().count());
        lb.cmp(&la)
    });
    // 工作串：已命中的 @提及从串中抹掉（替换为占位符），防止「@运营总监」被
    // 「@运营总监助理」的前缀子串误命中——长标签先消费，短标签才检查。
    let mut rest = content.to_string();
    let mut hits: Vec<String> = Vec::new();
    for p in sorted {
        let pid_tag = format!("@{}", p.persona_id);
        let name_tag = format!("@{}", p.display_name);
        let tag = if rest.contains(&pid_tag) {
            pid_tag
        } else if rest.contains(&name_tag) {
            name_tag
        } else {
            continue;
        };
        if !hits.contains(&p.persona_id) {
            hits.push(p.persona_id.clone());
        }
        rest = rest.replace(&tag, "\u{0}");
    }
    hits
}

/// 消息写入后异步触发被 @ 的分身应答（方案 §3.3）。
///
/// 由 handle_meeting_message 在消息入库 + 广播之后调用：本函数只做
/// scope 查询与提及解析（微秒级），随后为每个命中分身 spawn 独立任务跑
/// ask_persona_flow——HTTP 响应与消息广播都不被 LLM 延迟阻塞。
/// 未命中提及时不做任何事（AI 默认不抢话）。
pub(crate) async fn spawn_ask_for_mentions(
    st: &Arc<AppState>,
    meeting_id: &str,
    content: &str,
    caller: &str,
    caller_ns: &[String],
    admin: bool,
) {
    let agent_arc = {
        let g = st.agent.lock().await;
        g.as_ref().map(|a| a.clone())
    };
    let Some(agent_arc) = agent_arc else { return };
    let scope = agent_arc.get_meeting(meeting_id).map(|m| m.scope).flatten();
    let personas = agent_arc.list_personas_scoped(scope.as_deref());
    let hits = parse_mentions(content, &personas);
    for pid in hits {
        let st2 = st.clone();
        let mid = meeting_id.to_string();
        let caller2 = caller.to_string();
        let ns2 = caller_ns.to_vec();
        tokio::spawn(async move {
            match ask_persona_flow(&st2, &mid, &pid, "有人 @ 了你，请就议题发表你的看法", &caller2, &ns2, admin).await {
                Ok(_) => {
                    tracing::info!(meeting = %mid, persona = %pid, "@提及已触发分身应答");
                }
                Err((code, e)) => {
                    tracing::warn!(meeting = %mid, persona = %pid, code = %code,
                        "@提及触发分身应答失败: {}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona(pid: &str, name: &str) -> agent_core::runtime::self_runtime::Persona {
        agent_core::runtime::self_runtime::Persona {
            persona_id: pid.to_string(),
            display_name: name.to_string(),
            owner_user_id: "tester".to_string(),
            workspace_dir: None,
            tool_allowlist: Vec::new(),
            memory_namespace: format!("agent/tester_{}", pid),
            badge_token: String::new(),
            ns_full_path: None,
            llm: None,
            is_private: false,
        }
    }

    #[test]
    fn parse_mentions_matches_persona_id_and_display_name() {
        let ps = vec![persona("p1", "运行主任"), persona("p2", "环保工程师")];
        assert_eq!(parse_mentions("请 @p1 表态", &ps), vec!["p1"]);
        assert_eq!(parse_mentions("@环保工程师 怎么看？", &ps), vec!["p2"]);
        // 两条 @ 都命中，按长标签优先返回
        assert_eq!(parse_mentions("@p1 @环保工程师 都说说", &ps), vec!["p2", "p1"]);
        // 未 @ 任何分身 → 空（AI 默认不抢话）
        assert!(parse_mentions("普通发言，没有点名", &ps).is_empty());
    }

    #[test]
    fn parse_mentions_longest_label_wins_on_prefix_overlap() {
        let ps = vec![persona("p1", "运营总监"), persona("p2", "运营总监助理")];
        // @运营总监助理 应命中 p2，不被 p1 的前缀截胡（长标签优先）
        assert_eq!(parse_mentions("@运营总监助理 请答复", &ps), vec!["p2"]);
        assert_eq!(parse_mentions("@运营总监 请答复", &ps), vec!["p1"]);
    }

    #[test]
    fn parse_mentions_dedups_id_and_name_hit() {
        let ps = vec![persona("p1", "运行主任")];
        // 同一分身被 id 和显示名同时点名只应答一次
        assert_eq!(parse_mentions("@p1 @运行主任 都说说", &ps), vec!["p1"]);
    }

    #[test]
    fn ask_cooldown_blocks_second_call_within_window() {
        // 注意：测试进程内共享静态表，key 用独立 meeting/persona 避免与其他测试互扰
        let m = "meeting-cd-test";
        let p = "persona-cd-test";
        assert!(ask_cooldown_ok(m, p), "首次点名应放行");
        assert!(!ask_cooldown_ok(m, p), "10s 窗口内第二次点名应被拒");
        assert!(ask_cooldown_ok(m, "persona-other"), "其他分身不受影响");
    }
}
