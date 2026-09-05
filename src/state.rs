//! 运行时状态层（从 src/main.rs 拆出，P2 重构）。
//!
//! 承载：`AppState`（全局共享状态）、`BackgroundEvent`（多端唤醒事件队列）、
//! `Consciousness`（白龙马 A2 TICK 意识主循环）、dream health 写/回填。
//! 所有字段 `pub(crate)`：供 handlers / main 跨模块访问（纯搬移，零行为变更）。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_core::agent::{AgentCore, MeetingEvent};
use agent_core::metrics::MetricsRegistry;
use agent_core::resources::SharedResourceSnapshot;
use chrono::Local;
use tokio::sync::broadcast;
use tokio::sync::Mutex;

use crate::config::Config;

pub(crate) struct AppState {
    pub(crate) config: Mutex<Config>,
    /// 用 Arc 包装：chat/consolidate 等 handler 克隆 Arc 后立即释放全局锁，
    /// 使 LLM 往返在锁外并发执行（解除单点串行瓶颈）。
    pub(crate) agent: Mutex<Option<Arc<AgentCore>>>,
    #[allow(dead_code)]
    pub(crate) config_path: String,
    /// 身份认证缓存 (agent_id → (badge_token, expires_at))
    /// P2-10 修复：添加 TTL 过期
    pub(crate) auth_cache: tokio::sync::Mutex<HashMap<String, (String, std::time::Instant)>>,
    /// 命名空间授权缓存 agent_id → (allowed_ns, 获取时间)
    /// 仅以 agent_id 为 key（token 已在 Memoria 端验证过，不在内存留存明文 key，P1-1）
    /// 短 TTL（60s）以在「每次请求反查 memoria」的性能与「权限即时生效」间取平衡（R1）
    pub(crate) ns_cache: tokio::sync::Mutex<HashMap<String, (Vec<String>, std::time::Instant)>>,
    /// 协作收件箱「已读游标」：agent_id → 最近一次查看的 ISO 时间（用于未读计数）
    pub(crate) collab_seen: tokio::sync::Mutex<HashMap<String, String>>,
    /// Dream 巩固：上次成功跑完的本地日历日（YYYY-MM-DD），避免 02–05 点巡检重复巩固
    pub(crate) consolidate_last_ymd: tokio::sync::Mutex<String>,
    /// Dream 巩固：最近一次结果摘要（供 /health、/api/admin/consolidate）
    pub(crate) consolidate_last: tokio::sync::Mutex<serde_json::Value>,
    /// 白龙马 A2 TICK 心跳句柄（用户消息到达时 interrupt 抢占在途 tick）
    pub(crate) consciousness: tokio::sync::Mutex<Option<Arc<Consciousness>>>,
    /// 白龙马 Phase B A4: consolidation round-robin 游标（内存态，v1 不持久化，对齐白龙马游标）
    pub(crate) consolidate_cursor: tokio::sync::Mutex<usize>,
    /// 白龙马 Phase B: 多端唤醒 —— 后台活动事件队列（供 PFAiX 轮询拉取"唤醒"）
    pub(crate) background_events: tokio::sync::Mutex<VecDeque<BackgroundEvent>>,
    /// 白龙马 Phase C: 条件式本地资源门控 —— 启动扫描的只读资源快照句柄（与 AgentCore 共享）
    pub(crate) local_resources: SharedResourceSnapshot,
    /// 白龙马 Phase B: 事件自增 id
    pub(crate) next_event_id: AtomicU64,
    /// Phase 7：进化回路并发守卫（true=正在跑 /api/evolve，防止多请求并发覆盖隔离仓库）
    pub(crate) evolve_running: AtomicBool,
    /// 战略罗盘「可观测」：运行指标注册表（与 AgentCore 共享同一 Arc，供 /api/metrics 暴露）
    pub(crate) metrics: Arc<MetricsRegistry>,
    /// Step3：会议实时事件广播中枢（所有 SSE 订阅者从此订阅，按 meeting_id 过滤）
    // 每会议独立 broadcast 通道：避免单通道下单个繁忙会议的事件洪流唤醒所有会议的所有订阅者
    // （全局单通道会让无关订阅者被反复唤醒、落后 256 缓冲触发 Lagged、进而整会克隆 + 序列化，
    // 造成跨会议吞吐/延迟耦合与 agent 锁竞争）。通道仅在订阅时按需创建、SSE 任务结束时回收。
    pub(crate) meeting_tx: tokio::sync::Mutex<HashMap<String, broadcast::Sender<MeetingEvent>>>,
    /// Step3：会议在线表 meeting_id → (agent_id → 最近心跳 Instant)
    pub(crate) meeting_presence:
        tokio::sync::Mutex<HashMap<String, HashMap<String, std::time::Instant>>>,
}

/// 白龙马 Phase B：多端唤醒 —— 后台活动事件（心跳自主产生的活动，供 PFAiX 拉取"唤醒"）
/// 采用拉模型：agent-core 单方面维护队列 + 暴露 /api/agent/events，不依赖 PFAiX 改代码。
#[derive(Clone, serde::Serialize)]
pub(crate) struct BackgroundEvent {
    pub(crate) id: u64,
    pub(crate) ts: String,
    pub(crate) kind: String, // "consolidate" | "prefetch"
    pub(crate) summary: String,
}
impl BackgroundEvent {
    pub(crate) fn new(kind: &str, summary: String) -> Self {
        Self {
            id: 0, // 由 emit_event 分配自增 id
            ts: Local::now().to_rfc3339(),
            kind: kind.to_string(),
            summary,
        }
    }
}

/// 白龙马 A2: TICK 意识主循环（心跳 / 抢占 / watchdog）
/// 持有 AppState 以便空闲 tick 访问 Agent；interrupt 由用户消息 handler 触发抢占。
pub(crate) struct Consciousness {
    state: Arc<AppState>,
    interrupt: Arc<tokio::sync::Notify>,
    /// 白龙马 A2 深化：最近一次用户活动 unix 秒（interrupt 时刷新），驱动自适应 TICK 节奏。
    /// 用 AtomicU64 避免 Arc<Self> 内部可变性的锁开销（interrupt 与 run 并发访问）。
    last_activity_secs: AtomicU64,
}

/// 读 env 并解析为给定类型，失败/缺失回退 default（仅用于整数类配置）。
pub(crate) fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<T>().ok())
        .unwrap_or(default)
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 写 `/health.dream` 摘要。`touch_ymd=true` 时同步夜间去重游标（manual/nightly）；
/// tick/hydrate 必须 `false`，以免挡住当日低峰 meta_evolution。
pub(crate) async fn record_dream_health(
    state: &AppState,
    trigger: &str,
    results: Vec<serde_json::Value>,
    touch_ymd: bool,
) {
    let now_local = Local::now();
    let ymd = now_local.format("%Y-%m-%d").to_string();
    let summary = serde_json::json!({
        "status": "ok",
        "trigger": trigger,
        "ymd": ymd,
        "at": now_local.to_rfc3339(),
        "results": results,
    });
    if touch_ymd {
        *state.consolidate_last_ymd.lock().await = ymd;
    }
    *state.consolidate_last.lock().await = summary;
}

/// 启动时从 Memoria dream_state 回填 health（仅当仍为 never）。
pub(crate) async fn hydrate_dream_health_from_memoria(state: &AppState) {
    let still_never = {
        let g = state.consolidate_last.lock().await;
        g.get("status").and_then(|s| s.as_str()) == Some("never")
    };
    if !still_never {
        return;
    }
    let guard = state.agent.lock().await;
    let Some(agent) = guard.as_ref() else { return };
    let default_ns = format!("agent/{}", agent.config.identity.agent_id);
    let ns_list: Vec<String> = std::env::var("CONSOLIDATE_NAMESPACES")
        .unwrap_or_else(|_| default_ns.clone())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut results = Vec::new();
    for ns in &ns_list {
        match agent.peek_dream_consolidate(ns).await {
            Some(v) => {
                results.push(serde_json::json!({
                    "ns": ns,
                    "last_run": v.get("last_run").cloned().unwrap_or(serde_json::Value::Null),
                    "cursor_ts": v.get("cursor_ts").cloned().unwrap_or(serde_json::Value::Null),
                    "runs": v.get("runs").cloned().unwrap_or(serde_json::Value::Null),
                }));
            }
            None => {
                results.push(serde_json::json!({"ns": ns, "error": "dream_state_get failed"}));
            }
        }
    }
    drop(guard);
    if results.iter().any(|r| r.get("last_run").is_some()) {
        tracing::info!(target: "consciousness", "hydrate /health.dream from memoria dream_state");
        record_dream_health(state, "hydrate", results, false).await;
    }
}

impl Consciousness {
    pub(crate) fn new(state: Arc<AppState>) -> Arc<Self> {
        Arc::new(Self {
            state,
            interrupt: Arc::new(tokio::sync::Notify::new()),
            last_activity_secs: AtomicU64::new(now_unix_secs()),
        })
    }

    /// 用户消息到达 → 打断在途 tick（等价白龙马 AbortController.abort），并刷新活动时间戳。
    pub(crate) fn interrupt(&self) {
        self.last_activity_secs.store(now_unix_secs(), Ordering::SeqCst);
        self.interrupt.notify_one();
    }

    pub(crate) async fn run(self: Arc<Self>) {
        // 白龙马 A2 深化：自适应节奏（env 可配，默认向后兼容）
        // - AGENT_TICK_IDLE_SEC：无近期活动时空闲节奏（默认 1200s=20min）
        // - AGENT_TICK_ACTIVE_WINDOW_SEC：用户活动窗口（默认 600s）；窗口内下一跳缩到 min(idle, 120s)
        // - AGENT_TICK_BOOTSTRAP_SEC：启动后首跳（默认 15s），让 dream health 尽快离开 never
        // - 活跃期下限 120s：避免对话密集时 tick 过频挤占响应
        let idle_sec: u64 = env_parse("AGENT_TICK_IDLE_SEC", 1200);
        let active_window_sec: u64 = env_parse("AGENT_TICK_ACTIVE_WINDOW_SEC", 600);
        let bootstrap_sec: u64 = env_parse("AGENT_TICK_BOOTSTRAP_SEC", 15);
        let fast_sec: u64 = 120;
        let mut bootstrapped = false;
        tracing::info!(
            target: "consciousness",
            idle_sec, active_window_sec, fast_sec, bootstrap_sec,
            "consciousness: TICK 循环启动（自适应节奏 / 抢占 / 600s watchdog）"
        );
        loop {
            // 计算下一跳：首跳 bootstrap；其后最近有用户活动 → 加速；否则按 idle 节奏
            let next_sec = if !bootstrapped {
                bootstrapped = true;
                bootstrap_sec.max(1)
            } else {
                let since = now_unix_secs()
                    .saturating_sub(self.last_activity_secs.load(Ordering::SeqCst));
                if since < active_window_sec {
                    idle_sec.min(fast_sec)
                } else {
                    idle_sec
                }
            };
            let sleep = tokio::time::sleep(Duration::from_secs(next_sec));
            tokio::select! {
                _ = self.interrupt.notified() => {
                    tracing::info!("consciousness: 收到抢占信号（用户消息在途），跳过本轮空闲 tick");
                    continue;
                }
                _ = sleep => {}
            }
            let st = self.state.clone();
            let intr = self.interrupt.clone();
            let wd = tokio::time::timeout(Duration::from_secs(600), async move {
                tokio::select! {
                    _ = intr.notified() => {
                        tracing::info!("consciousness: tick 工作进行中被抢占，终止");
                    }
                    _ = Consciousness::tick_once(&st) => {}
                }
            })
            .await;
            if wd.is_err() {
                tracing::warn!(target: "consciousness_watchdog", "consciousness: 空闲 tick 超时(>600s)被 watchdog 回收");
            }
        }
    }

    async fn tick_once(state: &AppState) {
        // 取 agent 引用（沿用 A2 模式：持锁跨 await 调用 silent 心跳 + A4）
        let guard = state.agent.lock().await;
        let Some(agent) = guard.as_ref() else { return; };

        // 1) 静默心跳（更新内部状态，不回复用户）—— A2 原始语义
        agent.run_idle_tick().await;

        // 2) A4 深化: round-robin consolidation（每 tick 可推进 K 个 namespace）
        let events = Self::consolidate_round_robin(state, agent).await;
        for ev in events {
            Self::emit_event(state, ev).await;
        }

        // 3) 主动预取（深化：默认在线探针；exec 需显式开）
        if let Some(ev) = Self::guarded_prefetch(agent).await {
            Self::emit_event(state, ev).await;
        }

        // Phase 2: 分身真实 tick（复用空闲 tick 循环，每个已注册分身跑一次真实 LLM tick）
        for (pid, line) in agent.persona_tick_all().await {
            tracing::info!(target: "consciousness", "persona tick [{}]: {}", pid, line);
        }
    }

    /// A4 深化: 空闲 tick 推进 K 个 namespace 的 consolidation（round-robin 游标）
    /// 对齐白龙马 consolidation-loop.js：每轮按 `AGENT_CONSOLIDATE_PER_TICK`（默认 1，封顶 ns 数）推进，游标内存态不持久化。
    async fn consolidate_round_robin(
        state: &AppState,
        agent: &AgentCore,
    ) -> Vec<BackgroundEvent> {
        let default_ns = format!("agent/{}", agent.config.identity.agent_id);
        let ns_list: Vec<String> = std::env::var("CONSOLIDATE_NAMESPACES")
            .unwrap_or_else(|_| default_ns.clone())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if ns_list.is_empty() {
            return Vec::new();
        }
        let per_tick: usize = env_parse("AGENT_CONSOLIDATE_PER_TICK", 1).clamp(1, ns_list.len());
        let mut out = Vec::with_capacity(per_tick);
        let mut results_json: Vec<serde_json::Value> = Vec::with_capacity(per_tick);
        for _ in 0..per_tick {
            let idx = {
                let mut c = state.consolidate_cursor.lock().await;
                let i = *c % ns_list.len();
                *c = *c + 1;
                i
            };
            let ns = &ns_list[idx];
            tracing::info!(target: "consciousness", ns = %ns, cursor = idx, "A4: 空闲 tick 推进 consolidation round-robin");
            // 内层预算超时（外层 TICK 已有 600s watchdog），避免单次 consolidate 卡住整轮
            // 420s 覆盖典型批次：主提炼 chat_batch 单次尝试（确定性 ≤300s，ocr PR#70
            // 第二轮：无重试无 failover）+ memoria 拉取/写入往返。evolve 循环
            // 默认跳过（CONSOLIDATE_SKIP_EVOLVE），开启且批次巨大时会被本层
            // 截断——类型化 LlmError 优先于外层超时的不变量由 chat_batch 的
            // 单次尝试语义保证（≤300s < 420s）
            let res = tokio::time::timeout(Duration::from_secs(420), agent.consolidate(ns)).await;
            match res {
                Ok(outcome) => {
                    // P1-d：BackgroundEvent.summary 改为**结构化 JSON**（patterns_added 等字段
                    // 可被事件消费方直接读取，LLM 人读文本沉入 detail）——不再用一句转述文本
                    // 当事件载荷。
                    let line = outcome.summary_line();
                    tracing::info!(target: "consciousness", "{}", line);
                    results_json.push(serde_json::json!({
                        "ns": outcome.ns, "result": outcome.detail,
                        "status": outcome.status,
                        "patterns_added": outcome.patterns_added,
                        "observations": outcome.observations,
                        "observations_visible": outcome.observations_visible,
                    }));
                    let structured = serde_json::json!({
                        "kind": "consolidate", "ns": outcome.ns,
                        "status": outcome.status,
                        "patterns_added": outcome.patterns_added,
                        "observations": outcome.observations,
                        "observations_visible": outcome.observations_visible,
                        "fetched": outcome.fetched,
                        "cursor": outcome.cursor,
                        "detail": outcome.detail,
                    });
                    out.push(BackgroundEvent::new("consolidate", structured.to_string()));
                }
                Err(_) => {
                    tracing::warn!(target: "consciousness_watchdog", ns = %ns, "A4: consolidate 超时(>300s)跳过");
                    results_json.push(serde_json::json!({"ns": ns, "result": "timeout"}));
                }
            }
        }
        // 回写 /health.dream（不碰 consolidate_last_ymd，避免挡掉夜间 meta_evolution）
        if !results_json.is_empty() {
            record_dream_health(state, "tick", results_json, false).await;
        }
        out
    }

    /// 主动预取实验（深化：默认在线探针）
    /// 对齐白龙马死代码 cron 预热的反面：识别「只读 + 无必填参数」的候选工具并发事件，不预执行业务数据。
    /// 默认开启（AGENT_PRETEST=0/false 才关）；AGENT_PRETEST_EXEC=1 才实际 dummy 调用（默认关）。
    async fn guarded_prefetch(agent: &AgentCore) -> Option<BackgroundEvent> {
        // 深化：默认开启探针；仅 AGENT_PRETEST=0/false 才彻底关闭
        let enabled = std::env::var("AGENT_PRETEST")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        if !enabled {
            return None;
        }
        let allowed_ns: Vec<String> = vec![format!("agent/{}", agent.config.identity.agent_id)];
        let tools = agent.fetch_tools_filtered(&allowed_ns).await;
        // 收集至多 5 个「只读 + 无必填参数」的工具做 liveness probe 候选
        let mut candidates: Vec<String> = tools
            .iter()
            .filter(|t| {
                let name = t.function.name.as_str();
                if !agent_core::boundary::is_read_only_tool(name) {
                    return false;
                }
                let required = t.function.parameters.get("required").and_then(|r| r.as_array());
                match required {
                    None => true,
                    Some(arr) => arr.is_empty(),
                }
            })
            .map(|t| t.function.name.clone())
            .take(5)
            .collect();
        if candidates.is_empty() {
            tracing::info!(target: "consciousness", "guarded_prefetch: 无合适只读候选工具");
            return None;
        }
        let exec = std::env::var("AGENT_PRETEST_EXEC")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !exec {
            let summary = format!(
                "prefetch[probe]: 候选只读工具={}（未实际调用，AGENT_PRETEST_EXEC 未开）",
                candidates.join(", ")
            );
            tracing::info!(target: "consciousness", "{}", summary);
            return Some(BackgroundEvent::new("prefetch", summary));
        }
        // 实际 dummy 调用（仅无副作用的空参 READ 工具），带 60s 预算（取首个候选）
        let tool_name = candidates.remove(0);
        let trace_id = format!("prefetch-{}", Local::now().timestamp());
        let call = tokio::time::timeout(
            Duration::from_secs(60),
            agent.call_tool_routed(
                &tool_name,
                "default",
                &serde_json::json!({}),
                &allowed_ns,
                &trace_id,
            ),
        )
        .await;
        let summary = match call {
            Ok(Ok(out)) => format!("prefetch[exec]: {}=ok ({}B)", tool_name, out.len()),
            Ok(Err(e)) => format!("prefetch[exec]: {}=err: {}", tool_name, e),
            Err(_) => format!("prefetch[exec]: {}=timeout(>60s)", tool_name),
        };
        tracing::info!(target: "consciousness", "{}", summary);
        Some(BackgroundEvent::new("prefetch", summary))
    }

    /// 多端唤醒：把后台活动事件入队（供 PFAiX 轮询 /api/agent/events 拉取"唤醒"）
    async fn emit_event(state: &AppState, mut ev: BackgroundEvent) {
        let id = state.next_event_id.fetch_add(1, Ordering::SeqCst);
        ev.id = id;
        let mut q = state.background_events.lock().await;
        q.push_back(ev);
        while q.len() > 200 {
            q.pop_front();
        }
    }
}
