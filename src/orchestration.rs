//! LLM 编排层 v2（ADR-017）—— Flash 锚定引导 + Plan-Act-Reflect 基础设施。
//!
//! 安全纪律（与 ADR-017 一致）：
//! - **全部默认 OFF**；`[orchestration]` 任一开关关闭时，热路径零行为变化。
//! - bootstrap 只对 easy/flash 路由 + 非写意图 + 未 promoted 会话生效；
//!   危险/写工具永不进入 bootstrap 工具面。
//! - 故障方向永远向「可用」降级：存储失败 → 内存模式；工具选择失败 → 空工具面
//!   （LLM 先诚实作答，promote 后下一请求恢复全量目录）。
//!
//! 本模块只放纯逻辑与状态；热路径接线在 `agent.rs::llm_loop`。

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::llm::{Message, ToolDef};

// ── 配置 ────────────────────────────────────────────────────────────────

fn default_bootstrap_max_tokens() -> u32 {
    1024
}

fn default_bootstrap_max_tools() -> usize {
    3
}

fn default_max_reflect_rounds() -> usize {
    2
}

fn default_summary_threshold_chars() -> usize {
    8192
}

fn default_summary_start_round() -> usize {
    4
}

fn default_max_concurrent_reads() -> usize {
    4
}

/// Flash 锚定引导（ADR-017 §1）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// 总开关，默认 false。开启后仅 easy/flash 路由 + 非写意图 + 未 promoted 会话生效。
    #[serde(default)]
    pub enabled: bool,
    /// 首个请求的输出预算（社区实测 1024 锚定 flash 轨迹；promote 后恢复配置值）。
    #[serde(default = "default_bootstrap_max_tokens")]
    pub max_tokens: u32,
    /// bootstrap 工具面上限（按意图相关性取前 N 个；写/危险工具被硬排除）。
    #[serde(default = "default_bootstrap_max_tools")]
    pub max_tools: usize,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        BootstrapConfig {
            enabled: false,
            max_tokens: default_bootstrap_max_tokens(),
            max_tools: default_bootstrap_max_tools(),
        }
    }
}

/// Plan-Act-Reflect（ADR-017 §2）。P2 骨架：开关与参数先落地，状态机接线在 agent 层。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanReflectConfig {
    /// 总开关，默认 false。
    #[serde(default)]
    pub enabled: bool,
    /// Reflect 未达成时允许的重规划次数（含首次 reflect 判定）。
    #[serde(default = "default_max_reflect_rounds")]
    pub max_reflect_rounds: usize,
}

impl Default for PlanReflectConfig {
    fn default() -> Self {
        PlanReflectConfig {
            enabled: false,
            max_reflect_rounds: default_max_reflect_rounds(),
        }
    }
}

/// 工具结果 LLM 摘要（ADR-017 §4）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSummaryConfig {
    /// 总开关，默认 false；关闭时保持现有截断行为。
    #[serde(default)]
    pub enabled: bool,
    /// 单条工具结果超过该字符数才触发摘要。
    #[serde(default = "default_summary_threshold_chars")]
    pub threshold_chars: usize,
    /// 从第几轮起对所有工具结果摘要（防长会话上下文膨胀）。
    #[serde(default = "default_summary_start_round")]
    pub start_round: usize,
}

impl Default for ToolSummaryConfig {
    fn default() -> Self {
        ToolSummaryConfig {
            enabled: false,
            threshold_chars: default_summary_threshold_chars(),
            start_round: default_summary_start_round(),
        }
    }
}

/// 同轮 read 工具并行（ADR-017 §4）。写/dangerous 永远串行，不受此开关影响。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadParallelConfig {
    /// 总开关，默认 false。
    #[serde(default)]
    pub enabled: bool,
    /// 同轮并发上限。
    #[serde(default = "default_max_concurrent_reads")]
    pub max_concurrent: usize,
}

impl Default for ReadParallelConfig {
    fn default() -> Self {
        ReadParallelConfig {
            enabled: false,
            max_concurrent: default_max_concurrent_reads(),
        }
    }
}

/// 编排层总配置（agent.toml `[orchestration]`，缺省全默认 = 全 OFF）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrchestrationConfig {
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
    #[serde(default)]
    pub plan_reflect: PlanReflectConfig,
    #[serde(default)]
    pub tool_summary: ToolSummaryConfig,
    #[serde(default)]
    pub read_parallel: ReadParallelConfig,
}

// ── Session 相位存储 ────────────────────────────────────────────────────

/// session → promoted 的持久化真相源（挂 harness.db，append-only，不退档）。
pub struct SessionPhaseStore {
    conn: Option<Arc<Mutex<rusqlite::Connection>>>,
}

impl SessionPhaseStore {
    /// 打开（或创建）harness.db 中的 `orchestration_phase` 表。
    /// 任何失败都降级为内存模式（可用性优先，ADR-017 §1 降级安全）。
    pub fn open(db_path: &str) -> Self {
        match rusqlite::Connection::open(db_path) {
            Ok(conn) => {
                let created = conn
                    .execute_batch(
                        "CREATE TABLE IF NOT EXISTS orchestration_phase (
                             session_id TEXT PRIMARY KEY,
                             phase      TEXT NOT NULL,
                             updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                         );",
                    )
                    .is_ok();
                if created {
                    Self {
                        conn: Some(Arc::new(Mutex::new(conn))),
                    }
                } else {
                    tracing::warn!(target = "orchestration", db = %db_path,
                        "orchestration_phase 表创建失败，phase 存储降级为内存模式");
                    Self { conn: None }
                }
            }
            Err(e) => {
                tracing::warn!(target = "orchestration", db = %db_path, err = %e,
                    "harness.db 打开失败，phase 存储降级为内存模式");
                Self { conn: None }
            }
        }
    }

    /// 纯内存实例（单测 / 降级路径）。
    pub fn new_in_memory() -> Self {
        match rusqlite::Connection::open_in_memory() {
            Ok(conn) => {
                let _ = conn.execute_batch(
                    "CREATE TABLE orchestration_phase (
                         session_id TEXT PRIMARY KEY,
                         phase      TEXT NOT NULL,
                         updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                     );",
                );
                Self {
                    conn: Some(Arc::new(Mutex::new(conn))),
                }
            }
            Err(_) => Self { conn: None },
        }
    }

    pub fn is_promoted(&self, session_id: &str) -> bool {
        let Some(conn) = &self.conn else {
            return false;
        };
        let Ok(guard) = conn.lock() else {
            return false;
        };
        guard
            .query_row(
                "SELECT phase FROM orchestration_phase WHERE session_id=?1",
                rusqlite::params![session_id],
                |row| row.get::<_, String>(0),
            )
            .map(|phase| phase == "promoted")
            .unwrap_or(false)
    }

    /// 标记 promoted（INSERT OR IGNORE：append-only 幂等）。失败只告警，不阻断主流程。
    pub fn promote(&self, session_id: &str) -> bool {
        let Some(conn) = &self.conn else {
            return false;
        };
        let Ok(guard) = conn.lock() else {
            return false;
        };
        match guard.execute(
            "INSERT OR IGNORE INTO orchestration_phase (session_id, phase) VALUES (?1, 'promoted')",
            rusqlite::params![session_id],
        ) {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(target = "orchestration", session = %session_id, err = %e,
                    "promote 落盘失败（内存缓存仍生效，重启后该会话会重新 bootstrap）");
                false
            }
        }
    }
}

// ── 控制器 ──────────────────────────────────────────────────────────────

pub struct OrchestrationController {
    pub cfg: OrchestrationConfig,
    store: SessionPhaseStore,
    /// 进程内缓存：promote 是 append-only，缓存命中即真。
    promoted_cache: Mutex<HashSet<String>>,
    /// guardrail hooks（ADR-017 P2）。默认注册旧补丁的等价内置 hooks。
    hooks: HookRegistry,
}

impl OrchestrationController {
    pub fn new(cfg: OrchestrationConfig) -> Self {
        let cwd = std::env::current_dir().unwrap_or_default();
        let store = SessionPhaseStore::open(&cwd.join("harness.db").to_string_lossy());
        let hooks = HookRegistry::default();
        register_builtin_hooks(&hooks);
        OrchestrationController {
            cfg,
            store,
            promoted_cache: Mutex::new(HashSet::new()),
            hooks,
        }
    }

    #[cfg(test)]
    pub fn new_with_store(cfg: OrchestrationConfig, store: SessionPhaseStore) -> Self {
        let hooks = HookRegistry::default();
        register_builtin_hooks(&hooks);
        OrchestrationController {
            cfg,
            store,
            promoted_cache: Mutex::new(HashSet::new()),
            hooks,
        }
    }

    /// 扩展点：注册外部 guardrail hook（领域模块自注册用）。
    pub fn register_hook(&self, hook: std::sync::Arc<dyn OrchestrationHook>) {
        self.hooks.register(hook);
    }

    /// 执行某挂载点的全部 hooks（priority 升序，Abort 优先裁决）。
    pub fn run_hooks(&self, point: HookPoint, ctx: &HookContext) -> HookAction {
        self.hooks.run(point, ctx)
    }

    pub fn is_promoted(&self, session_id: &str) -> bool {
        {
            let Ok(cache) = self.promoted_cache.lock() else {
                return false;
            };
            if cache.contains(session_id) {
                return true;
            }
        }
        let promoted = self.store.is_promoted(session_id);
        if promoted {
            if let Ok(mut cache) = self.promoted_cache.lock() {
                cache.insert(session_id.to_string());
            }
        }
        promoted
    }

    pub fn promote(&self, session_id: &str) {
        if let Ok(mut cache) = self.promoted_cache.lock() {
            cache.insert(session_id.to_string());
        }
        self.store.promote(session_id);
    }

    /// 构造 bootstrap 工具面：按意图相关性取前 `max_tools` 个，写/危险工具硬排除。
    /// 无安全候选时返回空（LLM 先诚实作答；promote 后下一请求恢复全量目录）。
    pub fn bootstrap_tools(&self, _raw_message: &str, full_tools: &[ToolDef]) -> Vec<ToolDef> {
        let max = self.cfg.bootstrap.max_tools.max(1);
        let mut scored: Vec<(i32, usize, &ToolDef)> = full_tools
            .iter()
            .enumerate()
            .map(|(idx, tool)| (bootstrap_tool_score(&tool.function.name), idx, tool))
            .collect();
        // 稳定排序：分值降序、原顺序保持
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored
            .into_iter()
            .filter(|(score, _, _)| *score > BOOTSTRAP_DENY_SCORE)
            .take(max)
            .map(|(_, _, tool)| tool.clone())
            .collect()
    }
}

const BOOTSTRAP_DENY_SCORE: i32 = -1000;

/// 工具名打分：意图相关查询工具优先；写/危险/治理类工具一律 DENY（永不过 bootstrap 面）。
fn bootstrap_tool_score(name: &str) -> i32 {
    let n = name.to_ascii_lowercase();
    const DENY_SUBSTR: &[&str] = &[
        "write", "delete", "remove", "sync", "commit", "archive", "register", "login",
        "kill", "shutdown", "revoke", "batch_delete", "merge", "evolve", "repair",
        "respond", "send", "approval", "reboot", "restart",
    ];
    if DENY_SUBSTR.iter().any(|d| n.contains(d)) {
        return BOOTSTRAP_DENY_SCORE;
    }
    let score = if n.contains("query") {
        10
    } else if n.contains("get") {
        9
    } else if n.contains("search") || n.contains("find") {
        8
    } else if n.contains("read") || n.contains("list") || n.contains("stat") {
        6
    } else if n.contains("sql") || n.contains("plate") || n.contains("fuzzy") {
        5
    } else if n.contains("health") || n.contains("status") {
        4
    } else {
        1
    };
    score
}

// ── P2/P3 基础设施（默认 OFF，接线由 agent 层分阶段完成）─────────────────

/// 工具失败三分类（ADR-017 §6）。纯函数，供 execute_tool_calls 接线时使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// schema 校验失败 / 超时一次重试：回灌修正后重试
    Retryable,
    /// 近似匹配失败 / 源 unhealthy：换相近工具或降级路径
    Recoverable,
    /// 边界拒绝 / 审批拒绝 / 配额 / killswitch：立即中止或诚实报错
    Fatal,
}

/// 从错误文本做保守分类。默认 Recoverable（宁可多走降级，不把 fatal 误判成重试）。
pub fn classify_tool_failure(error: &str) -> FailureClass {
    let e = error.to_ascii_lowercase();
    if e.contains("schema") || e.contains("参数") || e.contains("invalid") || e.contains("timeout") {
        FailureClass::Retryable
    } else if e.contains("红线")
        || e.contains("审批")
        || e.contains("配额")
        || e.contains("kill switch")
        || e.contains("拒绝")
        || e.contains("unauthorized")
        || e.contains("forbidden")
    {
        FailureClass::Fatal
    } else {
        FailureClass::Recoverable
    }
}

/// guardrail hook 挂载点（ADR-017 §3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPoint {
    OnBootstrap,
    OnPromote,
    OnPrePlan,
    OnPlan,
    OnPreAct,
    OnToolResult,
    OnFinalAnswer,
}

/// hook 对编排循环的裁决。
#[derive(Debug, Clone)]
pub enum HookAction {
    Continue,
    Inject { messages: Vec<Message> },
    /// 重试：注入消息后回到循环顶部（等价于旧补丁的 push + continue）
    Retry { messages: Vec<Message> },
    Abort { reply: String },
}

/// guardrail hook 接口（P2：核心循环只遍历注册表，不 import 领域模块）。
pub trait OrchestrationHook: Send + Sync {
    fn point(&self) -> HookPoint;
    fn priority(&self) -> i32 {
        0
    }
    fn run(&self, _ctx: &HookContext) -> HookAction {
        HookAction::Continue
    }
}

/// hook 上下文（只读快照，避免 hook 直接改循环内部状态）。
pub struct HookContext<'a> {
    pub session_id: &'a str,
    pub raw_message: &'a str,
    pub trace_id: &'a str,
    pub messages: &'a [Message],
    pub executed_tools: &'a [String],
    pub did_work: bool,
    /// 意图分类结果（重构阶段3 的 Intent.data_query）
    pub data_query: bool,
    /// 附件豁免（对齐旧补丁的 intent.attachment 判断）
    pub attachment: bool,
    /// 快速通道已注入数据（对齐旧补丁的 fast_path_data 判断）
    pub fast_path_data: bool,
    /// 当前轮次（0-based，对齐旧补丁的 _round）
    pub round: u32,
    /// 轮数上限语义与旧补丁一致：`self.config.max_tool_rounds`（非 Easy 局部 3 轮上限）
    pub hard_max_rounds: u32,
    /// 待裁决的候选终答（OnFinalAnswer 专用；其他挂载点为 None）
    pub candidate_reply: Option<&'a str>,
}

/// 内置 guardrail hook 注册表。核心循环只依赖 `run_hooks`，不感知具体 hook。
pub struct HookRegistry {
    hooks: Mutex<Vec<std::sync::Arc<dyn OrchestrationHook>>>,
}

impl Default for HookRegistry {
    fn default() -> Self {
        HookRegistry {
            hooks: Mutex::new(Vec::new()),
        }
    }
}

impl HookRegistry {
    pub fn register(&self, hook: std::sync::Arc<dyn OrchestrationHook>) {
        if let Ok(mut hooks) = self.hooks.lock() {
            hooks.push(hook);
        }
    }

    /// 按 priority 升序执行同挂载点的 hooks，合并裁决：
    /// Abort 优先；否则首个 Retry；否则合并 Inject；否则 Continue。
    pub fn run(&self, point: HookPoint, ctx: &HookContext) -> HookAction {
        let snapshot: Vec<std::sync::Arc<dyn OrchestrationHook>> = {
            let Ok(guard) = self.hooks.lock() else {
                return HookAction::Continue;
            };
            let mut v: Vec<_> = guard.iter().filter(|h| h.point() == point).cloned().collect();
            v.sort_by_key(|h| h.priority());
            v
        };
        let mut injected: Vec<Message> = Vec::new();
        let mut retry: Option<HookAction> = None;
        for hook in snapshot {
            match hook.run(ctx) {
                HookAction::Abort { reply } => return HookAction::Abort { reply },
                HookAction::Retry { messages } => {
                    if retry.is_none() {
                        retry = Some(HookAction::Retry { messages });
                    }
                }
                HookAction::Inject { messages } => injected.extend(messages),
                HookAction::Continue => {}
            }
        }
        if let Some(r) = retry {
            r
        } else if injected.is_empty() {
            HookAction::Continue
        } else {
            HookAction::Inject { messages: injected }
        }
    }
}

// ── 内置 hooks（从 llm_loop 旧补丁迁移而来，行为逐字等价）────────────────

/// 迁移自旧补丁：业务数据意图 + 未取证 → 首轮前强制工具提示。
/// 附件豁免与快速通道豁免与旧判断一致。
struct DataQueryForceToolHook;

impl OrchestrationHook for DataQueryForceToolHook {
    fn point(&self) -> HookPoint {
        HookPoint::OnPreAct
    }
    fn priority(&self) -> i32 {
        100
    }
    fn run(&self, ctx: &HookContext) -> HookAction {
        if !ctx.data_query || ctx.attachment || ctx.fast_path_data {
            return HookAction::Continue;
        }
        HookAction::Inject {
            messages: vec![Message {
                role: "system".to_string(),
                content: Some(
                    "你正在处理一个业务数据查询（如进厂/车次/重量/白名单/固废种类等）。\
                     你必须先调用数据查询工具（query_* / nl_query / get_* / execute_sql）获取真实数据，\
                     再基于工具结果回答。禁止第一轮空手回答或凭记忆编造。"
                        .to_string(),
                ),
                tool_calls: None,
                tool_call_id: None,
            }],
        }
    }
}

/// 迁移自旧补丁：终答 JSON/代码块泄漏 → 注入「自然语言重写」重试一轮。
/// 末轮仍泄漏 → Continue（由 chat 出口的 reply_polish 包裹兜底），与旧逻辑一致。
struct ReplyPolishRetryHook;

impl OrchestrationHook for ReplyPolishRetryHook {
    fn point(&self) -> HookPoint {
        HookPoint::OnFinalAnswer
    }
    fn priority(&self) -> i32 {
        50
    }
    fn run(&self, ctx: &HookContext) -> HookAction {
        let Some(reply) = ctx.candidate_reply else {
            return HookAction::Continue;
        };
        if !crate::reply_polish::needs_polish(reply)
            || ctx.round.saturating_add(1) >= ctx.hard_max_rounds
        {
            return HookAction::Continue;
        }
        HookAction::Retry {
            messages: vec![Message {
                role: "user".to_string(),
                content: Some(
                    "⚠️ 请用自然语言重写你刚才的回答：不要输出 JSON 或代码块，直接把结果用中文文字、数字和表格描述清楚。"
                        .to_string(),
                ),
                tool_calls: None,
                tool_call_id: None,
            }],
        }
    }
}

/// 注册内置 hooks（llm_loop 旧补丁的等价物）。始终注册：hook 只在核心循环
/// 的对应挂载点执行，行为与迁移前的内联补丁逐字一致。
pub(crate) fn register_builtin_hooks(registry: &HookRegistry) {
    registry.register(std::sync::Arc::new(DataQueryForceToolHook));
    registry.register(std::sync::Arc::new(ReplyPolishRetryHook));
}

/// ADR-017 §5：统一 TurnBudget —— 把轮次上限与日 token 预算封装为单一查询接口。
/// 语义与原 `llm_loop` 的两处独立检查完全一致（同一 `NsQuotaStore` 调用），
/// 仅把「循环中只有一处检查」收口到本结构。
pub struct TurnBudget {
    ns: String,
    quota: std::sync::Arc<std::sync::Mutex<crate::quota::NsQuotaStore>>,
    max_rounds: u32,
}

impl TurnBudget {
    pub fn new(
        ns: &str,
        quota: std::sync::Arc<std::sync::Mutex<crate::quota::NsQuotaStore>>,
        max_rounds: u32,
    ) -> Self {
        TurnBudget {
            ns: ns.to_string(),
            quota,
            max_rounds,
        }
    }

    pub fn max_rounds(&self) -> u32 {
        self.max_rounds
    }

    /// 日 token 预算预估检查（等价原 quota.check_token_budget 调用）。
    pub fn check_token(&self, additional: u64) -> Result<(), String> {
        let mut store = self.quota.lock().unwrap_or_else(|p| p.into_inner());
        store.check_token_budget(&self.ns, additional)
    }

    /// 记录本次消耗（等价原 quota.record_token 调用）。
    pub fn record_token(&self, tokens: u64) {
        let mut store = self.quota.lock().unwrap_or_else(|p| p.into_inner());
        store.record_token(&self.ns, tokens);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(name: &str) -> ToolDef {
        ToolDef {
            type_: "function".to_string(),
            function: crate::llm::ToolDefFunction {
                name: name.to_string(),
                description: String::new(),
                parameters: json!({"type":"object"}),
            },
        }
    }

    #[test]
    fn defaults_are_all_off() {
        let cfg = OrchestrationConfig::default();
        assert!(!cfg.bootstrap.enabled);
        assert!(!cfg.plan_reflect.enabled);
        assert!(!cfg.tool_summary.enabled);
        assert!(!cfg.read_parallel.enabled);
        assert_eq!(cfg.bootstrap.max_tokens, 1024);
        assert_eq!(cfg.bootstrap.max_tools, 3);
    }

    #[test]
    fn bootstrap_picks_query_tools_and_denies_writes() {
        let cfg = OrchestrationConfig::default();
        let ctrl = OrchestrationController::new_with_store(cfg, SessionPhaseStore::new_in_memory());
        let full = vec![
            tool("query_entrance"),
            tool("get_vehicle"),
            tool("cw_write"),
            tool("repo_ws_write"),
            tool("execute_sql"),
            tool("read_doc"),
        ];
        let picked = ctrl.bootstrap_tools("查进厂记录", &full);
        let names: Vec<&str> = picked.iter().map(|t| t.function.name.as_str()).collect();
        assert_eq!(picked.len(), 3);
        assert!(names.contains(&"query_entrance"));
        assert!(names.contains(&"get_vehicle"));
        assert!(!names.iter().any(|n| n.contains("write")));
    }

    #[test]
    fn bootstrap_empty_when_all_denied() {
        let cfg = OrchestrationConfig::default();
        let ctrl = OrchestrationController::new_with_store(cfg, SessionPhaseStore::new_in_memory());
        let full = vec![tool("cw_write"), tool("repo_ws_write")];
        assert!(ctrl.bootstrap_tools("x", &full).is_empty());
    }

    #[test]
    fn phase_store_promote_is_idempotent_and_persistent() {
        let store = SessionPhaseStore::new_in_memory();
        assert!(!store.is_promoted("s1"));
        assert!(store.promote("s1"));
        assert!(store.is_promoted("s1"));
        assert!(store.promote("s1")); // idempotent
        assert!(store.is_promoted("s1"));
        assert!(!store.is_promoted("s2"));
    }

    #[test]
    fn failure_classification_is_conservative() {
        assert_eq!(classify_tool_failure("参数 schema 校验失败"), FailureClass::Retryable);
        assert_eq!(classify_tool_failure("timeout"), FailureClass::Retryable);
        assert_eq!(classify_tool_failure("红线：治理层不可修改"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("配额超限"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("some mcp error"), FailureClass::Recoverable);
    }

    fn hook_ctx<'a>(
        data_query: bool,
        attachment: bool,
        fast_path: bool,
        round: u32,
        hard_max: u32,
        reply: Option<&'a str>,
    ) -> HookContext<'a> {
        HookContext {
            session_id: "s",
            raw_message: "查进厂记录",
            trace_id: "t",
            messages: &[],
            executed_tools: &[],
            did_work: false,
            data_query,
            attachment,
            fast_path_data: fast_path,
            round,
            hard_max_rounds: hard_max,
            candidate_reply: reply,
        }
    }

    #[test]
    fn data_query_hook_matches_legacy_patch() {
        let registry = HookRegistry::default();
        register_builtin_hooks(&registry);
        // 命中：注入与旧内联补丁相同文本
        let ctx = hook_ctx(true, false, false, 0, 20, None);
        match registry.run(HookPoint::OnPreAct, &ctx) {
            HookAction::Inject { messages } => {
                assert_eq!(messages.len(), 1);
                assert!(messages[0].content.as_deref().unwrap_or("").contains("必须先调用数据查询工具"));
            }
            other => panic!("expected Inject, got {:?}", other),
        }
        // 附件豁免 / 快速通道豁免 / 非数据意图 → Continue
        assert!(matches!(
            registry.run(HookPoint::OnPreAct, &hook_ctx(true, true, false, 0, 20, None)),
            HookAction::Continue
        ));
        assert!(matches!(
            registry.run(HookPoint::OnPreAct, &hook_ctx(true, false, true, 0, 20, None)),
            HookAction::Continue
        ));
        assert!(matches!(
            registry.run(HookPoint::OnPreAct, &hook_ctx(false, false, false, 0, 20, None)),
            HookAction::Continue
        ));
    }

    #[test]
    fn reply_polish_hook_matches_legacy_patch() {
        let registry = HookRegistry::default();
        register_builtin_hooks(&registry);
        let leaky = "{\"result\": 123}";
        // 未到末轮 + 泄漏 → Retry（与旧内联补丁等价）
        match registry.run(
            HookPoint::OnFinalAnswer,
            &hook_ctx(false, false, false, 0, 20, Some(leaky)),
        ) {
            HookAction::Retry { messages } => {
                assert_eq!(messages.len(), 1);
                assert!(messages[0].content.as_deref().unwrap_or("").contains("自然语言重写"));
            }
            other => panic!("expected Retry, got {:?}", other),
        }
        // 末轮仍泄漏 → Continue（chat 出口 reply_polish 兜底）
        assert!(matches!(
            registry.run(
                HookPoint::OnFinalAnswer,
                &hook_ctx(false, false, false, 19, 20, Some(leaky)),
            ),
            HookAction::Continue
        ));
        // 正常文本 → Continue
        assert!(matches!(
            registry.run(
                HookPoint::OnFinalAnswer,
                &hook_ctx(false, false, false, 0, 20, Some("今天是晴天。")),
            ),
            HookAction::Continue
        ));
    }
}
