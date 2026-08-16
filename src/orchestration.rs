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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// 每轮最多摘要几条工具结果（防热路径串行 LLM 调用失控）。
    #[serde(default = "default_summary_max_per_round")]
    pub max_per_round: usize,
}

fn default_summary_max_per_round() -> usize {
    2
}

impl Default for ToolSummaryConfig {
    fn default() -> Self {
        ToolSummaryConfig {
            enabled: false,
            threshold_chars: default_summary_threshold_chars(),
            start_round: default_summary_start_round(),
            max_per_round: default_summary_max_per_round(),
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
                // 与 harness/session 连接并发写同一文件：设 busy_timeout + WAL，
                // 避免默认 0ms 超时下 promote 偶发 database is locked 静默丢持久化
                // （ocr 修复）。失败必须留痕，不能静默吞错。
                if let Err(e) = conn.busy_timeout(std::time::Duration::from_secs(2)) {
                    tracing::warn!(target = "orchestration", db = %db_path, err = %e,
                        "busy_timeout 设置失败");
                }
                if let Err(e) = conn.execute_batch("PRAGMA journal_mode=WAL;") {
                    tracing::warn!(target = "orchestration", db = %db_path, err = %e,
                        "journal_mode=WAL 设置失败");
                }
                match conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS orchestration_phase (
                         session_id TEXT PRIMARY KEY,
                         phase      TEXT NOT NULL,
                         updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                     );",
                ) {
                    Ok(_) => Self {
                        conn: Some(Arc::new(Mutex::new(conn))),
                    },
                    Err(e) => {
                        tracing::warn!(target = "orchestration", db = %db_path, err = %e,
                            "orchestration_phase 表创建失败，phase 存储降级为内存模式");
                        Self { conn: None }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target = "orchestration", db = %db_path, err = %e,
                    "harness.db 打开失败，phase 存储降级为内存模式");
                Self { conn: None }
            }
        }
    }

    /// 纯内存实例（单测 / 降级路径）。建表失败同样降级为无存储。
    pub fn new_in_memory() -> Self {
        match rusqlite::Connection::open_in_memory() {
            Ok(conn) => match conn.execute_batch(
                "CREATE TABLE orchestration_phase (
                     session_id TEXT PRIMARY KEY,
                     phase      TEXT NOT NULL,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );",
            ) {
                Ok(_) => Self {
                    conn: Some(Arc::new(Mutex::new(conn))),
                },
                Err(e) => {
                    tracing::warn!(target = "orchestration", err = %e,
                        "内存 phase 表创建失败");
                    Self { conn: None }
                }
            },
            Err(e) => {
                tracing::warn!(target = "orchestration", err = %e,
                    "内存 SQLite 打开失败，phase 存储降级为无存储");
                Self { conn: None }
            }
        }
    }

    /// 完全禁用（所有编排开关 OFF 时使用：零文件副作用，不建表、不开库）。
    pub fn disabled() -> Self {
        Self { conn: None }
    }

    pub fn is_promoted(&self, session_id: &str) -> bool {
        let Some(conn) = &self.conn else {
            return false;
        };
        let Ok(guard) = conn.lock() else {
            tracing::warn!(target = "orchestration", session = %session_id,
                "phase 存储连接 Mutex 中毒，按未 promoted 处理");
            return false;
        };
        // 每次请求最多走到这里一次（promoted_cache 命中后短路）；busy_timeout 上限 2s。
        // QueryReturnedNoRows 是「未 promoted」的正常负结果，不告警；仅真实 DB 错误告警。
        match rusqlite::OptionalExtension::optional(guard.query_row(
            "SELECT phase FROM orchestration_phase WHERE session_id=?1",
            rusqlite::params![session_id],
            |row| row.get::<_, String>(0),
        )) {
            Ok(Some(phase)) => phase == "promoted",
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(target = "orchestration", session = %session_id, err = %e,
                    "phase 查询失败，按未 promoted 处理（该会话可能重新 bootstrap）");
                false
            }
        }
    }

    /// 标记 promoted（INSERT OR IGNORE：append-only 幂等）。失败只告警，不阻断主流程。
    pub fn promote(&self, session_id: &str) -> bool {
        let Some(conn) = &self.conn else {
            return false;
        };
        let Ok(guard) = conn.lock() else {
            tracing::warn!(target = "orchestration", session = %session_id,
                "phase 存储连接 Mutex 中毒，promote 落盘跳过");
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

/// 进程内 session 集合的 LRU 上限：防止长驻服务中缓存随会话数无限增长。
/// 淘汰只丢缓存（真相在 SessionPhaseStore / 幂等重算），不影响正确性。
const SESSION_SET_CACHE_MAX: usize = 4096;
const NOT_PROMOTED_NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// 有界 LRU session 集合：`contains` 命中不刷新顺序（promote 是 append-only，
/// 无热/冷再排序语义），只保证容量上界。
#[derive(Default)]
struct BoundedSessionSet {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl BoundedSessionSet {
    fn contains(&self, session_id: &str) -> bool {
        self.set.contains(session_id)
    }

    fn insert(&mut self, session_id: &str) {
        if self.set.contains(session_id) {
            return;
        }
        if self.order.len() >= SESSION_SET_CACHE_MAX {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
        let owned = session_id.to_string();
        self.order.push_back(owned.clone());
        self.set.insert(owned);
    }
}

pub struct OrchestrationController {
    pub cfg: OrchestrationConfig,
    store: SessionPhaseStore,
    /// 进程内缓存：promote 是 append-only，缓存命中即真；有界（见
    /// `BoundedSessionSet`），淘汰只丢缓存、真相仍可回查 store。
    promoted_cache: Mutex<BoundedSessionSet>,
    /// bootstrap 首请求的 per-session 原子预留：同一 session 的并发 run
    /// 只有一个能进入最小工具面，其余 run 直接走常规路径。
    /// **必须无界**：这是「进行中」锁而非可重建缓存，误淘汰会重新打开
    /// 并发 bootstrap 窗口；条目在 finish/cancel 时删除，常态不增长。
    bootstrap_in_flight: Mutex<HashSet<String>>,
    /// 未 promoted 负缓存（短 TTL）：避免 bootstrap 竞争失败 / 冷启动期对同一
    /// session 的每次请求都同步回查 SQLite。
    not_promoted_cache: Mutex<HashMap<String, Instant>>,
    /// guardrail hooks（ADR-017 P2）。默认注册旧补丁的等价内置 hooks。
    hooks: HookRegistry,
}

impl OrchestrationController {
    pub fn new(cfg: OrchestrationConfig) -> Self {
        let store = if cfg.bootstrap.enabled {
            let cwd = std::env::current_dir().unwrap_or_default();
            SessionPhaseStore::open(&cwd.join("harness.db").to_string_lossy())
        } else {
            // 全部开关 OFF：零文件副作用（不建表、不开库）
            SessionPhaseStore::disabled()
        };
        let hooks = HookRegistry::default();
        register_builtin_hooks(&hooks);
        OrchestrationController {
            cfg,
            store,
            promoted_cache: Mutex::new(BoundedSessionSet::default()),
            bootstrap_in_flight: Mutex::new(HashSet::new()),
            not_promoted_cache: Mutex::new(HashMap::new()),
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
            promoted_cache: Mutex::new(BoundedSessionSet::default()),
            bootstrap_in_flight: Mutex::new(HashSet::new()),
            not_promoted_cache: Mutex::new(HashMap::new()),
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

    /// 查询 session 是否已 promoted（缓存命中即真；miss 时同步查 SQLite）。
    ///
    /// ⚠️ 异步调用方注意：缓存未命中时这里是同步 rusqlite 查询（std Mutex +
    /// busy_timeout 上限 2s）。bootstrap 开启时每个未命中 session 只在首请求
    /// 走一次该冷路径；若 harness.db 高并发写竞争，后续可把 store 调用迁到
    /// `tokio::task::spawn_blocking`。
    pub fn is_promoted(&self, session_id: &str) -> bool {
        {
            let Ok(cache) = self.promoted_cache.lock() else {
                tracing::warn!(target = "orchestration", session = %session_id,
                    "promoted_cache Mutex 中毒，按未 promoted 处理（会话可能重新 bootstrap）");
                return false;
            };
            if cache.contains(session_id) {
                return true;
            }
        }
        // 短 TTL 负缓存：避免未 promoted session 在竞争失败/冷启动期重复同步查库
        if let Ok(negative) = self.not_promoted_cache.lock() {
            if let Some(at) = negative.get(session_id) {
                if at.elapsed() < NOT_PROMOTED_NEGATIVE_TTL {
                    return false;
                }
            }
        }
        let promoted = self.store.is_promoted(session_id);
        if promoted {
            if let Ok(mut cache) = self.promoted_cache.lock() {
                cache.insert(session_id);
            } else {
                tracing::warn!(target = "orchestration", session = %session_id,
                    "promoted_cache Mutex 中毒，命中结果未写入缓存");
            }
            if let Ok(mut negative) = self.not_promoted_cache.lock() {
                negative.remove(session_id);
            }
        } else if let Ok(mut negative) = self.not_promoted_cache.lock() {
            negative.insert(session_id.to_string(), Instant::now());
        }
        promoted
    }

    /// 原子 compare-and-set：首次标记者返回 true，后续调用返回 false。
    /// 与 `promote` 一样 append-only；用于消除同 session 并发 run 的
    /// check-then-promote 窗口。
    ///
    /// ⚠️ 返回值语义：**仅表示本进程内存 CAS 是否赢**，不表示落盘持久化成功。
    /// 落盘失败由 `store.promote` 内部告警并降级为「重启后该 session 重新 bootstrap」。
    pub fn try_promote(&self, session_id: &str) -> bool {
        let won = {
            let Ok(mut cache) = self.promoted_cache.lock() else {
                tracing::warn!(target = "orchestration", session = %session_id,
                    "promoted_cache Mutex 中毒，promote 跳过（不阻塞主流程）");
                return false;
            };
            if cache.contains(session_id) {
                false
            } else {
                cache.insert(session_id);
                true
            }
        };
        if won {
            self.store.promote(session_id);
            if let Ok(mut negative) = self.not_promoted_cache.lock() {
                negative.remove(session_id);
            }
        }
        won
    }

    pub fn promote(&self, session_id: &str) {
        self.try_promote(session_id);
    }

    /// 尝试预留本 session 的 bootstrap 首请求（per-session 原子闸）。
    /// 仅当 session 未 promoted、也没有其他 run 正在 bootstrap 时成功。
    /// 调用方必须在首个 LLM 响应后 `finish_bootstrap`（成功）或
    /// `cancel_bootstrap`（失败/提前返回），防止预留泄漏。
    ///
    /// 锁策略：只把 in-flight 集合的查重+插入放在临界区，**不持锁查 SQLite**——
    /// 否则单 session 的 promoted 落盘查询（busy_timeout 最多 2s）会阻塞全部
    /// session 的 bootstrap 决策。先拿下预留，再到锁外复核 promoted；若复核为
    /// 已 promoted（例如其他进程刚写入），释放预留并返回 false。
    pub fn try_begin_bootstrap(&self, session_id: &str) -> bool {
        {
            let Ok(mut in_flight) = self.bootstrap_in_flight.lock() else {
                tracing::warn!(target = "orchestration", session = %session_id,
                    "bootstrap_in_flight Mutex 中毒，本次不进入 bootstrap");
                return false;
            };
            if in_flight.contains(session_id) {
                return false;
            }
            in_flight.insert(session_id.to_string());
        }
        // 锁外复核 promoted：预留已原子持有，同 session 并发 run 已拿不到第二张票。
        if self.is_promoted(session_id) {
            self.cancel_bootstrap(session_id);
            return false;
        }
        true
    }

    /// bootstrap 首请求成功：先 promote（append-only），再释放 per-session 预留。
    /// 顺序不能反——先释放会重新打开并发窗口，其他 run 可能看到未 promoted
    /// 而再次进入 bootstrap。
    pub fn finish_bootstrap(&self, session_id: &str) {
        self.promote(session_id);
        match self.bootstrap_in_flight.lock() {
            Ok(mut in_flight) => {
                in_flight.remove(session_id);
            }
            Err(_) => tracing::warn!(target = "orchestration", session = %session_id,
                "bootstrap_in_flight Mutex 中毒，预留未释放（promote 已完成，后续 run 不会重复 bootstrap）"),
        }
    }

    /// bootstrap 首请求失败/提前返回：只释放预留，不 promote。
    pub fn cancel_bootstrap(&self, session_id: &str) {
        match self.bootstrap_in_flight.lock() {
            Ok(mut in_flight) => {
                in_flight.remove(session_id);
            }
            Err(_) => tracing::warn!(target = "orchestration", session = %session_id,
                "bootstrap_in_flight Mutex 中毒，预留未释放（本次失败不 promote）"),
        }
    }

    /// 原子取得 per-session bootstrap 预留，返回 RAII guard。
    /// guard 在作用域结束（包括 async future 被取消/丢弃、panic unwind）时自动
    /// 释放预留；调用方在首请求成功后调用 `BootstrapReservation::promote`
    /// 落盘并释放。拿不到预留返回 None（同 session 已有 run 在 bootstrap）。
    pub fn acquire_bootstrap(self: &Arc<Self>, session_id: &str) -> Option<BootstrapReservation> {
        if !self.try_begin_bootstrap(session_id) {
            return None;
        }
        Some(BootstrapReservation {
            controller: Arc::clone(self),
            session_id: session_id.to_string(),
            active: true,
        })
    }

    /// 构造 bootstrap 工具面：只保留「权威边界判定为只读」的工具（`is_safe` 谓词
    /// 由调用方用 `boundary` 的 ToolClassifier/启发式实现），再按意图相关性取前
    /// `max_tools` 个。`max_tools=0` 表示「不给任何工具」（操作者显式意图，不静默改成 1）。
    /// 无安全候选时返回空（LLM 先诚实作答；promote 后同请求即恢复全量目录）。
    ///
    /// ⚠️ 安全语义：无论开关是否开启，`is_safe` 过滤**始终生效**。开关关闭时
    /// 不做相关性排序与 `max_tools` 截断，返回「通过安全谓词的全量目录」——
    /// 本函数是安全过滤器，不是 feature-flag pass-through；新增调用点不能假设
    /// 关闭时会原样返回输入。
    pub fn bootstrap_tools(
        &self,
        raw_message: &str,
        full_tools: &[ToolDef],
        is_safe: &dyn Fn(&str) -> bool,
    ) -> Vec<ToolDef> {
        if !self.cfg.bootstrap.enabled {
            return full_tools
                .iter()
                .filter(|tool| bootstrap_tool_allowed(&tool.function.name, is_safe(&tool.function.name)))
                .cloned()
                .collect();
        }
        let max = self.cfg.bootstrap.max_tools;
        if max == 0 {
            return Vec::new();
        }
        let mut scored: Vec<(i32, usize, &ToolDef)> = full_tools
            .iter()
            .enumerate()
            .filter(|(_, tool)| bootstrap_tool_allowed(&tool.function.name, is_safe(&tool.function.name)))
            .map(|(idx, tool)| {
                (
                    bootstrap_tool_score(&tool.function.name, raw_message),
                    idx,
                    tool,
                )
            })
            .collect();
        // 稳定排序：分值降序、原顺序保持
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored
            .into_iter()
            .take(max)
            .map(|(_, _, tool)| tool.clone())
            .collect()
    }
}

/// bootstrap per-session 预留的 RAII guard。
/// 正常成功路径调用 `promote`；其余所有路径（early-return、async future 被取消、
/// panic unwind）由 `Drop` 自动释放预留，杜绝 in-flight 泄漏。
pub struct BootstrapReservation {
    controller: Arc<OrchestrationController>,
    session_id: String,
    active: bool,
}

impl BootstrapReservation {
    /// 首请求成功：append-only promote + 释放 per-session 预留。
    pub fn promote(mut self) {
        if self.active {
            self.controller.finish_bootstrap(&self.session_id);
            self.active = false;
        }
    }
}

impl Drop for BootstrapReservation {
    fn drop(&mut self) {
        if self.active {
            self.controller.cancel_bootstrap(&self.session_id);
        }
    }
}

/// 动作段拒绝集：把工具名按 `_` / `-` / camelCase 边界切成段后**全段扫描**，
/// 任一段命中写/DDL 动词即拒绝。首段/尾段规则会漏掉 `query_batch_update_log`、
/// `cross_agent_register_user` 这类中间段带写动词的工具；只按 `_` 切分还会漏掉
/// `updateState`、`sendMessage`。`query_archive_log` 是唯一的已知误伤项，
/// 已放入 `BOOTSTRAP_EXPLICIT_ALLOW`（且 allow 不再越过 safe 门）。
/// 危险/写工具的第一道闸由 `boundary::is_read_only_tool` / ToolClassifier 承担；
/// 本表兜底覆盖常见写动词段（update/insert/create/fill/manage/save/add/put/post/
/// remember/dispatch 等）。
fn bootstrap_action_segments_ok(name: &str) -> bool {
    const DENY_ACTIONS: &[&str] = &[
        "write", "delete", "remove", "sync", "commit", "archive", "register", "login",
        "kill", "shutdown", "revoke", "merge", "evolve", "repair", "respond", "send",
        "reboot", "restart", "manage", "fill", "batch", "update", "insert", "create",
        "remember", "dispatch", "save", "add", "put", "post", "submit", "approve",
        "reject", "set", "reset", "clear", "purge", "refresh", "modify", "edit",
        "export", "import", "upload", "enable", "disable", "start", "stop", "run",
        "trigger", "forward", "execute", "alter", "drop", "truncate", "push",
        "publish", "install", "grant", "append", "move", "copy", "invoke",
    ];
    !action_segments(name)
        .iter()
        .any(|segment| DENY_ACTIONS.iter().any(|a| segment == *a))
}

/// 把工具名切成动作段：`_`、`-`、camelCase 与「缩写/数字 + 大写」边界都是分隔符。
/// 兼容 `updateState`、`getOSUpdate`、`OSSendMessage`、`get2Update` 这类命名，
/// 避免 write 动词粘在缩写/数字后面绕过分段检查。
fn action_segments(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    for (i, &ch) in chars.iter().enumerate() {
        if ch == '_' || ch == '-' {
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }
        let prev = i.checked_sub(1).and_then(|j| chars.get(j)).copied();
        let next = chars.get(i + 1).copied();
        let boundary = ch.is_ascii_uppercase()
            && !current.is_empty()
            && (matches!(prev, Some(p) if p.is_ascii_lowercase() || p.is_ascii_digit())
                || matches!(next, Some(n) if n.is_ascii_lowercase()));
        if boundary {
            segments.push(std::mem::take(&mut current));
        }
        current.push(ch.to_ascii_lowercase());
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

/// 显式允许名：只覆盖动作段兜底检查的**已知只读工具**（`query_archive_log` 的
/// 中间段 `archive` 是名词，不是写动作；`execute_sql` 在 dashboard 侧强制
/// SELECT-only，见 `db_write.rs` 注释与 `boundary::ToolClassifier` read 分类）。
/// 白名单不再越过 `safe` 门，也不越过 `bootstrap_explicit_deny`：边界分类为
/// 写/危险的工具永远进不了 bootstrap 面。
const BOOTSTRAP_EXPLICIT_ALLOW: &[&str] =
    &["execute_sql", "fuzzy_match_plate", "query_archive_log"];

fn bootstrap_tool_allowed(name: &str, safe: bool) -> bool {
    // 权威边界判定优先：safe=false 一律拒绝，白名单只豁免动作段启发式，
    // 不能把边界判为写/危险的工具重新放进 bootstrap（ADR-017 不变量）。
    if !safe {
        return false;
    }
    if bootstrap_explicit_deny(name) {
        return false;
    }
    if BOOTSTRAP_EXPLICIT_ALLOW
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
    {
        return true;
    }
    bootstrap_action_segments_ok(name)
}

/// 显式拒绝名：`boundary::is_read_only_tool` 的前缀启发式存在已知宽放项
/// （如 `cross_` 前缀），这些具名工具在 boundary 分类中具备写能力，
/// bootstrap 面必须精确排除（ocr security·high 修复）。
fn bootstrap_explicit_deny(name: &str) -> bool {
    const DENY_NAMES: &[&str] = &[
        "cross_agent_query",
        "reasonix_dispatch",
        "continue_task",
        "memory_remember",
        "memory_merge",
        "register_agent",
    ];
    DENY_NAMES.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// 工具名打分：查询/读取类优先；`raw_message` 带数据查询语义时 query/sql 类加权。
fn bootstrap_tool_score(name: &str, raw_message: &str) -> i32 {
    let n = name.to_ascii_lowercase();
    let query_intent = ["查询", "多少", "进厂", "车次", "数据", "记录", "统计", "白名单"]
        .iter()
        .any(|k| raw_message.contains(k));
    let mut score = if n.contains("query") {
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
    if query_intent && (n.contains("query") || n.contains("sql") || n.contains("get")) {
        score += 2;
    }
    score
}

/// YES/NO 评审解析（ADR-017 Reflect 用）：严格只认**以 YES/NO 开头**的答复；
/// `已达成NO`、`请继续执行YES`、自由文本等一律 None，由调用方按 fail-open 处理。
pub fn parse_yes_no(text: &str) -> Option<bool> {
    fn prefix_ok(t: &str, prefix: &str) -> bool {
        t.starts_with(prefix)
            && t[prefix.len()..]
                .chars()
                .next()
                .map(|c| !c.is_ascii_alphanumeric())
                .unwrap_or(true)
    }
    let t = text.trim().to_ascii_uppercase();
    if prefix_ok(&t, "YES") {
        Some(true)
    } else if prefix_ok(&t, "NO") {
        Some(false)
    } else {
        None
    }
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

/// 从错误文本做保守分类：**Fatal 判定优先于 Retryable**（错误文本可能同时含
/// 「参数/超时」与「审批/红线/拒绝」等词，fatal 必须赢），默认 Recoverable
/// （宁可多走降级，不把 fatal 误判成重试）。
///
/// ⚠️ 超时分类约束：`timeout` 归 Retryable 仅表示「可回灌修正后重试」的候选，
/// 但超时是不确定状态（服务端可能已提交副作用）。调用方**不得**据此对写/非幂等
/// 工具自动重试；当前 agent.rs 只把该分类用于结构化日志。
pub fn classify_tool_failure(error: &str) -> FailureClass {
    let e = error.to_ascii_lowercase();
    if e.contains("红线")
        || e.contains("审批")
        || e.contains("配额")
        || e.contains("kill switch")
        || e.contains("审批拒绝")
        || e.contains("拒绝访问")
        || e.contains("权限拒绝")
        || e.contains("拒绝执行")
        || e.contains("access denied")
        || e.contains("permission denied")
        || e.contains("unauthorized")
        || e.contains("forbidden")
        || e.contains("invalid token")
        || e.contains("invalid credentials")
        || e.contains("invalid session")
        || e.contains("session expired")
        || e.contains("token expired")
        || e.contains("session timeout")
        || e.contains("token timeout")
        || e.contains("会话超时")
        || e.contains("令牌超时")
        || e.contains("token 超时")
        || e.contains("令牌已过期")
        || e.contains("会话已过期")
        || e.contains("登录已过期")
        || e.contains("凭证已过期")
        || e.contains("已过期")
        || e.contains("无权限")
        || e.contains("无权")
        || e.contains("权限不足")
        || e.contains("未授权")
        || e.contains("禁止")
    {
        FailureClass::Fatal
    } else if e.contains("schema")
        || e.contains("参数")
        || e.contains("超时")
        || e.contains("timeout")
    {
        FailureClass::Retryable
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
        match self.hooks.lock() {
            Ok(mut hooks) => hooks.push(hook),
            Err(_) => tracing::warn!(target = "orchestration.hooks",
                point = ?hook.point(), priority = hook.priority(),
                "hooks Mutex 中毒，guardrail hook 注册被丢弃（安全钩可能静默失效）"),
        }
    }

    /// 按 priority 升序执行同挂载点的 hooks，合并裁决：
    /// Abort 优先；否则首个 Retry；否则合并 Inject；否则 Continue。
    ///
    /// ⚠️ 多个 Abort 的语义：升序遍历时**第一个** Abort 立即短路返回（先执行、
    /// 先 Abort 先赢）。若需要「更高 priority 的 Abort 覆盖更低 priority」，
    /// 注册方应把安全裁决 hook 放到更小 priority（先执行），或在注册前自行协调；
    /// 本注册表不做二次比较。
    pub fn run(&self, point: HookPoint, ctx: &HookContext) -> HookAction {
        let snapshot: Vec<std::sync::Arc<dyn OrchestrationHook>> = {
            let Ok(guard) = self.hooks.lock() else {
                tracing::error!(target = "orchestration.hooks", point = ?point,
                    "hooks Mutex 中毒，guardrail hook 全部失效；fail-closed Abort");
                return HookAction::Abort {
                    reply: "⚠️ 内部安全钩子（guardrail）注册表不可用，本次操作已中止。请重启服务或人工介入。"
                        .to_string(),
                };
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
            // Retry 时合并同挂载点其他 hook 的 Inject（ocr 修复：不能静默丢弃注入）
            match r {
                HookAction::Retry { mut messages } => {
                    messages.extend(injected);
                    HookAction::Retry { messages }
                }
                other => other,
            }
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
            // 至少 1 轮：0 轮会让 llm_loop 完全跳过循环体，bootstrap 预留释放与
            // 预算硬拒检查都执行不到（ocr bug·high）。
            max_rounds: max_rounds.max(1),
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

    fn bootstrap_on_cfg() -> OrchestrationConfig {
        OrchestrationConfig {
            bootstrap: BootstrapConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
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
        assert_eq!(cfg.tool_summary.max_per_round, 2);
    }

    #[test]
    fn bootstrap_picks_query_tools_and_denies_writes() {
        let cfg = bootstrap_on_cfg();
        let ctrl = OrchestrationController::new_with_store(cfg, SessionPhaseStore::new_in_memory());
        let full = vec![
            tool("query_entrance"),
            tool("get_vehicle"),
            tool("cw_write"),
            tool("repo_ws_write"),
            tool("execute_sql"),
            tool("read_doc"),
            tool("query_archive_log"),
        ];
        let picked = ctrl.bootstrap_tools("查进厂记录", &full, &|n| {
            crate::boundary::is_read_only_tool(n)
        });
        let names: Vec<&str> = picked.iter().map(|t| t.function.name.as_str()).collect();
        assert_eq!(picked.len(), 3);
        assert!(names.contains(&"query_entrance"));
        assert!(names.contains(&"get_vehicle"));
        assert!(!names.iter().any(|n| n.contains("write")));
        // 默认关闭时不做 max_tools 截断，但安全过滤（safe 谓词 + 动作段兜底）仍生效：
        // 本函数不是 pass-through，写工具即使传入 |_|true 也不能通过。
        let disabled = OrchestrationController::new_with_store(
            OrchestrationConfig::default(),
            SessionPhaseStore::new_in_memory(),
        );
        assert_eq!(disabled.bootstrap_tools("x", &full, &|_| true).len(), 5);
        assert!(disabled.bootstrap_tools("x", &full, &|n| n != "cw_write").iter().all(|t| {
            t.function.name != "cw_write"
        }));
    }

    #[test]
    fn bootstrap_empty_when_all_denied() {
        let cfg = bootstrap_on_cfg();
        let ctrl = OrchestrationController::new_with_store(cfg, SessionPhaseStore::new_in_memory());
        let full = vec![tool("cw_write"), tool("repo_ws_write")];
        assert!(ctrl.bootstrap_tools("x", &full, &|_| true).is_empty());
    }

    #[test]
    fn bootstrap_honors_zero_and_explicit_deny() {
        // max_tools=0 是操作者显式意图：不给任何工具，不得静默改成 1
        let cfg_zero = OrchestrationConfig {
            bootstrap: BootstrapConfig {
                enabled: true,
                max_tools: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let ctrl = OrchestrationController::new_with_store(cfg_zero, SessionPhaseStore::new_in_memory());
        let full = vec![tool("query_entrance")];
        assert!(ctrl.bootstrap_tools("x", &full, &|_| true).is_empty());

        // is_read_only 前缀启发式的已知宽放项必须被显式名单排除
        let cfg = bootstrap_on_cfg();
        let ctrl = OrchestrationController::new_with_store(cfg, SessionPhaseStore::new_in_memory());
        let full = vec![tool("cross_agent_query"), tool("query_entrance")];
        let picked = ctrl.bootstrap_tools("x", &full, &|_| true);
        let names: Vec<&str> = picked.iter().map(|t| t.function.name.as_str()).collect();
        assert!(!names.contains(&"cross_agent_query"));
        assert!(names.contains(&"query_entrance"));
    }

    #[test]
    fn bootstrap_whitelist_does_not_override_safe_or_explicit_deny() {
        let cfg = bootstrap_on_cfg();
        let ctrl = OrchestrationController::new_with_store(cfg, SessionPhaseStore::new_in_memory());
        let full = vec![tool("execute_sql"), tool("cross_agent_query")];
        // safe=false 时白名单必须失效（权威边界判定优先）
        assert!(ctrl.bootstrap_tools("x", &full, &|_| false).is_empty());
        // safe=true 但显式拒绝名单命中时，白名单也不得放行
        let picked =
            ctrl.bootstrap_tools("x", &full, &|n| n == "execute_sql" || n == "cross_agent_query");
        assert!(picked.iter().all(|t| t.function.name == "execute_sql"));
    }

    #[test]
    fn bootstrap_action_deny_scans_all_segments() {
        // 写动词位于中间段也必须被动作段兜底拦截
        assert!(!bootstrap_action_segments_ok("cross_agent_register_user"));
        assert!(!bootstrap_action_segments_ok("query_batch_update_log"));
        // camelCase / 连字符命名也不能绕过动作段扫描
        assert!(!bootstrap_action_segments_ok("updateState"));
        assert!(!bootstrap_action_segments_ok("send-message"));
        // 缩写/数字 + 大写边界也不能把写动词粘进同一段
        assert!(!bootstrap_action_segments_ok("getOSUpdate"));
        assert!(!bootstrap_action_segments_ok("OSSendMessage"));
        assert!(!bootstrap_action_segments_ok("get2Update"));
        // DDL/危险动词兜底（execute_sql 本身由白名单放行，见下）
        assert!(!bootstrap_action_segments_ok("alter_table"));
        assert!(!bootstrap_action_segments_ok("drop_table"));
        assert!(!bootstrap_action_segments_ok("truncate_log"));
        // 已知只读误伤项：名词 archive 在中间段，经显式允许放行
        assert!(!bootstrap_action_segments_ok("query_archive_log"));
        assert!(bootstrap_tool_allowed("query_archive_log", true));
        assert!(!bootstrap_tool_allowed("execute_sql", false));
    }

    #[test]
    fn bootstrap_reservation_is_atomic_and_releasable() {
        let cfg = bootstrap_on_cfg();
        let ctrl = OrchestrationController::new_with_store(cfg, SessionPhaseStore::new_in_memory());
        assert!(ctrl.try_begin_bootstrap("s1"));
        // 同 session 并发第二个 run 拿不到预留
        assert!(!ctrl.try_begin_bootstrap("s1"));
        // 不同 session 互不影响
        assert!(ctrl.try_begin_bootstrap("s2"));
        ctrl.cancel_bootstrap("s1");
        assert!(ctrl.try_begin_bootstrap("s1"));
        // 成功后 promote 并释放预留；已 promoted 的 session 不再能预留
        ctrl.finish_bootstrap("s1");
        assert!(ctrl.is_promoted("s1"));
        assert!(!ctrl.try_begin_bootstrap("s1"));
    }

    #[test]
    fn bootstrap_reservation_guard_autoreleases_on_drop() {
        let cfg = bootstrap_on_cfg();
        let ctrl = Arc::new(OrchestrationController::new_with_store(
            cfg,
            SessionPhaseStore::new_in_memory(),
        ));
        let guard = ctrl.acquire_bootstrap("s1").expect("预留应成功");
        assert!(!ctrl.try_begin_bootstrap("s1"));
        // 模拟 async future 取消 / panic unwind：drop guard 自动释放预留
        drop(guard);
        assert!(ctrl.try_begin_bootstrap("s1"));
        // 上面 try_begin 是手动探测，它留下的预留要清掉，再走 RAII acquire
        ctrl.cancel_bootstrap("s1");
        let guard = ctrl.acquire_bootstrap("s1").expect("释放后应可重新预留");
        guard.promote();
        assert!(ctrl.is_promoted("s1"));
        assert!(!ctrl.try_begin_bootstrap("s1"));
    }

    #[test]
    fn promoted_cache_is_bounded() {
        let cfg = bootstrap_on_cfg();
        let ctrl = OrchestrationController::new_with_store(cfg, SessionPhaseStore::disabled());
        for i in 0..(SESSION_SET_CACHE_MAX + 16) {
            ctrl.promote(&format!("s{i}"));
        }
        // 直接观察缓存容器：容量不能超过上限（LRU 淘汰，DB 仍可回查）
        {
            let cache = ctrl.promoted_cache.lock().unwrap();
            assert!(cache.order.len() <= SESSION_SET_CACHE_MAX);
            assert!(cache.set.len() <= SESSION_SET_CACHE_MAX);
        }
        // 仍在缓存中的最近 session 命中不受影响
        assert!(ctrl.is_promoted(&format!("s{}", SESSION_SET_CACHE_MAX + 15)));
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
        // Fatal 关键词优先于 Retryable 关键词（ocr 修复：混合错误文本不得误判为可重试）
        assert_eq!(classify_tool_failure("参数错误：审批拒绝"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("invalid: forbidden"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("参数错误：无权限"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("权限不足"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("未授权"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("禁止操作"), FailureClass::Fatal);
        // 网络层「连接被拒绝」是瞬时故障，不得被宽泛「拒绝」误判为 Fatal
        assert_eq!(classify_tool_failure("连接被拒绝"), FailureClass::Recoverable);
        assert_eq!(classify_tool_failure("connection denied"), FailureClass::Recoverable);
        // 会话/token 过期是认证终态，即使文本含 timeout 也必须 Fatal
        assert_eq!(classify_tool_failure("session timeout"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("token timeout"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("会话超时"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("令牌已过期"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("登录已过期"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("执行超时"), FailureClass::Retryable);
        // 认证/会话类 invalid 属于 Fatal，不因宽泛 invalid 误判为可重试
        assert_eq!(classify_tool_failure("invalid token"), FailureClass::Fatal);
        assert_eq!(classify_tool_failure("invalid session"), FailureClass::Fatal);
    }

    #[test]
    fn yes_no_parser_is_strict_and_fail_open_on_ambiguity() {
        assert_eq!(parse_yes_no("YES"), Some(true));
        assert_eq!(parse_yes_no("yes, 目标达成。"), Some(true));
        assert_eq!(parse_yes_no("NO"), Some(false));
        assert_eq!(parse_yes_no("NO - 缺少数据"), Some(false));
        // 歧义 → None（调用方 fail-open）
        assert_eq!(parse_yes_no("NOT SURE"), None);
        assert_eq!(parse_yes_no("The answer needs work"), None);
        // 首 token 不是 YES/NO 的一律 None（含 CJK 前缀）
        assert_eq!(parse_yes_no("已达成NO"), None);
        assert_eq!(parse_yes_no("请继续执行YES"), None);
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
