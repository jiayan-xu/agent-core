//! PR5 — Memoria 自我进化引擎（P-D 审批门控 + P-A 元进化闭环）
//!
//! 设计原则（圆桌硬约束 H1–H5）：
//! - 演化认知只在 `consolidate` 维护路径运行，绝不进 `call_tool_routed` 热路径。
//! - 每次演化可回滚（PR4 已保证 `evolution_log` + `evolution_rollback`）。
//! - 元进化默认 `enabled=false`，受控开启。
//! - 机制的机制可审计：L2 自身的演化记录落 `evolution_feedback`（机制账本）。
//!
//! 用户裁决（2026-07-20）：**取消人工审批** → `ApprovalMode::Auto` 为默认，
//! 高风险演化默认直接放行，但分类逻辑与日志保留，便于后续切回 `HumanInLoop`。

use std::sync::Arc;
use tokio::sync::Mutex;
use rusqlite::{params, Connection};

use serde::{Deserialize, Deserializer, Serialize};

use crate::llm::{LlmClient, Message};
use crate::mcp_client::McpClient;

// ─────────────────────────────────────────────────────────────
// 配置类型（同时被 agent.toml TOML 加载与 AgentConfig 使用）
// ─────────────────────────────────────────────────────────────

/// 元进化审批模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    /// 自动放行（用户裁决默认）：高风险演化直接通过，仅记日志
    Auto,
    /// 人类在环：高风险且无审批人时硬拒
    HumanInLoop,
}

impl Default for ApprovalMode {
    fn default() -> Self {
        ApprovalMode::Auto
    }
}

impl ApprovalMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalMode::Auto => "auto",
            ApprovalMode::HumanInLoop => "human_in_loop",
        }
    }
}

impl Serialize for ApprovalMode {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ApprovalMode {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(d)?;
        match raw.to_lowercase().as_str() {
            "auto" => Ok(ApprovalMode::Auto),
            "human" | "human_in_loop" | "humaninloop" => Ok(ApprovalMode::HumanInLoop),
            // 容错：未知值默认 Auto（受控，不阻塞启动）
            _ => Ok(ApprovalMode::Auto),
        }
    }
}

/// 元进化配置（落 agent.toml `[meta_evolution]`）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaEvolutionConfig {
    /// 默认关：显式开启（圆桌硬要求：受控开启）
    #[serde(default)]
    pub enabled: bool,
    /// 负样本时间窗（天）
    #[serde(default = "default_window_days")]
    pub window_days: i64,
    /// 样本不足不跑
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,
    /// holdout 占比（保留，供未来真 A/B）
    #[serde(default = "default_holdout")]
    pub holdout_ratio: f64,
    /// 相对回滚率降幅 ≥ 该值才 rollout
    #[serde(default = "default_improve")]
    pub improve_threshold: f64,
    /// 熔断阈值：线下 rollback_rate 超过则暂停 L2
    #[serde(default = "default_max_rollback")]
    pub max_rollback_rate: f64,
    /// 熔断后冷却（小时）
    #[serde(default = "default_cooldown")]
    pub cooldown_hours: i64,
    /// 优化器模型（提示用，真实模型由 LlmClient 配置决定）
    #[serde(default = "default_optimizer_model")]
    pub optimizer_model: String,
}

fn default_window_days() -> i64 {
    30
}
fn default_min_samples() -> usize {
    20
}
fn default_holdout() -> f64 {
    0.2
}
fn default_improve() -> f64 {
    0.05
}
fn default_max_rollback() -> f64 {
    0.15
}
fn default_cooldown() -> i64 {
    24
}
fn default_optimizer_model() -> String {
    "deepseek-v4-flash".to_string()
}

impl Default for MetaEvolutionConfig {
    fn default() -> Self {
        MetaEvolutionConfig {
            enabled: false,
            window_days: default_window_days(),
            min_samples: default_min_samples(),
            holdout_ratio: default_holdout(),
            improve_threshold: default_improve(),
            max_rollback_rate: default_max_rollback(),
            cooldown_hours: default_cooldown(),
            optimizer_model: default_optimizer_model(),
        }
    }
}

/// 安全配置（落 agent.toml `[safety]`）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    #[serde(default)]
    pub approval_mode: ApprovalMode,
    #[serde(default = "default_high_risk_tools")]
    pub high_risk_tools: Vec<String>,
    #[serde(default = "default_high_risk_change_types")]
    pub high_risk_change_types: Vec<String>,
}

fn default_high_risk_tools() -> Vec<String> {
    vec![
        "delete_*".to_string(),
        "export_*".to_string(),
        "send_*".to_string(),
        "upload_*".to_string(),
        "webhook_*".to_string(),
    ]
}

fn default_high_risk_change_types() -> Vec<String> {
    vec!["supersede".to_string(), "override".to_string()]
}

impl Default for SafetyConfig {
    fn default() -> Self {
        SafetyConfig {
            approval_mode: ApprovalMode::default(),
            high_risk_tools: default_high_risk_tools(),
            high_risk_change_types: default_high_risk_change_types(),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// P-D 审批门控
// ─────────────────────────────────────────────────────────────

/// 门控拒绝原因
#[derive(Debug, Clone)]
pub struct GateRejection {
    pub reason: String,
}

impl std::fmt::Display for GateRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// 简单 glob：`delete_*` 匹配任意以 `delete_` 开头的工具名；无 `*` 则精确匹配
fn glob_match(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        pattern == name
    }
}

/// 审批闸门：分类 high_risk + 按模式放行/硬拒
#[derive(Debug, Clone)]
pub struct ApprovalGate {
    high_risk_tools: Vec<String>,
    high_risk_change_types: Vec<String>,
    mode: ApprovalMode,
    approver: Option<String>,
}

impl ApprovalGate {
    pub fn from_safety(s: &SafetyConfig, approver: Option<String>) -> Self {
        ApprovalGate {
            high_risk_tools: s.high_risk_tools.clone(),
            high_risk_change_types: s.high_risk_change_types.clone(),
            mode: s.approval_mode,
            approver,
        }
    }

    /// 该工具名 / 演化类型是否高风险
    pub fn is_high_risk(&self, tool: &str, change_type: Option<&str>) -> bool {
        if self.high_risk_tools.iter().any(|p| glob_match(p, tool)) {
            return true;
        }
        if let Some(ct) = change_type {
            if self.high_risk_change_types.iter().any(|t| t == ct) {
                return true;
            }
        }
        false
    }

    /// 检查是否放行。Auto 模式永远放行（仅记日志）；HumanInLoop 模式高风险且无审批人则硬拒
    pub fn check(&self, tool: &str, change_type: Option<&str>) -> Result<(), GateRejection> {
        if !self.is_high_risk(tool, change_type) {
            return Ok(());
        }
        match self.mode {
            ApprovalMode::Auto => {
                tracing::info!(
                    target: "agent.gate",
                    tool = tool,
                    change_type = ?change_type,
                    "high-risk 自动放行（ApprovalMode::Auto，用户裁决免人工审批）"
                );
                Ok(())
            }
            ApprovalMode::HumanInLoop => match &self.approver {
                Some(_) => {
                    tracing::info!(target: "agent.gate", tool = tool, "high-risk 经审批人放行");
                    Ok(())
                }
                None => Err(GateRejection {
                    reason: format!("high-risk {} 需人工审批但无审批人", tool),
                }),
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 默认演化提示词（与 PR4 consolidate 第 7 步原硬编码文本一致）
// ─────────────────────────────────────────────────────────────

pub const DEFAULT_EVOLVE_PROMPT: &str = "你是记忆演化引擎。给定一批原始\"观察\"记忆和已提炼的高层模式，请为每条观察补充\"演化上下文\"：\
用一句话说明该观察如何被高层模式解释或关联（不要重复原观察内容，只写增量上下文；若无关联可写\"\"）。\
仅输出纯 JSON 数组，不要任何前缀后缀：\
[{\"id\":\"<记忆id>\",\"evolved_context\":\"<一句话增量上下文>\"}]";

// ─────────────────────────────────────────────────────────────
// 元进化数据模型
// ─────────────────────────────────────────────────────────────

/// 一条负样本（来自 memoria `evolution_log_query`）
#[derive(Debug, Clone)]
pub struct NegSample {
    pub change_type: String,
    pub old_value: String,
    pub new_value: String,
    pub context: String,
}

/// 候选演化提示词
#[derive(Debug, Clone)]
pub struct CandidatePrompt {
    pub text: String,
    pub hash: String,
}

/// 评估结果
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub baseline_rate: f64,
    pub candidate_rate: f64,
    /// 相对降幅（负=改善）
    pub delta: f64,
    pub passed: bool,
}

/// 一次 rollout 的结果（可序列化供 HTTP 返回）
#[derive(Debug, Clone, Serialize)]
pub struct RolloutResult {
    pub attempted: bool,
    pub status: String, // skipped | insufficient_samples | guarded | error | done
    pub reason: String,
    pub baseline_rate: f64,
    pub candidate_rate: f64,
    pub passed: bool,
    pub rolled_out: bool,
    pub prompt_hash_before: String,
    pub prompt_hash_after: String,
    pub feedback_id: String,
}

impl RolloutResult {
    fn skipped(reason: &str) -> Self {
        RolloutResult {
            attempted: false,
            status: "skipped".into(),
            reason: reason.into(),
            baseline_rate: 0.0,
            candidate_rate: 0.0,
            passed: false,
            rolled_out: false,
            prompt_hash_before: String::new(),
            prompt_hash_after: String::new(),
            feedback_id: String::new(),
        }
    }
    fn guarded(baseline: f64) -> Self {
        RolloutResult {
            attempted: true,
            status: "guarded".into(),
            reason: "rollback_guard 触发：baseline 超阈值，L2 暂停".into(),
            baseline_rate: baseline,
            candidate_rate: baseline,
            passed: false,
            rolled_out: false,
            prompt_hash_before: String::new(),
            prompt_hash_after: String::new(),
            feedback_id: String::new(),
        }
    }
    fn cooldown(hours: i64) -> Self {
        RolloutResult {
            attempted: false,
            status: "cooldown".into(),
            reason: format!("距上次元进化不足 {}h（cooldown 守卫，跳过本轮）", hours),
            baseline_rate: 0.0,
            candidate_rate: 0.0,
            passed: false,
            rolled_out: false,
            prompt_hash_before: String::new(),
            prompt_hash_after: String::new(),
            feedback_id: String::new(),
        }
    }
    fn error(msg: &str) -> Self {
        RolloutResult {
            attempted: true,
            status: "error".into(),
            reason: msg.into(),
            baseline_rate: 0.0,
            candidate_rate: 0.0,
            passed: false,
            rolled_out: false,
            prompt_hash_before: String::new(),
            prompt_hash_after: String::new(),
            feedback_id: String::new(),
        }
    }
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::json!({"status":"error"}))
    }
}

/// FNV-1a 32 位哈希 → 16 进制串（用于 prompt 版本指纹，避免引入外部依赖）
fn fnv1a(text: &str) -> String {
    let mut hash: u32 = 0x811c9dc5;
    for b in text.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    format!("{:08x}", hash)
}

// ─────────────────────────────────────────────────────────────
// 机制账本（rusqlite，镜像 HarnessStore 范式）
// ─────────────────────────────────────────────────────────────

pub struct MetaEvolutionStore {
    conn: Connection,
    db_path: String,
}

impl MetaEvolutionStore {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("open meta_evolution db: {}", e))?;
        let db_path = path.to_string();
        let mut s = MetaEvolutionStore { conn, db_path };
        s.init_schema()?;
        Ok(s)
    }

    pub fn open_memory() -> Result<Self, String> {
        let conn =
            Connection::open_in_memory().map_err(|e| format!("open memory: {}", e))?;
        let mut s = MetaEvolutionStore {
            conn,
            db_path: String::new(),
        };
        s.init_schema()?;
        Ok(s)
    }

    pub fn db_path(&self) -> String {
        self.db_path.clone()
    }

    fn init_schema(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS evolution_feedback (
                    id                TEXT PRIMARY KEY,
                    source_log_id     TEXT,
                    kind              TEXT,
                    prompt_hash_before TEXT,
                    prompt_hash_after  TEXT,
                    batch_id          TEXT,
                    rollback_rate_before REAL,
                    rollback_rate_after  REAL,
                    rolled_out        INTEGER DEFAULT 0,
                    created_at        INTEGER
                );
                CREATE TABLE IF NOT EXISTS meta_prompt (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    prompt_text  TEXT NOT NULL,
                    prompt_hash  TEXT NOT NULL,
                    created_at   INTEGER,
                    is_current   INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS meta_kv (
                    k TEXT PRIMARY KEY,
                    v TEXT
                );",
            )
            .map_err(|e| format!("init meta_evolution schema: {}", e))?;
        Ok(())
    }

    /// 读取当前生效的动态提示词（无则 None，调用方回退 DEFAULT）
    pub fn load_meta_prompt(&self) -> Option<String> {
        self.conn
            .query_row(
                "SELECT prompt_text FROM meta_prompt WHERE is_current = 1 ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
    }

    /// 写入新候选为当前版本（原子：先清旧 current，再插新）
    pub fn save_meta_prompt(&mut self, text: &str, hash: &str) -> Result<(), String> {
        let now = now_secs() as i64;
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("tx begin: {}", e))?;
        tx.execute("UPDATE meta_prompt SET is_current = 0", [])
            .map_err(|e| format!("clear current: {}", e))?;
        tx.execute(
            "INSERT INTO meta_prompt (prompt_text, prompt_hash, created_at, is_current) VALUES (?1, ?2, ?3, 1)",
            params![text, hash, now],
        )
        .map_err(|e| format!("insert prompt: {}", e))?;
        tx.commit().map_err(|e| format!("tx commit: {}", e))?;
        Ok(())
    }

    /// 记录一条机制账本（L2 自身演化记录）
    pub fn record_feedback(
        &mut self,
        source_log_id: &str,
        kind: &str,
        hash_before: &str,
        hash_after: &str,
        batch_id: &str,
        rollback_rate_before: f64,
        rollback_rate_after: f64,
        rolled_out: bool,
    ) -> Result<String, String> {
        let id = format!("fb_{}_{}", hash_after, now_secs() as i64);
        let now = now_secs() as i64;
        self.conn
            .execute(
                "INSERT INTO evolution_feedback \
                 (id, source_log_id, kind, prompt_hash_before, prompt_hash_after, batch_id, \
                  rollback_rate_before, rollback_rate_after, rolled_out, created_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    id,
                    source_log_id,
                    kind,
                    hash_before,
                    hash_after,
                    batch_id,
                    rollback_rate_before,
                    rollback_rate_after,
                    rolled_out as i32,
                    now
                ],
            )
            .map_err(|e| format!("insert feedback: {}", e))?;
        Ok(id)
    }

    /// 最近一条 feedback（供 status 展示）
    pub fn latest_feedback(&self) -> Option<serde_json::Value> {
        let row = self
            .conn
            .query_row(
                "SELECT id, kind, prompt_hash_before, prompt_hash_after, rolled_out, created_at \
                 FROM evolution_feedback ORDER BY created_at DESC LIMIT 1",
                [],
                |r| {
                    Ok(serde_json::json!({
                        "id": r.get::<_, String>(0)?,
                        "kind": r.get::<_, String>(1)?,
                        "prompt_hash_before": r.get::<_, String>(2)?,
                        "prompt_hash_after": r.get::<_, String>(3)?,
                        "rolled_out": r.get::<_, i32>(4)? != 0,
                        "created_at": r.get::<_, i64>(5)?,
                    }))
                },
            )
            .ok()?;
        Some(row)
    }

    pub fn feedback_count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM evolution_feedback", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    /// 读取 kv（持久化运行态，如 last_run_at）
    pub fn get_kv(&self, k: &str) -> Option<String> {
        self.conn
            .query_row("SELECT v FROM meta_kv WHERE k = ?1", params![k], |r| {
                r.get::<_, String>(0)
            })
            .ok()
    }

    /// 写入/覆盖 kv
    pub fn set_kv(&mut self, k: &str, v: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO meta_kv (k, v) VALUES (?1, ?2) \
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![k, v],
            )
            .map_err(|e| format!("set_kv {}: {}", k, e))?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────
// 元进化引擎（L2 闭环）
// ─────────────────────────────────────────────────────────────

pub struct MetaEvolver {
    pub config: MetaEvolutionConfig,
    store: Arc<Mutex<MetaEvolutionStore>>,
    llm: LlmClient,
    #[allow(dead_code)]
    memoria_url: String,
    #[allow(dead_code)]
    agent_id: String,
}

impl MetaEvolver {
    pub fn new(
        config: MetaEvolutionConfig,
        store: Arc<Mutex<MetaEvolutionStore>>,
        llm: LlmClient,
        memoria_url: String,
        agent_id: String,
    ) -> Self {
        MetaEvolver {
            config,
            store,
            llm,
            memoria_url,
            agent_id,
        }
    }

    /// 当前生效的演化提示词（动态 > 默认）
    pub async fn current_prompt(&self) -> String {
        let s = self.store.lock().await;
        s.load_meta_prompt()
            .unwrap_or_else(|| DEFAULT_EVOLVE_PROMPT.to_string())
    }

    /// 当前提示词指纹（status 用）
    pub async fn current_prompt_hash(&self) -> String {
        fnv1a(&self.current_prompt().await)
    }

    // ── 纯函数：可单测，不触网 ──────────────────────────

    /// 基线回滚率：rolled_back 样本占比
    pub fn baseline_rollback_rate(&self, samples: &[NegSample]) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let rb = samples
            .iter()
            .filter(|s| s.change_type == "rolled_back")
            .count() as f64;
        rb / samples.len() as f64
    }

    /// 估计候选提示词的回滚率：基线 × (1 − 失败模式覆盖率)
    /// 覆盖率为「rolled_back 样本中其 old_value 片段出现在候选提示词里的比例」。
    /// 这是 MVP 启发式（P-E 全量将替换为 LLM 重放评估），确定性、可单测。
    pub fn estimate_candidate_rate(&self, candidate_text: &str, samples: &[NegSample], baseline: f64) -> f64 {
        let rb_samples: Vec<&NegSample> = samples
            .iter()
            .filter(|s| s.change_type == "rolled_back")
            .collect();
        if rb_samples.is_empty() {
            return baseline * 0.5; // 无明确失败样本，保守给一半基线估计
        }
        let covered = rb_samples
            .iter()
            .filter(|s| {
                // 取前 12 字符作为「失败模式指纹」，并去掉尾部非字母数字（避免下划线/标点导致误不匹配）
                let frag: String = s
                    .old_value
                    .chars()
                    .take(12)
                    .collect::<String>()
                    .trim_end_matches(|c: char| !c.is_alphanumeric())
                    .to_string();
                !frag.is_empty() && candidate_text.contains(&frag)
            })
            .count() as f64;
        let coverage = covered / rb_samples.len() as f64;
        baseline * (1.0 - coverage)
    }

    /// 评估：相对降幅 ≥ improve_threshold 才算通过
    pub fn evaluate_candidate(
        &self,
        baseline_rate: f64,
        candidate_rate: f64,
        improve_threshold: f64,
    ) -> EvalResult {
        let delta = candidate_rate - baseline_rate;
        let passed = if baseline_rate <= 1e-9 {
            // 基线本身已无回滚，视为无需改进但允许 rollout（候选至少不更差）
            true
        } else {
            let rel = (baseline_rate - candidate_rate) / baseline_rate;
            rel >= improve_threshold
        };
        EvalResult {
            baseline_rate,
            candidate_rate,
            delta,
            passed,
        }
    }

    /// 解析 memoria `evolution_log_query` 返回为负样本
    pub fn parse_negative_samples(raw: &str) -> Vec<NegSample> {
        let v: serde_json::Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let items = v.get("items").and_then(|i| i.as_array()).cloned().unwrap_or_default();
        items
            .iter()
            .map(|it| NegSample {
                change_type: it
                    .get("change_type")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string(),
                old_value: it
                    .get("old_value")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string(),
                new_value: it
                    .get("new_value")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string(),
                context: it
                    .get("context")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
            .collect()
    }

    // ── 异步：触网（LLM / memoria） ─────────────────────

    /// 采集负样本（经 memoria `evolution_log_query`）
    pub async fn collect_negative_samples(
        &self,
        mem_client: &McpClient,
        limit: usize,
    ) -> Vec<NegSample> {
        let since = {
            let d = chrono::Utc::now() - chrono::Duration::days(self.config.window_days);
            // 与 memoria evolve.rs `now_iso` 同格式（无时区偏移），保证字典序比较正确
            d.format("%Y-%m-%dT%H:%M:%S").to_string()
        };
        let raw = mem_client
            .call(
                "evolution_log_query",
                &serde_json::json!({
                    "change_types": ["rolled_back", "corrected"],
                    "since": since,
                    "limit": limit,
                }),
            )
            .await
            .unwrap_or_default();
        Self::parse_negative_samples(&raw)
    }

    /// LLM 精炼演化提示词 → 候选
    pub async fn optimize_prompt(
        &self,
        samples: &[NegSample],
        model: &str,
    ) -> Result<CandidatePrompt, String> {
        let sample_txt: Vec<String> = samples
            .iter()
            .take(20)
            .map(|s| {
                format!(
                    "- [{}] old={} | new={} | ctx={}",
                    s.change_type,
                    s.old_value.chars().take(120).collect::<String>(),
                    s.new_value.chars().take(120).collect::<String>(),
                    s.context.chars().take(120).collect::<String>(),
                )
            })
            .collect();
        let prompt = format!(
            "你是「记忆演化引擎」的元优化器（meta-optimizer）。下面是一批演化被回滚/纠偏的负样本（说明当前演化提示词易犯的错误）。\
             请改写演化提示词，加入针对这些失败模式的禁忌与偏好，使未来演化更少被回滚。\
             只输出改写后的演化提示词全文（纯文本，不要解释、不要代码块标记）。\
             模型参考：{}\n\n## 负样本（最多 20 条）\n{}",
            model,
            sample_txt.join("\n")
        );
        let msg = Message {
            role: "system".to_string(),
            content: Some(prompt),
            tool_calls: None,
            tool_call_id: None,
        };
        let reply = self.llm.chat(&[msg], &[]).await.map_err(|e| e.to_string())?;
        let text = reply.text.trim().to_string();
        if text.is_empty() {
            return Err("optimizer 返回空提示词".to_string());
        }
        let hash = fnv1a(&text);
        Ok(CandidatePrompt {
            text,
            hash,
        })
    }

    /// rollout（写机制账本 + 更新动态提示词）。candidate_rate 由调用方传入（LLM 估计或测试指定）
    pub async fn rollout_if_better(
        &self,
        cand: &CandidatePrompt,
        baseline_rate: f64,
        candidate_rate: f64,
        _samples: &[NegSample],
        ns: &str,
    ) -> RolloutResult {
        let eval = self.evaluate_candidate(baseline_rate, candidate_rate, self.config.improve_threshold);
        let hash_before = self.current_prompt_hash().await;
        let mut s = self.store.lock().await;
        let (rolled_out, kind) = if eval.passed {
            if s.save_meta_prompt(&cand.text, &cand.hash).is_err() {
                return RolloutResult::error("保存动态提示词失败");
            }
            (true, "improved")
        } else {
            (false, "rejected")
        };
        let fb_id = match s.record_feedback(
            "",
            kind,
            &hash_before,
            &cand.hash,
            ns,
            baseline_rate,
            candidate_rate,
            rolled_out,
        ) {
            Ok(id) => id,
            Err(e) => return RolloutResult::error(&e),
        };
        RolloutResult {
            attempted: true,
            status: "done".into(),
            reason: if eval.passed {
                "候选通过评估，已 rollout".into()
            } else {
                "候选未达改进阈值，保留上一版".into()
            },
            baseline_rate,
            candidate_rate,
            passed: eval.passed,
            rolled_out,
            prompt_hash_before: hash_before,
            prompt_hash_after: cand.hash.clone(),
            feedback_id: fb_id,
        }
    }

    /// 一轮元进化（端到端）：采集 → 基线 → 优化 → rollout
    pub async fn run_once(&self, mem_client: &McpClient, ns: &str) -> RolloutResult {
        if !self.config.enabled {
            return RolloutResult::skipped("meta_evolution.enabled=false");
        }
        // cooldown 守卫：避免夜班 patrol / 手动 consolidate 高频反复跑 L2
        if self.config.cooldown_hours > 0 {
            let now = now_secs() as i64;
            let last = self
                .store
                .lock()
                .await
                .get_kv("last_run_at")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            if now - last < self.config.cooldown_hours * 3600 {
                return RolloutResult::cooldown(self.config.cooldown_hours);
            }
            // 通过守卫 → 记录本次触发时刻（即便随后 insufficient_samples 也记，避免空转）
            let mut g = self.store.lock().await;
            let _ = g.set_kv("last_run_at", &now.to_string());
        }
        let samples = self.collect_negative_samples(mem_client, 500).await;
        if samples.len() < self.config.min_samples {
            return RolloutResult {
                attempted: false,
                status: "insufficient_samples".into(),
                reason: format!("负样本 {} < min_samples {}", samples.len(), self.config.min_samples),
                baseline_rate: 0.0,
                candidate_rate: 0.0,
                passed: false,
                rolled_out: false,
                prompt_hash_before: String::new(),
                prompt_hash_after: String::new(),
                feedback_id: String::new(),
            };
        }
        let baseline = self.baseline_rollback_rate(&samples);
        // 熔断（P-E lite）：基线超阈值 → 暂停 L2，不影响 L1
        if baseline > self.config.max_rollback_rate {
            tracing::warn!(
                target: "agent.meta_evolve",
                baseline = baseline,
                max = self.config.max_rollback_rate,
                "rollback_guard 触发：暂停本轮 L2 元进化"
            );
            return RolloutResult::guarded(baseline);
        }
        let cand = match self.optimize_prompt(&samples, &self.config.optimizer_model).await {
            Ok(c) => c,
            Err(e) => return RolloutResult::error(&e),
        };
        let candidate_rate = self.estimate_candidate_rate(&cand.text, &samples, baseline);
        self.rollout_if_better(&cand, baseline, candidate_rate, &samples, ns)
            .await
    }

    /// 上次元进化触发时刻（Unix 秒），供 status 展示 cooldown 状态
    pub async fn last_run_at_secs(&self) -> Option<i64> {
        self.store
            .lock()
            .await
            .get_kv("last_run_at")
            .and_then(|s| s.parse::<i64>().ok())
    }
}

// ─────────────────────────────────────────────────────────────
// 工具
// ─────────────────────────────────────────────────────────────

fn now_secs() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ═════════════════════════════════════════════════════════════
// 测试
// ═════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> Arc<Mutex<MetaEvolutionStore>> {
        Arc::new(Mutex::new(MetaEvolutionStore::open_memory().unwrap()))
    }

    fn sample(ct: &str, old: &str) -> NegSample {
        NegSample {
            change_type: ct.to_string(),
            old_value: old.to_string(),
            new_value: String::new(),
            context: String::new(),
        }
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("delete_*", "delete_entrance_record"));
        assert!(glob_match("delete_*", "delete_anything"));
        assert!(!glob_match("delete_*", "export_x"));
        assert!(glob_match("exact_tool", "exact_tool"));
        assert!(!glob_match("exact_tool", "exact_tool2"));
    }

    #[test]
    fn test_gate_classify() {
        let g = ApprovalGate::from_safety(&SafetyConfig::default(), None);
        assert!(g.is_high_risk("delete_record", None));
        assert!(g.is_high_risk("memory_evolve", Some("supersede")));
        assert!(g.is_high_risk("memory_evolve", Some("override")));
        assert!(!g.is_high_risk("memory_evolve", Some("context_update")));
        assert!(!g.is_high_risk("query_plate", None));
    }

    #[test]
    fn test_gate_auto_passes_high_risk() {
        let g = ApprovalGate::from_safety(&SafetyConfig::default(), None);
        // Auto 模式：即便高风险也放行
        assert!(g.check("delete_record", None).is_ok());
        assert!(g.check("memory_evolve", Some("supersede")).is_ok());
    }

    #[test]
    fn test_gate_human_in_loop_no_approver_rejects() {
        let mut s = SafetyConfig::default();
        s.approval_mode = ApprovalMode::HumanInLoop;
        let g = ApprovalGate::from_safety(&s, None);
        assert!(g.check("delete_record", None).is_err());
        assert!(g.check("memory_evolve", Some("supersede")).is_err());
        // 非高风险仍放行
        assert!(g.check("query_plate", None).is_ok());
    }

    #[test]
    fn test_gate_human_in_loop_with_approver_passes() {
        let mut s = SafetyConfig::default();
        s.approval_mode = ApprovalMode::HumanInLoop;
        let g = ApprovalGate::from_safety(&s, Some("op-001".to_string()));
        assert!(g.check("delete_record", None).is_ok());
    }

    #[test]
    fn test_baseline_rollback_rate() {
        let ev = MetaEvolver::new(MetaEvolutionConfig::default(), test_store(), dummy_llm(), "".into(), "".into());
        let s = vec![
            sample("rolled_back", "a"),
            sample("corrected", "b"),
            sample("rolled_back", "c"),
        ];
        assert!((ev.baseline_rollback_rate(&s) - 2.0 / 3.0).abs() < 1e-9);
        assert!((ev.baseline_rollback_rate(&[]) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_evaluate_candidate_pass_and_fail() {
        let ev = MetaEvolver::new(MetaEvolutionConfig::default(), test_store(), dummy_llm(), "".into(), "".into());
        // 相对降 50% >= 5% → 通过
        let pass = ev.evaluate_candidate(0.20, 0.10, 0.05);
        assert!(pass.passed);
        assert!((pass.delta + 0.10).abs() < 1e-9);
        // 反而升高 → 不通过
        let fail = ev.evaluate_candidate(0.20, 0.25, 0.05);
        assert!(!fail.passed);
        // 基线 0 → 视为通过
        let zero = ev.evaluate_candidate(0.0, 0.0, 0.05);
        assert!(zero.passed);
    }

    #[test]
    fn test_estimate_candidate_rate_coverage() {
        let ev = MetaEvolver::new(MetaEvolutionConfig::default(), test_store(), dummy_llm(), "".into(), "".into());
        // 2 条 rolled_back，候选包含其中 1 条的 old_value 片段 → coverage 0.5 → rate = 0.30
        let s = vec![sample("rolled_back", "value_alpha_123"), sample("rolled_back", "value_beta_456")];
        let cand = "请避免对 value_alpha 类的观察过度演化";
        let rate = ev.estimate_candidate_rate(cand, &s, 0.30);
        assert!((rate - 0.15).abs() < 1e-9, "rate={}", rate);
    }

    #[test]
    fn test_parse_negative_samples() {
        let raw = r#"{"items":[{"change_type":"rolled_back","old_value":"x","new_value":"y","context":"z"},{"change_type":"corrected","old_value":"a","new_value":"b"}]}"#;
        let s = MetaEvolver::parse_negative_samples(raw);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].change_type, "rolled_back");
        assert_eq!(s[0].old_value, "x");
        // 非法 JSON 返回空
        assert_eq!(MetaEvolver::parse_negative_samples("not json").len(), 0);
    }

    #[test]
    fn test_store_meta_prompt_roundtrip() {
        let mut s = MetaEvolutionStore::open_memory().unwrap();
        s.save_meta_prompt("prompt v2", "hash2").unwrap();
        assert_eq!(s.load_meta_prompt().unwrap(), "prompt v2");
        // 写入新版本应替换 current
        s.save_meta_prompt("prompt v3", "hash3").unwrap();
        assert_eq!(s.load_meta_prompt().unwrap(), "prompt v3");
        // 仅一条 is_current
        let cnt: i64 = s.conn.query_row("SELECT COUNT(*) FROM meta_prompt WHERE is_current=1", [], |r| r.get(0)).unwrap();
        assert_eq!(cnt, 1);
    }

    #[test]
    fn test_store_feedback() {
        let mut s = MetaEvolutionStore::open_memory().unwrap();
        let id = s.record_feedback("", "improved", "h0", "h1", "batch1", 0.2, 0.1, true).unwrap();
        assert!(!id.is_empty());
        assert_eq!(s.feedback_count(), 1);
        let latest = s.latest_feedback().unwrap();
        assert_eq!(latest["prompt_hash_after"], "h1");
        assert_eq!(latest["rolled_out"], true);
    }

    #[test]
    fn test_rollout_if_better_passed() {
        // 构造通过评估的候选，验证落账本 + 动态提示词更新（不触网）
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = test_store();
            let ev = MetaEvolver::new(MetaEvolutionConfig::default(), store.clone(), dummy_llm(), "".into(), "".into());
            let cand = CandidatePrompt { text: "避免对 value_alpha 过度演化".into(), hash: "cand1".into() };
            let samples = vec![sample("rolled_back", "value_alpha_123"), sample("rolled_back", "value_beta_456")];
            let res = ev.rollout_if_better(&cand, 0.30, 0.15, &samples, "agent/test").await;
            assert!(res.attempted);
            assert!(res.passed);
            assert!(res.rolled_out);
            // 动态提示词已更新
            let cur = { store.lock().await.load_meta_prompt().unwrap() };
            assert_eq!(cur, "避免对 value_alpha 过度演化");
            // 账本 1 条
            let cnt = { store.lock().await.feedback_count() };
            assert_eq!(cnt, 1);
        });
    }

    #[test]
    fn test_rollout_if_better_rejected() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = test_store();
            let ev = MetaEvolver::new(MetaEvolutionConfig::default(), store.clone(), dummy_llm(), "".into(), "".into());
            // candidate_rate 不降反升 → 不通过
            let cand = CandidatePrompt { text: "no improvement".into(), hash: "cand2".into() };
            let samples = vec![sample("rolled_back", "value_alpha_123")];
            let res = ev.rollout_if_better(&cand, 0.30, 0.35, &samples, "agent/test").await;
            assert!(res.attempted);
            assert!(!res.passed);
            assert!(!res.rolled_out);
            // 动态提示词仍是默认（未更新）
            let cur = { store.lock().await.load_meta_prompt() };
            assert!(cur.is_none());
            let cnt = { store.lock().await.feedback_count() };
            assert_eq!(cnt, 1);
        });
    }

    // 测试用空 LlmClient（不实际联网）
    fn dummy_llm() -> LlmClient {
        // 指向无效端点，测试不触网
        LlmClient::new(crate::llm::LlmConfig {
            base_url: "http://127.0.0.1:9".to_string(),
            model: "dummy".to_string(),
            api_key: String::new(),
            chat_path: "/v1/chat/completions".to_string(),
            max_tokens: 4096,
            temperature: 0.0,
            fallbacks: Vec::new(),
        })
    }

    #[test]
    fn test_default_evolve_prompt_nonempty() {
        assert!(!DEFAULT_EVOLVE_PROMPT.is_empty());
        assert!(DEFAULT_EVOLVE_PROMPT.contains("演化上下文"));
    }
}
