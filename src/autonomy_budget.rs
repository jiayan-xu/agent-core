//! 四预算自治封套（P0，借鉴 Prime Agent，落地设计见 tech-docs/2026-08-11_agent-core四预算自治封套落地方案.md）。
//!
//! 给进化引擎（code_evolution / meta_evolution）一个**统一运行时封套**：
//! turns / tokens / wall-clock 三维 + 可选 pass/fail gate + continuations 窗口限流。
//! 语义：0 / None = 不限制（默认宽松，向后兼容旧配置）。
//! 硬红线：本模块是**加法护栏**，绝不绕过 `resolve_isolated_target` / `x-evolve-key` /
//! `dry_run`+`allow_commit` / 签名冻结 任一既有门禁。

use std::time::{Duration, Instant};

/// 四预算自治封套。所有字段 `serde(default)`：旧配置缺整个 budget 表仍解析（向后兼容）。
/// `deny_unknown_fields`：budget 表**内**拼错键名（如 max_turn）立即报错——
/// 防「拼错 → 静默 0 → 封套失效 = 无界 LLM 消耗」（安全红线，ocr 2026-08-12 bug·medium）。
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyBudget {
    /// 本任务最大 LLM 轮次（turns）。code_evolution=提议调用次数；meta_evolution=run_once 内 LLM 调用数。0=不限制。
    #[serde(default)]
    pub max_turns: usize,
    /// 本任务累计最大 token 数（过渡期用 chars/4 估算，见方案 §6）。0=不限制。
    #[serde(default)]
    pub max_tokens: u64,
    /// 本任务硬墙钟上限（秒）。超时立即停 + 回退 + 审计。0=不限制。
    #[serde(default)]
    pub max_wall_clock_secs: u64,
    /// 滚动窗口内允许的最大「续跑/触发」次数（continuations）。0=不限制。
    #[serde(default)]
    pub max_continuations_per_window: u32,
    /// 续跑窗口（秒），与 max_continuations_per_window 配合。
    #[serde(default)]
    pub continuation_window_secs: u64,
    /// 可选 pass/fail gate：任务结束前运行的 shell 命令，非 0 退出则整体否决 + 回退。
    #[serde(default)]
    pub gate_command: Option<String>,
}

impl Default for AutonomyBudget {
    /// 默认宽松：全 0 = 不限制（与「预算封套是叠加层、默认不开闸」的纪律一致）。
    fn default() -> Self {
        Self {
            max_turns: 0,
            max_tokens: 0,
            max_wall_clock_secs: 0,
            max_continuations_per_window: 0,
            continuation_window_secs: 0,
            gate_command: None,
        }
    }
}

impl AutonomyBudget {
    /// 是否完全未配置（全 0 / None）——用于「未开闸」判定与日志。
    /// **全部** 6 项均为默认值才判未开闸（含成对的 continuation_window_secs——
    /// 窗口非 0 而次数为 0 仍是「配了窗口但无限流」的异常组合，不视为未开闸；
    /// ocr 2026-08-12 bug·low/bug·medium：doc 与实现对齐）。
    pub fn is_unset(&self) -> bool {
        self.max_turns == 0
            && self.max_tokens == 0
            && self.max_wall_clock_secs == 0
            && self.max_continuations_per_window == 0
            && self.continuation_window_secs == 0
            && self.gate_command.is_none()
    }
}

/// 运行时追踪器（每个 evolve 任务一个实例）。
pub struct BudgetTracker {
    start: Instant,
    turns: usize,
    tokens: u64,
    budget: AutonomyBudget,
}

/// 违约类型。调用方须立即停止并按 §5 违约语义处理（回退 + 审计）。
/// 说明（ocr 2026-08-12 第四轮 maintainability·medium）：`Continuations` 由
/// 触发器层（run_meta_evolution 的窗口限流）直接判定并以 JSON skipped 返回，
/// 不经 BudgetTracker（tracker 只管 turns/tokens/wall-clock/gate 四项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetBreach {
    Turns,
    Tokens,
    WallClock,
    Gate,
    Continuations,
}

impl BudgetTracker {
    pub fn new(budget: AutonomyBudget) -> Self {
        Self {
            start: Instant::now(),
            turns: 0,
            tokens: 0,
            budget,
        }
    }

    /// 每次 LLM 轮次后调用；返回 Err 即违约，调用方须立即停止并回退。
    pub fn record_turn(&mut self, tokens: u64) -> Result<(), BudgetBreach> {
        self.turns += 1;
        self.tokens += tokens;
        if self.budget.max_turns > 0 && self.turns > self.budget.max_turns {
            return Err(BudgetBreach::Turns);
        }
        if self.budget.max_tokens > 0 && self.tokens > self.budget.max_tokens {
            return Err(BudgetBreach::Tokens);
        }
        if self.budget.max_wall_clock_secs > 0
            && self.start.elapsed() > Duration::from_secs(self.budget.max_wall_clock_secs)
        {
            return Err(BudgetBreach::WallClock);
        }
        Ok(())
    }

    /// 仅在循环顶部做纯墙钟检查（不消耗 turn）。
    pub fn check_wall_clock(&self) -> Result<(), BudgetBreach> {
        if self.budget.max_wall_clock_secs > 0
            && self.start.elapsed() > Duration::from_secs(self.budget.max_wall_clock_secs)
        {
            return Err(BudgetBreach::WallClock);
        }
        Ok(())
    }

    /// 生成 `Gate` 违约（供调用方在 gate_command 非 0 退出时统一语义）。
    /// gate 执行本身在调用方（handler 层需要 repo 上下文与异步进程），
    /// 本方法保证违约类型从单一来源构造（ocr 2026-08-12 bug·high：此前
    /// BudgetBreach::Gate 声明但无从构造，语义悬空）。
    pub fn gate_failed() -> BudgetBreach {
        BudgetBreach::Gate
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }

    pub fn turns_used(&self) -> usize {
        self.turns
    }

    pub fn tokens_used(&self) -> u64 {
        self.tokens
    }

    pub fn budget(&self) -> &AutonomyBudget {
        &self.budget
    }

    /// 测试专用构造：可控 start 时刻（墙钟 breach 路径可测，ocr 2026-08-12 test·medium）
    #[cfg(test)]
    pub(crate) fn new_with_start(budget: AutonomyBudget, start: Instant) -> Self {
        Self {
            start,
            turns: 0,
            tokens: 0,
            budget,
        }
    }
}

/// 过渡期 token 估算（方案 §6）：真实 usage 未打通前用 chars/4 近似。
/// 仅用于预算记账，不参与任何协议字段。
pub fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() / 4) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budget_is_unset() {
        assert!(AutonomyBudget::default().is_unset());
    }

    #[test]
    fn turns_breach() {
        let mut t = BudgetTracker::new(AutonomyBudget {
            max_turns: 2,
            ..Default::default()
        });
        assert!(t.record_turn(10).is_ok());
        assert!(t.record_turn(10).is_ok());
        assert_eq!(t.record_turn(10), Err(BudgetBreach::Turns));
    }

    #[test]
    fn tokens_breach() {
        let mut t = BudgetTracker::new(AutonomyBudget {
            max_tokens: 100,
            ..Default::default()
        });
        assert!(t.record_turn(60).is_ok());
        assert_eq!(t.record_turn(50), Err(BudgetBreach::Tokens)); // 60+50=110 > 100 → 违约
        assert_eq!(t.record_turn(1), Err(BudgetBreach::Tokens));
    }

    #[test]
    fn wall_clock_breach() {
        // 用可控 start 构造：start 早于 max_wall_clock_secs 对应时长 → 立即违约。
        // checked_sub 防单调钟刚启动（elapsed < 10s）时 underflow panic（ocr 第四轮 test·low）
        let old_start = match Instant::now().checked_sub(Duration::from_secs(10)) {
            Some(s) => s,
            None => return, // 单调钟运行不足 10s（极罕见），跳过
        };
        let t = BudgetTracker::new_with_start(
            AutonomyBudget {
                max_wall_clock_secs: 1,
                ..Default::default()
            },
            old_start,
        );
        assert_eq!(t.check_wall_clock(), Err(BudgetBreach::WallClock));
        // record_turn 内也做墙钟检查
        let mut t2 = BudgetTracker::new_with_start(
            AutonomyBudget {
                max_wall_clock_secs: 1,
                ..Default::default()
            },
            old_start,
        );
        assert_eq!(t2.record_turn(1), Err(BudgetBreach::WallClock));
    }

    #[test]
    fn ok_path_counts_turns_and_tokens() {
        let mut t = BudgetTracker::new(AutonomyBudget {
            max_turns: 10,
            max_tokens: 1000,
            ..Default::default()
        });
        for _ in 0..3 {
            assert!(t.record_turn(100).is_ok());
        }
        assert_eq!(t.turns_used(), 3);
        assert_eq!(t.tokens_used(), 300);
        // 墙钟合理性：3 次 record_turn 应在秒级内完成（防 elapsed 语义回归，ocr 第四轮 test·low）
        assert!(t.elapsed_secs() < 60, "elapsed_secs 异常: {}", t.elapsed_secs());
    }

    #[test]
    fn estimate_tokens_approximation() {
        // "abcd" 4 chars → 1 token
        assert_eq!(estimate_tokens("abcd"), 1);
        // 中文 4 chars → 1 token
        assert_eq!(estimate_tokens("固废监管"), 1);
    }

    #[test]
    fn misspelled_key_rejected() {
        // 安全红线：budget 表内拼错键名（max_turn 缺 s）必须解析失败，
        // 防「拼错 → 静默 0 → 封套失效」（ocr 2026-08-12 bug·medium）
        let toml = r#"
max_turn = 8
"#;
        let r: Result<AutonomyBudget, _> = toml::from_str(toml);
        assert!(r.is_err(), "拼错键名必须拒绝解析: {:?}", r);
    }
}

#[cfg(test)]
mod serde_probe_tests {
    use super::*;

    #[test]
    fn budget_top_level_keys_parse() {
        // 直接反序列化 AutonomyBudget 时键在顶层；嵌套表场景由 CodeEvolutionConfig
        // 的 [code_evolution.budget] 测试覆盖（config.rs budget_serde_tests）
        let toml = r#"
max_turns = 8
max_tokens = 200000
max_wall_clock_secs = 300
max_continuations_per_window = 5
continuation_window_secs = 3600
gate_command = "cargo test"
"#;
        let b: AutonomyBudget = toml::from_str(toml).expect("顶层键应解析");
        assert_eq!(b.max_turns, 8, "max_turns 应解析为 8, got {}", b.max_turns);
        assert_eq!(b.max_tokens, 200_000);
        assert_eq!(b.max_wall_clock_secs, 300);
        assert_eq!(b.max_continuations_per_window, 5);
        assert_eq!(b.continuation_window_secs, 3600);
        assert_eq!(b.gate_command.as_deref(), Some("cargo test"));
    }
}
