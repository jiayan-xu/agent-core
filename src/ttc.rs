//! HY3 TTC —— 推理时计算（test-time compute）：终答自一致性 + 预算感知采样。
//!
//! 定位：在「终答轮」（无工具调用、直接回复用户）上做 N 路采样 + 选择器择优，
//! 与 LATS（过程树）分层：LATS=过程，TTC=终答。已有 BoN 分支（`RoutedLlm::chat`）
//! 被 `tools.is_empty()` 关在生产路径外，TTC 显式接管终答轮，使其真正生效。
//!
//! 门控：仅 `features.ttc = true` 时 `AgentCore` 持有 `TtcController`；否则
//! `llm_loop` 终答轮走原单次调用，零改动。启用时带 **单次请求 token 预算上限**
//! （`token_budget`），超预算自动回退单次（原行为），避免成本失控。

use serde::{Deserialize, Serialize};

use crate::llm::ScorerMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtcConfig {
    /// 真正生效还需 features.ttc=true
    #[serde(default)]
    pub enabled: bool,
    /// 终答采样数（>=2 开启；默认 3）
    #[serde(default = "default_n")]
    pub best_of_n: usize,
    /// 选择器：Judge（相对排序打分）/ Heuristic（零额外调用）/ Majority（自一致性投票）
    #[serde(default = "default_scorer")]
    pub scorer: ScorerMode,
    /// 采样温度（默认 0.7，制造多样性）
    #[serde(default = "default_temp")]
    pub sample_temperature: f64,
    /// 单次终答请求的额外 token 预算上限（估算 = (ctx_chars/4) * best_of_n）；超限回退单次
    #[serde(default = "default_budget")]
    pub token_budget: u64,
    /// verifier-guided 生成：终答后用 judge（judge_provider）或主模型自评打分，
    /// 不通过（< verifier_threshold）则带批评反馈重新生成，最多 max_refine_rounds 轮。
    /// 默认 false —— 与自一致性（sample）正交，可单独或叠加开启。
    #[serde(default)]
    pub verifier_enabled: bool,
    /// 最多精炼轮数（生成 → 验证 → 重生成 循环）
    #[serde(default = "default_refine_rounds")]
    pub max_refine_rounds: usize,
    /// judge 分数阈值（0-10）；>= 阈值视为通过
    #[serde(default = "default_verifier_threshold")]
    pub verifier_threshold: f64,
}

fn default_n() -> usize {
    3
}
fn default_scorer() -> ScorerMode {
    ScorerMode::Majority
}
fn default_temp() -> f64 {
    0.7
}
fn default_budget() -> u64 {
    8000
}
fn default_refine_rounds() -> usize {
    2
}
fn default_verifier_threshold() -> f64 {
    7.0
}

impl Default for TtcConfig {
    fn default() -> Self {
        TtcConfig {
            enabled: false,
            best_of_n: default_n(),
            scorer: default_scorer(),
            sample_temperature: default_temp(),
            token_budget: default_budget(),
            verifier_enabled: false,
            max_refine_rounds: default_refine_rounds(),
            verifier_threshold: default_verifier_threshold(),
        }
    }
}

/// TTC 决策：采样 or 退回单次
pub enum TtcAction {
    Sample,
    Greedy,
}

/// TTC 控制器（持有配置；预算熔断在 `RoutedLlm::chat_ttc` 内按请求的 token_budget 做）
pub struct TtcController {
    cfg: TtcConfig,
}

impl TtcController {
    pub fn new(cfg: TtcConfig) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &TtcConfig {
        &self.cfg
    }

    /// 是否应对终答做 TTC 采样：未启用 → 退回单次
    pub fn decide(&self) -> TtcAction {
        if !self.cfg.enabled {
            return TtcAction::Greedy;
        }
        TtcAction::Sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_is_greedy() {
        let c = TtcController::new(TtcConfig {
            enabled: false,
            ..Default::default()
        });
        assert!(matches!(c.decide(), TtcAction::Greedy));
    }

    #[test]
    fn enabled_is_sample() {
        let c = TtcController::new(TtcConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(matches!(c.decide(), TtcAction::Sample));
    }

    #[test]
    fn default_off() {
        assert!(!TtcConfig::default().enabled);
        assert_eq!(TtcConfig::default().best_of_n, 3);
        assert!(matches!(TtcConfig::default().scorer, ScorerMode::Majority));
    }
}
