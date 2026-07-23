//! HY3 1.3 —— LATS 过程树搜索（挂在 `agent.execute_chat` 工具轨迹循环）。
//!
//! 定位：LATS（Language Agent Tree Search）对「过程」做树搜索（展开候选下一步 →
//! 评估 → 回溯择优），与 BoN（终答 N 选 1）分层。它**不**替换 `RoutedLlm::chat`
//! 的终答层，而是增强 agent 在调用工具前的规划。
//!
//! 门控：仅 `features.lats = true` 时 `AgentCore` 才持有 `LatsController`；否则
//! `maybe_lats_expand` 直接返回，原路径零改动。即便启用，也带 **日 token 预算
//! 熔断**：预算耗尽自动退回贪心（原行为），避免失控成本。
//!
//! 当前实现：多步过程树搜索（`best_plan` 用 beam 搜索从根向下展开 ≤max_depth 层，
//! 每层 ≤max_branches 候选「下一步」，由价值网络 `value_estimator` 打分引导回溯剪枝，
//! 选价值累计最高的路径作为多步规划提示注入）。默认 heuristic 价值网络零成本；
//! 可选 judge 模式复用 judge_provider 当价值估计器。

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::llm::{LlmClient, Message, ToolDef};

/// 价值网络评估方式：对过程树候选「下一步」打分，引导 beam 回溯择优。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValueEstimatorMode {
    /// 本地启发式（关键词加权），零成本、不依赖 judge_provider（默认）
    #[serde(rename = "heuristic")]
    Heuristic,
    /// 用 judge_provider 当价值估计器打分 0-1（需配置 judge_provider，否则降级 heuristic）
    #[serde(rename = "judge")]
    Judge,
}

impl Default for ValueEstimatorMode {
    fn default() -> Self {
        ValueEstimatorMode::Heuristic
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatsConfig {
    /// 是否在编译期武装（真正生效还需 AgentConfig.features.lats=true）
    #[serde(default)]
    pub enabled: bool,
    /// 过程树最大深度（beam 搜索展开层数，默认 3）
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    /// 每层最大分支数（候选「下一步」条数）
    #[serde(default = "default_max_branches")]
    pub max_branches: usize,
    /// 日 token 预算（估算，进程内计数；跨进程/跨天重置由上层配额负责）
    #[serde(default = "default_budget")]
    pub daily_token_budget: u64,
    /// 价值网络评估方式（默认 heuristic，零成本、不依赖 judge_provider）
    #[serde(default)]
    pub value_estimator: ValueEstimatorMode,
    /// Beam 搜索宽度：每层保留价值最高的 top-k 候选继续向下展开（>=1，默认 2）
    #[serde(default = "default_beam")]
    pub beam_width: usize,
}

fn default_max_depth() -> usize {
    3
}
fn default_max_branches() -> usize {
    3
}
fn default_budget() -> u64 {
    200_000
}
fn default_beam() -> usize {
    2
}

impl Default for LatsConfig {
    fn default() -> Self {
        LatsConfig {
            enabled: false,
            max_depth: default_max_depth(),
            max_branches: default_max_branches(),
            daily_token_budget: default_budget(),
            value_estimator: ValueEstimatorMode::default(),
            beam_width: default_beam(),
        }
    }
}

/// LATS 决策：搜索 or 退回贪心
pub enum LatsAction {
    Search,
    Greedy,
}

/// LATS 控制器（持有日 token 用量，用于熔断）
pub struct LatsController {
    cfg: LatsConfig,
    used: Mutex<u64>,
}

impl LatsController {
    pub fn new(cfg: LatsConfig) -> Self {
        Self {
            cfg,
            used: Mutex::new(0),
        }
    }

    /// 是否应展开搜索：未启用或预算耗尽 → 贪心（原行为）
    pub fn decide(&self) -> LatsAction {
        if !self.cfg.enabled {
            return LatsAction::Greedy;
        }
        let used = *self.used.lock().unwrap_or_else(|p| p.into_inner());
        if used >= self.cfg.daily_token_budget {
            tracing::warn!(
                target = "agent.lats",
                lats = "circuit_breaker",
                reason = "daily_token_budget_exhausted",
                "LATS 退回贪心（预算耗尽）"
            );
            return LatsAction::Greedy;
        }
        LatsAction::Search
    }

    /// 记录 token 消耗（请求 + 响应估算）
    pub fn record_tokens(&self, n: u64) {
        if let Ok(mut u) = self.used.lock() {
            *u += n;
        }
    }

    /// 当前价值网络模式（getter，供调用方在 shallow/judge 路径间选择）
    pub fn value_estimator(&self) -> ValueEstimatorMode {
        self.cfg.value_estimator
    }

    /// 浅层过程树展开：用 LLM 生成 ≤max_branches 个候选「下一步」并返回。
    /// 失败返回空（调用方据此不注入，退回原路径）。
    pub async fn expand_once(&self, llm: &LlmClient, ctx: &str) -> Vec<String> {
        let prompt = format!(
            "给定任务上下文：\n{}\n\n请列出至多 {} 个可行的「下一步执行动作」（每行一个，简短动词开头），\
             用于过程树搜索候选。只输出候选行，不要解释。",
            ctx, self.cfg.max_branches
        );
        match llm
            .chat(
                &[Message {
                    role: "user".to_string(),
                    content: Some(prompt),
                    tool_calls: None,
                    tool_call_id: None,
                }],
                &[] as &[ToolDef],
            )
            .await
        {
            Ok(r) => r
                .text
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .take(self.cfg.max_branches)
                .collect(),
            Err(e) => {
                tracing::warn!(target = "agent.lats", "LATS expand_once 失败: {}", e);
                Vec::new()
            }
        }
    }

    /// 启发式价值：命中高价值动作词加权，归一化到 0-1（零成本，不调 LLM）。
    fn heuristic_value(&self, step: &str) -> f64 {
        let high = [
            "检索", "查询", "查找", "搜索", "分析", "验证", "检查", "核对", "计算", "推导",
            "规划", "分解", "对比", "汇总", "试验", "调用", "读取", "提取", "获取",
        ];
        let low = ["直接回答", "输出", "告诉", "回复", "总结一下", "直接说"];
        let hit_high = high.iter().filter(|k| step.contains(*k)).count() as f64;
        let hit_low = low.iter().filter(|k| step.contains(*k)).count() as f64;
        let raw = (hit_high * 0.34) - (hit_low * 0.15);
        (0.5 + raw).clamp(0.0, 1.0)
    }

    /// 价值网络：评估单个候选「下一步」对完成任务的价值（0-1）。
    /// Heuristic：关键词加权（零成本）；Judge：用 value_client 打分，None 时降级 heuristic。
    async fn estimate_value(
        &self,
        value_client: Option<&LlmClient>,
        ctx: &str,
        step: &str,
    ) -> f64 {
        match (self.cfg.value_estimator, value_client) {
            (ValueEstimatorMode::Judge, Some(jc)) => {
                let prompt = format!(
                    "请评估以下「下一步执行动作」对完成整体任务的价值，仅输出 0 到 1 之间的小数（不要解释）。\n\
                     整体任务：{}\n候选动作：{}\n价值分数：",
                    ctx, step
                );
                match jc
                    .chat(
                        &[Message {
                            role: "user".to_string(),
                            content: Some(prompt),
                            tool_calls: None,
                            tool_call_id: None,
                        }],
                        &[] as &[ToolDef],
                    )
                    .await
                {
                    Ok(r) => {
                        let v = r
                            .text
                            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
                            .filter_map(|s| s.parse::<f64>().ok())
                            .next();
                        let score = v.unwrap_or_else(|| self.heuristic_value(step));
                        self.record_tokens((r.text.len() / 4) as u64);
                        score.clamp(0.0, 1.0)
                    }
                    Err(e) => {
                        tracing::warn!(target = "agent.lats", "LATS judge value 失败: {}", e);
                        self.heuristic_value(step)
                    }
                }
            }
            _ => self.heuristic_value(step),
        }
    }

    /// 多步过程树搜索：beam 从根向下展开 ≤max_depth 层，每层 ≤max_branches 候选，
    /// 价值网络打分引导回溯剪枝，返回累计价值最高的多步规划路径文本（根→…→叶）。
    /// `value_client=None` → 强制 heuristic 价值网络（零成本）；传 judge client 启用 judge 模式。
    /// 失败或空树返回 None（调用方据此不注入，退回原路径）。
    pub async fn best_plan(
        &self,
        llm: &LlmClient,
        ctx: &str,
        value_client: Option<&LlmClient>,
    ) -> Option<String> {
        // paths: (步骤序列, 累计价值)
        let mut paths: Vec<(Vec<String>, f64)> = vec![(Vec::new(), 0.0)];
        for _depth in 1..=self.cfg.max_depth {
            let mut next: Vec<(Vec<String>, f64)> = Vec::new();
            for (steps, acc) in &paths {
                let context = if steps.is_empty() {
                    ctx.to_string()
                } else {
                    format!("{}\n\n已有规划步骤：\n{}", ctx, steps.join("\n"))
                };
                let candidates = self.expand_once(llm, &context).await;
                for c in candidates {
                    let v = self.estimate_value(value_client, ctx, &c).await;
                    let mut ns = steps.clone();
                    ns.push(c);
                    next.push((ns, acc + v));
                }
            }
            if next.is_empty() {
                break;
            }
            next.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            paths = next.into_iter().take(self.cfg.beam_width).collect();
        }
        paths.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let best = paths.first()?;
        if best.0.is_empty() {
            return None;
        }
        let plan = best
            .0
            .iter()
            .enumerate()
            .map(|(i, s)| format!("{}. {}", i + 1, s))
            .collect::<Vec<_>>()
            .join("\n");
        Some(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_is_greedy() {
        let c = LatsController::new(LatsConfig {
            enabled: false,
            ..Default::default()
        });
        assert!(matches!(c.decide(), LatsAction::Greedy));
    }

    #[test]
    fn budget_exhausted_is_greedy() {
        let c = LatsController::new(LatsConfig {
            enabled: true,
            daily_token_budget: 10,
            ..Default::default()
        });
        c.record_tokens(20);
        assert!(matches!(c.decide(), LatsAction::Greedy));
    }

    #[test]
    fn enabled_under_budget_searches() {
        let c = LatsController::new(LatsConfig {
            enabled: true,
            daily_token_budget: 1000,
            ..Default::default()
        });
        assert!(matches!(c.decide(), LatsAction::Search));
    }

    #[test]
    fn default_value_estimator_is_heuristic() {
        assert!(matches!(
            ValueEstimatorMode::default(),
            ValueEstimatorMode::Heuristic
        ));
    }

    #[test]
    fn heuristic_value_favors_high_value_action() {
        let c = LatsController::new(LatsConfig::default());
        let high = c.heuristic_value("检索相关文档并分析差异");
        let low = c.heuristic_value("直接回答用户即可");
        assert!(
            high > low,
            "heuristic 应给高价值动作更高分 ({} vs {})",
            high, low
        );
        assert!((0.0..=1.0).contains(&high));
        assert!((0.0..=1.0).contains(&low));
    }
}
