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
//! 当前实现：浅层单步展开（`expand_once` 用 LLM 生成 ≤max_branches 个候选「下一步」，
//! 取最优者作为规划提示注入）。多层回溯 / 价值网络留待 G 门复验后再深化。

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::llm::{LlmClient, Message, ToolDef};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatsConfig {
    /// 是否在编译期武装（真正生效还需 AgentConfig.features.lats=true）
    #[serde(default)]
    pub enabled: bool,
    /// 过程树最大深度（当前浅层实现仅用第 1 层，保留供深化）
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    /// 每层最大分支数（候选「下一步」条数）
    #[serde(default = "default_max_branches")]
    pub max_branches: usize,
    /// 日 token 预算（估算，进程内计数；跨进程/跨天重置由上层配额负责）
    #[serde(default = "default_budget")]
    pub daily_token_budget: u64,
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

impl Default for LatsConfig {
    fn default() -> Self {
        LatsConfig {
            enabled: false,
            max_depth: default_max_depth(),
            max_branches: default_max_branches(),
            daily_token_budget: default_budget(),
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
}
