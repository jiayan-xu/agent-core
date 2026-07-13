//! P2-1：命名空间级配额与成本管控
//!
//! 按「调用者命名空间」(caller ns) 维度记账，提供三层配额：
//! - `max_tool_rounds`：每命名空间当日工具调用轮次上限
//! - `daily_token_budget`：每命名空间当日 token 预算（估算 = 字符数 / 4）
//! - `max_concurrent_sessions`：每命名空间并发会话上限
//!
//! 超限硬拒绝 + 审计。管理员可经 `/api/admin/quota` 临时调整某 ns 策略。
//! 配额存储与 AgentCore 解耦，单测可独立覆盖（见模块底部 `#[cfg(test)]`）。

use std::collections::HashMap;

use serde::Serialize;

/// 每命名空间配额策略
#[derive(Debug, Clone, Serialize)]
pub struct NsQuotaPolicy {
    /// 当日工具调用轮次上限
    pub max_tool_rounds: u32,
    /// 当日 token 预算（估算单位：字符数 / 4）
    pub daily_token_budget: u64,
    /// 并发会话上限
    pub max_concurrent_sessions: u32,
}

impl Default for NsQuotaPolicy {
    fn default() -> Self {
        NsQuotaPolicy {
            max_tool_rounds: DEFAULT_MAX_TOOL_ROUNDS,
            daily_token_budget: DEFAULT_DAILY_TOKEN_BUDGET,
            max_concurrent_sessions: DEFAULT_MAX_CONCURRENT_SESSIONS,
        }
    }
}

/// 每命名空间当日用量
#[derive(Debug, Clone, Serialize, Default)]
pub struct NsQuotaUsage {
    /// 记账日（YYYY-MM-DD），跨天自动重置
    pub day: String,
    /// 当日工具调用轮次
    pub tool_rounds: u32,
    /// 当日已用 token（估算）
    pub token_used: u64,
    /// 当前活跃会话数
    pub active_sessions: u32,
}

impl NsQuotaUsage {
    fn new(day: String) -> Self {
        NsQuotaUsage {
            day,
            ..Default::default()
        }
    }

    fn reset(&mut self, day: String) {
        self.day = day;
        self.tool_rounds = 0;
        self.token_used = 0;
        self.active_sessions = 0;
    }
}

/// 默认配额常量（可在 `agent.toml` 经未来配置项覆盖；当前以代码常量兜底）
pub const DEFAULT_MAX_TOOL_ROUNDS: u32 = 16;
pub const DEFAULT_DAILY_TOKEN_BUDGET: u64 = 500_000;
pub const DEFAULT_MAX_CONCURRENT_SESSIONS: u32 = 8;

/// 配额存储：per-ns 策略 + per-ns 用量
pub struct NsQuotaStore {
    policies: HashMap<String, NsQuotaPolicy>,
    usage: HashMap<String, NsQuotaUsage>,
    default_policy: NsQuotaPolicy,
}

impl NsQuotaStore {
    pub fn new() -> Self {
        NsQuotaStore {
            policies: HashMap::new(),
            usage: HashMap::new(),
            default_policy: NsQuotaPolicy::default(),
        }
    }

    fn today() -> String {
        chrono::Local::now().format("%Y-%m-%d").to_string()
    }

    /// 设置某命名空间的配额策略（管理员接口）
    pub fn set_policy(&mut self, ns: &str, policy: NsQuotaPolicy) {
        self.policies.insert(ns.to_string(), policy);
    }

    /// 读取某命名空间配额策略（无则回默认）
    pub fn get_policy(&self, ns: &str) -> NsQuotaPolicy {
        self.policies
            .get(ns)
            .cloned()
            .unwrap_or_else(|| self.default_policy.clone())
    }

    fn usage_mut(&mut self, ns: &str) -> &mut NsQuotaUsage {
        let today = Self::today();
        let u = self
            .usage
            .entry(ns.to_string())
            .or_insert_with(|| NsQuotaUsage::new(today.clone()));
        if u.day != today {
            u.reset(today);
        }
        u
    }

    /// 检查并累加工具轮次；超限返回 Err（调用方硬拒 + 审计）
    pub fn check_tool_round(&mut self, ns: &str) -> Result<(), String> {
        let policy = self.get_policy(ns);
        let u = self.usage_mut(ns);
        if u.tool_rounds >= policy.max_tool_rounds {
            return Err(format!(
                "已达当日工具轮次上限 {}（已用 {}）",
                policy.max_tool_rounds, u.tool_rounds
            ));
        }
        u.tool_rounds += 1;
        Ok(())
    }

    /// 检查日 token 预算是否足够（`additional` 为本次预估增量）；不足返回 Err
    pub fn check_token_budget(&mut self, ns: &str, additional: u64) -> Result<(), String> {
        let policy = self.get_policy(ns);
        let u = self.usage_mut(ns);
        if u.token_used + additional > policy.daily_token_budget {
            return Err(format!(
                "当日 token 预算 {} 已用尽（已用 {} + 预计 {}）",
                policy.daily_token_budget, u.token_used, additional
            ));
        }
        Ok(())
    }

    /// 记录已消耗的 token（跨天自动重置）
    pub fn record_token(&mut self, ns: &str, tokens: u64) {
        let u = self.usage_mut(ns);
        u.token_used += tokens;
    }

    /// 进入会话：检查并发上限并 +1；成功返回 `()`，失败返回 Err（调用方硬拒）
    pub fn enter_session(&mut self, ns: &str) -> Result<(), String> {
        let policy = self.get_policy(ns);
        let u = self.usage_mut(ns);
        if u.active_sessions >= policy.max_concurrent_sessions {
            return Err(format!(
                "并发会话已达上限 {}（活跃 {}）",
                policy.max_concurrent_sessions, u.active_sessions
            ));
        }
        u.active_sessions += 1;
        Ok(())
    }

    /// 离开会话：活跃会话 -1（饱和下界）
    pub fn leave_session(&mut self, ns: &str) {
        let today = Self::today();
        if let Some(u) = self.usage.get_mut(ns) {
            if u.day != today {
                return; // 跨天已重置，无需再减
            }
            u.active_sessions = u.active_sessions.saturating_sub(1);
        }
    }

    /// 只读快照，供 `/api/metrics` 与 `/api/admin/quota` 返回
    pub fn status(&self) -> serde_json::Value {
        let today = Self::today();
        let mut ns_list: Vec<serde_json::Value> = Vec::new();
        for (ns, u) in &self.usage {
            let policy = self.get_policy(ns);
            ns_list.push(serde_json::json!({
                "namespace": ns,
                "day": u.day,
                "tool_rounds": u.tool_rounds,
                "tool_rounds_limit": policy.max_tool_rounds,
                "token_used": u.token_used,
                "token_budget": policy.daily_token_budget,
                "active_sessions": u.active_sessions,
                "max_concurrent_sessions": policy.max_concurrent_sessions,
            }));
        }
        // 已显式配置策略的命名空间（未必已有用量记录，仍需在管理视图可见）
        let mut configured: Vec<serde_json::Value> = self
            .policies
            .iter()
            .map(|(ns, p)| {
                serde_json::json!({
                    "namespace": ns,
                    "max_tool_rounds": p.max_tool_rounds,
                    "daily_token_budget": p.daily_token_budget,
                    "max_concurrent_sessions": p.max_concurrent_sessions,
                })
            })
            .collect();
        configured.sort_by(|a, b| {
            a.get("namespace")
                .and_then(|v| v.as_str())
                .cmp(&b.get("namespace").and_then(|v| v.as_str()))
        });
        serde_json::json!({
            "default_policy": {
                "max_tool_rounds": self.default_policy.max_tool_rounds,
                "daily_token_budget": self.default_policy.daily_token_budget,
                "max_concurrent_sessions": self.default_policy.max_concurrent_sessions,
            },
            "configured_policies": configured,
            "namespaces": ns_list,
            "today": today,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_rounds_enforce_and_reset_on_new_day() {
        let mut s = NsQuotaStore::new();
        for _ in 0..DEFAULT_MAX_TOOL_ROUNDS {
            assert!(s.check_tool_round("ns/a").is_ok());
        }
        // 第 N+1 次应被拒
        assert!(s.check_tool_round("ns/a").is_err());
        // 模拟跨天：手动改 day 后下次调用应重置
        s.usage.get_mut("ns/a").unwrap().day = "2000-01-01".to_string();
        assert!(s.check_tool_round("ns/a").is_ok());
    }

    #[test]
    fn token_budget_blocks_when_exhausted() {
        let mut s = NsQuotaStore::new();
        assert!(s.check_token_budget("ns/b", 100).is_ok());
        s.record_token("ns/b", 100);
        // 预算默认 500_000，再要 600_000 必超
        assert!(s.check_token_budget("ns/b", 600_000).is_err());
        assert!(s.check_token_budget("ns/b", 100).is_ok());
    }

    #[test]
    fn session_concurrency_limit() {
        let mut s = NsQuotaStore::new();
        for _ in 0..DEFAULT_MAX_CONCURRENT_SESSIONS {
            assert!(s.enter_session("ns/c").is_ok());
        }
        assert!(s.enter_session("ns/c").is_err());
        s.leave_session("ns/c");
        assert!(s.enter_session("ns/c").is_ok());
    }

    #[test]
    fn policy_override_applies() {
        let mut s = NsQuotaStore::new();
        s.set_policy(
            "ns/d",
            NsQuotaPolicy {
                max_tool_rounds: 2,
                ..Default::default()
            },
        );
        assert!(s.check_tool_round("ns/d").is_ok());
        assert!(s.check_tool_round("ns/d").is_ok());
        assert!(s.check_tool_round("ns/d").is_err());
    }
}
