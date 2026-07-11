//! P1-5 降级收缩状态机
//!
//! 把「降级收缩」显式化为可观测的状态机，避免故障时裸崩或无限重试：
//!
//! | 触发 | 行为 |
//! |------|------|
//! | 某 MCP 源连续失败 | 标记 source unhealthy，工具列表剔除，审计 |
//! | 全部业务 MCP 不可用 | 仅保留 Memoria 只读记忆检索 + 纯聊天（[`DegradeMode::MemoriaReadonlyChat`]） |
//! | LLM 主 provider 超时 | failover 切备用（[`crate::llm`] 已做）；仍失败 → 可重试错误（见 `agent.rs` llm_loop） |
//! | Kill switch | 全局拒绝工具，仅系统状态查询（[`DegradeMonitor::set_kill_switch`]） |

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// 连续失败阈值：超过即标记源 unhealthy 并剔除其工具
pub const UNHEALTHY_THRESHOLD: u32 = 3;

/// 降级模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradeMode {
    /// 正常
    Normal,
    /// 部分业务源不健康（已剔除其工具，其余正常）
    SourceDegraded,
    /// 全部业务 MCP 不可用：仅保留 Memoria 只读记忆检索 + 纯聊天
    MemoriaReadonlyChat,
    /// Kill switch：全局拒绝工具，仅系统状态查询
    KillSwitch,
}

impl DegradeMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DegradeMode::Normal => "normal",
            DegradeMode::SourceDegraded => "source_degraded",
            DegradeMode::MemoriaReadonlyChat => "memoria_readonly_chat",
            DegradeMode::KillSwitch => "kill_switch",
        }
    }
}

/// 单源健康度（用 Arc<Atomic> 以便跨 McpSource 克隆共享同一状态）
#[derive(Clone)]
pub struct SourceHealth {
    pub consecutive_failures: Arc<AtomicU32>,
    pub unhealthy: Arc<AtomicBool>,
    pub last_error: Arc<Mutex<Option<String>>>,
}

impl SourceHealth {
    pub fn new() -> Self {
        SourceHealth {
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            unhealthy: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(Mutex::new(None)),
        }
    }

    /// 记录一次失败，返回是否「刚刚跨过阈值变为 unhealthy」
    pub fn record_failure(&self, err: &str) -> bool {
        if let Ok(mut le) = self.last_error.lock() {
            *le = Some(err.to_string());
        }
        let n = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if n >= UNHEALTHY_THRESHOLD && !self.unhealthy.load(Ordering::SeqCst) {
            self.unhealthy.store(true, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// 记录一次成功：重置计数器并恢复健康
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        self.unhealthy.store(false, Ordering::SeqCst);
        if let Ok(mut le) = self.last_error.lock() {
            *le = None;
        }
    }

    pub fn is_unhealthy(&self) -> bool {
        self.unhealthy.load(Ordering::SeqCst)
    }

    pub fn failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::SeqCst)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|g| g.clone())
    }
}

/// 降级监视器（[`crate::agent::AgentCore`] 持有）
pub struct DegradeMonitor {
    /// 源名 → 健康度
    health: Mutex<HashMap<String, SourceHealth>>,
    /// Kill switch（全局）
    kill_switch: AtomicBool,
}

impl DegradeMonitor {
    pub fn new() -> Self {
        DegradeMonitor {
            health: Mutex::new(HashMap::new()),
            kill_switch: AtomicBool::new(false),
        }
    }

    /// 为某个源注册健康槽位（AgentCore::new 时对每个源调用一次），返回其健康句柄
    pub fn register_source(&self, name: &str) -> SourceHealth {
        let h = SourceHealth::new();
        if let Ok(mut map) = self.health.lock() {
            map.insert(name.to_string(), h.clone());
        }
        h
    }

    pub fn get_health(&self, name: &str) -> Option<SourceHealth> {
        self.health.lock().ok()?.get(name).cloned()
    }

    /// 记录源失败，返回是否「刚刚变 unhealthy」
    pub fn record_failure(&self, name: &str, err: &str) -> bool {
        self.get_health(name).map(|h| h.record_failure(err)).unwrap_or(false)
    }

    pub fn record_success(&self, name: &str) {
        if let Some(h) = self.get_health(name) {
            h.record_success();
        }
    }

    pub fn is_unhealthy(&self, name: &str) -> bool {
        self.get_health(name).map(|h| h.is_unhealthy()).unwrap_or(false)
    }

    pub fn health_snapshot(&self) -> Vec<(String, bool, u32, Option<String>)> {
        self.health
            .lock()
            .ok()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.is_unhealthy(), v.failures(), v.last_error()))
                    .collect()
            })
            .unwrap_or_default()
    }

    // ── Kill switch ──
    pub fn set_kill_switch(&self, on: bool) {
        self.kill_switch.store(on, Ordering::SeqCst);
        tracing::warn!(kill_switch = on, "Kill switch 状态变更");
    }

    pub fn kill_switch_on(&self) -> bool {
        self.kill_switch.load(Ordering::SeqCst)
    }

    /// 计算当前降级模式
    ///
    /// `business_sources`：除 memoria 外的业务 MCP 源名列表。
    /// - Kill switch 开 → [`DegradeMode::KillSwitch`]
    /// - 有业务源且全部 unhealthy → [`DegradeMode::MemoriaReadonlyChat`]
    /// - 有至少一个业务源 unhealthy → [`DegradeMode::SourceDegraded`]
    /// - 否则 → [`DegradeMode::Normal`]
    pub fn current_mode(&self, business_sources: &[String]) -> DegradeMode {
        if self.kill_switch_on() {
            return DegradeMode::KillSwitch;
        }
        if business_sources.is_empty() {
            return DegradeMode::Normal;
        }
        let unhealthy_count = business_sources
            .iter()
            .filter(|n| self.is_unhealthy(n))
            .count();
        if unhealthy_count == business_sources.len() {
            DegradeMode::MemoriaReadonlyChat
        } else if unhealthy_count > 0 {
            DegradeMode::SourceDegraded
        } else {
            DegradeMode::Normal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_health_threshold() {
        let h = SourceHealth::new();
        assert!(!h.is_unhealthy());
        assert!(!h.record_failure("e1"));
        assert!(!h.record_failure("e2"));
        assert!(h.record_failure("e3"), "第 3 次失败应跨过阈值");
        assert!(h.is_unhealthy());
        // 继续失败不再「刚变 unhealthy」
        assert!(!h.record_failure("e4"));
        // 成功恢复
        h.record_success();
        assert!(!h.is_unhealthy());
        assert_eq!(h.failures(), 0);
    }

    #[test]
    fn test_monitor_mode_transitions() {
        let m = DegradeMonitor::new();
        m.register_source("memoria");
        m.register_source("dashboard");
        m.register_source("bridge");
        let biz = vec!["dashboard".to_string(), "bridge".to_string()];

        assert_eq!(m.current_mode(&biz), DegradeMode::Normal);

        // 一个业务源挂 → SourceDegraded
        m.record_failure("dashboard", "down");
        m.record_failure("dashboard", "down");
        m.record_failure("dashboard", "down");
        assert_eq!(m.current_mode(&biz), DegradeMode::SourceDegraded);

        // 另一业务源也挂 → 全部业务不可用 → MemoriaReadonlyChat
        m.record_failure("bridge", "down");
        m.record_failure("bridge", "down");
        m.record_failure("bridge", "down");
        assert_eq!(m.current_mode(&biz), DegradeMode::MemoriaReadonlyChat);

        // 恢复 bridge → 回到 SourceDegraded
        m.record_success("bridge");
        assert_eq!(m.current_mode(&biz), DegradeMode::SourceDegraded);

        // Kill switch 覆盖一切
        m.set_kill_switch(true);
        assert_eq!(m.current_mode(&biz), DegradeMode::KillSwitch);
        m.set_kill_switch(false);
        assert_eq!(m.current_mode(&biz), DegradeMode::SourceDegraded);

        // 无业务源 → 永远 Normal
        assert_eq!(m.current_mode(&[]), DegradeMode::Normal);
    }
}
