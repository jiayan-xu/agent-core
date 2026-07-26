//! 摄入侧治本过滤（opt-in）
//!
//! 在 agent-core 写入 Memoria 之前拦截三类噪声，避免「噪声进记忆库后再清理」：
//! 1. **测试件隔离**（`test_ns_isolation`）：写入命名空间匹配测试/实验模式
//!    （`lme_*` / `pm_*` / `agent/rt*` / `default` / `smoke` / `meta_evolution` / `*_test_*`）
//!    时，丢弃或重定向到隔离命名空间，不污染真实记忆。
//! 2. **A2A 回执过滤**（`a2a_receipt_drop`）：丢弃 `{"body":"y"}` 类自动回执 / 极简确认
//!    （07-14 那批 1747 条 A2A 回执的主源），这些东西无记忆价值。
//! 3. **对话捕获加筛选**（`dialog_substance`）：消防水带式 `memory_observe` 仅捕获
//!    「实质性」对话（长度 / 工具调用 / 中文句子），跳过闲聊与极短消息。
//!
//! 设计纪律（与 `persona_auto_memory` 一致）：全部 opt-in，默认全 false；
//! 由 agent.toml `[intake_filter]` 控制，不启用则零行为变化。

use serde::{Deserialize, Serialize};

/// 摄入过滤配置（落 agent.toml `[intake_filter]`）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntakeFilterConfig {
    /// 总开关。false 时下列三个子开关全部不生效（零行为变化）。
    #[serde(default)]
    pub enabled: bool,
    /// Filter1：测试/实验命名空间隔离。
    #[serde(default)]
    pub test_ns_isolation: bool,
    /// Filter2：A2A 自动回执丢弃。
    #[serde(default)]
    pub a2a_receipt_drop: bool,
    /// Filter3：对话捕获仅保留实质性内容。
    #[serde(default)]
    pub dialog_substance: bool,
    /// Filter3 长度阈值（字节数）。低于此长度且无其他信号则视为非实质。
    #[serde(default = "default_min_len")]
    pub min_substance_len: usize,
    /// Filter1 重定向目标命名空间。空字符串=直接丢弃；非空=重定向到该隔离 ns。
    #[serde(default)]
    pub quarantine_ns: String,
}

fn default_min_len() -> usize {
    12
}

impl IntakeFilterConfig {
    /// 主开关 + 子开关联合判定：仅当总开关开启且子开关开启时返回 true。
    pub fn active(&self, sub: bool) -> bool {
        self.enabled && sub
    }
}

/// 测试/实验命名空间判定。
/// 覆盖：lme_* / pm_* / agent/rt* / default / smoke / meta_evolution / *_test_* / test_* / *_test。
pub fn is_test_namespace(ns: &str) -> bool {
    if ns.is_empty() {
        return false;
    }
    let l = ns.to_lowercase();
    let bare = l.strip_prefix("agent/").unwrap_or(&l);
    if l == "default" || l == "smoke" || l == "meta_evolution" {
        return true;
    }
    if bare.starts_with("lme_") || bare.starts_with("pm_") || bare.starts_with("rt_") {
        return true;
    }
    if l.starts_with("agent/rt") {
        return true;
    }
    // 收紧（B 批防误伤）：仅匹配「test 作为整体前缀 / 后缀 / 裸命名空间」的情形，
    // 不再用 contains("_test_") 做子串匹配——否则 `agent/proj_test_scripts` 这类真实命名空间
    // 会被误判为测试件，在 quarantine_ns 为空时静默丢弃（数据丢失）。
    // 偏向「不误删」：宁让少量测试噪声进入（可后清理），也不静默丢掉真实记忆。
    if l.starts_with("test_") || l.ends_with("_test") || bare == "test" {
        return true;
    }
    false
}

/// A2A 自动回执判定：极简确认（y/ok/ack…）或 `{"body":"y",...}` 信封。
pub fn is_auto_receipt(content: &str) -> bool {
    let t = content.trim();
    if t.is_empty() {
        return true;
    }
    let tl = t.to_lowercase();
    if matches!(
        tl.as_str(),
        "y" | "yes" | "ok" | "n" | "no" | "ack" | "received" | "done" | "thanks" | "thank you"
            | "👍" | "✅"
    ) {
        return true;
    }
    // JSON 信封：含 body 且为极简确认、且无实质 content
    if t.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            if let Some(b) = v.get("body").and_then(|x| x.as_str()) {
                let bl = b.trim().to_lowercase();
                if matches!(bl.as_str(), "y" | "yes" | "ok" | "n" | "no" | "ack" | "received") {
                    let content_short = match v.get("content").and_then(|x| x.as_str()) {
                        None => true,
                        Some(c) => c.trim().len() < 40,
                    };
                    if content_short {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// 对话是否「实质性」：长度达标，或含代码/URL/SQL 信号，或含 ≥4 个中文字。
pub fn is_substantial(dialog: &str, min_len: usize) -> bool {
    let d = dialog.trim();
    if d.len() >= min_len {
        return true;
    }
    if d.contains("```")
        || d.contains("http://")
        || d.contains("https://")
        || d.contains("SELECT ")
        || d.contains("INSERT ")
        || d.contains("UPDATE ")
        || d.contains("fn ")
        || d.contains("def ")
        || d.contains("class ")
        || d.contains("import ")
    {
        return true;
    }
    let cjk = d.chars().filter(|c| ('\u{4e00}'..='\u{9fff}').contains(c)).count();
    if cjk >= 4 {
        return true;
    }
    false
}

/// 解析写入命名空间：
/// - 返回 `None` = 丢弃（测试命名空间 + 未配置 quarantine_ns）；
/// - 返回 `Some(ns)` = 使用（必要时重定向到隔离 ns）。
pub fn resolve_ns(ns: &str, cfg: &IntakeFilterConfig) -> Option<String> {
    if !cfg.active(cfg.test_ns_isolation) {
        return Some(ns.to_string());
    }
    if is_test_namespace(ns) {
        if cfg.quarantine_ns.is_empty() {
            return None;
        }
        return Some(cfg.quarantine_ns.clone());
    }
    Some(ns.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_patterns() {
        assert!(is_test_namespace("lme_abc"));
        assert!(is_test_namespace("pm_xyz"));
        assert!(is_test_namespace("agent/rt_123"));
        assert!(is_test_namespace("default"));
        assert!(is_test_namespace("smoke"));
        assert!(is_test_namespace("meta_evolution"));
        assert!(is_test_namespace("agent/lme_42"));
        assert!(is_test_namespace("foo_test_bar"));
        assert!(is_test_namespace("test_run"));
        assert!(is_test_namespace("my_test"));
        // 真实命名空间不应被误判
        assert!(!is_test_namespace("agent/xujiayan"));
        assert!(!is_test_namespace("agent/jarvis"));
        assert!(!is_test_namespace("jarvis"));
    }

    #[test]
    fn test_auto_receipt() {
        assert!(is_auto_receipt("y"));
        assert!(is_auto_receipt("Y"));
        assert!(is_auto_receipt("ok"));
        assert!(is_auto_receipt("{\"body\":\"y\",\"from_agent\":\"dashboard-agent\"}"));
        assert!(is_auto_receipt("{\"body\":\"y\",\"created_at\":\"x\",\"from_agent\":\"a\",\"scope\":\"org\",\"subject\":\"x\"}"));
        // 带实质 content 的信封不是回执
        assert!(!is_auto_receipt("{\"body\":\"y\",\"content\":\"这是一段较长的实质性回复内容用来测试阈值判断逻辑是否生效因为这是正文\"}"));
        // 正常记忆不是回执
        assert!(!is_auto_receipt("今天修复了记忆路由的 404 问题，根因是 matchit 版本不兼容"));
    }

    #[test]
    fn test_substance() {
        assert!(is_substantial("今天修复了记忆路由的 404 问题", 12));
        assert!(!is_substantial("y", 12));
        assert!(!is_substantial("谢谢", 12)); // 2 中文字，非实质
        assert!(is_substantial("帮我查一下昨天的车次", 12)); // 8 中文字
        assert!(is_substantial("SELECT * FROM t", 12));
    }

    #[test]
    fn test_resolve_ns() {
        let mut cfg = IntakeFilterConfig {
            enabled: true,
            test_ns_isolation: true,
            ..Default::default()
        };
        assert!(resolve_ns("lme_x", &cfg).is_none()); // 丢弃
        cfg.quarantine_ns = "quarantine/test".to_string();
        assert_eq!(resolve_ns("lme_x", &cfg).unwrap(), "quarantine/test");
        assert_eq!(resolve_ns("agent/xujiayan", &cfg).unwrap(), "agent/xujiayan");
        // 关闭时不过滤
        cfg.enabled = false;
        assert_eq!(resolve_ns("lme_x", &cfg).unwrap(), "lme_x");
    }
}
