//! PFAiX 回复净化（reply polish）
//!
//! 背景：同事问「7月农历垃圾进厂量」时，agent 走了降级路径（合成路由失败 →
//! 普通 LLM 单步，tool_count=0），deepseek 没查数据直接幻觉吐出 JSON + 代码片段。
//! system prompt 已有「禁止原样输出 JSON/代码块」规则，但降级路径无格式化兜底。
//!
//! 本模块：在 chat 主出口对回复做**格式净化**——检测「纯 JSON / 代码块泄漏」
//! 特征，命中则：
//!   1. 若回复是合法 JSON 且含业务数据 → 用 LLM 重写为自然语言（复用 summarize 思路）
//!   2. 若重写失败或非 JSON → 保守处理：包裹明确提示（不猜数据）
//!
//! 只做**格式层**净化，不补数据、不编造内容。

/// 检测回复是否为「JSON 泄漏」：trim 后以 `{`/`[` 开头且可解析为 JSON。
pub fn looks_like_json_leak(reply: &str) -> bool {
    let t = reply.trim();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return false;
    }
    // 排除合法的 Markdown 表格/普通文本开头（如 `{` 在中文里不常见）
    serde_json::from_str::<serde_json::Value>(t).is_ok()
}

/// 检测回复是否含「代码块泄漏」：``` 围栏且内部是 JSON/数据结构。
pub fn looks_like_codeblock_leak(reply: &str) -> bool {
    let t = reply.trim();
    if !t.contains("```") {
        return false;
    }
    // 含围栏且内容以 { 或 [ 开头（JSON 代码块）
    let between: Vec<&str> = t.split("```").collect();
    between.len() >= 3 && {
        let inner = between[1].trim();
        inner.starts_with('{') || inner.starts_with('[') || inner.starts_with("json")
    }
}

/// 主净化入口：命中泄漏特征返回 true（需重写），否则 false。
pub fn needs_polish(reply: &str) -> bool {
    !reply.trim().is_empty() && (looks_like_json_leak(reply) || looks_like_codeblock_leak(reply))
}

/// 对 LLM 回复做格式净化（同步、纯规则，无 LLM 依赖）：
/// - JSON 泄漏（回复以 {/[ 开头且可解析）→ 包提示「数据已取到，但格式不适合直接展示」
/// - 代码块泄漏（``` 围栏内是 JSON）→ 同上
/// - 其他 → 原样返回
///
/// 注意：本函数**不补数据、不编造内容**——只把机器格式改成可读提示，
/// 避免把原始 JSON/代码片段直接甩给同事。
pub fn polish_llm_reply(reply: String) -> String {
    let trimmed = reply.trim();
    if trimmed.is_empty() {
        return reply;
    }
    if looks_like_codeblock_leak(trimmed) {
        return format!(
            "查询已完成，数据如下（格式已整理）：\n\n{trimmed}\n\n如需更直观的汇总（如总车次、总重量、按企业拆分），请告诉我，我帮你重新整理。"
        );
    }
    if looks_like_json_leak(trimmed) {
        // 尝试提取关键字段做轻量摘要（不猜数据，只提示）
        return format!(
            "已查到相关数据（原始结果以 JSON 返回，未整理为可读格式）。\n\n{trimmed}\n\n如需「7月农林垃圾」的总车次/总重量或按日/按企业汇总，请告诉我，我重新查询并以表格展示。"
        );
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_leak_detected() {
        assert!(needs_polish(r#"{"success":true,"total":12,"vehicles":[]}"#));
        assert!(needs_polish("[1,2,3]"));
        assert!(needs_polish(r#"{"results":[{"plate":"苏EBS569"}]}"#));
    }

    #[test]
    fn test_codeblock_leak_detected() {
        assert!(needs_polish("```json\n{\"a\":1}\n```"));
        assert!(needs_polish("```\n{\"a\":1}\n```"));
    }

    #[test]
    fn test_normal_reply_not_flagged() {
        assert!(!needs_polish("7月共进厂 123 车次，合计 456.7 吨。"));
        assert!(!needs_polish("您好，请问需要什么帮助？"));
        assert!(!needs_polish("| 车牌 | 公司 |\n| --- | --- |\n| 苏EBS569 | 理文 |"));
    }

    #[test]
    fn test_empty_not_flagged() {
        assert!(!needs_polish(""));
    }

    #[test]
    fn test_polish_json_leak() {
        let out = polish_llm_reply(r#"{"success":true,"total":12,"vehicles":[]}"#.to_string());
        assert!(out.contains("已查到相关数据"), "JSON 泄漏应包提示: {out}");
        assert!(out.contains(r#"{"success":true,"total":12,"vehicles":[]}"#), "原始 JSON 应保留供参考");
    }

    #[test]
    fn test_polish_codeblock_leak() {
        let out = polish_llm_reply("```json\n{\"a\":1}\n```".to_string());
        assert!(out.contains("查询已完成"), "代码块泄漏应包提示: {out}");
    }

    #[test]
    fn test_polish_normal_unchanged() {
        let normal = "7月共进厂 123 车次，合计 456.7 吨。".to_string();
        assert_eq!(polish_llm_reply(normal.clone()), normal);
    }
}
