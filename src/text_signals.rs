//! P2.2d：retain/consolidate 路径 LLM 抽取 text_signals 并持久化为 Memoria tags。
//!
//! 格式与 memoria-open 对齐：`signal:num:` / `signal:date:` / `signal:update:`。
//! 薄存储仍由 Memoria remember 落库；脑子在 agent-core。

use serde_json::Value;

pub const SIGNAL_NUM_PREFIX: &str = "signal:num:";
pub const SIGNAL_DATE_PREFIX: &str = "signal:date:";
pub const SIGNAL_UPDATE_PREFIX: &str = "signal:update:";

const MAX_NUMBERS: usize = 8;
const MAX_DATES: usize = 4;
const MAX_UPDATE_MARKERS: usize = 4;

/// consolidate 路径默认开；`AGENT_TEXT_SIGNALS_LLM=0` 关闭。
pub fn llm_text_signals_enabled() -> bool {
    match std::env::var("AGENT_TEXT_SIGNALS_LLM") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            !(t == "0" || t == "false" || t == "off" || t == "no")
        }
        Err(_) => true,
    }
}

/// chat retain（memory_remember 工具）默认关，避免每写入一次 LLM。
pub fn llm_retain_signals_enabled() -> bool {
    match std::env::var("AGENT_TEXT_SIGNALS_LLM_RETAIN") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "on" || t == "yes"
        }
        Err(_) => false,
    }
}

/// 构造 LLM 抽取 prompt（单条或多条文本）。
pub fn build_extract_prompt(texts: &[&str]) -> String {
    let body: String = texts
        .iter()
        .enumerate()
        .map(|(i, t)| format!("[{}] {}", i, t.chars().take(800).collect::<String>()))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "从以下记忆文本抽取结构化信号。仅输出纯 JSON 数组，不要 markdown 或解释。\n\
         每项格式：{{\"index\":0,\"numbers\":[\"120\"],\"dates\":[\"YYYY-MM-DD\"],\"update_markers\":[\"改为\"]}}\n\
         规则：numbers 为关键数值（最多 {MAX_NUMBERS}）；dates 为绝对日期 YYYY-MM-DD（最多 {MAX_DATES}）；\
         update_markers 为变更/更新词（最多 {MAX_UPDATE_MARKERS}）；无则空数组。\n\n{textbody}",
        MAX_NUMBERS = MAX_NUMBERS,
        MAX_DATES = MAX_DATES,
        MAX_UPDATE_MARKERS = MAX_UPDATE_MARKERS,
        textbody = body,
    )
}

/// 解析 LLM 返回的 JSON 数组（容错最外层 `[`…`]`）。
pub fn parse_llm_signal_array(text: &str) -> Vec<Value> {
    if let Ok(arr) = serde_json::from_str::<Vec<Value>>(text) {
        return arr;
    }
    if let (Some(start), Some(end)) = (text.find('['), text.rfind(']')) {
        if end >= start {
            return serde_json::from_str(&text[start..=end]).unwrap_or_default();
        }
    }
    Vec::new()
}

/// 单条 LLM 信号对象 → `signal:*` tags。
pub fn signal_tags_from_llm_item(item: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(nums) = item["numbers"].as_array() {
        for n in nums.iter().take(MAX_NUMBERS) {
            if let Some(s) = n.as_str() {
                if !s.is_empty() {
                    out.push(format!("{SIGNAL_NUM_PREFIX}{s}"));
                }
            }
        }
    }
    if let Some(dates) = item["dates"].as_array() {
        for d in dates.iter().take(MAX_DATES) {
            if let Some(s) = d.as_str() {
                if s.len() >= 10 {
                    out.push(format!("{SIGNAL_DATE_PREFIX}{}", &s[..10]));
                }
            }
        }
    }
    if let Some(markers) = item["update_markers"].as_array() {
        for m in markers.iter().take(MAX_UPDATE_MARKERS) {
            if let Some(s) = m.as_str() {
                if !s.is_empty() {
                    out.push(format!("{SIGNAL_UPDATE_PREFIX}{s}"));
                }
            }
        }
    }
    out
}

/// 合并已有 tags 数组与新的 signal tags（去重、替换同前缀）。
pub fn merge_tags_with_signals(existing: &[Value], signal_tags: &[String]) -> Vec<Value> {
    let mut tags: Vec<String> = existing
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    tags.retain(|t| {
        let s = t.trim();
        !s.starts_with(SIGNAL_NUM_PREFIX)
            && !s.starts_with(SIGNAL_DATE_PREFIX)
            && !s.starts_with(SIGNAL_UPDATE_PREFIX)
    });
    for st in signal_tags {
        if !tags.iter().any(|x| x == st) {
            tags.push(st.clone());
        }
    }
    tags.into_iter().map(Value::String).collect()
}

/// 把 LLM 抽取结果按 index 映射到每条文本的 signal tags。
pub fn map_llm_signals_by_index(items: &[Value], count: usize) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = vec![Vec::new(); count];
    for item in items {
        let idx = item["index"].as_u64().unwrap_or(0) as usize;
        if idx < count {
            out[idx] = signal_tags_from_llm_item(item);
        }
    }
    out
}

/// 为 memory_remember 参数合并 LLM signal tags（原地修改 `tags` 字段）。
pub fn enrich_remember_args(args: &mut Value, signal_tags: &[String]) {
    if signal_tags.is_empty() {
        return;
    }
    let existing: Vec<Value> = args
        .get("tags")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();
    let merged = merge_tags_with_signals(&existing, signal_tags);
    args.as_object_mut()
        .map(|o| o.insert("tags".to_string(), Value::Array(merged)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_llm_array_tolerant() {
        let raw = r#"说明
[{"index":0,"numbers":["120"],"dates":["2026-07-01"],"update_markers":["改为"]}]"#;
        let arr = parse_llm_signal_array(raw);
        assert_eq!(arr.len(), 1);
        let tags = signal_tags_from_llm_item(&arr[0]);
        assert!(tags.iter().any(|t| t == "signal:num:120"));
    }

    #[test]
    fn merge_tags_keeps_occurred() {
        let existing = vec![
            json!("pattern"),
            json!("occurred:2026-07-10"),
        ];
        let merged = merge_tags_with_signals(
            &existing,
            &["signal:num:88".to_string()],
        );
        let s: Vec<String> = merged.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        assert!(s.iter().any(|t| t == "occurred:2026-07-10"));
        assert!(s.iter().any(|t| t == "signal:num:88"));
    }

    #[test]
    fn map_by_index() {
        let items = vec![json!({"index":1,"numbers":["30"],"dates":[],"update_markers":[]})];
        let mapped = map_llm_signals_by_index(&items, 2);
        assert!(mapped[0].is_empty());
        assert!(mapped[1].iter().any(|t| t == "signal:num:30"));
    }
}
