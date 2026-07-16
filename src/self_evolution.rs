//! Self-Evolution 护栏（O4）— HMS 四条确定性控制规则。
//!
//! 挂在 agent-core `search_memory`→knowledge 路径；零 LLM、纯关键词启发式。
//! P2.2：消费 Memoria ledger `text_signals` 生成 dedup/校准注记。
//! 不依赖 Memoria MCP 响应里的 `guardrails` 字段。

use serde_json::Value;
use std::collections::HashMap;

/// 中英文关键词 → 控制规则注记。返回命中的规则文本列表（可能为空）。
pub fn guardrails(query: &str) -> Vec<String> {
    let q = query.to_lowercase();
    let mut notes: Vec<String> = Vec::new();

    let count_kw = [
        "how many", "total", "count", "数量", "总数", "几个", "多少个", "累计",
    ];
    if count_kw.iter().any(|k| q.contains(k)) {
        notes.push(
            "COUNT_TOTAL_DEDUP: 先枚举唯一事件再计数，避免把同一事件的多次提及重复累加。"
                .to_string(),
        );
    }

    let date_kw = [
        "ago", "before", "after", "last", "next", "yesterday", "tomorrow", "前", "后", "之前",
        "之后", "昨天", "明天", "上周", "本周", "这周", "上月", "上个月", "下个月", "下月",
        "去年", "今年", "本月", "今天", "今日", "当日", "当天", "近年", "相对",
    ];
    if date_kw.iter().any(|k| q.contains(k)) {
        notes.push(
            "RELATIVE_DATE_GROUNDING: 以问题时间为锚点解析相对日期，落到具体记忆的 occurred/mentioned 区间。"
                .to_string(),
        );
    }

    let amount_kw = [
        "how much", "difference", "cost", "spent", "amount", "差额", "花了多少", "差多少",
        "成本", "余额", "多少钱",
    ];
    if amount_kw.iter().any(|k| q.contains(k)) {
        notes.push(
            "AMOUNT_DIFFERENCE_CALIBRATION: 仅当差值两侧数据齐全时才计算，缺一侧时保守表述而非硬算。"
                .to_string(),
        );
    }

    let state_kw = [
        "current", "latest", "previous", "initially", "before", "当前", "最新", "之前", "最初",
        "原先", "现在", "过去",
    ];
    if state_kw.iter().any(|k| q.contains(k)) {
        notes.push(
            "CURRENT_PREVIOUS_ARBITRATION: 当前态取最新有效版本(occurred 最近)，历史态取最旧版本，勿混用。"
                .to_string(),
        );
    }

    notes
}

/// P2.2：从 ledger `text_signals` 生成数据驱动 dedup/校准注记（零 LLM）。
pub fn text_signals_guardrails(query: &str, ledger: &[Value]) -> Vec<String> {
    if ledger.is_empty() {
        return Vec::new();
    }
    let q = query.to_lowercase();
    let mut notes: Vec<String> = Vec::new();

    let mut number_rows: HashMap<String, usize> = HashMap::new();
    let mut all_dates: Vec<String> = Vec::new();
    let mut update_rows = 0usize;

    for row in ledger {
        let Some(ts) = row.get("text_signals") else {
            continue;
        };
        if let Some(nums) = ts["numbers"].as_array() {
            for n in nums {
                if let Some(s) = n.as_str() {
                    *number_rows.entry(s.to_string()).or_insert(0) += 1;
                }
            }
        }
        if let Some(dates) = ts["dates"].as_array() {
            for d in dates {
                if let Some(s) = d.as_str() {
                    if !all_dates.iter().any(|x| x == s) {
                        all_dates.push(s.to_string());
                    }
                }
            }
        }
        if let Some(markers) = ts["update_markers"].as_array() {
            if !markers.is_empty() {
                update_rows += 1;
            }
        }
    }

    let count_kw = [
        "how many", "total", "count", "数量", "总数", "几个", "多少个", "累计",
    ];
    if count_kw.iter().any(|k| q.contains(k)) {
        let dup: Vec<String> = number_rows
            .iter()
            .filter(|(_, c)| **c > 1)
            .map(|(n, c)| format!("{n}({c}条)"))
            .collect();
        if !dup.is_empty() {
            notes.push(format!(
                "TEXT_SIGNALS_DEDUP: 召回记忆共现数字 {}，计数前先按事件去重。",
                dup.join(", ")
            ));
        }
    }

    let amount_kw = [
        "how much", "difference", "cost", "spent", "amount", "差额", "花了多少", "差多少",
        "成本", "余额", "多少钱",
    ];
    if amount_kw.iter().any(|k| q.contains(k)) && number_rows.len() > 1 {
        let nums: Vec<&str> = number_rows.keys().map(String::as_str).collect();
        notes.push(format!(
            "TEXT_SIGNALS_AMOUNT: 召回含多个数值 {:?}，仅两侧齐全时再算差值。",
            nums
        ));
    }

    let date_kw = [
        "ago", "before", "after", "last", "next", "yesterday", "tomorrow", "前", "后", "之前",
        "之后", "昨天", "明天", "上周", "本周", "这周", "上月", "上个月", "下个月", "下月",
        "去年", "今年", "本月", "今天", "今日", "当日", "当天", "近年", "相对",
    ];
    if date_kw.iter().any(|k| q.contains(k)) && !all_dates.is_empty() {
        all_dates.sort();
        let span = if all_dates.len() == 1 {
            all_dates[0].clone()
        } else {
            format!("{} ~ {}", all_dates.first().unwrap(), all_dates.last().unwrap())
        };
        notes.push(format!(
            "TEXT_SIGNALS_DATE_GROUND: 召回 text_signals 日期跨度 {span}，相对问句锚定此区间。"
        ));
    }

    if update_rows > 0 {
        notes.push(format!(
            "TEXT_SIGNALS_UPDATE: {update_rows} 条记忆含更新标记，当前态取 occurred 最新、历史态取最旧。"
        ));
    }

    notes
}

/// 将护栏注记追加进 knowledge（O4：全部 search_memory→knowledge 路径调用）。
pub fn append_to_knowledge(knowledge: &mut Vec<String>, query: &str, ledger: &[Value]) {
    let mut notes = guardrails(query);
    notes.extend(text_signals_guardrails(query, ledger));
    if notes.is_empty() {
        return;
    }
    let mut block = String::from("[Self-Evolution 护栏]\n");
    for n in &notes {
        block.push_str("- ");
        block.push_str(n);
        block.push('\n');
    }
    knowledge.push(block);
    tracing::debug!(count = notes.len(), "self_evolution guardrails injected into knowledge");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers_four_rules() {
        assert!(guardrails("how many 项目").iter().any(|s| s.starts_with("COUNT_TOTAL_DEDUP")));
        assert!(guardrails("上个月总量")
            .iter()
            .any(|s| s.starts_with("RELATIVE_DATE_GROUNDING")));
        assert!(guardrails("差额是多少")
            .iter()
            .any(|s| s.starts_with("AMOUNT_DIFFERENCE_CALIBRATION")));
        assert!(guardrails("当前最新状态")
            .iter()
            .any(|s| s.starts_with("CURRENT_PREVIOUS_ARBITRATION")));
        assert!(guardrails("你好").is_empty());
    }

    #[test]
    fn text_signals_dedup_from_ledger() {
        let ledger = vec![serde_json::json!({
            "text_signals": {"numbers": ["120"], "dates": ["2026-07-01"], "update_markers": []}
        }), serde_json::json!({
            "text_signals": {"numbers": ["120", "30"], "dates": [], "update_markers": ["改为"]}
        })];
        let notes = text_signals_guardrails("how many 总量", &ledger);
        assert!(notes.iter().any(|s| s.starts_with("TEXT_SIGNALS_DEDUP")));
        assert!(notes.iter().any(|s| s.starts_with("TEXT_SIGNALS_UPDATE")));
    }

    #[test]
    fn append_adds_block() {
        let mut k = vec!["mem".to_string()];
        append_to_knowledge(&mut k, "how many items last month", &[]);
        assert_eq!(k.len(), 2);
        assert!(k[1].contains("Self-Evolution"));
        assert!(k[1].contains("COUNT_TOTAL_DEDUP"));
    }
}
