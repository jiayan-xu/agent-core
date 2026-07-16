//! Self-Evolution 护栏（O4）— HMS 四条确定性控制规则。
//!
//! 挂在 agent-core `search_memory`→knowledge 路径；零 LLM、纯关键词启发式。
//! 不依赖 Memoria MCP 响应里的 `guardrails` 字段。

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

/// 将护栏注记追加进 knowledge（O4：全部 search_memory→knowledge 路径调用）。
pub fn append_to_knowledge(knowledge: &mut Vec<String>, query: &str) {
    let notes = guardrails(query);
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
    fn append_adds_block() {
        let mut k = vec!["mem".to_string()];
        append_to_knowledge(&mut k, "how many items last month");
        assert_eq!(k.len(), 2);
        assert!(k[1].contains("Self-Evolution"));
        assert!(k[1].contains("COUNT_TOTAL_DEDUP"));
    }
}
