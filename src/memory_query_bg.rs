//! Phase B ①（WeKnora 吸收 §3.3 路径①「query rewriter 背景注入」+ 路径③「兴趣
//! 词表」的确定性子集，2026-10-04）。
//!
//! WeKnora 的原设计在 query 理解阶段注入 `<asker_background>`，让长期记忆
//! 「从只影响回答 prompt，变成影响检索什么」。本仓对齐其三条边界约定：
//!
//! 1. **Advisory 而非 filter**——背景只放宽匹配面，绝不缩窄或排除任何命名空间
//!    （"关于上季度项目的陈旧笔记，不能让本季度的文档不可达"）。
//! 2. **确定性、零 LLM**——用字符 bigram Dice 相似度挑「对当前 query 的扩写型
//!    兴趣词」（如 query「排班怎么改」× 兴趣「门店排班管理」），仅当相似度
//!    过阈值且不重复时追加一词。这不是改写问题语义，是给检索器多一个
//!    站得住的召回入口。
//! 3. **有界**——最多追加 1 个词；`AGENT_MEMORY_QUERY_BG=0` 一键关闭。
//!
//! 路径②（affinity rerank）**判定不做**：memoria 召回内部已有共现加成
//! （cooccur）与频率分量（MEMORIA_RERANK_W_FREQ / access_count）两个「使用
//! 信号影响排序」机制，agent-core 层再建一层即重复造轮子（2026-10-04 核实）。
//!
//! 兴趣词自暖：`search_memory` 首个成功的 memory_context 响应里 profile.static
//! 的条目被收割进会话级缓存（TTL 10 分钟），后续消息的检索 query 用缓存扩展；
//! 首条消息不扩展（无背景可用），不产生任何额外 MCP 调用。

/// 紧急关闭：`AGENT_MEMORY_QUERY_BG=0`。
pub fn bg_enabled() -> bool {
    std::env::var("AGENT_MEMORY_QUERY_BG").ok().as_deref() != Some("0")
}

/// 字符 bigram Dice 相似度 ∈ [0,1]（中文无词分隔，bigram 比整词稳；
/// Dice 比 Jaccard 宽容一方更长——「排班管理」vs「门店排班管理」的扩写情形）。
/// 交集按**双侧多重集**计（每个 bigram 的重数在两侧间匹配消耗）——
/// 2026-10-04 审查修复：原实现 left 按重数累加而 right.contains 是集合判定，
/// 「aaaa」×「aa」会得 1.5 越界，自反性随重复 bigram 破坏。
pub fn bigram_dice(a: &str, b: &str) -> f64 {
    let left = bigrams(a);
    let right = bigrams(b);
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<&str, i32> = std::collections::HashMap::new();
    for g in &left {
        *counts.entry(g.as_str()).or_insert(0) += 1;
    }
    let mut shared = 0usize;
    for g in &right {
        if let Some(c) = counts.get_mut(g.as_str()) {
            if *c > 0 {
                shared += 1;
                *c -= 1;
            }
        }
    }
    2.0 * shared as f64 / (left.len() + right.len()) as f64
}

fn bigrams(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.trim().to_lowercase().chars().collect();
    if chars.is_empty() {
        return Vec::new();
    }
    if chars.len() == 1 {
        return vec![chars[0].to_string()];
    }
    chars.windows(2).map(|w| w.iter().collect()).collect()
}

/// 扩展阈值：低于此相似度的兴趣词不追加（防把无关偏好灌进检索 query）。
/// 标定：真实查询常比兴趣词长（「排班怎么改」vs「门店排班管理」dice≈0.22，
/// 「排班管理」vs「门店排班管理」≈0.57），0.20 让扩写型命中可触发；假阳性
/// 代价有限——追加词只放宽召回（advisory），memoria 仍按相关性排序。
const ELABORATION_THRESHOLD: f64 = 0.20;

/// 用兴趣词表扩展检索 query：挑与 query 最相似且过阈值的**一个**兴趣词追加。
/// query 已含该词 / 无过阈词 / 词表空 → 原样返回（advisory，绝不改变原语义）。
pub fn expand_query(query: &str, interests: &[String]) -> String {
    let q = query.trim();
    if q.is_empty() || interests.is_empty() {
        return q.to_string();
    }
    let mut best: Option<(f64, &str)> = None;
    for it in interests {
        let it = it.trim();
        if it.is_empty() || q.contains(it) {
            continue;
        }
        let sim = bigram_dice(q, it);
        if sim >= ELABORATION_THRESHOLD && sim > best.map(|(s, _)| s).unwrap_or(0.0) {
            best = Some((sim, it));
        }
    }
    match best {
        Some((sim, it)) => {
            tracing::debug!(
                "[QUERY-BG] 记忆检索 query 背景扩展：『{q}』+『{it}』(dice={sim:.2})"
            );
            format!("{q} {it}")
        }
        None => q.to_string(),
    }
}

/// 从 memory_context 响应的 profile.static 收割兴趣词（≤24 字符/条，≤8 条）。
/// 过长者跳过而非截断——截断产生的半截词会污染检索。
pub fn harvest_interests(profile_static: &[serde_json::Value]) -> Vec<String> {
    let mut out = Vec::new();
    for it in profile_static {
        if let Some(c) = it.get("content").and_then(|v| v.as_str()) {
            let c = c.trim();
            let n = c.chars().count();
            if (4..=24).contains(&n) && !out.iter().any(|e: &String| e == c) {
                out.push(c.to_string());
                if out.len() >= 8 {
                    break;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dice_elaboration_scores_high() {
        // 真实查询比兴趣词长：共享 1 个 bigram、分母 9 → ≈0.22（>0.20 阈值）
        assert!(bigram_dice("排班怎么改", "门店排班管理") >= 0.20);
        assert!(bigram_dice("排班管理", "门店排班管理") > 0.5);
        assert!(bigram_dice("排班", "固废清运") < 0.2);
        assert_eq!(bigram_dice("", "任意"), 0.0);
    }

    /// 2026-10-04 审查修复回归：重复 bigram 不得使 Dice 越界或破坏自反性
    /// （原实现「aaaa」×「aa」=1.5，会让扩写阈值在重复字符 query 上误判）。
    #[test]
    fn dice_bounded_and_reflexive_on_repeated_bigrams() {
        assert!(bigram_dice("aaaa", "aa") <= 1.0);
        assert!(bigram_dice("高高高", "高高") <= 1.0);
        for x in ["aaaa", "高高高", "门店排班管理", "aa", "abc"] {
            let r = bigram_dice(x, x);
            assert!((r - 1.0).abs() < 1e-9, "自反性破坏：dice({x},{x})={r}");
        }
    }

    #[test]
    fn expand_appends_best_elaboration_only() {
        let interests = vec![
            "门店排班管理".to_string(),
            "固废清运调度".to_string(),
        ];
        let q = expand_query("排班怎么改", &interests);
        assert!(q.starts_with("排班怎么改"));
        assert!(q.contains("门店排班管理"), "应追加最相关兴趣词: {q}");
        assert!(!q.contains("固废清运"), "不应追加无关词: {q}");
    }

    #[test]
    fn expand_is_advisory_no_op_cases() {
        // query 已含兴趣词 → 原样
        assert_eq!(expand_query("门店排班管理的规则", &["门店排班管理".to_string()]), "门店排班管理的规则");
        // 无过阈词 → 原样
        assert_eq!(expand_query("今天天气", &["固废清运调度".to_string()]), "今天天气");
        // 空表/空 query → 原样
        assert_eq!(expand_query("任意", &[]), "任意");
        assert_eq!(expand_query("", &["任意词".to_string()]), "");
    }

    #[test]
    fn harvest_filters_by_length_and_dedup() {
        let profile = serde_json::json!([
            {"content": "门店排班管理"},
            {"content": "门店排班管理"},
            {"content": "短"},
            {"content": "这一条特别长特别长特别长特别长特别长特别长特别长特别长"},
            {"content": "固废清运调度"}
        ]);
        let arr = profile.as_array().unwrap().clone();
        let got = harvest_interests(&arr);
        assert_eq!(got, vec!["门店排班管理".to_string(), "固废清运调度".to_string()]);
    }
}
