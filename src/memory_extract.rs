//! PR2 — 写入前门提取压缩（对标 Mem0；脑子在 agent-core，Memoria 当哑存储）。
//!
//! 在 `call_tool_routed` 调用 memoria `memory_remember` / `memory` 之前拦截：
//! 用 LLM 把一条长 raw 文本拆解为 N 条原子事实，每条单独写入；
//! 原文以 `memory_type=raw` 存档（parent_id 指向它）。
//!
//! 硬约束（执行单 H1/H2）：**不在 Memoria 热路径强制 LLM**；本模块仅在 agent-core 调用侧触发。
//! 失败 / 解析失败 / 语义保真校验不过 → **降级原样写入**（与今日行为一致，不阻塞）。

use serde_json::Value;

pub const EXTRACT_MAX_FACTS: usize = 12;
pub const EXTRACT_MAX_ENTITIES: usize = 10;
pub const EXTRACT_MAX_PREFERENCES: usize = 6;
pub const EXTRACT_MAX_RELATIONS: usize = 6;

/// PR2 默认开；`AGENT_MEMORY_EXTRACT=0/false/off/no` 关闭（回退到原样写入）。
pub fn agent_memory_extract_enabled() -> bool {
    match std::env::var("AGENT_MEMORY_EXTRACT") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            !(t == "0" || t == "false" || t == "off" || t == "no")
        }
        Err(_) => true,
    }
}

/// LLM 抽取结果结构。
#[derive(Debug, Default, Clone)]
pub struct Extraction {
    pub facts: Vec<String>,
    pub entities: Vec<String>,
    pub preferences: Vec<String>,
    pub relations: Vec<String>,
    pub memory_type: Option<String>,
    pub actor: Option<String>,
}

/// 构造中文抽取 prompt（纯 JSON 输出）。
pub fn build_extract_prompt(raw: &str) -> String {
    format!(
        "你是一个记忆压缩器。把下面这段原始记忆文本，拆解为若干条独立、原子化、可单独检索的事实。\n\
         要求：\n\
         1. 每条 fact 是一个完整短句，自带必要主语/宾语，不依赖上下文也能独立理解。\n\
         2. 必须保留原文中所有关键实体、数字、金额、日期、时间、地点，不得遗漏或改写。\n\
         3. entities 为文中出现的关键命名实体（人名 / 组织 / 产品 / 地点）。\n\
         4. preferences 为用户明确表达的偏好 / 要求 / 禁忌。\n\
         5. relations 为实体之间的关系（如「A 属于 B」「A 在 B 工作」）。\n\
         6. memory_type 为这条记忆的类别（declarative / procedural / episodic / preference），默认 declarative。\n\
         7. actor 为信息来源主体（说话人 / 系统 / 文档名），若未知留空字符串。\n\
         只输出一个纯 JSON 对象，不要 markdown 代码块或任何解释。格式严格如下：\n\
         {{\"facts\":[\"...\"],\"entities\":[\"...\"],\"preferences\":[\"...\"],\"relations\":[\"...\"],\"memory_type\":\"declarative\",\"actor\":\"\"}}\n\
         facts 最多 {max_f} 条，entities 最多 {max_e} 条，preferences 最多 {max_p} 条，relations 最多 {max_r} 条。\n\n\
         原始记忆：\n{r}",
        max_f = EXTRACT_MAX_FACTS,
        max_e = EXTRACT_MAX_ENTITIES,
        max_p = EXTRACT_MAX_PREFERENCES,
        max_r = EXTRACT_MAX_RELATIONS,
        r = raw.chars().take(4000).collect::<String>(),
    )
}

/// 从 LLM 返回中容错解析出 Extraction（容忍外层 ```json 或解释文本）。
pub fn parse_extraction(text: &str) -> Option<Extraction> {
    let obj: Value = if let Ok(v) = serde_json::from_str::<Value>(text.trim()) {
        v
    } else if let (Some(s), Some(e)) = (text.find('{'), text.rfind('}')) {
        serde_json::from_str(&text[s..=e]).ok()?
    } else {
        return None;
    };
    if !obj.is_object() {
        return None;
    }
    let mut ex = Extraction::default();

    let take_arr = |key: &str, sink: &mut Vec<String>| {
        if let Some(a) = obj.get(key).and_then(|v| v.as_array()) {
            for v in a {
                if let Some(s) = v.as_str() {
                    let t = s.trim().to_string();
                    if !t.is_empty() {
                        sink.push(t);
                    }
                }
            }
        }
    };
    take_arr("facts", &mut ex.facts);
    take_arr("entities", &mut ex.entities);
    take_arr("preferences", &mut ex.preferences);
    take_arr("relations", &mut ex.relations);

    ex.memory_type = obj
        .get("memory_type")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    ex.actor = obj
        .get("actor")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if ex.facts.is_empty()
        && ex.entities.is_empty()
        && ex.preferences.is_empty()
        && ex.relations.is_empty()
    {
        return None;
    }
    Some(ex)
}

/// 是否需要真正分解：仅当产出多于 1 条，或唯一 fact 与原文不同（避免与原文完全重复）。
pub fn should_decompose(ex: &Extraction, raw: &str) -> bool {
    let total = ex.facts.len() + ex.entities.len() + ex.preferences.len() + ex.relations.len();
    if total >= 2 {
        return true;
    }
    // 唯一一条 fact
    if let Some(only) = ex.facts.first() {
        return only.trim() != raw.trim();
    }
    false
}

/// 语义保真校验（圆桌强制）：压缩后关键数字 / 日期不得丢失。
/// 仅做规则检查（数字 >=2 位、绝对日期），缺失即判失败 → 调用方降级原样写入。
pub fn fidelity_ok(raw: &str, ex: &Extraction) -> bool {
    let (raw_nums, raw_dates) = critical_tokens(raw);
    if raw_nums.is_empty() && raw_dates.is_empty() {
        return true; // 无关键 token，跳过校验
    }
    let combined = {
        let mut v = ex.facts.clone();
        v.extend(ex.entities.iter().cloned());
        v.extend(ex.preferences.iter().cloned());
        v.extend(ex.relations.iter().cloned());
        v.join("\n")
    };
    let (fact_nums, fact_dates) = critical_tokens(&combined);
    for n in &raw_nums {
        if !fact_nums.iter().any(|x| x == n) {
            tracing::debug!("[PR2][fidelity] 关键数字丢失: {}", n);
            return false;
        }
    }
    for d in &raw_dates {
        if !fact_dates.iter().any(|x| x == d) {
            tracing::debug!("[PR2][fidelity] 关键日期丢失: {}", d);
            return false;
        }
    }
    true
}

/// 从 memoria `memory_remember` 的返回文本中抽取记忆 id（`{"status":"remembered","id":"..."}`）。
pub fn extract_id(resp: &str) -> Option<String> {
    let v: Value = serde_json::from_str(resp.trim()).ok()?;
    v.get("id").and_then(|x| x.as_str()).map(|s| s.to_string())
}

/// ── 内部：关键 token 抽取（无 regex 依赖） ──

/// 返回 (数字 token 列表, 日期 token 列表)。日期规范为 `YYYY-MM-DD` / `YYYY-MM`。
fn critical_tokens(text: &str) -> (Vec<String>, Vec<String>) {
    // 去除千分位逗号，避免 "1,200" 与 "1200" 误判不一致
    let normalized = text.replace(',', "");
    let numbers = extract_numbers(&normalized);
    let dates = extract_dates(&normalized);
    (numbers, dates)
}

fn extract_numbers(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            if s.len() >= 2 && !out.contains(&s) {
                out.push(s);
            }
        } else {
            i += 1;
        }
    }
    out
}

fn extract_dates(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= n {
        if is_4digits(&chars[i..i + 4]) {
            let y: String = chars[i..i + 4].iter().collect();
            // YYYY-MM-DD
            if i + 10 <= n
                && chars[i + 4] == '-'
                && chars[i + 7] == '-'
                && is_2digits(&chars[i + 5..i + 7])
                && is_2digits(&chars[i + 8..i + 10])
            {
                let d = format!(
                    "{}-{}-{}",
                    y,
                    collect(&chars[i + 5..i + 7]),
                    collect(&chars[i + 8..i + 10])
                );
                push_uniq(&mut out, d);
                i += 10;
                continue;
            }
            // YYYY-MM
            if i + 7 <= n && chars[i + 4] == '-' && is_2digits(&chars[i + 5..i + 7]) {
                let d = format!("{}-{}", y, collect(&chars[i + 5..i + 7]));
                push_uniq(&mut out, d);
                i += 7;
                continue;
            }
            // YYYY年[MM]月[DD]日 / YYYY年[MM]月  (月/日可 1~2 位)
            if i + 5 <= n && chars[i + 4] == '年' {
                let (mo, mc) = read_1_2_digits(&chars, i + 5);
                if !mo.is_empty() && i + 5 + mc < n && chars[i + 5 + mc] == '月' {
                    let mo2 = pad2(&mo);
                    let j = i + 5 + mc + 1; // 跳过 '月'
                    // YYYY年MM月DD日
                    let (da, dc) = read_1_2_digits(&chars, j);
                    if !da.is_empty() && j + dc < n && chars[j + dc] == '日' {
                        let d = format!("{}-{}-{}", y, mo2, pad2(&da));
                        push_uniq(&mut out, d);
                        i = j + dc + 1;
                        continue;
                    }
                    // YYYY年MM月 (无日)
                    let d = format!("{}-{}", y, mo2);
                    push_uniq(&mut out, d);
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn is_4digits(s: &[char]) -> bool {
    s.len() == 4 && s.iter().all(|c| c.is_ascii_digit())
}
fn is_2digits(s: &[char]) -> bool {
    s.len() == 2 && s.iter().all(|c| c.is_ascii_digit())
}
fn collect(s: &[char]) -> String {
    s.iter().collect()
}
fn pad2(s: &str) -> String {
    format!("{:0>2}", s)
}
fn read_1_2_digits(chars: &[char], pos: usize) -> (String, usize) {
    let mut s = String::new();
    let mut c = 0;
    while c < 2 && pos + c < chars.len() && chars[pos + c].is_ascii_digit() {
        s.push(chars[pos + c]);
        c += 1;
    }
    (s, c)
}
fn push_uniq(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_default_and_off() {
        std::env::remove_var("AGENT_MEMORY_EXTRACT");
        assert!(agent_memory_extract_enabled());
        std::env::set_var("AGENT_MEMORY_EXTRACT", "0");
        assert!(!agent_memory_extract_enabled());
        std::env::set_var("AGENT_MEMORY_EXTRACT", "1");
        assert!(agent_memory_extract_enabled());
        std::env::remove_var("AGENT_MEMORY_EXTRACT");
    }

    #[test]
    fn parse_wrapped_json() {
        let raw = "好的，下面是结果：\n```json\n{\"facts\":[\"张三在A公司工作\"],\"entities\":[\"张三\"],\"preferences\":[],\"relations\":[\"张三属于A公司\"],\"memory_type\":\"declarative\",\"actor\":\"\"}\n```\n以上。";
        let ex = parse_extraction(raw).expect("应解析成功");
        assert_eq!(ex.facts.len(), 1);
        assert_eq!(ex.entities, vec!["张三".to_string()]);
        assert_eq!(ex.relations, vec!["张三属于A公司".to_string()]);
    }

    #[test]
    fn parse_empty_returns_none() {
        let ex = parse_extraction("{\"facts\":[],\"entities\":[]}");
        assert!(ex.is_none());
    }

    #[test]
    fn date_iso_and_cn() {
        let d1 = extract_dates("合同签署于 2026-07-20 生效");
        assert!(d1.contains(&"2026-07-20".to_string()));
        let d2 = extract_dates("他于 2026年7月20日 离职，2025年3月 入职");
        assert!(d2.contains(&"2026-07-20".to_string()));
        assert!(d2.contains(&"2025-03".to_string()));
    }

    #[test]
    fn fidelity_catches_missing_number() {
        let raw = "成交额 1200 吨，金额 88 万元";
        let mut ex = Extraction::default();
        ex.facts.push("成交额很大".to_string());
        // 数字 1200 / 88 均丢失 → 不过
        assert!(!fidelity_ok(raw, &ex));
        ex.facts.push("成交额 1200 吨".to_string());
        ex.facts.push("金额 88 万元".to_string());
        assert!(fidelity_ok(raw, &ex));
    }

    #[test]
    fn fidelity_catches_missing_date() {
        let raw = "他在 2026-07-20 入职";
        let mut ex = Extraction::default();
        ex.facts.push("他入职了".to_string());
        assert!(!fidelity_ok(raw, &ex));
        ex.facts.push("他在 2026-07-20 入职".to_string());
        assert!(fidelity_ok(raw, &ex));
    }

    #[test]
    fn should_decompose_logic() {
        let mut ex = Extraction::default();
        ex.facts.push("A".to_string());
        assert!(!should_decompose(&ex, "A")); // 完全重复 → 不分解
        ex.facts.push("B".to_string());
        assert!(should_decompose(&ex, "A B")); // 两条 → 分解
        let mut ex2 = Extraction::default();
        ex2.facts.push("改写后的句子".to_string());
        assert!(should_decompose(&ex2, "原始长句内容")); // 不同 → 分解
    }
}
