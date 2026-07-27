//! 偏好 / 决策落盘约定（对齐 Memoria Profile：category + tags）。
//!
//! - preference：`category=preference`，tags ∈ {hard_rule, pref, style}
//! - decision：`category=decision`，tags 含 `decision`
//! - 肯定评价 / 强指令：用户话术命中启发式 → 自动 remember（不经 LLM）

/// 强触发：用户明确要求「记住/硬规则/偏好」时抽取落盘内容。
/// 返回 `(content, tag)`，tag ∈ hard_rule|pref。
pub fn strong_pref_trigger(user_msg: &str) -> Option<(String, &'static str)> {
    let t = user_msg.trim();
    if t.chars().count() < 6 || t.chars().count() > 500 {
        return None;
    }
    let lower = t.to_lowercase();

    // 硬规则信号
    const HARD: &[&str] = &[
        "硬性要求",
        "必须这样",
        "绝对不要",
        "永远不要",
        "严禁",
        "禁止",
        "以后都不要",
        "以后不许",
    ];
    for h in HARD {
        if t.contains(h) {
            return Some((t.to_string(), "hard_rule"));
        }
    }

    // 偏好 / 肯定落盘信号
    const PREF: &[&str] = &[
        "请记住",
        "记住这个",
        "记住：",
        "记住,",
        "记住，",
        "以后都按",
        "以后就按",
        "就按这个办",
        "就这么办",
        "按这个执行",
        "我喜欢",
        "我偏好",
        "优先用",
        "优先使用",
        "默认用",
        "以后默认",
    ];
    for p in PREF {
        if t.contains(p) || lower.contains(&p.to_lowercase()) {
            return Some((t.to_string(), "pref"));
        }
    }

    // 肯定 + 指令合体（短句）
    if (t.contains("你说得对") || t.contains("没错") || t.contains("就这样"))
        && (t.contains("按") || t.contains("记住") || t.contains("以后"))
    {
        return Some((t.to_string(), "pref"));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_rule_trigger() {
        let r = strong_pref_trigger("硬性要求：生产库禁止直接 DROP").unwrap();
        assert_eq!(r.1, "hard_rule");
    }

    #[test]
    fn pref_trigger() {
        let r = strong_pref_trigger("请记住：回复默认用简体中文").unwrap();
        assert_eq!(r.1, "pref");
    }

    #[test]
    fn ignore_noise() {
        assert!(strong_pref_trigger("好的").is_none());
        assert!(strong_pref_trigger("看看日志").is_none());
    }
}
