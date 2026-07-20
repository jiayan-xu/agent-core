//! PR4（Phase A 演化）：agent-core 侧演化决策开关 + LLM 输出解析。
//!
//! 演化认知在 `AgentCore::consolidate`（批处理 / 夜间 / 空闲 tick）产出，
//! 经 MCP `memory_evolve` 落库到 Memoria（哑存储，守 H1/H2）。本模块只提供：
//!  - `agent_memory_evolve_enabled()` 功能开关（默认开，仿 PR2 的 `AGENT_MEMORY_EXTRACT`）
//!  - `parse_evolution_array()` 解析 LLM 返回的演化决策 JSON 数组

use serde_json::Value;

/// PR4 默认开；`AGENT_MEMORY_EVOLVE=0/false/off/no` 关闭（回退到不演化，记忆保持待演化状态）。
pub fn agent_memory_evolve_enabled() -> bool {
    match std::env::var("AGENT_MEMORY_EVOLVE") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            !(t == "0" || t == "false" || t == "off" || t == "no")
        }
        Err(_) => true,
    }
}

/// 解析演化决策 LLM 输出：期望纯 JSON 数组 `[{"id":..,"evolved_context":..}, ...]`。
/// 容错：直接解析失败则截取最外层 `[...]` 再试。返回 `(记忆 id, 演化上下文)` 列表。
pub fn parse_evolution_array(text: &str) -> Vec<(String, String)> {
    let text = text.trim();
    let arr: Option<Value> = serde_json::from_str(text).ok().or_else(|| {
        let start = text.find('[')?;
        let end = text.rfind(']')?;
        serde_json::from_str(&text[start..=end]).ok()
    });
    let arr = match arr {
        Some(Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for e in arr {
        let id = e
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ctx = e
            .get("evolved_context")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !id.is_empty() && !ctx.is_empty() {
            out.push((id, ctx));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_default_on() {
        std::env::remove_var("AGENT_MEMORY_EVOLVE");
        assert!(agent_memory_evolve_enabled());
        std::env::set_var("AGENT_MEMORY_EVOLVE", "0");
        assert!(!agent_memory_evolve_enabled());
        std::env::set_var("AGENT_MEMORY_EVOLVE", "no");
        assert!(!agent_memory_evolve_enabled());
        std::env::remove_var("AGENT_MEMORY_EVOLVE");
    }

    #[test]
    fn parse_array_skips_empty() {
        let j = r#"[{"id":"m1","evolved_context":"关联到周三例会"},{"id":"m2","evolved_context":""}]"#;
        let v = parse_evolution_array(j);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "m1");
        assert_eq!(v[0].1, "关联到周三例会");
    }

    #[test]
    fn parse_array_with_surrounding_text() {
        let j = "好的，这是演化结果：\n[{\"id\":\"m9\",\"evolved_context\":\"X\"}]\n以上。";
        let v = parse_evolution_array(j);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "m9");
    }
}
