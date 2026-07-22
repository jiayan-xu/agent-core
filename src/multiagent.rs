//! HY3 1.3 —— MultiAgent Compose（子 agent 派发；**非** Meta RSI 的 HyperAgents）。
//!
//! 定位：把一个 Hard 任务 decompose 成若干可独立子任务，逐派发执行并聚合。
//! 与战略报告里的 HyperAgents（≈ 改改进机制 / Meta RSI）**不是一回事**——本文只是
//! 最朴素的「任务分解 + 并行/顺序派发」编排，是 LATS/技能库之上的应用层。
//!
//! 门控：仅 `features.multiagent = true` 时 `AgentCore` 才持有 `MultiAgentConfig`；
//! `maybe_compose` 在 flag 关或任务非 Hard 或分解为空时返回 None，走原路径。
//! 当前 `dispatch` 为顺序派发（stub）；真实并行派发/隔离沙箱留待 G 门复验后深化。

use serde::{Deserialize, Serialize};

use crate::llm::{LlmClient, Message, RoutedLlm, ToolDef};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAgentConfig {
    /// 是否在编译期武装（真正生效还需 AgentConfig.features.multiagent=true）
    #[serde(default)]
    pub enabled: bool,
    /// 最大子 agent 数（分解出的子任务上限）
    #[serde(default = "default_fanout")]
    pub max_subagents: usize,
    /// opt-in 守卫：消息须含此 token（如 "[compose]"）才允许劫持主路径。
    /// 默认 `Some("[compose]")` —— 即默认不劫持，避免生产 Hard 任务被无声改写为纯 LLM 作文
    /// （P0-2：原行为判 Hard 即整段接管、绕过工具/composer/LATS、耗时 >3min）。
    /// 设为空字符串 "" 视为关闭 token 校验（但仍可走 task_whitelist）。
    #[serde(default = "default_opt_in_token")]
    pub opt_in_token: Option<String>,
    /// 任务白名单（子串匹配）：命中其一即视为已 opt-in（即便消息无 token）。
    #[serde(default)]
    pub task_whitelist: Vec<String>,
}

fn default_fanout() -> usize {
    4
}

fn default_opt_in_token() -> Option<String> {
    Some("[compose]".to_string())
}

impl Default for MultiAgentConfig {
    fn default() -> Self {
        MultiAgentConfig {
            enabled: false,
            max_subagents: default_fanout(),
            opt_in_token: default_opt_in_token(),
            task_whitelist: Vec::new(),
        }
    }
}

/// 一个子任务
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubTask {
    pub title: String,
    pub description: String,
}

/// 把任务 decompose 成若干子任务（LLM 调用）。失败/空返回空 vec。
pub async fn plan_decomposition(llm: &LlmClient, task: &str) -> Vec<SubTask> {
    let prompt = format!(
        "把以下任务分解为至多 {} 个可独立执行的子任务。\n\
         严格按 JSON 输出：{{\"tasks\":[{{\"title\":\"简短标题\",\"description\":\"子任务具体描述\"}}]}}\n\
         任务：{}",
        default_fanout(),
        task
    );
    match llm
        .chat(
            &[Message {
                role: "user".to_string(),
                content: Some(prompt),
                tool_calls: None,
                tool_call_id: None,
            }],
            &[] as &[ToolDef],
        )
        .await
    {
        Ok(r) => parse_subtasks(&r.text),
        Err(e) => {
            tracing::warn!(target = "agent.multiagent", "decompose 失败: {}", e);
            Vec::new()
        }
    }
}

/// 从 LLM 输出解析子任务列表（容忍前后废话，抽取首个 `{...}` 块）。
pub fn parse_subtasks(json: &str) -> Vec<SubTask> {
    let start = json.find('{');
    let end = json.rfind('}');
    if let (Some(s), Some(e)) = (start, end) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json[s..=e]) {
            if let Some(arr) = v.get("tasks").and_then(|t| t.as_array()) {
                return arr
                    .iter()
                    .filter_map(|t| {
                        let title = t.get("title")?.as_str()?.to_string();
                        let description = t.get("description")?.as_str()?.to_string();
                        Some(SubTask { title, description })
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

/// 逐子任务派发（当前顺序执行 + 聚合；真实并行留待深化）。
pub async fn dispatch(rt: &RoutedLlm, subtasks: &[SubTask]) -> String {
    let mut out = String::new();
    for st in subtasks {
        match rt
            .chat(
                &[Message {
                    role: "user".to_string(),
                    content: Some(st.description.clone()),
                    tool_calls: None,
                    tool_call_id: None,
                }],
                &[] as &[ToolDef],
            )
            .await
        {
            Ok(r) => out.push_str(&format!("### {}\n{}\n\n", st.title, r.text)),
            Err(e) => out.push_str(&format!("### {} (失败: {})\n\n", st.title, e)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subtasks_ok() {
        let j = r#"无关文字 {"tasks":[{"title":"A","description":"做A"},{"title":"B","description":"做B"}]} 结尾"#;
        let v = parse_subtasks(j);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].title, "A");
        assert_eq!(v[1].description, "做B");
    }

    #[test]
    fn parse_subtasks_empty_on_garbage() {
        assert!(parse_subtasks("not json at all").is_empty());
    }
}
