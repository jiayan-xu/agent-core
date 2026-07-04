//! 组合路由引擎 — 多 Skill 分解、路由、执行
//!
//! 借鉴阿里 SkillWeaver 的 decompose-retrieve-compose 思路，
//! 轻量实现：LLM 分解 + 按依赖序串行执行。
//!
//! composer 只处理 data 结构 + decompose。
//! execute_plan 放在 AgentCore 中（需要访问 call_tool_routed）。

use crate::llm::{LlmClient, Message, ToolDef};

/// 执行计划中的一个步骤
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StepPlan {
    pub step_id: u32,
    pub description: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub depends_on: Vec<u32>,
}

/// 完整执行计划
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutionPlan {
    pub steps: Vec<StepPlan>,
}

/// 将用户请求分解为多步执行计划
///
/// 返回 ExecutionPlan，如果请求很简单只需一步也返回单步 plan。
/// 解析失败时返回 Err，调用方应降级到普通 LLM loop。
pub async fn decompose(llm: &LlmClient, query: &str, tools: &[ToolDef]) -> Result<ExecutionPlan, String> {
    // 构建工具摘要（名称 + 简短描述）
    let mut tools_summary = String::new();
    for t in tools.iter().take(30) {
        let desc: String = t.function.description.chars().take(80).collect();
        tools_summary.push_str(&format!("- `{}`: {}\n", t.function.name, desc));
    }

    let system_prompt = format!(
        r#"你是一个任务规划器。将用户的请求分解为多个步骤，每个步骤使用一个工具。

可用工具：
{tools_summary}
输出格式（纯 JSON，不要 markdown 代码块标记，不要多余文字）：
{{"steps":[{{"step_id":1,"description":"步骤描述","tool":"工具名","arguments":{{"key":"value"}},"depends_on":[]}}]}}

规则：
- 每个步骤只能用一个工具，使用上面列表中的工具名
- 如果步骤 B 依赖步骤 A 的结果，在 B.depends_on 中写上 A 的 step_id
- 如果不依赖任何前置步骤，depends_on 为空数组
- arguments 中的值如果是字符串直接写；如果需要引用上一步的结果，使用 "step_N" 占位符（例如 "data": "step_1" 表示使用 step_1 的输出）
- 如果请求很简单只需要一步，返回一个 step 即可
- 确保 JSON 合法，不要有多余文字"#,
    );

    let msgs = vec![
        Message { role: "system".to_string(), content: Some(system_prompt), tool_calls: None, tool_call_id: None },
        Message { role: "user".to_string(), content: Some(query.to_string()), tool_calls: None, tool_call_id: None },
    ];

    let response = llm.chat(&msgs, &[]).await?;
    let text = response.text.trim().to_string();

    // 清理可能的 markdown 代码块包裹
    let cleaned = text
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let plan: ExecutionPlan = serde_json::from_str(cleaned)
        .map_err(|e| format!("解析计划失败: {} (原始: {})", e, text.chars().take(120).collect::<String>()))?;

    if plan.steps.is_empty() {
        return Err("计划为空".to_string());
    }

    // 校验：所有工具名必须在 tools 列表中
    let tool_names: std::collections::HashSet<&str> = tools.iter().map(|t| t.function.name.as_str()).collect();
    for step in &plan.steps {
        if !tool_names.contains(step.tool.as_str()) {
            return Err(format!("Step {} 使用了未知工具: {}", step.step_id, step.tool));
        }
    }

    Ok(plan)
}
