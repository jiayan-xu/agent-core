//! 组合路由引擎 — 多 Skill 分解、路由、执行
//!
//! 借鉴阿里 SkillWeaver 的 decompose-retrieve-compose 思路，
//! 轻量实现：LLM 分解 + 按依赖序串行执行。
//!
//! composer 只处理 data 结构 + decompose。
//! execute_plan 放在 AgentCore 中（需要访问 call_tool_routed）。

use crate::llm::{LlmClient, Message, ToolDef};

/// 执行计划中的一个步骤
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ExecutionPlan {
    pub steps: Vec<StepPlan>,
}

/// 将用户请求分解为多步执行计划
///
/// 返回 ExecutionPlan，如果请求很简单只需一步也返回单步 plan。
/// 解析失败时返回 Err，调用方应降级到普通 LLM loop。
pub async fn decompose(
    llm: &LlmClient,
    query: &str,
    tools: &[ToolDef],
) -> Result<ExecutionPlan, String> {
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
- arguments 中的值如果是字符串直接写；如果需要引用上一步的结果，使用 "step_N" 占位符
- 如果请求很简单只需要一步，返回一个 step 即可
- 确保 JSON 合法，不要有多余文字"#,
    );

    let msgs = vec![
        Message {
            role: "system".to_string(),
            content: Some(system_prompt),
            tool_calls: None,
            tool_call_id: None,
        },
        Message {
            role: "user".to_string(),
            content: Some(query.to_string()),
            tool_calls: None,
            tool_call_id: None,
        },
    ];

    let response = llm.chat(&msgs, &[]).await?;
    let raw_text = response.text.trim().to_string();

    // 多策略解析，从宽松到严格
    let plan = try_parse_plan(&raw_text).map_err(|e| {
        format!(
            "解析计划失败: {} (原始: {})",
            e,
            raw_text.chars().take(160).collect::<String>()
        )
    })?;

    if plan.steps.is_empty() {
        return Err("计划为空".to_string());
    }

    // 校验：所有工具名必须在 tools 列表中
    let tool_names: std::collections::HashSet<&str> =
        tools.iter().map(|t| t.function.name.as_str()).collect();
    for step in &plan.steps {
        if !tool_names.contains(step.tool.as_str()) {
            return Err(format!(
                "Step {} 使用了未知工具: {}",
                step.step_id, step.tool
            ));
        }
    }

    Ok(plan)
}

/// 多策略尝试解析 LLM 输出的 JSON 计划
///
/// 策略 1: 直接解析（最干净的情况）
/// 策略 2: 提取 ```json ... ``` 代码块
/// 策略 3: 提取第一个 json 对象
/// 策略 4: 修复常见问题后重试
fn try_parse_plan(text: &str) -> Result<ExecutionPlan, String> {
    let strategies: [&str; 3] = ["direct", "codeblock", "first_json"];

    for strategy in &strategies {
        let candidate = match *strategy {
            "direct" => text.to_string(),
            "codeblock" => extract_code_block(text),
            "first_json" => extract_first_json(text),
            _ => continue,
        };

        if candidate.is_empty() {
            continue;
        }

        // 尝试直接解析
        if let Ok(plan) = serde_json::from_str::<ExecutionPlan>(&candidate) {
            return Ok(plan);
        }

        // 尝试修复常见问题后解析
        let fixed = fix_common_issues(&candidate);
        if let Ok(plan) = serde_json::from_str::<ExecutionPlan>(&fixed) {
            return Ok(plan);
        }
    }

    Err("所有解析策略都失败".to_string())
}

/// 提取 markdown 代码块中的内容
fn extract_code_block(text: &str) -> String {
    // 查找 ```json 或 ``` 包裹的内容
    let lines: Vec<&str> = text.lines().collect();
    let mut in_block = false;
    let mut content = Vec::new();

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_block {
                // 代码块结束
                break;
            } else {
                // 代码块开始
                in_block = true;
                continue;
            }
        }
        if in_block {
            content.push(*line);
        }
    }

    if content.is_empty() {
        return String::new();
    }
    content.join("\n").trim().to_string()
}

/// 提取文本中的第一个 JSON 对象或数组
fn extract_first_json(text: &str) -> String {
    // 找第一个 {
    let start = match text.find('{') {
        Some(i) => i,
        None => return String::new(),
    };

    // 找匹配的 }
    let mut depth = 0u32;
    let mut in_string = false;
    let mut escaped = false;
    let mut end = start;

    for (i, ch) in text[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    end = start + i + ch.len_utf8();
                    break;
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return String::new(); // 括号不匹配
    }

    text[start..end].to_string()
}

/// 修复 JSON 中的常见问题
fn fix_common_issues(text: &str) -> String {
    let mut s = text.to_string();

    // 修复单引号 → 双引号
    s = s.replace('\'', "\"");

    // 移除末尾多余的逗号（在 } 或 ] 前）
    s = remove_trailing_commas(&s);

    // 也移除无空格模式的 ,} → }
    s = s.replace(",}", "}");
    s = s.replace(",]", "]");

    s
}

/// 移除 JSON 中数组/对象末尾多余的逗号
fn remove_trailing_commas(text: &str) -> String {
    // 移除 ,} → } 和 ,] → ]
    let mut s = text.to_string();
    loop {
        let prev = s.clone();
        s = s.replace(",\n}", "}");
        s = s.replace(",\n]", "]");
        s = s.replace(", }", "}");
        s = s.replace(", ]", "]");
        if s == prev {
            break;
        }
    }
    s
}

// ══════════════════════════════════════════════════════
// 测试
// ══════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan_json() -> &'static str {
        r#"{"steps":[{"step_id":1,"description":"查数据","tool":"query_sql","arguments":{"sql":"SELECT 1"},"depends_on":[]}]}"#
    }

    fn sample_plan() -> ExecutionPlan {
        ExecutionPlan {
            steps: vec![StepPlan {
                step_id: 1,
                description: "查数据".to_string(),
                tool: "query_sql".to_string(),
                arguments: serde_json::json!({"sql": "SELECT 1"}),
                depends_on: vec![],
            }],
        }
    }

    #[test]
    fn test_direct_parse() {
        let plan = try_parse_plan(sample_plan_json()).unwrap();
        assert_eq!(plan, sample_plan());
    }

    #[test]
    fn test_codeblock_json() {
        let text = format!("思考过程...\n```json\n{}\n```\n结束", sample_plan_json());
        let plan = try_parse_plan(&text).unwrap();
        assert_eq!(plan, sample_plan());
    }

    #[test]
    fn test_codeblock_no_lang() {
        let text = format!("```\n{}\n```", sample_plan_json());
        let plan = try_parse_plan(&text).unwrap();
        assert_eq!(plan, sample_plan());
    }

    #[test]
    fn test_extra_text_before() {
        let text = format!(
            "好的，我来帮你分解任务：\n\n{}\n\n确认这个方案吗？",
            sample_plan_json()
        );
        let plan = try_parse_plan(&text).unwrap();
        assert_eq!(plan, sample_plan());
    }

    #[test]
    fn test_trailing_commas() {
        let text = r#"{"steps":[{"step_id":1,"description":"查数据","tool":"query_sql","arguments":{"sql":"SELECT 1"},}],}"#;
        let plan = try_parse_plan(text).unwrap();
        assert_eq!(plan, sample_plan());
    }

    #[test]
    fn test_single_quotes() {
        let text = r#"{'steps':[{'step_id':1,'description':'查数据','tool':'query_sql','arguments':{'sql':'SELECT 1'},'depends_on':[]}]}"#;
        let plan = try_parse_plan(text).unwrap();
        assert_eq!(plan, sample_plan());
    }

    #[test]
    fn test_extract_first_json_with_prefix() {
        let text = "一些文字在前面 {\"steps\":[]} 后面还有文字";
        let extracted = extract_first_json(text);
        assert_eq!(extracted, "{\"steps\":[]}");
    }

    #[test]
    fn test_empty_input() {
        assert!(try_parse_plan("").is_err());
        assert!(try_parse_plan("完全没有JSON内容").is_err());
    }

    #[test]
    fn test_multi_step_plan() {
        let json = r#"{"steps":[
            {"step_id":1,"description":"查数据","tool":"query_sql","arguments":{"sql":"SELECT 1"},"depends_on":[]},
            {"step_id":2,"description":"发邮件","tool":"send_email","arguments":{"to":"admin"},"depends_on":[1]}
        ]}"#;
        let plan = try_parse_plan(json).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].tool, "query_sql");
        assert_eq!(plan.steps[1].depends_on, vec![1]);
    }
}
