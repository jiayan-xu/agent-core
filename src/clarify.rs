//! P2-3 澄清工具（Palantir Request clarification 对标）
//!
//! agent 在任务需求模糊 / 缺关键信息 / 多义时，暂停执行并返回结构化澄清信号
//! （`__clarify_required: true`），由 LLM 循环识别后以提问形式呈现给用户。
//! 纯对话工具：无副作用、无数据访问，不进 boundary/配额。

/// 构造澄清结果：缺 question 报错；有 question 返回结构化 JSON（可附 options）。
pub fn build_clarify_result(args: &serde_json::Value) -> Result<String, String> {
    let question = args
        .get("question")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if question.is_empty() {
        return Err("request_clarification 需要 question 参数".into());
    }
    let options: Vec<String> = args
        .get("options")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mut payload = serde_json::json!({
        "__clarify_required": true,
        "question": question,
    });
    if !options.is_empty() {
        payload["options"] = serde_json::Value::Array(
            options.into_iter().map(serde_json::Value::String).collect(),
        );
    }
    Ok(serde_json::to_string(&payload).unwrap_or_else(|_| {
        r#"{"__clarify_required":true,"question":"需要澄清"}"#.to_string()
    }))
}

/// 澄清工具的定义（供 fetch_tools_filtered 注入）
pub fn tool_def() -> crate::llm::ToolDef {
    crate::llm::ToolDef {
        type_: "function".to_string(),
        function: crate::llm::ToolDefFunction {
            name: "request_clarification".to_string(),
            description: "当任务需求模糊、缺少关键信息（如车牌/日期/企业名/操作对象），或存在多个可能解释时，暂停执行并向用户提出澄清问题。用法：给出具体 question，可附 2-4 个 options 供用户选择。调用后不要继续猜测执行，等待用户回答。"
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "question": {"type": "string", "description": "向用户提出的澄清问题"},
                    "options": {"type": "array", "items": {"type": "string"}, "description": "可选选项（2-4 个）"}
                },
                "required": ["question"]
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_clarify_result_basic() {
        let args = serde_json::json!({"question": "请确认查询哪个车牌？"});
        let out = build_clarify_result(&args).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["__clarify_required"], true);
        assert_eq!(v["question"], "请确认查询哪个车牌？");
        assert!(v.get("options").is_none());
    }

    #[test]
    fn test_build_clarify_result_with_options() {
        let args = serde_json::json!({
            "question": "按哪个维度对账？",
            "options": ["按日", "按月", "按企业"]
        });
        let out = build_clarify_result(&args).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["options"].as_array().unwrap().len(), 3);
        assert_eq!(v["options"][0], "按日");
    }

    #[test]
    fn test_build_clarify_result_empty_question() {
        let args = serde_json::json!({"options": ["a"]});
        assert!(build_clarify_result(&args).is_err());
    }

    #[test]
    fn test_tool_def_shape() {
        let def = tool_def();
        assert_eq!(def.function.name, "request_clarification");
        assert!(def.function.parameters["required"][0] == "question");
    }
}
