//! 会话经验 memo（P1-A：/refine 合成点，对照文档 §3 P1 最佳合成点）。
//!
//! 背景：`meta_evolution` 的 `min_samples=20` 冷启动门槛依赖 memoria `evolution_log`
//! 的 `rolled_back`/`corrected` 负样本——回滚日志稀少时永远 `insufficient_samples`。
//! Prime Agent 的 `/refine`（每会话经验 memo）正解此门：把**运行时工具失败教训**
//! 结构化沉淀为 memo，作为 meta_evolution 评估器的**第二样本源**（写入侧主动积累，
//! 不依赖回滚事件），既保留「持续经验学习」，又喂「可验证进化闸门」。
//!
//! 数据流：
//!   execute_tool_calls 失败分支 → `record_experience_memo()` 写 memoria
//!   （category=experience_memo，标签 `[experience_memo, lesson, <tool>]`）
//!   → `collect_negative_samples` 增补 `collect_memo_samples()` 召回合并。

use crate::mcp_client::McpClient;

/// 写入一条会话经验 memo（工具失败教训）。best-effort：失败仅告警不阻断。
/// 结构：content 含 工具名 / 错误摘要 / 触发上下文；tag 便于按工具召回；
/// 与 evolution_log 样本共走 `min_samples` 门槛（两源合并计数）。
pub async fn record_experience_memo(
    mcp: &McpClient,
    tool: &str,
    err: &str,
    ns: &str,
) {
    let err_preview: String = err.chars().take(200).collect();
    let content = format!(
        "[experience_memo] 工具 {} 执行失败：{}",
        tool, err_preview
    );
    let args = serde_json::json!({
        "content": content,
        "tags": ["experience_memo", "lesson", tool],
        "category": "experience_memo",
        "confidence": 70,
        "importance": 3,
        "namespace": ns,
    });
    match mcp.call_json("memory_remember", &args).await {
        Ok(_) => {
            tracing::debug!(tool = %tool, ns = %ns, "experience_memo 已写入");
        }
        Err(e) => {
            tracing::warn!(tool = %tool, "experience_memo 写入失败（best-effort）: {}", e);
        }
    }
}

/// 召回经验 memo 样本（第二样本源）：按标签 `experience_memo` + `lesson` 检索，
/// 取窗口内最近 `limit` 条，映射为 `NegSample`（change_type 语义：
/// 用工具名近似「易错操作」，old/new 承载错误上下文，供元优化器学习禁忌）。
pub async fn collect_memo_samples(
    mcp: &McpClient,
    ns: &str,
    limit: usize,
) -> Vec<crate::meta_evolve::NegSample> {
    let args = serde_json::json!({
        "query": "experience_memo 工具执行失败 lesson",
        "namespace": ns,
        "category": "experience_memo",
        "max_results": limit.min(50),
    });
    let raw = mcp
        .call_json("memory_search_v2", &args)
        .await
        .unwrap_or_else(|_| serde_json::json!({}));
    let results = raw
        .get("results")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    results
        .into_iter()
        .filter_map(|it| {
            let content = it
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            if content.is_empty() || !content.contains("experience_memo") {
                return None;
            }
            // 从 content 提取工具名（"[experience_memo] 工具 X 执行失败：..."）
            let tool = content
                .split("工具 ")
                .nth(1)
                .and_then(|s| s.split(' ').next())
                .unwrap_or("unknown")
                .to_string();
            Some(crate::meta_evolve::NegSample {
                change_type: format!("tool_failure:{}", tool),
                old_value: content.clone(),
                new_value: String::new(),
                context: content,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_content_parses_tool_name() {
        // 解析 content 提取工具名的纯逻辑验证
        let content = "[experience_memo] 工具 fill_excel_log 执行失败：写入被拒";
        let tool = content
            .split("工具 ")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .unwrap_or("unknown");
        assert_eq!(tool, "fill_excel_log");
    }
}
