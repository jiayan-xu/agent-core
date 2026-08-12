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
/// **双写**（bug·medium 第六轮）：会话 ns（隔离粒度，`agent/{id}/{caller}`）+ 根 ns
/// （`agent/{id}`，collect 的检索源）各写一份——否则第二样本源永远取不到
/// （写会话 ns、读根 ns 的缺口）。
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
    // 从会话 ns 推导根 ns：`agent/{id}/{caller}` → `agent/{id}`；非该形态则
    // 只写原 ns（不猜测）。
    let root_ns: Option<String> = {
        let parts: Vec<&str> = ns.split('/').collect();
        if parts.len() >= 2 && parts[0] == "agent" && !parts[1].is_empty() {
            Some(format!("agent/{}", parts[1]))
        } else {
            None
        }
    };
    let mut targets = vec![ns.to_string()];
    if let Some(rn) = &root_ns {
        if rn != ns {
            targets.push(rn.clone());
        }
    }
    for target in &targets {
        let args = serde_json::json!({
            "content": content,
            "tags": ["experience_memo", "lesson", tool],
            "category": "experience_memo",
            "confidence": 70,
            "importance": 3,
            "namespace": target,
        });
        match mcp.call_json("memory_remember", &args).await {
            Ok(_) => {
                tracing::debug!(tool = %tool, ns = %target, "experience_memo 已写入");
            }
            Err(e) => {
                tracing::warn!(tool = %tool, ns = %target, "experience_memo 写入失败（best-effort）: {}", e);
            }
        }
    }
}

/// 从 memo content 提取工具名（"[experience_memo] 工具 X 执行失败：..."）。
/// 纯函数（test·medium 第九轮：测试调用真实实现而非内联复制）。
/// 约定：record_experience_memo 固定写入该格式；工具名含空格时取首段近似；
/// 解析失败回落 "unknown"。
pub fn parse_tool_from_memo(content: &str) -> String {
    // bug·low（第十一轮）：空工具名（"工具  " 后无内容）也会命中 split，需
    // 显式判空回落 unknown。
    match content.split("工具 ").nth(1).and_then(|s| s.split(' ').next()) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => "unknown".to_string(),
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
        .unwrap_or_else(|e| {
            // other·medium：MCP 错误不能静默变空结果（否则样本源故障无迹可查）
            tracing::warn!(target: "agent.meta_evolve", ns = %ns, "experience_memo 召回失败: {}", e);
            serde_json::json!({})
        });
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
            // 从 content 提取工具名（"[experience_memo] 工具 X 执行失败：..."）。
            // 约定：record_experience_memo 固定写入该格式；若工具名含空格（极罕见），
            // 只取首段作为近似标签（maintainability·low 已文档化；解析失败回落
            // "unknown" 不阻断采样）。
            let tool = parse_tool_from_memo(&content);
            Some(crate::meta_evolve::NegSample {
                change_type: format!("tool_failure:{}", tool),
                old_value: content.clone(),
                new_value: String::new(),
                context: content,
            })
        })
        .collect()
}

/// P1-C（RLM 上下文外置）：把组合计划的大步骤结果外置到 memoria（外部变量）。
/// key 语义：`plan_step:{session_id}:{step_id}`，标签 `[plan_step_result, composer]`。
/// 后续 summarize/续跑可经 `recall_plan_step` 按 key 召回，prompt 只带指针/摘要，
/// 长任务上下文不随步骤数线性膨胀（对照文档 §3 P1）。
/// best-effort：memoria 写失败仅告警，本地 step_results 不受影响。
pub async fn externalize_plan_step(
    mcp: &McpClient,
    session_id: &str,
    step_id: u32,
    result: &str,
    ns: &str,
) {
    // 结果超长时截断存储体（bug·medium 第四轮：只存 head 会丢尾部结论——
    // 工具结果的关键汇总常在末尾。改为 head + tail 摘要，中间省略标记；
    // 总长仍限 4096 字符，防 memoria 单条过大）。
    let stored: String = if result.chars().count() > 4096 {
        let head: String = result.chars().take(3000).collect();
        let tail: String = result.chars().skip(result.chars().count() - 1000).collect();
        format!("{}…[中段省略 {} 字符]…{}", head, result.chars().count() - 4000, tail)
    } else {
        result.to_string()
    };
    let content = format!(
        "[plan_step_result] session={} step={}\n{}",
        session_id, step_id, stored
    );
    let args = serde_json::json!({
        "content": content,
        "tags": ["plan_step_result", "composer", format!("step:{}", step_id)],
        "category": "plan_step_result",
        "confidence": 90,
        "importance": 2,
        "namespace": ns,
    });
    match mcp.call_json("memory_remember", &args).await {
        Ok(_) => {
            tracing::debug!(session = %session_id, step = %step_id, "plan_step 已外置到 Memoria");
        }
        Err(e) => {
            tracing::warn!(session = %session_id, step = %step_id, "plan_step 外置失败（best-effort）: {}", e);
        }
    }
}

/// 召回外置的 plan_step 结果（P1-C：崩溃恢复 / 跨会话续跑时按 key 取回）。
/// best-effort：未命中返回 None。
pub async fn recall_plan_step(
    mcp: &McpClient,
    session_id: &str,
    step_id: u32,
    ns: &str,
) -> Option<String> {
    let query = format!("plan_step_result session={} step={}", session_id, step_id);
    let args = serde_json::json!({
        "query": query,
        "namespace": ns,
        "category": "plan_step_result",
        // bug·medium（第三轮）：语义搜索 top1 可能不是目标 step（语义相近的其它
        // 步骤结果更靠前）——取 5 个候选，靠下方的精确 session+step 过滤命中。
        "max_results": 5,
    });
    let raw = mcp
        .call_json("memory_search_v2", &args)
        .await
        .map_err(|e| {
            // other·medium：后端失败与未命中必须可区分（补日志）
            tracing::warn!(target: "agent.composer", ns = %ns, "plan_step 召回失败: {}", e);
            e
        })
        .ok()?;
    let results = raw.get("results").and_then(|r| r.as_array()).cloned()?;
    for it in results {
        let content = it
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        // 精确 step/session 匹配（bug·medium 第九轮修正）：**只匹配元信息前缀行**
        // （首行 `[plan_step_result] session=.. step=..`）——结果体可能含
        // "session=.."/"step=.." 字样（如查询内容），全段扫描会误配。
        let header = content.lines().next().unwrap_or("");
        let step_pat = format!("step={}", step_id);
        let session_pat = format!("session={}", session_id);
        let exact_match = |line: &str, pat: &str| -> bool {
            line.find(pat).map(|pos| {
                let before = line[..pos].chars().next_back().map(|c| !c.is_ascii_alphanumeric()).unwrap_or(true);
                // after 边界拒字母数字（bug·low 第十一轮）：`step=3x` 与 `step=3`
                // 是不同 token，仅拒数字会误配（step=3 匹配 step=3a 之类）
                let after = line[pos + pat.len()..]
                    .chars()
                    .next()
                    .map(|c| !c.is_ascii_alphanumeric())
                    .unwrap_or(true);
                before && after
            }).unwrap_or(false)
        };
        let session_ok = exact_match(header, &session_pat);
        let step_ok = exact_match(header, &step_pat);
        if session_ok && step_ok {
            // 剥掉元信息前缀，返回纯结果
            return Some(
                content
                    .split_once('\n')
                    .map(|(_, rest)| rest.to_string())
                    .unwrap_or(content),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_content_parses_tool_name() {
        // test·medium（第九轮）：调用真实实现 parse_tool_from_memo，不内联复制
        let content = "[experience_memo] 工具 fill_excel_log 执行失败：写入被拒";
        assert_eq!(parse_tool_from_memo(content), "fill_excel_log");
        // 无工具名格式 → unknown 回落
        assert_eq!(parse_tool_from_memo("随便一段文本"), "unknown");
    }

    #[test]
    fn plan_step_content_roundtrip() {
        // 外置内容：剥元信息前缀后应还原结果体（纯逻辑验证）
        let content = "[plan_step_result] session=s1 step=3\n查询结果：7 月进厂 42 车";
        let rest: String = match content.split_once('\n') {
            Some((_, body)) => body.to_string(),
            None => content.to_string(),
        };
        assert_eq!(rest, "查询结果：7 月进厂 42 车");
    }
}
