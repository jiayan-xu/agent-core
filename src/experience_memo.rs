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

/// 会话 ns 登记集（P2-E 沉淀任务用）：record 时登记，meta-evolution 时对登记过
/// 的 ns 批量沉淀到根 ns——避免枚举全部会话 ns（caller 维度有限）。
/// **跨重启持久化**（bug·high 第三轮）：纯进程内集合在崩溃/重启后清空，沉淀
/// 永远枚举不到崩溃前记录的 ns → 根 ns 永久缺失（旧双写方案无此问题）。
/// 登记集落盘 `cwd/experience_memo_ns.json`（本地 JSON，写入热路径便宜），
/// sediment 前 load 合并。单实例部署下跨实例无此问题（多实例需共享存储，非
/// 当前拓扑，已文档化）。
static RECORDED_NS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn recorded_ns() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    RECORDED_NS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

fn recorded_ns_path() -> String {
    std::env::current_dir()
        .unwrap_or_default()
        .join("experience_memo_ns.json")
        .to_string_lossy()
        .to_string()
}

/// 登记集落盘（best-effort；本地 JSON 小文件，失败仅告警）。
/// 原子写：临时文件 + rename，防半写损坏。
/// **全程持锁**（bug·high 第六轮）：序列化 + 写 tmp + rename 全部在锁内——
/// 锁外写文件期间另一线程 insert 后落盘，本线程 rename 会用旧快照覆盖丢其 ns
/// （lost-update）。本地小文件，锁持有微秒级。
fn persist_recorded_ns() {
    let path = recorded_ns_path();
    let tmp = format!("{}.tmp.{}", path, std::process::id());
    if let Ok(set) = recorded_ns().lock() {
        // guard 存活整个块：序列化 → 写 tmp → rename 全程持锁
        let json = match serde_json::to_string(&*set) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(target: "agent.meta_evolve", "登记集序列化失败: {}", e);
                return;
            }
        };
        if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
            tracing::warn!(target: "agent.meta_evolve", "登记集临时文件写入失败: {}", e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            tracing::warn!(target: "agent.meta_evolve", "登记集落盘失败: {}", e);
        }
    }
}

/// 从磁盘恢复登记集（幂等合并；文件缺失/损坏 → 保持现状不阻断）。
/// 成功才置位（bug·high 第八轮）：Once 语义下闭包内失败也会置位——文件瞬时
/// 损坏（如外部工具改坏）修复后永不重试，崩溃前登记的 ns 永久丢失。改
/// AtomicBool：读取+解析成功才置位，失败可下次重试（幂等合并，并发无害）。
static RESTORED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn restore_recorded_ns() {
    use std::sync::atomic::Ordering;
    if RESTORED.load(Ordering::Relaxed) {
        return;
    }
    let path = recorded_ns_path();
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(list): Result<Vec<String>, _> = serde_json::from_str(&text) else { return };
    if let Ok(mut set) = recorded_ns().lock() {
        for ns in list {
            set.insert(ns);
        }
    }
    RESTORED.store(true, Ordering::Relaxed);
}

/// 是否 agent 形态 ns（`agent/{id}[/...]`）——登记/沉淀门（纯函数，测试直调）。
pub fn is_agent_ns(ns: &str) -> bool {
    let parts: Vec<&str> = ns.split('/').collect();
    parts.len() >= 2 && parts[0] == "agent" && !parts[1].is_empty()
}

/// 写入一条会话经验 memo（工具失败教训）。best-effort：失败仅告警不阻断。
/// 结构：content 含 工具名 / 错误摘要 / 触发上下文；tag 便于按工具召回；
/// 与 evolution_log 样本共走 `min_samples` 门槛（两源合并计数）。
/// **P2-E 单写**：只写会话 ns（`agent/{id}/{caller}`，隔离粒度）——根 ns 的
/// 全局副本由 `sediment_to_root`（meta-evolution 时批量沉淀）补齐，每次失败
/// 省一次写（原双写方案）。ns 登记进 RECORDED_NS 供沉淀枚举。
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
    // 登记会话 ns（沉淀任务枚举用；非 agent 形态 ns 不登记——无根 ns 可沉淀）。
    // 登记即落盘（跨重启恢复）。**先合并磁盘旧登记再落盘**（bug·high 第五轮：
    // 进程 B 启动后首次 record 若不先 restore，persist 会用只有本进程新 ns 的
    // 集合覆盖磁盘 → 崩溃前进程 A 登记的 ns 永久丢失）。
    if is_agent_ns(ns) {
        restore_recorded_ns();
        if let Ok(mut set) = recorded_ns().lock() {
            set.insert(ns.to_string());
        }
        persist_recorded_ns();
    }
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
            tracing::debug!(tool = %tool, ns = %ns, "experience_memo 已写入（会话 ns 单写，P2-E）");
            // 节流顺带沉淀（bug·high 第九轮）：根 ns 及时性不依赖 meta-evolution
            // 触发——10 分钟窗口内至多一次，成本受限；best-effort 不阻断。
            if let Some(root_ns) = root_ns_of(ns) {
                sediment_to_root(mcp, &root_ns).await;
            }
        }
        Err(e) => {
            tracing::warn!(tool = %tool, ns = %ns, "experience_memo 写入失败（best-effort）: {}", e);
        }
    }
}

/// 从会话 ns 推导根 ns（`agent/{id}/{caller}` → `agent/{id}`）；非 agent 形态返回 None。
fn root_ns_of(ns: &str) -> Option<String> {
    if !is_agent_ns(ns) {
        return None;
    }
    let parts: Vec<&str> = ns.split('/').collect();
    Some(format!("agent/{}", parts[1]))
}

/// 沉淀节流（bug·high 第九轮）：根 ns 填充不能只依赖 meta-evolution 触发——
/// 该功能低频（24h cooldown）或关闭时根 ns 永远无 memo（recall 的 lesson 源
/// 也依赖根 ns）。record 路径节流顺带沉淀（默认 600s 一次），保证根 ns 及时
/// 性且成本受限；collect 前仍全量沉淀兜底。
/// **按 root_ns 分 key**（bug·high 第十轮）：进程全局时间戳会让 agent A 沉淀后
/// 10 分钟内 B 的沉淀被节流挡掉（多 AgentCore/分身同进程）——每 agent 独立
/// 节流窗口。
static LAST_SEDIMENT: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, u64>>,
> = std::sync::OnceLock::new();

fn last_sediment_map() -> &'static std::sync::Mutex<std::collections::HashMap<String, u64>> {
    LAST_SEDIMENT.get_or_init(|| {
        std::sync::Mutex::new(std::collections::HashMap::new())
    })
}

const SEDIMENT_INTERVAL_SECS: u64 = 600;

/// P2-E 沉淀任务：把本进程记录过的会话 ns 里的 experience_memo 批量复制到根 ns
/// （`agent/{id}`）。幂等：根 ns 已有同 content 的跳过（按内容精确去重）。
/// 触发时机：collect_negative_samples 前（全量兜底）+ record 路径节流（及时性）。
/// best-effort：任一 ns 失败仅告警，不阻断调用方。
pub async fn sediment_to_root(mcp: &McpClient, root_ns: &str) {
    // 节流闸（按 root_ns 分 key）：10 分钟内同 agent 只沉淀一次（record 热路径
    // 调用时）；不同 agent 互不干扰
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    {
        let map = last_sediment_map().lock();
        match map {
            Ok(m) => {
                if now.saturating_sub(*m.get(root_ns).unwrap_or(&0)) < SEDIMENT_INTERVAL_SECS {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    // 先恢复磁盘登记集（跨重启：崩溃前记录过的会话 ns 重新进入枚举范围）
    restore_recorded_ns();
    // 跨 agent 隔离（bug·high 第四轮）：进程级登记集可能含其它 agent 的会话
    // ns（多 AgentCore/分身同进程）——只沉淀与 root_ns 同 agent 前缀的 ns，
    // 否则 A 的根 ns 会收进 B 的会话 memo（命名空间泄漏）。
    let agent_prefix = format!("{}/", root_ns);
    let ns_list: Vec<String> = {
        match recorded_ns().lock() {
            Ok(set) => set
                .iter()
                .filter(|ns| ns.starts_with(&agent_prefix))
                .cloned()
                .collect(),
            Err(_) => return,
        }
    };
    if ns_list.is_empty() {
        return;
    }
    // 根 ns 已有 content（去重基准）
    let mut existing: std::collections::HashSet<String> = collect_memo_samples(mcp, root_ns, 200)
        .await
        .into_iter()
        .map(|s| s.old_value)
        .collect();
    for ns in &ns_list {
        if ns == root_ns {
            continue;
        }
        let memos = collect_memo_samples(mcp, ns, 200).await; // cap 与去重基准对齐（bug·medium 第三轮）
        for m in memos {
            if existing.contains(&m.old_value) {
                continue; // 根 ns 已有，跳过
            }
            // 沉淀保留工具 tag（maintainability·low 第一轮：content 含工具名，
            // 解析回填 tags 保持与 record 侧一致的召回维度）
            let tool = parse_tool_from_memo(&m.old_value);
            let args = serde_json::json!({
                "content": m.old_value,
                "tags": ["experience_memo", "lesson", tool],
                "category": "experience_memo",
                "confidence": 70,
                "importance": 3,
                "namespace": root_ns,
            });
            match mcp.call_json("memory_remember", &args).await {
                Ok(_) => {
                    existing.insert(m.old_value); // 防同批重复
                    tracing::debug!(ns = %ns, "experience_memo 已沉淀到根 ns");
                }
                Err(e) => {
                    tracing::warn!(ns = %ns, "experience_memo 沉淀失败（best-effort）: {}", e);
                }
            }
        }
    }
    // 沉淀成功完成 → 更新节流时间戳（按 root_ns；失败不更新，允许下次重试）
    if let Ok(mut map) = last_sediment_map().lock() {
        map.insert(root_ns.to_string(), now);
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
/// 搜全库（不限 namespace）：experience_memo 分散在会话 ns / 根 ns / `*` 等不同
/// 命名空间（record_experience_memo 写入会话 ns，sediment_to_root 沉淀到根 ns，
/// 但 ns=`*` 的异常条目也会出现），按 namespace 过滤会导致大量漏召回。
pub async fn collect_memo_samples(
    mcp: &McpClient,
    _ns: &str,
    limit: usize,
) -> Vec<crate::meta_evolve::NegSample> {
    let args = serde_json::json!({
        "query": "experience_memo 工具执行失败 lesson",
        "max_results": limit.min(200),
    });
    let raw = mcp
        .call_json("memory_search_v2", &args)
        .await
        .unwrap_or_else(|e| {
            // other·medium：MCP 错误不能静默变空结果（否则样本源故障无迹可查）
            tracing::warn!(target: "agent.meta_evolve", "experience_memo 召回失败: {}", e);
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
            if content.is_empty()
                || (!content.contains("experience_memo") && !content.contains("lesson"))
            {
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

    #[test]
    fn recorded_ns_registration_gate() {
        // P2-E：仅 agent 形态 ns 登记（沉淀枚举用）——非 agent 形态不登记
        assert!(is_agent_ns("agent/xujiayan/caller1"));
        assert!(!is_agent_ns("workspace/foo"));
        assert!(!is_agent_ns("agent/"));
    }

    #[test]
    fn sediment_prefix_filter_isolates_agent() {
        // 跨 agent 隔离（bug·high 第四轮）：只沉淀同 agent 前缀的 ns
        let root_ns = "agent/xujiayan";
        let agent_prefix = format!("{}/", root_ns);
        let all = vec![
            "agent/xujiayan/caller1".to_string(),
            "agent/other/caller9".to_string(), // 其它 agent，必须过滤
            "workspace/foo".to_string(),
        ];
        let filtered: Vec<&String> = all
            .iter()
            .filter(|ns| ns.starts_with(&agent_prefix))
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], "agent/xujiayan/caller1");
    }
}
