//! HY3 1.3 —— MultiAgent Compose（子 agent 派发；**非** Meta RSI 的 HyperAgents）。
//!
//! 定位：把一个 Hard 任务 decompose 成若干可独立子任务，逐派发执行并聚合。
//! 与战略报告里的 HyperAgents（≈ 改改进机制 / Meta RSI）**不是一回事**——本文只是
//! 最朴素的「任务分解 + 并行/顺序派发」编排，是 LATS/技能库之上的应用层。
//!
//! 门控：仅 `features.multiagent = true` 时 `AgentCore` 才持有 `MultiAgentConfig`；
//! `maybe_compose` 在 flag 关或任务非 Hard 或分解为空时返回 None，走原路径。
//! `dispatch` 已为**并发派发**（`futures::join_all` + 每子任务 `tokio::time::timeout` 隔离）；
//! 隔离沙箱（独立进程/权限边界）留待后续增强。

use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures::future::join_all;

use crate::llm::{LlmClient, Message, RoutedLlm, ToolDef};

/// P2-2 黑板模式：多 Agent 协作的共享工作区（SharedState）。
///
/// 与 A2A 消息通道互补——消息是「异步通信」，黑板是「共享结构化状态」：
/// 子 agent 把中间产物（数据切片、半成品、结论草稿）写入黑板，供后续
/// 阶段或其他子 agent 读取，避免重复劳动与结论不一致。
///
/// 并发语义：`version` 每次写操作自增（乐观锁）；`merge` 批量合并为一次写。
/// 本实现为进程内共享（compose 派发期间有效），跨进程黑板留待后续。
#[derive(Clone, Debug, Default)]
pub struct SharedState {
    data: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    version: Arc<AtomicU64>,
}

impl SharedState {
    /// 空黑板（版本 0）
    pub fn new() -> Self {
        SharedState::default()
    }

    /// 读取一个键
    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.data.read().ok()?.get(key).cloned()
    }

    /// 写入一个键，版本号自增；返回新版本号
    pub fn set(&self, key: &str, value: serde_json::Value) -> u64 {
        let mut v = self.data.write().expect("blackboard poisoned");
        v.insert(key.to_string(), value);
        let ver = self.version.fetch_add(1, Ordering::SeqCst) + 1;
        ver
    }

    /// 当前版本号（0 = 从未写入）
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// 全量快照（子 agent 只读上下文用）
    pub fn snapshot(&self) -> HashMap<String, serde_json::Value> {
        self.data.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// 批量合并（子 agent 回写），版本号自增一次；返回新版本号
    pub fn merge(&self, changes: &HashMap<String, serde_json::Value>) -> u64 {
        if changes.is_empty() {
            return self.version();
        }
        let mut v = self.data.write().expect("blackboard poisoned");
        for (k, val) in changes {
            v.insert(k.clone(), val.clone());
        }
        self.version.fetch_add(1, Ordering::SeqCst) + 1
    }
}

/// 从子 agent 回复中解析黑板回写块：回复末尾附
/// `{"__blackboard__": {"key": value}}` JSON 块即视为回写意图。
/// 解析成功返回 (回写映射, 剔除回写块后的正文)；失败返回 (空, 原文)。
fn extract_blackboard_write(text: &str) -> (HashMap<String, serde_json::Value>, String) {
    let trimmed = text.trim_end();
    // 查找最后一个 ```json 代码块（容错：子 agent 可能不用代码围栏，直接尾随 JSON）
    let candidates: Vec<&str> = trimmed.split("```json").collect();
    for cand in candidates.iter().rev() {
        let block = cand.split("```").next().unwrap_or("");
        let block = block.trim().trim_matches('`').trim();
        if block.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(block) {
            if let Some(obj) = v.as_object() {
                if let Some(bw) = obj.get("__blackboard__").and_then(|x| x.as_object()) {
                    let mut changes = HashMap::new();
                    for (k, val) in bw {
                        changes.insert(k.clone(), val.clone());
                    }
                    let mut cleaned = text.to_string();
                    if let Some(pos) = cleaned.find(block) {
                        cleaned.replace_range(pos..pos + block.len(), "");
                        cleaned = cleaned.trim_end().to_string();
                    }
                    return (changes, cleaned);
                }
            }
        }
    }
    (HashMap::new(), text.to_string())
}

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
    /// 单子任务超时（秒）：超出则隔离为「超时」说明，不拖垮整体派发。默认 120。
    #[serde(default = "default_subagent_timeout")]
    pub subagent_timeout_secs: u64,
}

fn default_subagent_timeout() -> u64 {
    120
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
            subagent_timeout_secs: default_subagent_timeout(),
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

/// 每子任务默认超时（秒）。单个子任务卡死/慢不影响其他子任务，整体可预期收敛。
const DEFAULT_SUBAGENT_TIMEOUT_SECS: u64 = 120;

/// 逐子任务派发（并发 + 单点超时隔离）。
///
/// 用 `futures::join_all` 并发跑所有子任务（不再顺序阻塞，N 子任务耗时≈最慢单个而非总和），
/// 每个子任务包 `tokio::time::timeout` 隔离：超时/失败仅该子任务降级为说明，不拖垮整体输出。
/// 结果按 subtask 原始顺序拼装，保证输出可预期。
pub async fn dispatch(rt: &RoutedLlm, subtasks: &[SubTask]) -> String {
    dispatch_with_timeout(rt, subtasks, DEFAULT_SUBAGENT_TIMEOUT_SECS, None).await
}

/// 带超时参数的派发（供 `maybe_compose` 传入配置中的 `subagent_timeout_secs`）。
/// `blackboard`：可选黑板（P2-2）。传 Some 时，每个子任务消息前注入黑板快照作为
/// 共享上下文；子任务回复若附 `{"__blackboard__": {...}}` 回写块则合并回黑板并从
/// 汇总文本剔除。传 None 则与旧行为完全一致（纯并行独立）。
pub async fn dispatch_with_timeout(
    rt: &RoutedLlm,
    subtasks: &[SubTask],
    timeout_secs: u64,
    blackboard: Option<SharedState>,
) -> String {
    let timeout = Duration::from_secs(timeout_secs);
    // 每个子任务一个 future；rt 为 &RoutedLlm（引用 Copy），闭包内仅借用 rt、持有自有 title/desc，
    // 可安全并发。空工具列表 `&[] as &[ToolDef]` 为语句内临时，跨 await 存活（与原顺序版同构）。
    let futures = subtasks.iter().map(|st| {
        let title = st.title.clone();
        let desc = st.description.clone();
        let bb = blackboard.clone();
        async move {
            // P2-2：黑板快照注入子任务上下文（只读参考；回写走 __blackboard__ 协议）
            let mut content = desc;
            if let Some(bb) = &bb {
                let snap = bb.snapshot();
                if !snap.is_empty() {
                    if let Ok(snap_json) = serde_json::to_string_pretty(&snap) {
                        content = format!(
                            "{content}\n\n## 协作黑板（共享状态，只读参考）\n```json\n{snap_json}\n```\n\
                             如需把中间产物共享给其他子 agent，在回复**末尾**附一个 JSON 代码块：\n\
                             ```json\n{{\"__blackboard__\": {{\"键\": 值}}}}\n```\n\
                             该块不会进入最终汇总，仅写入黑板供后续阶段读取。"
                        );
                    }
                }
            }
            let msg = Message {
                role: "user".to_string(),
                content: Some(content),
                tool_calls: None,
                tool_call_id: None,
            };
            let r = tokio::time::timeout(timeout, rt.chat(&[msg], &[] as &[ToolDef])).await;
            (title, r)
        }
    });
    let results = join_all(futures).await;
    let mut out = String::new();
    for (title, res) in results {
        match res {
            Ok(Ok(r)) => {
                // P2-2：解析黑板回写块 → 合并进黑板 → 正文剔除回写块
                let (changes, body) = extract_blackboard_write(&r.text);
                if !changes.is_empty() {
                    if let Some(bb) = &blackboard {
                        let ver = bb.merge(&changes);
                        tracing::info!(
                            target: "agent.multiagent",
                            keys = ?changes.keys().collect::<Vec<_>>(),
                            version = ver,
                            "黑板回写合并（子任务: {}）",
                            title
                        );
                    }
                }
                out.push_str(&format!("### {}\n{}\n\n", title, body));
            }
            Ok(Err(e)) => out.push_str(&format!("### {} (失败: {})\n\n", title, e)),
            Err(_) => out.push_str(&format!("### {} (超时 {}s，已隔离)\n\n", title, timeout_secs)),
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

    #[test]
    fn blackboard_set_get_version() {
        let bb = SharedState::new();
        assert_eq!(bb.version(), 0);
        assert!(bb.get("k").is_none());
        bb.set("k", serde_json::json!("v1"));
        assert_eq!(bb.version(), 1);
        assert_eq!(bb.get("k"), Some(serde_json::json!("v1")));
        bb.set("k", serde_json::json!("v2"));
        assert_eq!(bb.version(), 2);
        assert_eq!(bb.get("k"), Some(serde_json::json!("v2")));
    }

    #[test]
    fn blackboard_merge_and_snapshot() {
        let bb = SharedState::new();
        let mut m = HashMap::new();
        m.insert("a".to_string(), serde_json::json!(1));
        m.insert("b".to_string(), serde_json::json!("x"));
        let ver = bb.merge(&m);
        assert_eq!(ver, 1);
        let snap = bb.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap["a"], serde_json::json!(1));
        // 空合并不推进版本
        assert_eq!(bb.merge(&HashMap::new()), 1);
    }

    #[test]
    fn blackboard_extract_write_removes_block() {
        let text = "分析完成，结论见上。\n```json\n{\"__blackboard__\": {\"summary\": \"xxx\", \"count\": 3}}\n```\n";
        let (changes, body) = extract_blackboard_write(text);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes["summary"], serde_json::json!("xxx"));
        assert_eq!(changes["count"], serde_json::json!(3));
        assert!(!body.contains("__blackboard__"));
        assert!(body.contains("分析完成"));
    }

    #[test]
    fn blackboard_extract_no_write_returns_original() {
        let text = "正常回复，无回写块";
        let (changes, body) = extract_blackboard_write(text);
        assert!(changes.is_empty());
        assert_eq!(body, text);
    }
}
