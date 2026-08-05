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

use std::collections::{BTreeMap, HashMap};
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
/// 阶段化：compose 派发按 `SubTask.stage` 分组，同 stage 并行、stage 间顺序，
/// 后一 stage 能看到前一 stage 的回写（同 stage 内并发快照互不可见，语义诚实）。
///
/// 安全：黑板内容源于不可信模型文本，写入受限（键数/深度/单值/总量上限），
/// 超限丢弃并告警；锁中毒时优雅降级（与 get/snapshot 一致），不 panic。
#[derive(Clone, Debug, Default)]
pub struct SharedState {
    data: Arc<RwLock<BTreeMap<String, serde_json::Value>>>,
    version: Arc<AtomicU64>,
}

/// 黑板写入防护上限（内容源于不可信模型文本）
const BB_MAX_KEYS: usize = 32; // 最大键数
const BB_MAX_VALUE_DEPTH: usize = 4; // 单值最大嵌套深度
const BB_MAX_VALUE_WIDTH: usize = 512; // 单值数组/对象最大元素数（宽度预检，防宽数组物化）
const BB_MAX_VALUE_BYTES: usize = 4096; // 单值序列化最大字节
const BB_MAX_TOTAL_BYTES: usize = 65536; // 黑板全量序列化字节上限（merge 时强校验）

fn json_depth(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(a) => a.iter().map(json_depth).max().unwrap_or(0) + 1,
        serde_json::Value::Object(o) => o.values().map(json_depth).max().unwrap_or(0) + 1,
        _ => 0,
    }
}

fn json_width(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(a) => a.len(),
        serde_json::Value::Object(o) => o.len(),
        _ => 0,
    }
}

/// 序列化字节数（深度/宽度预检通过后调用，物化代价可控）
fn value_bytes(v: &serde_json::Value) -> usize {
    serde_json::to_string(v).map(|s| s.len()).unwrap_or(0)
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

    /// 写入一个键（受深度/宽度/大小/总量上限约束），版本号自增；返回新版本号
    pub fn set(&self, key: &str, value: serde_json::Value) -> u64 {
        if !Self::value_allowed(&value) {
            tracing::warn!(
                target: "agent.multiagent",
                key = %key,
                "黑板写入拒绝：值超限（深度/宽度/大小）"
            );
            return self.version();
        }
        let mut v = match self.data.write() {
            Ok(g) => g,
            Err(p) => {
                tracing::warn!(target: "agent.multiagent", "黑板锁中毒恢复（set）");
                p.into_inner()
            }
        };
        if v.len() >= BB_MAX_KEYS && !v.contains_key(key) {
            tracing::warn!(
                target: "agent.multiagent",
                key = %key,
                "黑板写入拒绝：键数达上限 {}",
                BB_MAX_KEYS
            );
            return self.version();
        }
        // 总量上限：全量字节 - 旧键字节 + 新值字节
        let old_bytes = v.get(key).map(value_bytes).unwrap_or(0);
        let new_bytes = value_bytes(&value);
        let total: usize = v.values().map(value_bytes).sum();
        if total as i64 - old_bytes as i64 + new_bytes as i64 > BB_MAX_TOTAL_BYTES as i64 {
            tracing::warn!(
                target: "agent.multiagent",
                key = %key,
                "黑板写入拒绝：总量超上限 {}",
                BB_MAX_TOTAL_BYTES
            );
            return self.version();
        }
        v.insert(key.to_string(), value);
        self.version.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// 当前版本号（0 = 从未写入）
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// 全量快照（子 agent 只读上下文用；BTreeMap 保证注入顺序确定性）
    pub fn snapshot(&self) -> BTreeMap<String, serde_json::Value> {
        self.data.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// 单值是否可入黑板（深度/宽度/大小上限，均先预检再序列化）
    fn value_allowed(value: &serde_json::Value) -> bool {
        if json_depth(value) > BB_MAX_VALUE_DEPTH {
            return false;
        }
        if json_width(value) > BB_MAX_VALUE_WIDTH {
            return false;
        }
        value_bytes(value) <= BB_MAX_VALUE_BYTES
    }

    /// 批量合并（子 agent 回写），版本号自增一次；返回新版本号
    pub fn merge(&self, changes: &HashMap<String, serde_json::Value>) -> u64 {
        if changes.is_empty() {
            return self.version();
        }
        let mut v = match self.data.write() {
            Ok(g) => g,
            Err(p) => {
                tracing::warn!(target: "agent.multiagent", "黑板锁中毒恢复（merge）");
                p.into_inner()
            }
        };
        // 总量上限预校验：全量字节 + 增量（新值-旧值）
        let mut delta: i64 = 0;
        for (k, val) in changes {
            if !Self::value_allowed(val) {
                continue;
            }
            delta += value_bytes(val) as i64 - v.get(k).map(value_bytes).unwrap_or(0) as i64;
        }
        let total: i64 = v.values().map(|x| value_bytes(x) as i64).sum();
        if total + delta > BB_MAX_TOTAL_BYTES as i64 {
            tracing::warn!(
                target: "agent.multiagent",
                delta,
                "黑板回写整体拒绝：总量超上限 {}",
                BB_MAX_TOTAL_BYTES
            );
            return self.version();
        }
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for (k, val) in changes {
            if !Self::value_allowed(val) {
                rejected += 1;
                continue;
            }
            if v.len() >= BB_MAX_KEYS && !v.contains_key(k) {
                rejected += 1;
                continue;
            }
            v.insert(k.clone(), val.clone());
            accepted += 1;
        }
        if rejected > 0 {
            tracing::warn!(
                target: "agent.multiagent",
                accepted, rejected,
                "黑板回写部分拒绝（深度/宽度/大小/键数上限）"
            );
        }
        if accepted > 0 {
            return self.version.fetch_add(1, Ordering::SeqCst) + 1;
        }
        self.version()
    }
}

/// 从子 agent 回复中解析黑板回写块：回复末尾附
/// `{"__blackboard__": {"key": value}}` JSON 代码块即视为回写意图。
/// 解析成功返回 (回写映射, 剔除**所有**回写代码块含围栏后的正文)；失败返回 (空, 原文)。
/// 容错：存在多个回写块时，合并取最靠后的一个；所有回写块（控制面）均从正文剔除。
fn extract_blackboard_write(text: &str) -> (HashMap<String, serde_json::Value>, String) {
    // 顺序扫描所有 ```json 代码块（pos 逐块前跳，区间有序且不重叠）
    let mut removals: Vec<(usize, usize)> = Vec::new();
    let mut last_changes: Option<HashMap<String, serde_json::Value>> = None;
    let mut pos = 0usize;
    while let Some(rel) = text[pos..].find("```json") {
        let open = pos + rel;
        let after = open + "```json".len();
        // 收尾围栏候选循环：JSON 内容内可能合法嵌入 ```（如代码示例），
        // 首个候选解析失败则继续找更远的 ``` 重试，直到解析成功或耗尽。
        let mut close_opt = text[after..].find("```").map(|r| after + r);
        let mut handled = false;
        while let Some(close) = close_opt {
            let block = &text[after..close];
            let t = block.trim().trim_matches('`').trim();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
                if let Some(bw) = v
                    .as_object()
                    .and_then(|o| o.get("__blackboard__"))
                    .and_then(|x| x.as_object())
                {
                    let mut changes = HashMap::new();
                    for (k, val) in bw {
                        changes.insert(k.clone(), val.clone());
                    }
                    // 顺序扫描：最后一次赋值即最靠后的回写块
                    last_changes = Some(changes);
                    removals.push((open, close + 3)); // 含 ```json 与收尾 ```
                }
                // 该块 JSON 合法（无论是否回写块），块边界确定 → 跳过整个块
                handled = true;
                pos = close + 3;
                break;
            }
            // 解析失败 → 内容里嵌了 ```，找下一个收尾候选重试
            close_opt = text[close + 3..].find("```").map(|r| close + 3 + r);
        }
        if !handled {
            // 无合法收尾（可能被 ``` 截断的残缺块）→ 跳过 ```json 标记避免死循环
            pos = after;
        }
    }
    match last_changes {
        Some(changes) => {
            // 重建正文：跳过所有回写块区间（有序不重叠，无索引漂移）
            let mut cleaned = String::with_capacity(text.len());
            let mut cursor = 0usize;
            for (s, e) in &removals {
                cleaned.push_str(&text[cursor..*s]);
                cursor = *e;
            }
            cleaned.push_str(&text[cursor..]);
            (changes, cleaned.trim_end().to_string())
        }
        None => (HashMap::new(), text.to_string()),
    }
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
    /// P2-2 黑板模式：阶段号（默认 0 = 单轮）。同 stage 的子任务并行执行；
    /// stage 间顺序执行——后一 stage 能看到前一 stage 写入黑板的中间产物。
    #[serde(default)]
    pub stage: u32,
}

/// 把任务 decompose 成若干子任务（LLM 调用）。失败/空返回空 vec。
pub async fn plan_decomposition(llm: &LlmClient, task: &str) -> Vec<SubTask> {
    let prompt = format!(
        "把以下任务分解为至多 {} 个可独立执行的子任务。\n\
         严格按 JSON 输出：{{\"tasks\":[{{\"title\":\"简短标题\",\"description\":\"子任务具体描述\",\"stage\":0}}]}}\n\
         说明：stage 为阶段号（从 0 起）。若子任务间有先后依赖（后一任务依赖前一任务的中间结果），\n\
         给它们不同的 stage（0 先执行，1 后执行……）；无依赖则全部 stage=0（并行执行）。\n\
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
                        // stage 源于不可信 LLM JSON：钳制到 [0,255]，防恶意大值 as u32 静默回绕
                        // 与低 stage 合并、打乱预期执行顺序
                        let stage = t
                            .get("stage")
                            .and_then(|s| s.as_u64())
                            .map(|s| s.min(255) as u32)
                            .unwrap_or(0);
                        Some(SubTask {
                            title,
                            description,
                            stage,
                        })
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
/// `blackboard`：可选黑板（P2-2）。传 Some 时：
/// - 子任务按 `stage` 分组执行——同 stage 并行（`join_all`），stage 间顺序；
/// - 每个子任务消息前注入**当前**黑板快照（含前序 stage 的回写，只读参考）；
/// - 子任务回复若附 `{"__blackboard__": {...}}` 回写块则合并进黑板，并从汇总文本
///   剔除整个代码块（不污染最终聚合）。
/// 传 None 则与旧行为完全一致（纯并行独立，stage 忽略）。
pub async fn dispatch_with_timeout(
    rt: &RoutedLlm,
    subtasks: &[SubTask],
    timeout_secs: u64,
    blackboard: Option<SharedState>,
) -> String {
    let timeout = Duration::from_secs(timeout_secs);
    // None = 旧行为完全一致（纯并行独立，stage 忽略）
    if blackboard.is_none() {
        let futures = subtasks.iter().map(|st| {
            let title = st.title.clone();
            let desc = st.description.clone();
            async move {
                let msg = Message {
                    role: "user".to_string(),
                    content: Some(desc),
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
                Ok(Ok(r)) => out.push_str(&format!("### {}\n{}\n\n", title, r.text)),
                Ok(Err(e)) => out.push_str(&format!("### {} (失败: {})\n\n", title, e)),
                Err(_) => {
                    out.push_str(&format!("### {} (超时 {}s，已隔离)\n\n", title, timeout_secs))
                }
            }
        }
        return out;
    }
    // P2-2：黑板模式——按 stage 分组（BTreeMap 保证阶段顺序 0,1,2...）
    let mut by_stage: BTreeMap<u32, Vec<&SubTask>> = BTreeMap::new();
    for st in subtasks {
        by_stage.entry(st.stage).or_default().push(st);
    }
    let mut out = String::new();
    let mut any_bb = false;
    for (_stage, group) in by_stage {
        // 同一 stage 内并行；rt 为 &RoutedLlm（引用 Copy），闭包内仅借用 rt、
        // 持有自有 title/desc 与黑板句柄，可安全并发。
        let futures = group.iter().map(|st| {
            let title = st.title.clone();
            let desc = st.description.clone();
            let bb = blackboard.clone();
            async move {
                // P2-2：注入**当前**黑板快照（前序 stage 回写已可见；同 stage 互不可见）
                let mut content = desc;
                if let Some(bb) = &bb {
                    let snap = bb.snapshot();
                    if !snap.is_empty() {
                        if let Ok(snap_json) = serde_json::to_string_pretty(&snap) {
                            content = format!(
                                "{content}\n\n## 协作黑板（共享状态，只读参考）\n```json\n{snap_json}\n```\n\
                                 如需把中间产物共享给后续阶段，在回复**末尾**附一个 JSON 代码块：\n\
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
        for (title, res) in results {
            match res {
                Ok(Ok(r)) => {
                    // P2-2：解析黑板回写块 → 合并进黑板 → 正文剔除整个代码块
                    let (changes, body) = extract_blackboard_write(&r.text);
                    if !changes.is_empty() {
                        if let Some(bb) = &blackboard {
                            let ver = bb.merge(&changes);
                            any_bb = true;
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
                Err(_) => {
                    out.push_str(&format!("### {} (超时 {}s，已隔离)\n\n", title, timeout_secs))
                }
            }
        }
    }
    if any_bb {
        if let Some(bb) = &blackboard {
            out.push_str(&format!(
                "\n---\n协作黑板最终状态（版本 {}，键 {} 个）\n",
                bb.version(),
                bb.snapshot().len()
            ));
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
        // 围栏也要干净移除（不残留空代码块）
        assert!(!body.contains("```"));
        assert!(body.contains("分析完成"));
    }

    #[test]
    fn blackboard_extract_no_write_returns_original() {
        let text = "正常回复，无回写块";
        let (changes, body) = extract_blackboard_write(text);
        assert!(changes.is_empty());
        assert_eq!(body, text);
    }

    #[test]
    fn blackboard_extract_multiple_blocks_takes_last() {
        let text = "第一段\n```json\n{\"__blackboard__\": {\"a\": 1}}\n```\n中间\n```json\n{\"__blackboard__\": {\"b\": 2}}\n```\n";
        let (changes, body) = extract_blackboard_write(text);
        assert!(changes.contains_key("b"));
        assert!(!changes.contains_key("a"));
        assert!(!body.contains("```"));
    }

    #[test]
    fn blackboard_size_caps_reject() {
        let bb = SharedState::new();
        // 深度超限（5 层）
        let deep = serde_json::json!({"a": {"b": {"c": {"d": {"e": 1}}}}});
        assert_eq!(bb.set("deep", deep), 0); // 拒绝，版本不变
        // 大值超限（> 4KB）
        let big = serde_json::json!({"x": "y".repeat(6000)});
        assert_eq!(bb.set("big", big), 0);
        // 正常值可写
        bb.set("ok", serde_json::json!(1));
        assert_eq!(bb.version(), 1);
    }

    #[test]
    fn subtask_stage_parse() {
        let j = r#"{"tasks":[{"title":"A","description":"做A","stage":0},{"title":"B","description":"做B","stage":1}]}"#;
        let v = parse_subtasks(j);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].stage, 0);
        assert_eq!(v[1].stage, 1);
        // 无 stage 字段向后兼容
        let v2 = parse_subtasks(r#"{"tasks":[{"title":"C","description":"做C"}]}"#);
        assert_eq!(v2[0].stage, 0);
        // 恶意超大 stage 钳制到 255（不回绕到 0 与低 stage 合并）
        let v3 = parse_subtasks(r#"{"tasks":[{"title":"D","description":"做D","stage":4294967296}]}"#);
        assert_eq!(v3[0].stage, 255);
    }

    #[test]
    fn blackboard_total_bytes_cap() {
        let bb = SharedState::new();
        // 单值 ~4KB（序列化后 4002 字节 < 4096 单值上限），16 个 = 64KB 内；第 17 个超总量 64KB
        let big = serde_json::json!(serde_json::Value::String("x".repeat(4000)));
        for i in 0..16 {
            bb.set(&format!("k{i}"), big.clone());
        }
        assert_eq!(bb.version(), 16);
        // 第 17 个被总量上限拒绝
        bb.set("k16", big.clone());
        assert_eq!(bb.version(), 16);
        // 小值可写
        bb.set("small", serde_json::json!(1));
        assert_eq!(bb.version(), 17);
    }

    #[test]
    fn blackboard_extract_fence_inside_content() {
        // JSON 字符串值内含 ```（代码示例）——不应截断块
        let text = "结果如下\n```json\n{\"__blackboard__\": {\"code\": \"先看 ``` 再写\"}}\n```\n正文";
        let (changes, body) = extract_blackboard_write(text);
        assert!(changes.contains_key("code"));
        assert!(body.contains("正文"));
        assert!(!body.contains("```"));
    }

    #[test]
    fn blackboard_width_cap_rejects_wide_array() {
        let bb = SharedState::new();
        let wide = serde_json::json!((0..600).collect::<Vec<u32>>()); // 600 元素 > 512 宽度上限
        assert_eq!(bb.set("wide", wide), 0); // 拒绝
    }
}
