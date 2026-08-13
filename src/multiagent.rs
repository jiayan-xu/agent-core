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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    /// 全量序列化字节计数器（写锁内增量维护，O(1) 总量判断）
    total_bytes: Arc<AtomicUsize>,
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

/// 序列化字节数（深度/宽度预检通过后调用，物化代价可控）。
/// 返回 None 表示序列化失败（如 NaN/Infinity 非有限浮点）——调用方应拒绝该值，
/// 避免非有限值被量成 0 字节绕过字节上限防护。
fn value_bytes(v: &serde_json::Value) -> Option<usize> {
    serde_json::to_string(v).ok().map(|s| s.len())
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
                "黑板写入拒绝：值超限（深度/宽度/大小/序列化失败）"
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
        // 总量上限（O(1) 增量）：当前总量 + (新值 - 旧值)
        let new_bytes = value_bytes(&value).unwrap_or(0) as i64;
        let old_bytes = v.get(key).and_then(value_bytes).unwrap_or(0) as i64;
        let delta = new_bytes - old_bytes;
        let total = self.total_bytes.load(Ordering::Relaxed) as i64;
        if total + delta > BB_MAX_TOTAL_BYTES as i64 {
            tracing::warn!(
                target: "agent.multiagent",
                key = %key,
                "黑板写入拒绝：总量超上限 {}",
                BB_MAX_TOTAL_BYTES
            );
            return self.version();
        }
        let _ = self.total_bytes.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |t| Some((t as i64 + delta) as usize),
        );
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

    /// 单值是否可入黑板（深度/宽度/大小上限，均先预检再序列化；序列化失败即拒绝）
    fn value_allowed(value: &serde_json::Value) -> bool {
        if json_depth(value) > BB_MAX_VALUE_DEPTH {
            return false;
        }
        if json_width(value) > BB_MAX_VALUE_WIDTH {
            return false;
        }
        match value_bytes(value) {
            Some(n) => n <= BB_MAX_VALUE_BYTES,
            None => false, // NaN/Infinity 等序列化失败 → 拒绝（防 0 字节绕过）
        }
    }

    /// 批量合并（子 agent 回写）：逐键增量总量检查，部分接受（能放下的键都收），版本号自增一次。
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
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        let mut delta: i64 = 0;
        let total = self.total_bytes.load(Ordering::Relaxed) as i64;
        // 排序键迭代：部分接受时接受/拒绝子集确定（HashMap 遍历序随机）
        let mut keys: Vec<&String> = changes.keys().collect();
        keys.sort();
        for k in keys {
            let val = &changes[k];
            if !Self::value_allowed(val) {
                rejected += 1;
                continue;
            }
            if v.len() >= BB_MAX_KEYS && !v.contains_key(k) {
                rejected += 1;
                continue;
            }
            let k_delta = value_bytes(val).unwrap_or(0) as i64
                - v.get(k).and_then(value_bytes).unwrap_or(0) as i64;
            if total + delta + k_delta > BB_MAX_TOTAL_BYTES as i64 {
                rejected += 1;
                continue;
            }
            delta += k_delta;
            v.insert(k.clone(), val.clone());
            accepted += 1;
        }
        if rejected > 0 {
            tracing::warn!(
                target: "agent.multiagent",
                accepted, rejected,
                "黑板回写部分拒绝（深度/宽度/大小/键数/总量上限）"
            );
        }
        if accepted > 0 {
            let _ = self.total_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |t| Some((t as i64 + delta) as usize),
            );
            return self.version.fetch_add(1, Ordering::SeqCst) + 1;
        }
        self.version()
    }

    // ── P2-2 补全：黑板持久化（断线协作恢复） ─────────────

    /// 持久化黑板到 JSON 文件（格式 `{"version":N,"data":{...}}`）。
    /// 复用 P1-B 受控写模式（ocr 已验证三件套）：
    /// 1. **快照一致性**——写锁内 clone 出 (version, data) 快照（黑板 ≤64KB，
    ///    clone 微秒级；快照语义 = 定期落盘点，此后并发 set 由下次 save 覆盖，
    ///    与 P1-B 的强一致锁内写文件不同——黑板非强一致状态，可接受）；
    /// 2. **tmp 不可预测后缀**（pid+seq+随机段）——并发 save 不互相覆盖，且
    ///    防符号链接预创建攻击（security·medium 第三轮：纯 pid+seq 可猜测）；
    /// 3. **fsync + rename**——tmp 数据 fsync 落盘后原子替换；**目录 fsync 未做**
    ///    （Windows 平台不支持目录 fsync；断电瞬间 rename 元数据可能未落盘，
    ///    最坏丢失最近一次黑板快照，但不会产生半写损坏——诚实表述，bug·medium
    ///    第六轮：doc 不再宣称「断电不丢已确认数据」）。
    /// 写失败返回 Err（调用方可决定告警/重试），不吞错。
    pub async fn save(&self, path: &str) -> Result<(), String> {
        // 写锁内 clone 快照后立即释放 guard（不持锁跨 await）——guard 借用
        // 若被 json! 宏拖进 future 会因 RwLockWriteGuard 非 Send 报 E0277。
        let (version, data) = {
            let guard = match self.data.write() {
                Ok(g) => g,
                Err(p) => {
                    tracing::warn!(target: "agent.multiagent", "黑板锁中毒恢复（save）");
                    p.into_inner()
                }
            };
            let data: BTreeMap<String, serde_json::Value> = guard.clone();
            let v = self.version();
            (v, data)
        }; // guard 在此 drop
        let payload = serde_json::json!({ "version": version, "data": data });
        let json = serde_json::to_string_pretty(&payload)
            .map_err(|e| format!("黑板序列化失败: {}", e))?;
        static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // security·medium（第三轮）：pid+seq 可预测 → 攻击者可预创建同名 symlink
        // 让 save 写穿；追加随机段（rand::thread_rng，64 位随机）。
        let rnd: u64 = rand::random();
        let tmp = format!("{}.tmp.{}.{}.{:016x}", path, std::process::id(), seq, rnd);
        {
            use tokio::io::AsyncWriteExt;
            // security·medium（第二轮）：File::create 默认 0644——黑板数据可能含
            // 敏感业务中间产物，0644 会让同机其它用户可读。unix 下显式 0600
            // （仅属主读写）；Windows 权限模型（ACL）无此问题。
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = tokio::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let mut f = opts
                .open(&tmp)
                .await
                .map_err(|e| format!("创建黑板临时文件失败: {}", e))?;
            if let Err(e) = async {
                f.write_all(json.as_bytes()).await?;
                f.flush().await?;
                f.sync_all().await?;
                Ok::<(), std::io::Error>(())
            }
            .await
            {
                // bug·low（第四轮）：remove_file 前必须显式 drop(f)——f 在
                // 外层作用域仍存活，Windows 上文件句柄未关时删除必失败
                // （sharing violation），残留 tmp。
                drop(f);
                let _ = std::fs::remove_file(&tmp);
                return Err(format!("写黑板临时文件失败: {}", e));
            }
        } // f 在此 drop（成功路径）
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("原子替换黑板文件失败: {}", e));
        }
        Ok(())
    }

    /// 从 JSON 文件恢复黑板（断线协作续跑：进程重启后按 session 文件恢复，
    /// 版本号一并恢复，乐观锁不回退）。文件不存在 → 空黑板（首跑）。
    /// 恢复防护（ocr 第二轮 bug·medium）：
    /// - 逐值重跑 value_allowed（超限剔除）；
    /// - 键数恢复 BB_MAX_KEYS 上限（超出截断，防恢复后 set 拒绝但已有键超限）；
    /// - 总量重算 total_bytes；
    /// - version 字段类型严格校验：存在但非 u64（浮点/字符串/负数）→ Corrupted
    ///   （文件损坏，静默归 0 会掩盖写侧 bug）；缺失 → 0 + 告警（老格式兼容）。
    /// async 化（perf·medium 第二轮）：读文件改 tokio::fs，避免阻塞 async 路径。
    pub async fn load(path: &str) -> (SharedState, LoadStatus) {
        let bb = SharedState::new();
        let text = match tokio::fs::read_to_string(path).await {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (bb, LoadStatus::Missing);
            }
            // other·low（第七轮）：保留底层 IO 错误详情供排查（此前静默丢弃）
            Err(e) => {
                tracing::warn!(
                    target: "agent.multiagent",
                    path = %path,
                    "黑板文件读取失败（权限/IO）: {}",
                    e
                );
                return (bb, LoadStatus::Unreadable);
            }
        };
        let v: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => return (bb, LoadStatus::Corrupted),
        };
        // 根级类型校验（bug·medium 第五轮）：JSON 合法但根非对象（`[1,2,3]` /
        // `"str"` / `123`）→ Corrupted——save 永远写对象，非对象根 = 文件损坏，
        // 静默当空黑板会掩盖写侧 bug。
        if !v.is_object() {
            let kind = if v.is_array() {
                "array"
            } else if v.is_string() {
                "string"
            } else if v.is_number() {
                "number"
            } else if v.is_boolean() {
                "boolean"
            } else {
                "null"
            };
            tracing::warn!(
                target: "agent.multiagent",
                path = %path,
                "黑板文件根元素非对象（{}）——视为损坏",
                kind
            );
            return (bb, LoadStatus::Corrupted);
        }
        // version 严格校验
        let version = match v.get("version") {
            None => {
                tracing::warn!(
                    target: "agent.multiagent",
                    path = %path,
                    "黑板文件缺 version 字段（老格式？）——按 0 恢复"
                );
                0
            }
            Some(x) => match x.as_u64() {
                Some(n) => n,
                None => {
                    tracing::warn!(
                        target: "agent.multiagent",
                        path = %path,
                        "黑板文件 version 字段类型非法（非 u64）——视为损坏"
                    );
                    return (bb, LoadStatus::Corrupted);
                }
            },
        };
        // data 字段严格校验（bug·medium 第三轮）：存在但非对象（"data": 123 /
        // [] / "str"）→ Corrupted——静默当空黑板会掩盖写侧 bug（save 永远写对象）。
        let data = match v.get("data") {
            None => {
                tracing::warn!(
                    target: "agent.multiagent",
                    path = %path,
                    "黑板文件缺 data 字段（老格式？）——按空数据恢复"
                );
                serde_json::Map::new()
            }
            Some(x) => match x.as_object() {
                Some(o) => o.clone(),
                None => {
                    tracing::warn!(
                        target: "agent.multiagent",
                        path = %path,
                        "黑板文件 data 字段非对象——视为损坏"
                    );
                    return (bb, LoadStatus::Corrupted);
                }
            },
        };
        let mut guard = match bb.data.write() {
            Ok(g) => g,
            Err(p) => {
                tracing::warn!(target: "agent.multiagent", "黑板锁中毒恢复（load）");
                p.into_inner()
            }
        };
        let mut bytes: usize = 0;
        let mut inserted: usize = 0;
        // 键数上限恢复：排序键遍历（BTreeMap 已有序），超出 BB_MAX_KEYS 截断
        // 总量上限恢复（bug·medium 第六轮）：超 BB_MAX_TOTAL_BYTES 时按序
        // 截断——否则恢复后 total_bytes 超上限，后续 set 的增量检查基于
        // 超限总量，护栏失效。
        for (k, val) in data {
            if inserted >= BB_MAX_KEYS {
                tracing::warn!(
                    target: "agent.multiagent",
                    key = %k,
                    "黑板恢复：键数超上限 {}，截断",
                    BB_MAX_KEYS
                );
                break;
            }
            if !SharedState::value_allowed(&val) {
                tracing::warn!(
                    target: "agent.multiagent",
                    key = %k,
                    "黑板恢复：值超限剔除（深度/宽度/大小）"
                );
                continue;
            }
            let val_bytes = value_bytes(&val).unwrap_or(0);
            if bytes + val_bytes > BB_MAX_TOTAL_BYTES {
                tracing::warn!(
                    target: "agent.multiagent",
                    key = %k,
                    "黑板恢复：总量超上限 {}，截断",
                    BB_MAX_TOTAL_BYTES
                );
                break;
            }
            bytes += val_bytes;
            guard.insert(k, val);
            inserted += 1;
        }
        let _ = bb.total_bytes.store(bytes, Ordering::Relaxed);
        let _ = bb.version.store(version, Ordering::SeqCst);
        drop(guard);
        (bb, LoadStatus::Loaded)
    }
}

/// 黑板文件加载状态（与 persistent_subagent 同款语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStatus {
    Loaded,
    /// 文件不存在（正常首跑）
    Missing,
    /// 文件存在但解析失败（落盘 bug 或人为损坏）
    Corrupted,
    /// 读失败（权限/IO）
    Unreadable,
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
    dispatch_with_timeout(rt, subtasks, DEFAULT_SUBAGENT_TIMEOUT_SECS, None, None).await
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
    save_path: Option<&str>,
) -> String {
    let timeout = Duration::from_secs(timeout_secs);
    let mut out = String::new();
    match &blackboard {
        // None = 旧行为完全一致：纯并行独立（stage 忽略）
        None => {
            let group: Vec<&SubTask> = subtasks.iter().collect();
            out.push_str(&dispatch_group(rt, &group, timeout, None).await);
        }
        // P2-2：黑板模式——按 stage 分组（BTreeMap 保证阶段顺序 0,1,2...）
        Some(bb) => {
            let mut by_stage: BTreeMap<u32, Vec<&SubTask>> = BTreeMap::new();
            for st in subtasks {
                by_stage.entry(st.stage).or_default().push(st);
            }
            for (_stage, group) in by_stage {
                out.push_str(&dispatch_group(rt, &group, timeout, Some(bb)).await);
                // P2-2 补全：每 stage 完成后持久化（stage 间是黑板最有价值的
                // 恢复点——崩溃后可从最近 stage 续跑，不丢前序中间产物）。
                // best-effort：失败告警不阻断（黑板是协作加速器非强一致状态）。
                if let Some(p) = save_path {
                    if let Err(e) = bb.save(p).await {
                        tracing::warn!(
                            target: "agent.multiagent",
                            path = %p,
                            "黑板 stage 持久化失败: {}",
                            e
                        );
                    }
                }
            }
            if bb.version() > 0 {
                out.push_str(&format!(
                    "\n---\n协作黑板最终状态（版本 {}，键 {} 个）\n",
                    bb.version(),
                    bb.snapshot().len()
                ));
            }
        }
    }
    out
}

/// 执行一组子任务并聚合结果（格式化逻辑 None/Some 共用，杜绝分支漂移）。
/// `blackboard`：Some 时组内每个子任务消息前注入**当前**黑板快照（只读参考），
/// 回复附 `__blackboard__` 回写块则合并进黑板并从正文剔除整个代码块；
/// None 时纯并行独立（无注入、无回写解析），语义与旧行为一致。
async fn dispatch_group(
    rt: &RoutedLlm,
    group: &[&SubTask],
    timeout: Duration,
    blackboard: Option<&SharedState>,
) -> String {
    let futures = group.iter().map(|st| {
        let title = st.title.clone();
        let desc = st.description.clone();
        let bb = blackboard.cloned();
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
    let mut out = String::new();
    for (title, res) in results {
        match res {
            Ok(Ok(r)) => {
                let body = if let Some(bb) = blackboard {
                    // P2-2：解析黑板回写块 → 合并进黑板 → 正文剔除整个代码块
                    let (c, b) = extract_blackboard_write(&r.text);
                    if !c.is_empty() {
                        let ver = bb.merge(&c);
                        tracing::info!(
                            target: "agent.multiagent",
                            keys = ?c.keys().collect::<Vec<_>>(),
                            version = ver,
                            "黑板回写合并（子任务: {}）",
                            title
                        );
                    }
                    b
                } else {
                    r.text.clone()
                };
                out.push_str(&format!("### {}\n{}\n\n", title, body));
            }
            Ok(Err(e)) => out.push_str(&format!("### {} (失败: {})\n\n", title, e)),
            Err(_) => out.push_str(&format!("### {} (超时 {}s，已隔离)\n\n", title, timeout.as_secs())),
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

    #[tokio::test]
    async fn blackboard_save_load_roundtrip() {
        // P2-2 补全：持久化往返——数据 + 版本号均恢复（乐观锁不回退）
        let bb = SharedState::new();
        let v1 = bb.set("k1", serde_json::json!({"a": 1}));
        assert!(v1 > 0);
        let v2 = bb.set("k2", serde_json::json!([1, 2, 3]));
        assert!(v2 > v1);
        let tmp = std::env::temp_dir().join("blackboard_test.json");
        let path = tmp.to_string_lossy().to_string();
        bb.save(&path).await.unwrap();
        let (restored, status) = SharedState::load(&path).await;
        assert_eq!(status, LoadStatus::Loaded);
        assert_eq!(restored.version(), v2); // 版本号恢复
        assert_eq!(restored.get("k1"), Some(serde_json::json!({"a": 1})));
        assert_eq!(restored.get("k2"), Some(serde_json::json!([1, 2, 3])));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn blackboard_load_status_semantics() {
        // 文件缺失 = Missing；损坏 = Corrupted；恢复时超限值剔除；version 类型校验
        let missing = std::env::temp_dir().join("blackboard_nonexistent.json");
        let (_, st) = SharedState::load(&missing.to_string_lossy().as_ref()).await;
        assert_eq!(st, LoadStatus::Missing);

        // 损坏文件（非法 JSON）
        let tmp = std::env::temp_dir().join("blackboard_corrupt.json");
        std::fs::write(&tmp, "not-json{{{").unwrap();
        let (_, st) = SharedState::load(&tmp.to_string_lossy().as_ref()).await;
        assert_eq!(st, LoadStatus::Corrupted);
        let _ = std::fs::remove_file(&tmp);

        // version 字段类型非法 → Corrupted（bug·medium 第二轮：不静默归 0）
        let tmp3 = std::env::temp_dir().join("blackboard_badversion.json");
        let bad = serde_json::json!({"version": "abc", "data": {}});
        std::fs::write(&tmp3, serde_json::to_string(&bad).unwrap()).unwrap();
        let (_, st) = SharedState::load(&tmp3.to_string_lossy().as_ref()).await;
        assert_eq!(st, LoadStatus::Corrupted);
        let _ = std::fs::remove_file(&tmp3);

        // 超限值剔除（宽数组 600 元素 > 512）
        let tmp2 = std::env::temp_dir().join("blackboard_oversize.json");
        let wide = serde_json::json!((0..600).collect::<Vec<u32>>());
        let payload = serde_json::json!({"version": 5, "data": {"wide": wide, "ok": 1}});
        std::fs::write(&tmp2, serde_json::to_string(&payload).unwrap()).unwrap();
        let (bb, st) = SharedState::load(&tmp2.to_string_lossy().as_ref()).await;
        assert_eq!(st, LoadStatus::Loaded);
        assert_eq!(bb.get("wide"), None); // 超限剔除
        assert_eq!(bb.get("ok"), Some(serde_json::json!(1)));
        assert_eq!(bb.version(), 5); // 版本号仍恢复
        let _ = std::fs::remove_file(&tmp2);
    }

    #[tokio::test]
    async fn blackboard_load_enforces_key_cap() {
        // 键数上限恢复（bug·medium 第二轮）：文件 40 键 > BB_MAX_KEYS(32) → 截断
        let tmp = std::env::temp_dir().join("blackboard_manykeys.json");
        let mut data = serde_json::Map::new();
        for i in 0..40 {
            data.insert(format!("k{}", i), serde_json::json!(i));
        }
        let payload = serde_json::json!({"version": 3, "data": data});
        std::fs::write(&tmp, serde_json::to_string(&payload).unwrap()).unwrap();
        let (bb, st) = SharedState::load(&tmp.to_string_lossy().as_ref()).await;
        assert_eq!(st, LoadStatus::Loaded);
        assert_eq!(bb.snapshot().len(), BB_MAX_KEYS); // 截断到上限
        assert_eq!(bb.version(), 3);
        let _ = std::fs::remove_file(&tmp);
    }
}
