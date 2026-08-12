//! P1-B 递归持久子 agent（对照文档 §3 P1：借鉴 rlm() 模式——spawn 后脱离终端、
//! 断线续跑、彼此消息）。
//!
//! 设计（最小可行句柄，复用既有 A2A Bridge）：
//! - `PersistentSubAgent` 句柄：注册到 AgentCore.sub_agents，携带任务上下文与收件箱；
//! - 子 agent 之间消息经既有 `collab_send_raw`（a2a_send）投递，收件箱经 a2a_recv 收取；
//! - 状态（Idle/Running/Done/Failed）与收件箱落盘 `sub_agents.json`，进程重启后恢复
//!   （断线续跑）；未完成子 agent 可在新会话中继续收件/推进。
//!
//! 硬约束：本模块只做**句柄与路由**，不自行 spawn 线程/LLM 循环——子 agent 的执行
//! 由调用方（agent 层）按需驱动（`tick` 模式），避免常驻后台进程的资源与生命周期问题。

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::sync::mpsc;

/// 子 agent 生命周期状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SubAgentState {
    Idle,
    Running,
    Done,
    Failed,
}

/// 子 agent 之间的消息（经 A2A 信封投递的收件箱条目）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubAgentMessage {
    pub from: String,
    pub content: String,
    pub ts: String,
}

/// 持久子 agent 句柄
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistentSubAgent {
    /// 全局唯一 id（形如 "sub-<agent_id>-<seq>"）
    pub id: String,
    /// 任务描述（LLM 提示上下文）
    pub task_desc: String,
    /// 所属命名空间（A2A 收件箱定位）
    pub ns: String,
    pub state: SubAgentState,
    /// 收件箱（跨会话累积；消费经 sub_agent_take_inbox 显式清空，完成态子 agent
    /// 由老化 sweep 整体回收——不在 Done 时自动清，保留审计痕迹）
    pub inbox: Vec<SubAgentMessage>,
    pub created_at: String,
    /// 最近一次活动（Unix 秒，用于老化清理）
    pub last_active: u64,
    /// 通知通道（内存态；持久化后重建）。
    /// 直接存 UnboundedSender（Clone+Send+Sync，send 取 &self）——无需 Mutex 包裹
    /// （bug·medium 第三轮：Arc<Mutex<Sender>> 是过度设计，且引入锁序问题）。
    #[serde(skip)]
    pub notify: Option<mpsc::UnboundedSender<SubAgentMessage>>,
}

impl PersistentSubAgent {
    pub fn new(id: String, task_desc: String, ns: String) -> Self {
        Self {
            id,
            task_desc,
            ns,
            state: SubAgentState::Idle,
            inbox: Vec::new(),
            created_at: now_iso(),
            last_active: now_unix(),
            notify: None,
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.state, SubAgentState::Done | SubAgentState::Failed)
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_iso() -> String {
    let d = chrono::Local::now();
    d.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// 子 agent 注册表（进程内句柄 + 持久化恢复）
#[derive(Default)]
pub struct SubAgentRegistry {
    agents: HashMap<String, PersistentSubAgent>,
}

impl SubAgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, a: PersistentSubAgent) {
        self.agents.insert(a.id.clone(), a);
    }

    pub fn get(&self, id: &str) -> Option<&PersistentSubAgent> {
        self.agents.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut PersistentSubAgent> {
        self.agents.get_mut(id)
    }

    pub fn remove(&mut self, id: &str) -> Option<PersistentSubAgent> {
        self.agents.remove(id)
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PersistentSubAgent> {
        self.agents.values()
    }

    /// 老化清理：超过 `max_idle_secs` 无活动的已完成/失败子 agent 移除。
    pub fn sweep(&mut self, now_unix: u64, max_idle_secs: u64) -> usize {
        let before = self.agents.len();
        self.agents.retain(|_, a| {
            !a.is_finished() || now_unix.saturating_sub(a.last_active) < max_idle_secs
        });
        before - self.agents.len()
    }

    /// 从现有 id 推断最大 seq（id 形如 `sub-<agent_id>-<seq>`）——重启后
    /// seq 恢复用，防新 id 与恢复的旧 id 重复（ocr 2026-08-12 bug·high）。
    /// bug·medium（第五轮）：仅统计**本 agent 前缀**的 id（agent_id 可能含数字，
    /// 全局尾数推断会被其它 agent 的子 agent 污染）；无匹配返回 0（调用方从 1 起）。
    pub fn max_seq(&self, agent_id: &str) -> u64 {
        let prefix = format!("sub-{}-", agent_id);
        self.agents
            .keys()
            .filter(|id| id.starts_with(&prefix))
            .filter_map(|id| id.rsplit('-').next().and_then(|s| s.parse::<u64>().ok()))
            .max()
            .unwrap_or(0)
    }
}

/// 消息投递：入收件箱 + 通知（若子 agent 已注册 notify 通道）。
/// 未找到目标子 agent 返回 Err（调用方可用 A2A 原生投递兜底）。
/// 锁序修复（ocr 2026-08-12 bug·high/第三轮）：notify 直接存 UnboundedSender
/// （send 取 &self 且线程安全）——registry 锁内只写收件箱，锁外再 send，
/// 不持有任何跨 await 的锁。
pub async fn deliver(
    registry: &Arc<Mutex<SubAgentRegistry>>,
    to_sub_id: &str,
    from: &str,
    content: &str,
) -> Result<(), String> {
    let msg = SubAgentMessage {
        from: from.to_string(),
        content: content.to_string(),
        ts: now_iso(),
    };
    let notify_sender = {
        let mut reg = registry.lock().await;
        let agent = reg
            .get_mut(to_sub_id)
            .ok_or_else(|| format!("子 agent {} 不存在", to_sub_id))?;
        agent.inbox.push(msg.clone());
        agent.last_active = now_unix();
        agent.notify.clone()
    };
    if let Some(sender) = notify_sender {
        let _ = sender.send(msg);
    }
    Ok(())
}

/// 持久化注册表到 JSON 文件（断线续跑：重启后 `load` 恢复）。
/// 受控写：临时文件 + rename（避免半写损坏）。
/// tmp 唯一后缀（bug·medium 第三轮）：并发 save 共用 `{path}.tmp` 会互相覆盖/
/// rename 竞态——用 pid+计数唯一后缀，写完后 rename 到目标。
/// 持锁范围（bug·high 第六轮）：序列化到 rename **全程持锁**——锁外写文件期间
/// 其它线程改注册表会写入旧快照（lost-update）。小文件写微秒级，持锁成本可忽略。
pub async fn save(registry: &Arc<Mutex<SubAgentRegistry>>, path: &str) -> Result<(), String> {
    let mut reg = registry.lock().await;
    let json = serde_json::to_string_pretty(&reg.agents)
        .map_err(|e| format!("序列化子 agent 注册表失败: {}", e))?;
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = format!("{}.tmp.{}.{}", path, std::process::id(), seq);
    tokio::fs::write(&tmp, json.as_bytes())
        .await
        .map_err(|e| format!("写子 agent 注册表临时文件失败: {}", e))?;
    // rename 阻塞（perf·medium 已文档化）：同盘 rename 为元数据操作，小文件
    // 微秒级；跨盘场景罕见（path 固定在工作目录），可接受。
    std::fs::rename(&tmp, path).map_err(|e| format!("原子替换子 agent 注册表失败: {}", e))
}

/// 加载结果状态（区分「文件缺失」与「文件损坏」——other·medium：
/// 损坏是配置/落盘 bug，应告警而非静默当空注册表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStatus {
    Loaded,
    /// 文件不存在（正常首启）
    Missing,
    /// 文件存在但解析失败（落盘 bug）
    Corrupted,
    /// 读失败（权限/IO 错误——bug·high 第五轮：此前折叠为 Missing 掩盖权限问题）
    Unreadable,
}

/// 从 JSON 文件恢复注册表（重启续跑入口）。文件不存在/损坏 → 空注册表（不阻断启动）。
/// 返回状态供调用方区分处理（损坏/不可读时告警）。
/// 同步实现：供 AgentCore::new（非 async）启动恢复调用。
pub fn load(path: &str) -> (SubAgentRegistry, LoadStatus) {
    let mut reg = SubAgentRegistry::new();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (reg, LoadStatus::Missing),
        Err(_) => return (reg, LoadStatus::Unreadable),
    };
    match serde_json::from_str::<HashMap<String, PersistentSubAgent>>(&text) {
        Ok(mut map) => {
            // 崩溃恢复（bug·medium 第六轮）：Running 状态是进程内存态，重启后
            // 执行上下文已丢失——统一复位 Idle（由调用方按收件箱/任务重新驱动），
            // 否则永远卡 Running（无法推进/老化）。
            for a in map.values_mut() {
                if a.state == SubAgentState::Running {
                    a.state = SubAgentState::Idle;
                }
                a.notify = None; // 通知通道是内存态，重启后无接收方
            }
            reg.agents = map;
            (reg, LoadStatus::Loaded)
        }
        Err(_) => (reg, LoadStatus::Corrupted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[test]
    fn registry_crud_and_sweep() {
        let mut reg = SubAgentRegistry::new();
        reg.insert(PersistentSubAgent::new(
            "sub-1".into(),
            "查固废数据".into(),
            "agent/xujiayan".into(),
        ));
        assert_eq!(reg.len(), 1);
        assert!(reg.get("sub-1").is_some());

        // 未完成的不被 sweep
        let removed = reg.sweep(now() + 9999, 60);
        assert_eq!(removed, 0);
        assert_eq!(reg.len(), 1);

        // 完成后老化可清
        reg.get_mut("sub-1").unwrap().state = SubAgentState::Done;
        reg.get_mut("sub-1").unwrap().last_active = now() - 120;
        let removed = reg.sweep(now(), 60);
        assert_eq!(removed, 1);
        assert!(reg.is_empty());
    }

    #[tokio::test]
    async fn deliver_roundtrip() {
        let reg = Arc::new(Mutex::new(SubAgentRegistry::new()));
        {
            let mut g = reg.lock().await;
            g.insert(PersistentSubAgent::new(
                "sub-a".into(),
                "任务A".into(),
                "agent/xujiayan".into(),
            ));
        }
        deliver(&reg, "sub-a", "sub-b", "你好").await.unwrap();
        let g = reg.lock().await;
        assert_eq!(g.get("sub-a").unwrap().inbox.len(), 1);
        assert_eq!(g.get("sub-a").unwrap().inbox[0].content, "你好");
        assert_eq!(g.get("sub-a").unwrap().inbox[0].from, "sub-b");
    }

    #[tokio::test]
    async fn save_load_roundtrip() {
        let reg = Arc::new(Mutex::new(SubAgentRegistry::new()));
        {
            let mut g = reg.lock().await;
            let mut a = PersistentSubAgent::new("sub-x".into(), "任务X".into(), "agent/x".into());
            a.state = SubAgentState::Running;
            a.inbox.push(SubAgentMessage {
                from: "sub-y".into(),
                content: "进度？".into(),
                ts: "2026-08-12T10:00:00".into(),
            });
            g.insert(a);
        }
        let tmp = std::env::temp_dir().join("sub_agent_test.json");
        let path = tmp.to_string_lossy().to_string();
        save(&reg, &path).await.unwrap();
        let (restored, status) = load(&path);
        assert_eq!(status, LoadStatus::Loaded);
        assert_eq!(restored.len(), 1);
        let a = restored.get("sub-x").unwrap();
        // 崩溃恢复语义：Running 复位 Idle（第六轮 bug·medium）
        assert_eq!(a.state, SubAgentState::Idle);
        assert_eq!(a.inbox.len(), 1);
        assert_eq!(a.inbox[0].from, "sub-y");
        let _ = std::fs::remove_file(&path);
    }
}
