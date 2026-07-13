//! 会话管理器 — 多轮对话状态、历史缓存、LRU 淘汰
//!
//! 从 AgentCore 中提取的独立模块，纯逻辑可测。

use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;

use crate::llm::Message;

/// 会话状态（任务级确认状态机）
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// 新会话或刚结束上一个任务
    New,
    /// 等待用户确认理解
    AwaitingConfirmation,
    /// 已确认，可正常执行
    Confirmed,
}

/// 待确认操作
#[derive(Debug, Clone)]
pub struct PendingAction {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub description: String,
}

/// 会话管理器
///
/// 集中管理多轮对话的全部状态，包括：
/// - 会话历史缓存（内存 + SQLite）
/// - 确认状态机状态
/// - 待确认操作
/// - LRU 淘汰
pub struct SessionManager {
    /// 多轮会话历史缓存（session_id → messages）
    session_history: Mutex<HashMap<String, Vec<Message>>>,
    /// 待确认操作（session_id → pending action）
    pending_actions: Mutex<HashMap<String, PendingAction>>,
    /// 会话状态追踪（session_id → state）
    session_state: Mutex<HashMap<String, SessionState>>,
    /// 待确认的原始消息（session_id → original message）
    pending_original_message: Mutex<HashMap<String, String>>,
    /// 确认状态开始时间（session_id → Instant）
    confirm_started_at: Mutex<HashMap<String, Instant>>,
    /// session_history LRU 追踪（限制缓存的 session 数量）
    session_lru: Mutex<Vec<String>>,
}

/// 默认 LRU 上限
const MAX_SESSIONS: usize = 50;

impl SessionManager {
    /// 创建新的会话管理器
    pub fn new() -> Self {
        SessionManager {
            session_history: Mutex::new(HashMap::new()),
            pending_actions: Mutex::new(HashMap::new()),
            session_state: Mutex::new(HashMap::new()),
            pending_original_message: Mutex::new(HashMap::new()),
            confirm_started_at: Mutex::new(HashMap::new()),
            session_lru: Mutex::new(Vec::new()),
        }
    }

    // ── 会话状态 ──

    /// 获取会话状态
    pub async fn get_state(&self, session_id: &str) -> SessionState {
        let states = self.session_state.lock().await;
        states.get(session_id).cloned().unwrap_or(SessionState::New)
    }

    /// 设置会话状态
    pub async fn set_state(&self, session_id: &str, state: SessionState) {
        // 进入 AwaitingConfirmation 时记录开始时间
        if state == SessionState::AwaitingConfirmation {
            self.confirm_started_at
                .lock()
                .await
                .insert(session_id.to_string(), Instant::now());
        } else {
            // 离开确认状态时清除时间戳
            self.confirm_started_at.lock().await.remove(session_id);
        }
        self.session_state
            .lock()
            .await
            .insert(session_id.to_string(), state);
    }

    /// 移除会话状态
    pub async fn remove_state(&self, session_id: &str) {
        self.session_state.lock().await.remove(session_id);
    }

    // ── 待确认操作 ──

    /// 获取并移除待确认操作
    pub async fn take_pending_action(&self, session_id: &str) -> Option<PendingAction> {
        self.pending_actions.lock().await.remove(session_id)
    }

    /// 设置待确认操作
    pub async fn set_pending_action(&self, session_id: &str, action: PendingAction) {
        self.pending_actions
            .lock()
            .await
            .insert(session_id.to_string(), action);
    }

    /// 查询是否存在待确认操作
    pub async fn has_pending_action(&self, session_id: &str) -> bool {
        self.pending_actions.lock().await.contains_key(session_id)
    }

    // ── 原始消息 ──

    /// 获取并移除待确认的原始消息
    pub async fn take_original_message(&self, session_id: &str) -> Option<String> {
        self.pending_original_message
            .lock()
            .await
            .remove(session_id)
    }

    /// 获取待确认的原始消息（不移除）
    pub async fn get_original_message(&self, session_id: &str) -> Option<String> {
        self.pending_original_message
            .lock()
            .await
            .get(session_id)
            .cloned()
    }

    /// 设置待确认的原始消息
    pub async fn set_original_message(&self, session_id: &str, message: &str) {
        self.pending_original_message
            .lock()
            .await
            .insert(session_id.to_string(), message.to_string());
    }

    // ── 会话历史（内存缓存） ──

    /// 从内存缓存获取历史（不移除）
    pub async fn get_cached_history(&self, session_id: &str) -> Option<Vec<Message>> {
        let cache = self.session_history.lock().await;
        cache.get(session_id).cloned()
    }

    /// 从内存缓存 + SQLite 加载历史对话
    ///
    /// 先查内存缓存，未命中则从 SQLite 恢复并写回缓存。
    /// `db_path` 和 `namespace` 由调用方提供。
    pub async fn load_history(
        &self,
        session_id: &str,
        namespace: &str,
        db_path: &str,
    ) -> Vec<Message> {
        // 先从内存缓存
        let cache = self.session_history.lock().await;
        if let Some(msgs) = cache.get(session_id) {
            if !msgs.is_empty() {
                return msgs.clone();
            }
        }
        drop(cache);

        // 内存没有 → 从 SQLite 恢复
        if db_path.is_empty() {
            return Vec::new();
        }

        let sid = session_id.to_string();
        let ns = namespace.to_string();
        let db = db_path.to_string();
        let msgs: Vec<Message> = tokio::task::spawn_blocking(move || {
            let mut result = Vec::new();
            if let Ok(conn) = rusqlite::Connection::open(&db) {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT role, content FROM chat_history WHERE session_id=?1 AND namespace=?2 ORDER BY id DESC LIMIT 20"
                ) {
                    if let Ok(rows) = stmt.query_map(rusqlite::params![sid, ns], |row| {
                        let role: String = row.get(0)?;
                        let content: String = row.get(1)?;
                        Ok((role, content))
                    }) {
                        for row in rows.flatten() {
                            result.push(Message {
                                role: row.0,
                                content: Some(row.1),
                                tool_calls: None,
                                tool_call_id: None,
                            });
                        }
                    }
                }
            }
            result.reverse();
            result
        }).await.unwrap_or_default();

        // 写回内存缓存
        if !msgs.is_empty() {
            let mut cache = self.session_history.lock().await;
            cache.insert(session_id.to_string(), msgs.clone());
        }

        msgs
    }

    /// 保存对话到内存缓存 + SQLite 持久化
    ///
    /// 内存缓存带 LRU 淘汰（最多缓存 `MAX_SESSIONS` 个 session）。
    /// SQLite 持久化通过 `db_path` 和 `namespace` 参数完成。
    pub async fn save_to_history(
        &self,
        session_id: &str,
        namespace: &str,
        db_path: &str,
        user_msg: &str,
        assistant_reply: &str,
    ) {
        // 内存缓存
        let mut cache = self.session_history.lock().await;
        let history = cache.entry(session_id.to_string()).or_insert_with(Vec::new);
        history.push(Message {
            role: "user".to_string(),
            content: Some(user_msg.to_string()),
            tool_calls: None,
            tool_call_id: None,
        });
        history.push(Message {
            role: "assistant".to_string(),
            content: Some(assistant_reply.to_string()),
            tool_calls: None,
            tool_call_id: None,
        });
        // 只保留最近 10 轮（20 条消息）：先推后截，确保 buf ≤ 20
        if history.len() > 20 {
            history.drain(0..history.len() - 20);
        }

        // LRU 追踪：把当前 session 移到末尾
        {
            let mut lru = self.session_lru.lock().await;
            lru.retain(|s| s != session_id);
            lru.push(session_id.to_string());
            // 超出上限时淘汰最旧的 session
            while lru.len() > MAX_SESSIONS {
                if let Some(old) = lru.first().cloned() {
                    lru.remove(0);
                    cache.remove(&old);
                } else {
                    break;
                }
            }
        }
        drop(cache);

        // SQLite 持久化
        let ns = namespace.to_string();
        let db = db_path.to_string();
        let sid = session_id.to_string();
        let u_msg = user_msg.to_string();
        let a_msg = assistant_reply.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(conn) = rusqlite::Connection::open(&db) {
                conn.execute(
                    "INSERT INTO chat_history (session_id, namespace, role, content, created_at) VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                    rusqlite::params![sid, ns, "user", u_msg],
                ).ok();
                conn.execute(
                    "INSERT INTO chat_history (session_id, namespace, role, content, created_at) VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                    rusqlite::params![sid, ns, "assistant", a_msg],
                ).ok();
            }
        }).await;
    }

    /// 清空指定 session 的所有状态
    pub async fn clear_session(&self, session_id: &str) {
        self.session_history.lock().await.remove(session_id);
        self.pending_actions.lock().await.remove(session_id);
        self.session_state.lock().await.remove(session_id);
        self.pending_original_message
            .lock()
            .await
            .remove(session_id);
        self.confirm_started_at.lock().await.remove(session_id);
        self.session_lru.lock().await.retain(|s| s != session_id);
    }

    /// 检查所有 pending 确认是否超时（默认5分钟）
    ///
    /// 返回超时的 session_id 列表，并自动重置这些会话状态。
    pub async fn check_confirm_timeouts(&self, timeout_secs: u64) -> Vec<String> {
        let now = Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let mut timed_out = Vec::new();

        let started = self.confirm_started_at.lock().await;
        for (session_id, start) in started.iter() {
            if now.duration_since(*start) > timeout {
                timed_out.push(session_id.clone());
            }
        }
        drop(started);

        // 重置超时会话
        for sid in &timed_out {
            self.session_state.lock().await.remove(sid);
            self.confirm_started_at.lock().await.remove(sid);
            self.pending_actions.lock().await.remove(sid);
            self.pending_original_message.lock().await.remove(sid);
        }

        timed_out
    }

    /// 当前缓存的 session 数量
    pub async fn cached_count(&self) -> usize {
        self.session_history.lock().await.len()
    }

    /// LRU 列表长度
    pub async fn lru_len(&self) -> usize {
        self.session_lru.lock().await.len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_new() {
        assert_eq!(SessionState::New, SessionState::New);
        assert_ne!(SessionState::New, SessionState::Confirmed);
        assert_ne!(SessionState::New, SessionState::AwaitingConfirmation);
    }

    #[test]
    fn test_pending_action_construction() {
        let action = PendingAction {
            tool_name: "query_plate".to_string(),
            arguments: serde_json::json!({"plate": "京A12345"}),
            description: "查询车牌".to_string(),
        };
        assert_eq!(action.tool_name, "query_plate");
        assert_eq!(action.description, "查询车牌");
    }

    #[tokio::test]
    async fn test_session_manager_new() {
        let sm = SessionManager::new();
        assert_eq!(sm.cached_count().await, 0);
        assert_eq!(sm.lru_len().await, 0);
    }

    #[tokio::test]
    async fn test_get_state_default_new() {
        let sm = SessionManager::new();
        assert_eq!(sm.get_state("nonexistent").await, SessionState::New);
    }

    #[tokio::test]
    async fn test_set_and_get_state() {
        let sm = SessionManager::new();
        sm.set_state("s1", SessionState::Confirmed).await;
        assert_eq!(sm.get_state("s1").await, SessionState::Confirmed);
        assert_eq!(sm.get_state("s2").await, SessionState::New);
    }

    #[tokio::test]
    async fn test_remove_state() {
        let sm = SessionManager::new();
        sm.set_state("s1", SessionState::AwaitingConfirmation).await;
        assert_eq!(sm.get_state("s1").await, SessionState::AwaitingConfirmation);
        sm.remove_state("s1").await;
        assert_eq!(sm.get_state("s1").await, SessionState::New);
    }

    #[tokio::test]
    async fn test_pending_action_roundtrip() {
        let sm = SessionManager::new();
        let action = PendingAction {
            tool_name: "manage_whitelist".to_string(),
            arguments: serde_json::json!({"action": "add"}),
            description: "添加白名单".to_string(),
        };
        sm.set_pending_action("s1", action).await;
        assert!(sm.has_pending_action("s1").await);

        let taken = sm.take_pending_action("s1").await;
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().tool_name, "manage_whitelist");
        assert!(!sm.has_pending_action("s1").await);
    }

    #[tokio::test]
    async fn test_original_message() {
        let sm = SessionManager::new();
        sm.set_original_message("s1", "帮我查车牌京A12345").await;
        assert_eq!(
            sm.get_original_message("s1").await,
            Some("帮我查车牌京A12345".to_string())
        );

        let taken = sm.take_original_message("s1").await;
        assert_eq!(taken, Some("帮我查车牌京A12345".to_string()));
        assert_eq!(sm.get_original_message("s1").await, None);
    }

    #[tokio::test]
    async fn test_clear_session() {
        let sm = SessionManager::new();
        sm.set_state("s1", SessionState::Confirmed).await;
        sm.set_original_message("s1", "test").await;

        sm.clear_session("s1").await;
        assert_eq!(sm.get_state("s1").await, SessionState::New);
        assert_eq!(sm.get_original_message("s1").await, None);
    }

    #[tokio::test]
    async fn test_history_cache_and_lru() {
        let sm = SessionManager::new();
        let ns = "agent/test";
        let db_path = ""; // 无 SQLite，只测内存

        // 第一次加载，空历史
        let history = sm.load_history("s1", ns, db_path).await;
        assert!(history.is_empty());

        // 保存对话
        sm.save_to_history("s1", ns, db_path, "你好", "你好！有什么可以帮你的？")
            .await;
        let history = sm.load_history("s1", ns, db_path).await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].content.as_deref(), Some("你好"));
        assert_eq!(
            history[1].content.as_deref(),
            Some("你好！有什么可以帮你的？")
        );

        assert_eq!(sm.cached_count().await, 1);
        assert_eq!(sm.lru_len().await, 1);
    }

    #[tokio::test]
    async fn test_history_truncation() {
        let sm = SessionManager::new();
        let ns = "agent/test";
        let db_path = "";

        // 写 15 轮（30 条消息），先推后截，最终保留最近 10 轮（20 条）
        for i in 0..15 {
            sm.save_to_history(
                "s1",
                ns,
                db_path,
                &format!("msg{}", i),
                &format!("reply{}", i),
            )
            .await;
        }

        let history = sm.load_history("s1", ns, db_path).await;
        assert_eq!(history.len(), 20);
        // 最后一条应该是 reply14
        assert_eq!(history.last().unwrap().content.as_deref(), Some("reply14"));
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        let sm = SessionManager::new();
        let ns = "agent/test";
        let db_path = "";

        // MAX_SESSIONS = 50，建 55 个 session 触发淘汰
        for i in 0..55 {
            let sid = format!("s{}", i);
            sm.save_to_history(&sid, ns, db_path, "hi", "hello").await;
        }

        assert_eq!(sm.cached_count().await, 50);
        // s0 应该被淘汰了
        let history = sm.load_history("s0", ns, db_path).await;
        assert!(history.is_empty());
        // s54 应该还在
        let history = sm.load_history("s54", ns, db_path).await;
        assert_eq!(history.len(), 2);
    }
}
