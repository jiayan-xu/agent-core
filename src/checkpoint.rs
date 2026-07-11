//! Checkpoint 控制面 — 会话 / 计划 / 审批的可续跑持久化
//!
//! 与 `session.rs` 的「对话历史（chat_history）」职责严格分离：
//! - `chat_history`：对话内容（数据面）
//! - `checkpoints`：控制面状态（`New | AwaitingConfirmation | Confirmed |
//!   PendingApproval | ExecutingPlan | Done | Failed`）及其 payload_json
//!
//! 进程重启后，`chat()` 入口先 `restore_checkpoint` 把状态恢复到内存，
//! 使确认态 / 组合计划 / 待审批可在崩溃后续跑。借鉴 LangGraph checkpoint
//! 的「持久状态 + 恢复」思想，但存储用现有 rusqlite 生态，不引入图框架。

use rusqlite::{params, Connection};

/// 控制面状态机
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointState {
    New,
    AwaitingConfirmation,
    Confirmed,
    PendingApproval,
    ExecutingPlan,
    Done,
    Failed,
}

impl CheckpointState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckpointState::New => "New",
            CheckpointState::AwaitingConfirmation => "AwaitingConfirmation",
            CheckpointState::Confirmed => "Confirmed",
            CheckpointState::PendingApproval => "PendingApproval",
            CheckpointState::ExecutingPlan => "ExecutingPlan",
            CheckpointState::Done => "Done",
            CheckpointState::Failed => "Failed",
        }
    }
    pub fn from_str(s: &str) -> CheckpointState {
        match s {
            "AwaitingConfirmation" => CheckpointState::AwaitingConfirmation,
            "Confirmed" => CheckpointState::Confirmed,
            "PendingApproval" => CheckpointState::PendingApproval,
            "ExecutingPlan" => CheckpointState::ExecutingPlan,
            "Done" => CheckpointState::Done,
            "Failed" => CheckpointState::Failed,
            _ => CheckpointState::New,
        }
    }
}

/// 控制面快照（一次持久化状态）
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub session_id: String,
    pub agent_id: String,
    pub state: CheckpointState,
    pub payload: serde_json::Value,
    pub updated_at: String,
}

/// checkpoint 存储（SQLite）
pub struct CheckpointStore {
    conn: Connection,
}

impl CheckpointStore {
    /// 打开（或创建）checkpoint 数据库。建议使用独立文件以与 chat_history 隔离。
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("open checkpoint db: {}", e))?;
        let mut store = CheckpointStore { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// 内存模式（用于测试）
    pub fn open_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| format!("open memory: {}", e))?;
        let mut store = CheckpointStore { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS checkpoints (
                    session_id   TEXT PRIMARY KEY,
                    agent_id     TEXT NOT NULL DEFAULT '',
                    state        TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at   TEXT DEFAULT (datetime('now')),
                    updated_at   TEXT DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_checkpoint_state ON checkpoints(state);",
            )
            .map_err(|e| format!("init checkpoint schema: {}", e))?;
        Ok(())
    }

    /// upsert 一个 checkpoint（状态迁移成功即写）
    pub fn save(
        &self,
        session_id: &str,
        agent_id: &str,
        state: CheckpointState,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let payload_str = serde_json::to_string(payload)
            .map_err(|e| format!("serialize checkpoint payload: {}", e))?;
        self.conn
            .execute(
                "INSERT INTO checkpoints (session_id, agent_id, state, payload_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))
                 ON CONFLICT(session_id) DO UPDATE SET
                    agent_id     = excluded.agent_id,
                    state        = excluded.state,
                    payload_json = excluded.payload_json,
                    updated_at   = datetime('now')",
                params![session_id, agent_id, state.as_str(), payload_str],
            )
            .map_err(|e| format!("save checkpoint: {}", e))?;
        Ok(())
    }

    /// 读取 session 的最新 checkpoint
    pub fn load(&self, session_id: &str) -> Option<Checkpoint> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT session_id, agent_id, state, payload_json, updated_at \
                 FROM checkpoints WHERE session_id=?1",
            )
            .ok()?;
        let mut rows = stmt.query(params![session_id]).ok()?;
        if let Some(row) = rows.next().ok().flatten() {
            let sid: String = row.get(0).ok()?;
            let agent_id: String = row.get(1).ok()?;
            let state: String = row.get(2).ok()?;
            let payload_str: String = row.get(3).ok()?;
            let updated_at: String = row.get(4).ok()?;
            let payload: serde_json::Value =
                serde_json::from_str(&payload_str).unwrap_or(serde_json::json!({}));
            return Some(Checkpoint {
                session_id: sid,
                agent_id,
                state: CheckpointState::from_str(&state),
                payload,
                updated_at,
            });
        }
        None
    }

    /// 删除（会话清理时调用）
    pub fn delete(&self, session_id: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM checkpoints WHERE session_id=?1", params![session_id])
            .map_err(|e| format!("delete checkpoint: {}", e))?;
        Ok(())
    }

    /// 列出过期（超过 ttl 秒未更新）的 session_id
    pub fn list_stale(&self, ttl_secs: u64) -> Vec<String> {
        let delta = format!("-{} seconds", ttl_secs);
        let mut out = Vec::new();
        if let Ok(mut stmt) = self.conn.prepare(
            "SELECT session_id FROM checkpoints WHERE updated_at <= datetime('now', ?1)",
        ) {
            if let Ok(mut rows) = stmt.query(params![delta]) {
                while let Ok(Some(row)) = rows.next() {
                    if let Ok(sid) = row.get::<_, String>(0) {
                        out.push(sid);
                    }
                }
            }
        }
        out
    }

    /// 清理过期 checkpoint（默认 24h 语义由调用方传入 ttl）
    pub fn purge_stale(&self, ttl_secs: u64) -> usize {
        let delta = format!("-{} seconds", ttl_secs);
        match self
            .conn
            .execute(
                "DELETE FROM checkpoints WHERE updated_at <= datetime('now', ?1)",
                params![delta],
            )
        {
            Ok(n) => n as usize,
            Err(_) => 0,
        }
    }
}

// ══════════════════════════════════════════════════════
// 测试
// ══════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_roundtrip() {
        assert_eq!(
            CheckpointState::from_str("ExecutingPlan"),
            CheckpointState::ExecutingPlan
        );
        assert_eq!(CheckpointState::from_str("unknown"), CheckpointState::New);
        assert_eq!(
            CheckpointState::AwaitingConfirmation.as_str(),
            "AwaitingConfirmation"
        );
    }

    #[test]
    fn test_save_load_overwrite_delete() {
        let store = CheckpointStore::open_memory().unwrap();
        let payload = serde_json::json!({"original_message": "帮我查数据"});
        store
            .save("s1", "agent1", CheckpointState::AwaitingConfirmation, &payload)
            .unwrap();
        let cp = store.load("s1").unwrap();
        assert_eq!(cp.state, CheckpointState::AwaitingConfirmation);
        assert_eq!(
            cp.payload["original_message"].as_str(),
            Some("帮我查数据")
        );

        // 覆盖
        let payload2 = serde_json::json!({"original_message": "改了"});
        store
            .save("s1", "agent1", CheckpointState::ExecutingPlan, &payload2)
            .unwrap();
        let cp2 = store.load("s1").unwrap();
        assert_eq!(cp2.state, CheckpointState::ExecutingPlan);
        assert_eq!(cp2.payload["original_message"].as_str(), Some("改了"));

        store.delete("s1").unwrap();
        assert!(store.load("s1").is_none());
    }

    #[test]
    fn test_payload_roundtrip_plan() {
        let store = CheckpointStore::open_memory().unwrap();
        let payload = serde_json::json!({
            "plan": {"steps":[{"step_id":1,"description":"d","tool":"t","arguments":{},"depends_on":[]}]},
            "step_results": {"1": "ok"}
        });
        store
            .save("p1", "a", CheckpointState::ExecutingPlan, &payload)
            .unwrap();
        let cp = store.load("p1").unwrap();
        assert_eq!(cp.payload["step_results"]["1"].as_str(), Some("ok"));
        assert_eq!(
            cp.payload["plan"]["steps"][0]["tool"].as_str(),
            Some("t")
        );
    }

    #[test]
    fn test_nonexistent() {
        let store = CheckpointStore::open_memory().unwrap();
        assert!(store.load("nope").is_none());
    }
}
