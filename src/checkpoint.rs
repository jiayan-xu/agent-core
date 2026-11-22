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

/// P0-2/BizBuddy WriteDedup：in-flight 占坑超过该秒数视为陈旧（执行方崩溃 /
/// 释放失败等残留），可被重新占坑。10 分钟来自设计定案。
const WRITE_DEDUP_STALE_SECS: u64 = 600;

/// P0-2/BizBuddy WriteDedup：登记摘要的最大字符数（按字符截断，绝不切 UTF-8 中间）。
const WRITE_DEDUP_SUMMARY_CHARS: usize = 500;

/// P0-2/BizBuddy WriteDedup：受控写执行前占坑（claim）的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteDedupClaim {
    /// 首次占坑成功 → 放行执行
    Claimed,
    /// 与上次已成功操作指纹相同 → 跳过执行，返回上次摘要
    Duplicate { summary: String },
    /// 同指纹操作正在执行中（未超时）→ 跳过本次调用
    InFlight,
}

/// 控制面状态机
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointState {
    New,
    AwaitingConfirmation,
    Confirmed,
    PendingApproval,
    ExecutingPlan,
    PlanPreview,
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
            CheckpointState::PlanPreview => "PlanPreview",
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
            "PlanPreview" => CheckpointState::PlanPreview,
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
                CREATE INDEX IF NOT EXISTS idx_checkpoint_state ON checkpoints(state);
                CREATE TABLE IF NOT EXISTS write_dedup (
                    session_id     TEXT NOT NULL,
                    tool_name      TEXT NOT NULL,
                    operation_hash TEXT NOT NULL,
                    result_summary TEXT,
                    created_at     INTEGER NOT NULL,
                    PRIMARY KEY(session_id, tool_name, operation_hash)
                );",
            )
            .map_err(|e| format!("init checkpoint schema: {}", e))?;
        Ok(())
    }

    /// P0-2/BizBuddy WriteDedup：受控写执行前占坑。
    /// - 首次插入成功 → `Claimed`（放行执行）；
    /// - 已有行且 result_summary 非空 → `Duplicate`（命中上次成功摘要，跳过执行）；
    /// - 已有行但摘要为空（in-flight）→ 未超 600s 视为进行中返回 `InFlight`；
    ///   超 600s 视为陈旧残留：DELETE 后重新占坑放行。
    pub fn claim_write_dedup(
        &self,
        session_id: &str,
        tool_name: &str,
        operation_hash: &str,
    ) -> Result<WriteDedupClaim, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let inserted = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO write_dedup
                    (session_id, tool_name, operation_hash, result_summary, created_at)
                 VALUES (?1, ?2, ?3, NULL, ?4)",
                params![session_id, tool_name, operation_hash, now as i64],
            )
            .map_err(|e| format!("claim write_dedup: {}", e))?;
        if inserted == 1 {
            return Ok(WriteDedupClaim::Claimed);
        }

        // 已有行：读回判定（result_summary / created_at）
        let existing: Option<(Option<String>, i64)> = self
            .conn
            .query_row(
                "SELECT result_summary, created_at FROM write_dedup
                 WHERE session_id=?1 AND tool_name=?2 AND operation_hash=?3",
                params![session_id, tool_name, operation_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let (summary, _created_at) = match existing {
            Some(v) => v,
            None => {
                // 理论不可达（INSERT 冲突但读不到行，如跨进程并发删除竞态）：
                // fail-open 放行，避免误跳过真实写操作
                tracing::warn!(
                    session = %session_id,
                    tool = %tool_name,
                    "write_dedup: 占坑冲突但读不到行，fail-open 放行"
                );
                return Ok(WriteDedupClaim::Claimed);
            }
        };
        // 摘要非空 → 命中上次成功执行
        if let Some(s) = summary.filter(|s| !s.is_empty()) {
            return Ok(WriteDedupClaim::Duplicate { summary: s });
        }
        // in-flight：超过 600s 视为陈旧 → 清理后重新占坑。
        // P2-1（ocr 复核）：陈旧性谓词与 DELETE 原子一致（result_summary IS NULL 且
        // created_at < now-600s），跨进程并发下也不会误删他人刚占的新坑——他人新坑
        // 删不掉，随后 INSERT OR IGNORE 冲突（again==0）→ InFlight。
        let cutoff = now.saturating_sub(WRITE_DEDUP_STALE_SECS) as i64;
        self.conn
            .execute(
                "DELETE FROM write_dedup
                 WHERE session_id=?1 AND tool_name=?2 AND operation_hash=?3
                   AND result_summary IS NULL AND created_at < ?4",
                params![session_id, tool_name, operation_hash, cutoff],
            )
            .map_err(|e| format!("reclaim write_dedup (delete): {}", e))?;
        let again = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO write_dedup
                    (session_id, tool_name, operation_hash, result_summary, created_at)
                 VALUES (?1, ?2, ?3, NULL, ?4)",
                params![session_id, tool_name, operation_hash, now as i64],
            )
            .map_err(|e| format!("reclaim write_dedup: {}", e))?;
        if again == 1 {
            return Ok(WriteDedupClaim::Claimed);
        }
        Ok(WriteDedupClaim::InFlight)
    }

    /// P0-2/BizBuddy WriteDedup：执行**成功**后登记摘要（供后续同指纹调用跳过时回显）。
    /// 摘要按字符边界截断到 500 字符，绝不截断 UTF-8 中间。
    pub fn finalize_write_dedup(
        &self,
        session_id: &str,
        tool_name: &str,
        operation_hash: &str,
        result_summary: &str,
    ) -> Result<(), String> {
        let summary: String = result_summary
            .chars()
            .take(WRITE_DEDUP_SUMMARY_CHARS)
            .collect();
        self.conn
            .execute(
                "UPDATE write_dedup SET result_summary=?4
                 WHERE session_id=?1 AND tool_name=?2 AND operation_hash=?3",
                params![session_id, tool_name, operation_hash, summary],
            )
            .map_err(|e| format!("finalize write_dedup: {}", e))?;
        Ok(())
    }

    /// P0-2/BizBuddy WriteDedup：执行**未成功**（require_confirm / error / Err）释放占坑，
    /// 保留修正重试与审批后续执行能力。
    pub fn release_write_dedup(
        &self,
        session_id: &str,
        tool_name: &str,
        operation_hash: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM write_dedup
                 WHERE session_id=?1 AND tool_name=?2 AND operation_hash=?3",
                params![session_id, tool_name, operation_hash],
            )
            .map_err(|e| format!("release write_dedup: {}", e))?;
        Ok(())
    }

    /// P0-2/BizBuddy WriteDedup：任务边界清理——删除该 session 全部占坑行。
    /// 在 checkpoint 终态（Done/Failed）与 checkpoint 删除路径调用。
    pub fn clear_session(&self, session_id: &str) -> Result<usize, String> {
        let n = self
            .conn
            .execute(
                "DELETE FROM write_dedup WHERE session_id=?1",
                params![session_id],
            )
            .map_err(|e| format!("clear write_dedup session: {}", e))?;
        Ok(n as usize)
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
            .execute(
                "DELETE FROM checkpoints WHERE session_id=?1",
                params![session_id],
            )
            .map_err(|e| format!("delete checkpoint: {}", e))?;
        Ok(())
    }

    /// 列出过期（超过 ttl 秒未更新）的 session_id
    pub fn list_stale(&self, ttl_secs: u64) -> Vec<String> {
        let delta = format!("-{} seconds", ttl_secs);
        let mut out = Vec::new();
        if let Ok(mut stmt) = self
            .conn
            .prepare("SELECT session_id FROM checkpoints WHERE updated_at <= datetime('now', ?1)")
        {
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
        match self.conn.execute(
            "DELETE FROM checkpoints WHERE updated_at <= datetime('now', ?1)",
            params![delta],
        ) {
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
            .save(
                "s1",
                "agent1",
                CheckpointState::AwaitingConfirmation,
                &payload,
            )
            .unwrap();
        let cp = store.load("s1").unwrap();
        assert_eq!(cp.state, CheckpointState::AwaitingConfirmation);
        assert_eq!(cp.payload["original_message"].as_str(), Some("帮我查数据"));

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
        assert_eq!(cp.payload["plan"]["steps"][0]["tool"].as_str(), Some("t"));
    }

    #[test]
    fn test_nonexistent() {
        let store = CheckpointStore::open_memory().unwrap();
        assert!(store.load("nope").is_none());
    }

    /// 战略罗盘「持久执行」核心实证：checkpoint 写入**文件**后，模拟进程崩溃/重启
    /// （drop 旧 store + 同路径 reopen），状态与 payload（计划 + 步骤结果）必须存活。
    /// 这是「可续跑持久化」成立的边界证据——`open_memory()` 测试无法覆盖此restart语义。
    #[test]
    fn test_file_durability_across_reopen() {
        let path = std::env::temp_dir()
            .join(format!("ckpt_dur_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // 「进程运行 1」：存一个进行中的多步计划 checkpoint
        {
            let store = CheckpointStore::open(path.to_str().unwrap()).unwrap();
            let payload = serde_json::json!({
                "plan": {"steps":[
                    {"step_id":1,"description":"查询","tool":"db_query","arguments":{},"depends_on":[]},
                    {"step_id":2,"description":"汇总","tool":"summarize","arguments":{},"depends_on":[1]}
                ]},
                "step_results": {"1": "ok"}
            });
            store
                .save("exec1", "agent1", CheckpointState::ExecutingPlan, &payload)
                .unwrap();
        }

        // 「进程重启」：drop 旧 store，重新打开同一文件
        let store2 = CheckpointStore::open(path.to_str().unwrap()).unwrap();
        let cp = store2.load("exec1").expect("checkpoint must survive reopen");
        assert_eq!(cp.state, CheckpointState::ExecutingPlan);
        assert_eq!(cp.payload["step_results"]["1"].as_str(), Some("ok"));
        assert_eq!(cp.payload["plan"]["steps"][0]["tool"].as_str(), Some("db_query"));
        assert_eq!(cp.payload["plan"]["steps"][1]["step_id"].as_u64(), Some(2));

        // 恢复决策谓词（与 agent.rs restore_checkpoint 一致）：非 New => 触发恢复计数 + 续跑
        assert!(
            cp.state != CheckpointState::New,
            "restored ExecutingPlan must trigger recovery path"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// 文档化 `restore_checkpoint` 的恢复计数判定（state != New 才计入恢复）：
    /// New / 不存在 => 不计入；非 New（如 PendingApproval）=> 计入。
    #[test]
    fn test_recovery_decision_predicate() {
        let store = CheckpointStore::open_memory().unwrap();
        store
            .save("x", "a", CheckpointState::New, &serde_json::json!({}))
            .unwrap();
        let new_cp = store.load("x").unwrap();
        assert_eq!(new_cp.state, CheckpointState::New);
        assert!(!(new_cp.state != CheckpointState::New)); // 不会计入恢复

        store
            .save("y", "a", CheckpointState::PendingApproval, &serde_json::json!({}))
            .unwrap();
        let pa = store.load("y").unwrap();
        assert!(pa.state != CheckpointState::New); // 会计入恢复

        assert!(store.load("zzz").is_none()); // 不存在 => 不计入恢复
    }

    /// P0-2/BizBuddy WriteDedup：claim / finalize / duplicate / release 全生命周期。
    /// 首次占坑放行 → in-flight 未超时跳过 → 成功登记摘要后二次调用命中返回摘要 →
    /// 失败释放后可重试；不同指纹互不影响。
    #[test]
    fn write_dedup_claim_finalize_duplicate_release() {
        let store = CheckpointStore::open_memory().unwrap();
        // 首次占坑 → 放行
        assert_eq!(
            store.claim_write_dedup("s1", "cw_write", "h1").unwrap(),
            WriteDedupClaim::Claimed
        );
        // 同指纹未登记摘要（in-flight 未超时）→ 跳过
        assert_eq!(
            store.claim_write_dedup("s1", "cw_write", "h1").unwrap(),
            WriteDedupClaim::InFlight
        );
        // 成功登记摘要 → 二次调用命中返回摘要
        store
            .finalize_write_dedup("s1", "cw_write", "h1", "白名单已更新：苏EZQ117")
            .unwrap();
        match store.claim_write_dedup("s1", "cw_write", "h1").unwrap() {
            WriteDedupClaim::Duplicate { summary } => assert!(summary.contains("苏EZQ117")),
            other => panic!("expect Duplicate, got {:?}", other),
        }
        // 不同指纹互不影响
        assert_eq!(
            store.claim_write_dedup("s1", "cw_write", "h2").unwrap(),
            WriteDedupClaim::Claimed
        );
        // 失败释放后可重试（保留修正重试能力）
        store.release_write_dedup("s1", "cw_write", "h2").unwrap();
        assert_eq!(
            store.claim_write_dedup("s1", "cw_write", "h2").unwrap(),
            WriteDedupClaim::Claimed
        );
    }

    /// P0-2/BizBuddy WriteDedup：摘要登记按字符边界截断到 500，绝不切 UTF-8 中间。
    #[test]
    fn write_dedup_summary_truncated_on_char_boundary() {
        let store = CheckpointStore::open_memory().unwrap();
        let long = "汉".repeat(600);
        store.claim_write_dedup("s", "edit_code", "h").unwrap();
        store.finalize_write_dedup("s", "edit_code", "h", &long).unwrap();
        match store.claim_write_dedup("s", "edit_code", "h").unwrap() {
            WriteDedupClaim::Duplicate { summary } => {
                assert_eq!(summary.chars().count(), 500);
                assert_eq!(summary, "汉".repeat(500));
            }
            other => panic!("expect Duplicate, got {:?}", other),
        }
    }

    /// P0-2/BizBuddy WriteDedup：in-flight 超过 600s 视为陈旧 → DELETE 后重新占坑；
    /// 重新占坑后 created_at 已刷新，回到未超时语义。
    #[test]
    fn write_dedup_stale_inflight_reclaimed() {
        let store = CheckpointStore::open_memory().unwrap();
        store.claim_write_dedup("s1", "local_fs_write", "h").unwrap();
        // 人为把 created_at 拨回 700s 前，模拟执行方崩溃残留的陈旧占坑
        store
            .conn
            .execute(
                "UPDATE write_dedup SET created_at = created_at - 700 WHERE session_id='s1'",
                params![],
            )
            .unwrap();
        assert_eq!(
            store.claim_write_dedup("s1", "local_fs_write", "h").unwrap(),
            WriteDedupClaim::Claimed
        );
        assert_eq!(
            store.claim_write_dedup("s1", "local_fs_write", "h").unwrap(),
            WriteDedupClaim::InFlight
        );
    }

    /// P0-2/BizBuddy WriteDedup：文件持久化跨 reopen 存活（仿 test_file_durability_across_reopen），
    /// 且与 checkpoints 同库共存；clear_session 只清目标会话，不波及其它会话。
    #[test]
    fn write_dedup_clear_session_and_survive_reopen() {
        let path = std::env::temp_dir().join(format!("wdedup_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let store = CheckpointStore::open(path.to_str().unwrap()).unwrap();
            // 同文件放一条 checkpoint，验证同库共存不互扰
            store
                .save("s1", "a", CheckpointState::Done, &serde_json::json!({}))
                .unwrap();
            store.claim_write_dedup("s1", "cw_write", "h1").unwrap();
            store
                .finalize_write_dedup("s1", "cw_write", "h1", "done")
                .unwrap();
            store.claim_write_dedup("s2", "cw_write", "h1").unwrap();
        }
        // reopen：占坑与摘要必须存活
        {
            let store = CheckpointStore::open(path.to_str().unwrap()).unwrap();
            assert!(store.load("s1").is_some());
            match store.claim_write_dedup("s1", "cw_write", "h1").unwrap() {
                WriteDedupClaim::Duplicate { summary } => assert_eq!(summary, "done"),
                other => panic!("expect Duplicate, got {:?}", other),
            }
            // s2 的 in-flight 占坑（摘要为空、未超时）也应存活
            assert_eq!(
                store.claim_write_dedup("s2", "cw_write", "h1").unwrap(),
                WriteDedupClaim::InFlight
            );
            // clear_session 只清目标会话
            store.clear_session("s1").unwrap();
            assert_eq!(
                store.claim_write_dedup("s1", "cw_write", "h1").unwrap(),
                WriteDedupClaim::Claimed
            );
            assert_eq!(
                store.claim_write_dedup("s2", "cw_write", "h1").unwrap(),
                WriteDedupClaim::InFlight
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// P0-2/BizBuddy（复核补测）：require_confirm 未产生写入 → release → 审批通过后
    /// 同指纹重 claim 应得 Claimed——「保留修正重试与审批后续执行能力」的语义回归。
    #[test]
    fn write_dedup_release_then_reclaim_after_require_confirm() {
        let store = CheckpointStore::open_memory().unwrap();
        // 首次发起：占坑放行
        assert_eq!(
            store.claim_write_dedup("s1", "cw_write", "h").unwrap(),
            WriteDedupClaim::Claimed
        );
        // 执行返回 require_confirm（未产生写入）→ 释放
        store.release_write_dedup("s1", "cw_write", "h").unwrap();
        // 审批通过后同参数重执行 → 重新占坑放行，而不是被旧坑锁死
        assert_eq!(
            store.claim_write_dedup("s1", "cw_write", "h").unwrap(),
            WriteDedupClaim::Claimed
        );
    }

    /// P0-2/BizBuddy（复核补测）：两 tokio task 并发同参占坑——经
    /// Arc<tokio::sync::Mutex<CheckpointStore>> 串行化（与生产 call_tool_routed 的
    /// `checkpoint_store.lock().await` 同一互斥模型），恰好一个 Claimed、一个 InFlight。
    #[tokio::test]
    async fn write_dedup_concurrent_claim_single_winner() {
        let store = std::sync::Arc::new(tokio::sync::Mutex::new(
            CheckpointStore::open_memory().unwrap(),
        ));
        let s1 = store.clone();
        let s2 = store.clone();
        let (r1, r2) = tokio::join!(
            async move { s1.lock().await.claim_write_dedup("s", "cw_write", "h").unwrap() },
            async move { s2.lock().await.claim_write_dedup("s", "cw_write", "h").unwrap() },
        );
        let single_winner = (matches!(r1, WriteDedupClaim::Claimed)
            && matches!(r2, WriteDedupClaim::InFlight))
            || (matches!(r1, WriteDedupClaim::InFlight)
                && matches!(r2, WriteDedupClaim::Claimed));
        assert!(
            single_winner,
            "expect exactly one Claimed + one InFlight, got {:?} / {:?}",
            r1, r2
        );
    }
}
