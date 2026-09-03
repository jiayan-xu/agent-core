//! 审批权威存储（TASK-652 / ADR-015）— 与 checkpoints 同库异表。
//!
//! P1：SQLite 为主写路径；JSON 双写由 ApprovalManager 负责。
//! 表 `approvals` 挂在 `checkpoints.db`，不另开文件。

use rusqlite::{params, Connection};

/// 权威表状态（比内存 PendingApproval.status 多 Consumed）
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ApprovalRecordStatus {
    Pending,
    Approved,
    Denied,
    Consumed,
    /// 分级审批：LLM judge 自动批准（已执行，不可再决策；区别于人工 Approved）
    AutoApproved,
}

impl ApprovalRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Approved => "Approved",
            Self::Denied => "Denied",
            Self::Consumed => "Consumed",
            Self::AutoApproved => "AutoApproved",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "Approved" => Self::Approved,
            "Denied" => Self::Denied,
            "Consumed" => Self::Consumed,
            "AutoApproved" => Self::AutoApproved,
            _ => Self::Pending,
        }
    }
}

/// 一行审批权威记录
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub arguments_json: String,
    pub description: String,
    pub operation_hash: String,
    pub approver_id: String,
    pub requester_id: String,
    pub status: ApprovalRecordStatus,
    pub created_at: f64,
    pub decided_at: Option<f64>,
    pub consumed_at: Option<f64>,
    pub decision_reason: Option<String>,
    pub response_json: Option<String>,
}

/// 审批 SQLite 存储（与 CheckpointStore 共用 db 路径）
pub struct ApprovalStore {
    conn: Connection,
}

impl ApprovalStore {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("open approval db: {}", e))?;
        let mut store = ApprovalStore { conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| format!("open memory: {}", e))?;
        let mut store = ApprovalStore { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS approvals (
                    approval_id     TEXT PRIMARY KEY,
                    session_id      TEXT NOT NULL DEFAULT 'legacy',
                    agent_id        TEXT NOT NULL DEFAULT '',
                    tool_name       TEXT NOT NULL,
                    arguments_json  TEXT NOT NULL DEFAULT '{}',
                    description     TEXT NOT NULL DEFAULT '',
                    operation_hash  TEXT NOT NULL DEFAULT '',
                    approver_id     TEXT NOT NULL DEFAULT '',
                    requester_id    TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL,
                    created_at      REAL NOT NULL,
                    decided_at      REAL,
                    consumed_at     REAL,
                    decision_reason TEXT,
                    response_json   TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
                CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);",
            )
            .map_err(|e| format!("init approvals schema: {}", e))?;
        // 2026-09-03 分级审批：自动批准记录携带 judge 理由 / 改前状态 / 撤销链。
        // ALTER ADD COLUMN 幂等：已存在则忽略错误。
        // ocr R7：区分「已存在列」（预期，忽略）和真实迁移失败（传播）
        for col in ["risk_reason TEXT", "before_state_json TEXT", "judge_meta TEXT", "undone_by TEXT"] {
            if let Err(e) = self.conn.execute(&format!("ALTER TABLE approvals ADD COLUMN {}", col), []) {
                let msg = e.to_string();
                if !msg.contains("duplicate column name") {
                    return Err(format!("approvals migration failed ({}): {}", col, msg));
                }
            }
        }
        Ok(())
    }

    pub fn upsert(&self, rec: &ApprovalRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO approvals (
                    approval_id, session_id, agent_id, tool_name, arguments_json,
                    description, operation_hash, approver_id, requester_id, status,
                    created_at, decided_at, consumed_at, decision_reason, response_json
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
                 ON CONFLICT(approval_id) DO UPDATE SET
                    session_id=excluded.session_id,
                    agent_id=excluded.agent_id,
                    tool_name=excluded.tool_name,
                    arguments_json=excluded.arguments_json,
                    description=excluded.description,
                    operation_hash=excluded.operation_hash,
                    approver_id=excluded.approver_id,
                    requester_id=excluded.requester_id,
                    status=excluded.status,
                    created_at=excluded.created_at,
                    decided_at=excluded.decided_at,
                    consumed_at=excluded.consumed_at,
                    decision_reason=excluded.decision_reason,
                    response_json=excluded.response_json",
                params![
                    rec.approval_id,
                    rec.session_id,
                    rec.agent_id,
                    rec.tool_name,
                    rec.arguments_json,
                    rec.description,
                    rec.operation_hash,
                    rec.approver_id,
                    rec.requester_id,
                    rec.status.as_str(),
                    rec.created_at,
                    rec.decided_at,
                    rec.consumed_at,
                    rec.decision_reason,
                    rec.response_json,
                ],
            )
            .map_err(|e| format!("upsert approval: {}", e))?;
        Ok(())
    }

    pub fn get(&self, approval_id: &str) -> Option<ApprovalRecord> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT approval_id, session_id, agent_id, tool_name, arguments_json,
                        description, operation_hash, approver_id, requester_id, status,
                        created_at, decided_at, consumed_at, decision_reason, response_json
                 FROM approvals WHERE approval_id=?1",
            )
            .ok()?;
        let mut rows = stmt.query(params![approval_id]).ok()?;
        let row = rows.next().ok().flatten()?;
        Some(Self::row_to_record(row).ok()?)
    }

    fn row_to_record(row: &rusqlite::Row<'_>) -> Result<ApprovalRecord, rusqlite::Error> {
        Ok(ApprovalRecord {
            approval_id: row.get(0)?,
            session_id: row.get(1)?,
            agent_id: row.get(2)?,
            tool_name: row.get(3)?,
            arguments_json: row.get(4)?,
            description: row.get(5)?,
            operation_hash: row.get(6)?,
            approver_id: row.get(7)?,
            requester_id: row.get(8)?,
            status: ApprovalRecordStatus::from_str(&row.get::<_, String>(9)?),
            created_at: row.get(10)?,
            decided_at: row.get(11)?,
            consumed_at: row.get(12)?,
            decision_reason: row.get(13)?,
            response_json: row.get(14)?,
        })
    }

    /// 加载可进内存缓存的活跃项（非 Consumed）
    pub fn list_active(&self) -> Vec<ApprovalRecord> {
        let mut out = Vec::new();
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT approval_id, session_id, agent_id, tool_name, arguments_json,
                    description, operation_hash, approver_id, requester_id, status,
                    created_at, decided_at, consumed_at, decision_reason, response_json
             FROM approvals WHERE status NOT IN ('Consumed', 'AutoApproved')",
        ) else {
            return out;
        };
        let Ok(mut rows) = stmt.query([]) else {
            return out;
        };
        while let Ok(Some(row)) = rows.next() {
            if let Ok(rec) = Self::row_to_record(row) {
                out.push(rec);
            }
        }
        out
    }

    /// 审批历史（含已消费/已拒绝），按创建时间倒序，供审批台审计留证查看
    // ── 分级审批（2026-09-03）：AutoApproved 记录与撤销链 ──

    /// 写入自动批准记录（status=AutoApproved，创建即批准）
    pub fn insert_auto_approval(
        &self,
        approval_id: &str,
        session_id: &str,
        agent_id: &str,
        tool_name: &str,
        arguments_json: &str,
        risk_reason: &str,
        judge_meta: &str,
        before_state_json: Option<&str>,
    ) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO approvals (
                    approval_id, session_id, agent_id, tool_name, arguments_json,
                    description, operation_hash, approver_id, requester_id, status,
                    created_at, decided_at, consumed_at, decision_reason, response_json,
                    risk_reason, before_state_json, judge_meta, undone_by
                ) VALUES (?, ?, ?, ?, ?, '', '', ?, ?, 'AutoApproved', ?, ?, NULL, ?, NULL, ?, ?, ?, NULL)",
                params![
                    approval_id,
                    session_id,
                    agent_id,
                    tool_name,
                    arguments_json,
                    agent_id,
                    agent_id,
                    now,
                    now,
                    format!("llm-judge: {}", risk_reason),
                    risk_reason,
                    before_state_json.unwrap_or(""),
                    judge_meta,
                ],
            )
            .map(|_| ())
            .map_err(|e| format!("insert_auto_approval: {}", e))
    }

    /// 回填执行结果（AutoApproved 的 response_json）
    pub fn set_auto_response(&self, approval_id: &str, response: &str) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE approvals SET response_json = ? WHERE approval_id = ?",
                params![response, approval_id],
            )
            .map(|_| ())
            .map_err(|e| format!("set_auto_response: {}", e))
    }

    /// 标记已被撤销（记录撤销单 id，防重复撤销）
    pub fn mark_undone(&self, approval_id: &str, undo_approval_id: &str) -> Result<(), String> {
        let n = self
            .conn
            .execute(
                "UPDATE approvals SET undone_by = ? WHERE approval_id = ? AND undone_by IS NULL",
                params![undo_approval_id, approval_id],
            )
            .map_err(|e| format!("mark_undone: {}", e))?;
        if n == 0 {
            return Err("already-undone-or-missing".to_string());
        }
        Ok(())
    }

    /// 近期自动批准列表（倒序）
    pub fn list_auto_approvals(&self, limit: usize) -> Vec<serde_json::Value> {
        let mut stmt = match self.conn.prepare(
            "SELECT approval_id, agent_id, tool_name, arguments_json, status, created_at,
                    risk_reason, before_state_json, judge_meta, response_json, undone_by
             FROM approvals WHERE status = 'AutoApproved' ORDER BY created_at DESC LIMIT ?",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(serde_json::json!({
                "approval_id": r.get::<_, String>(0).unwrap_or_default(),
                "agent_id": r.get::<_, String>(1).unwrap_or_default(),
                "tool_name": r.get::<_, String>(2).unwrap_or_default(),
                "arguments": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(3).unwrap_or_default()).unwrap_or(serde_json::Value::Null),
                "created_at": r.get::<_, f64>(5).unwrap_or(0.0),
                "risk_reason": r.get::<_, String>(6).unwrap_or_default(),
                "before_state": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(7).unwrap_or_default()).unwrap_or(serde_json::Value::Null),
                "judge_meta": r.get::<_, String>(8).unwrap_or_default(),
                "response": r.get::<_, Option<String>>(9).unwrap_or(None),
                "undone_by": r.get::<_, Option<String>>(10).unwrap_or(None),
            }))
        });
        match rows {
            Ok(it) => it.filter_map(|x| x.ok()).collect(),
            Err(_) => vec![],
        }
    }

    /// 取单条自动批准（撤销端点用）
    pub fn get_auto_approval(&self, approval_id: &str) -> Option<serde_json::Value> {
        let mut stmt = self.conn.prepare(
            "SELECT approval_id, agent_id, tool_name, arguments_json, before_state_json, undone_by
             FROM approvals WHERE approval_id = ? AND status = 'AutoApproved'",
        )
        .ok()?;
        stmt.query_row(params![approval_id], |r| {
            Ok(serde_json::json!({
                "approval_id": r.get::<_, String>(0).unwrap_or_default(),
                "agent_id": r.get::<_, String>(1).unwrap_or_default(),
                "tool_name": r.get::<_, String>(2).unwrap_or_default(),
                "arguments": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(3).unwrap_or_default()).unwrap_or(serde_json::Value::Null),
                "before_state": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(4).unwrap_or_default()).unwrap_or(serde_json::Value::Null),
                "undone_by": r.get::<_, Option<String>>(5).unwrap_or(None),
            }))
        })
        .ok()
    }

    /// 每人当日 AutoApproved 计数（quota）
    pub fn count_auto_today(&self, agent_id: &str) -> u32 {
        let day_start = {
            use chrono::TimeZone;
            let today = chrono::Utc::now().date_naive();
            chrono::Utc
                .from_utc_datetime(&today.and_hms_opt(0, 0, 0).unwrap())
                .timestamp() as f64
        };
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE status = 'AutoApproved' AND agent_id = ? AND created_at >= ?",
                params![agent_id, day_start],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c as u32)
            .unwrap_or(u32::MAX) // fail-closed：查不到→配额视为已满，不自动批准（ocr R7）
    }

    pub fn list_history(&self, limit: usize) -> Vec<ApprovalRecord> {
        let mut out = Vec::new();
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT approval_id, session_id, agent_id, tool_name, arguments_json,
                    description, operation_hash, approver_id, requester_id, status,
                    created_at, decided_at, consumed_at, decision_reason, response_json
             FROM approvals ORDER BY created_at DESC LIMIT ?",
        ) else {
            return out;
        };
        let Ok(mut rows) = stmt.query(params![limit as i64]) else {
            return out;
        };
        while let Ok(Some(row)) = rows.next() {
            if let Ok(rec) = Self::row_to_record(row) {
                out.push(rec);
            }
        }
        out
    }

    pub fn mark_consumed(&self, approval_id: &str, consumed_at: f64) -> Result<(), String> {        self.conn
            .execute(
                "UPDATE approvals SET status='Consumed', consumed_at=?2 WHERE approval_id=?1",
                params![approval_id, consumed_at],
            )
            .map_err(|e| format!("mark consumed: {}", e))?;
        Ok(())
    }

    pub fn count_by_status(&self, status: ApprovalRecordStatus) -> usize {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE status=?1",
                params![status.as_str()],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as usize)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_get_consume() {
        let store = ApprovalStore::open_memory().unwrap();
        let rec = ApprovalRecord {
            approval_id: "apr_1".into(),
            session_id: "s1".into(),
            agent_id: "a1".into(),
            tool_name: "sync_whitelist_plates".into(),
            arguments_json: r#"{"action":"add"}"#.into(),
            description: "test".into(),
            operation_hash: "abc".into(),
            approver_id: "dashboard-admin".into(),
            requester_id: "a1".into(),
            status: ApprovalRecordStatus::Pending,
            created_at: 1.0,
            decided_at: None,
            consumed_at: None,
            decision_reason: None,
            response_json: None,
        };
        store.upsert(&rec).unwrap();
        let got = store.get("apr_1").unwrap();
        assert_eq!(got.session_id, "s1");
        assert_eq!(got.status, ApprovalRecordStatus::Pending);
        assert_eq!(store.list_active().len(), 1);

        store.mark_consumed("apr_1", 2.0).unwrap();
        assert_eq!(store.get("apr_1").unwrap().status, ApprovalRecordStatus::Consumed);
        assert!(store.list_active().is_empty());
        assert_eq!(store.count_by_status(ApprovalRecordStatus::Consumed), 1);
    }

    #[test]
    fn same_path_as_checkpoint_table_coexists() {
        let path = std::env::temp_dir().join(format!(
            "ckpt_appr_coexist_{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let p = path.to_string_lossy().to_string();
        let cp = crate::checkpoint::CheckpointStore::open(&p).unwrap();
        cp.save(
            "s1",
            "a1",
            crate::checkpoint::CheckpointState::PendingApproval,
            &serde_json::json!({"approval_id": "apr_x"}),
        )
        .unwrap();
        let ap = ApprovalStore::open(&p).unwrap();
        ap.upsert(&ApprovalRecord {
            approval_id: "apr_x".into(),
            session_id: "s1".into(),
            agent_id: "a1".into(),
            tool_name: "edit_code".into(),
            arguments_json: "{}".into(),
            description: "d".into(),
            operation_hash: "h".into(),
            approver_id: "admin".into(),
            requester_id: "a1".into(),
            status: ApprovalRecordStatus::Pending,
            created_at: 1.0,
            decided_at: None,
            consumed_at: None,
            decision_reason: None,
            response_json: None,
        })
        .unwrap();
        assert!(cp.load("s1").is_some());
        assert!(ap.get("apr_x").is_some());
        let _ = std::fs::remove_file(&path);
    }
}
