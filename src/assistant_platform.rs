//! Personal Assistant Platform store（Phase 0，2026-10-23）。
//!
//! 承载 BYO 本地智能体的控制面持久化：
//! - `assistant_bindings`：用户级助手绑定（user + assistant + device 的唯一实例）
//! - `assistant_tokens`：短期 opaque scoped token（只存 hash，不存明文）
//! - `a2a_tasks` / `a2a_task_events`：A2A 任务与状态事件
//! - `a2a_messages`：binding 收件箱
//! - `assistant_events`：平台侧事件（与 agent-core AuditLogger 双写）
//!
//! 设计边界：本模块只管平台身份/资源/协作记录，不采集、不控制本地智能体行为。

use std::path::Path;
use std::sync::Mutex;

use chrono::Local;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(crate) const ALLOWED_SCOPES: &[&str] = &[
    "assistant:heartbeat",
    "memory:read:self",
    "memory:write:self",
    "a2a:send",
    "a2a:receive",
    // P4（§9.3 Resource Gateway）：只读平台工具代理；写工具审批属 P4-2，暂无 scope
    "tools:call:read",
];

const DEFAULT_SCOPES: &[&str] = &[
    "assistant:heartbeat",
    "memory:read:self",
    "memory:write:self",
    "a2a:send",
    "a2a:receive",
];

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AssistantBinding {
    pub(crate) binding_id: String,
    pub(crate) user_id: String,
    pub(crate) assistant_type: String,
    pub(crate) assistant_name: String,
    pub(crate) device_id: String,
    pub(crate) capabilities: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) status: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) last_seen_at: Option<String>,
    pub(crate) revoked_at: Option<String>,
}

#[derive(Debug)]
pub(crate) struct NewBinding {
    pub(crate) user_id: String,
    pub(crate) assistant_type: String,
    pub(crate) assistant_name: String,
    pub(crate) device_id: String,
    pub(crate) capabilities: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) public_key: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct IssuedToken {
    pub(crate) token_id: String,
    pub(crate) binding_id: String,
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) expires_at: String,
}

/// P3（§8.3）：A2A artifact 元数据——大文件本体在本地受控目录，
/// 消息/任务里只传 artifact 引用（id/type/title/sha256），不 base64。
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Artifact {
    pub(crate) artifact_id: String,
    pub(crate) meeting_id: String,
    pub(crate) task_id: String,
    pub(crate) from_binding: String,
    pub(crate) to_binding: String,
    pub(crate) art_type: String,
    pub(crate) title: String,
    pub(crate) size_bytes: i64,
    pub(crate) sha256: String,
    pub(crate) trace_id: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone)]
pub(crate) struct TokenAuth {
    pub(crate) token_id: String,
    pub(crate) binding_id: String,
    pub(crate) user_id: String,
    pub(crate) assistant_type: String,
    pub(crate) device_id: String,
    pub(crate) scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct A2aTask {
    pub(crate) task_id: String,
    pub(crate) meeting_id: Option<String>,
    pub(crate) from_binding: String,
    pub(crate) from_user: String,
    pub(crate) to_binding: String,
    pub(crate) to_user: String,
    pub(crate) task_type: String,
    pub(crate) subject: String,
    pub(crate) body: String,
    pub(crate) status: String,
    pub(crate) result: Option<String>,
    pub(crate) trace_id: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct A2aMessage {
    pub(crate) message_id: String,
    pub(crate) meeting_id: Option<String>,
    pub(crate) from_binding: String,
    pub(crate) to_binding: String,
    pub(crate) task_id: Option<String>,
    pub(crate) message_type: String,
    pub(crate) body: String,
    pub(crate) created_at: String,
}

pub(crate) struct AssistantPlatformStore {
    conn: Mutex<Connection>,
    /// P3：artifact 落盘根目录（agent.toml 同目录下 artifacts/；None=测试模式不落盘）
    artifacts_dir: Option<std::path::PathBuf>,
}

fn now() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn expires(hours: i64) -> String {
    (Local::now() + chrono::Duration::hours(hours))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf[..]);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    let out = h.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// P3：字节内容 sha256（artifact 完整性）。
fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect::<String>()
        .trim()
        .to_string()
}

/// 员工 user_id 允许 Unicode 姓名型 ID（memoria 现网已有中文身份），
/// 但去掉空白与 `/`，保证可作为 `agent/<user_id>` 的单一 namespace 段。
fn sanitize_user_id(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect::<String>()
        .trim()
        .to_string()
}

fn sanitize_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

pub(crate) fn normalize_scopes(requested: &[String]) -> Vec<String> {
    let source = if requested.is_empty() {
        DEFAULT_SCOPES
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    } else {
        requested.to_vec()
    };
    let mut out = Vec::new();
    for s in source {
        let s = s.trim().to_string();
        if ALLOWED_SCOPES.contains(&s.as_str()) && !out.contains(&s) {
            out.push(s);
        }
    }
    if !out.contains(&"assistant:heartbeat".to_string()) {
        out.push("assistant:heartbeat".to_string());
    }
    out
}

impl AssistantPlatformStore {
    pub(crate) fn open(db_path: &Path) -> Result<Self, String> {
        let conn = Connection::open(db_path).map_err(|e| format!("open assistant db: {e}"))?;
        // P3：artifact 目录跟随 db 同目录（agent.toml 旁 artifacts/）；:memory: 测试库不落盘
        let artifacts_dir = if db_path.to_string_lossy().contains(":memory:") {
            None
        } else {
            let d = db_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("artifacts");
            std::fs::create_dir_all(&d).map_err(|e| format!("create artifacts dir: {e}"))?;
            Some(d)
        };
        Self::init(conn).map(|conn| Self {
            conn: Mutex::new(conn),
            artifacts_dir,
        })
    }

    fn init(conn: Connection) -> Result<Connection, String> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS assistant_bindings (
                binding_id     TEXT PRIMARY KEY,
                user_id        TEXT NOT NULL,
                assistant_type TEXT NOT NULL,
                assistant_name TEXT NOT NULL,
                device_id      TEXT NOT NULL,
                capabilities   TEXT NOT NULL DEFAULT '[]',
                scopes         TEXT NOT NULL DEFAULT '',
                public_key     TEXT NOT NULL DEFAULT '',
                status         TEXT NOT NULL DEFAULT 'active',
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL,
                last_seen_at   TEXT,
                revoked_at     TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_assistant_binding_instance
                ON assistant_bindings(user_id, assistant_type, device_id);
            CREATE INDEX IF NOT EXISTS idx_assistant_binding_user
                ON assistant_bindings(user_id, status);

            CREATE TABLE IF NOT EXISTS assistant_tokens (
                token_id     TEXT PRIMARY KEY,
                binding_id   TEXT NOT NULL,
                token_hash   TEXT NOT NULL UNIQUE,
                refresh_hash TEXT NOT NULL UNIQUE,
                scopes       TEXT NOT NULL,
                issued_at    TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                revoked_at   TEXT,
                FOREIGN KEY(binding_id) REFERENCES assistant_bindings(binding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_assistant_token_binding
                ON assistant_tokens(binding_id, revoked_at);

            CREATE TABLE IF NOT EXISTS a2a_tasks (
                task_id      TEXT PRIMARY KEY,
                meeting_id   TEXT,
                from_binding TEXT NOT NULL,
                from_user    TEXT NOT NULL,
                to_binding   TEXT NOT NULL,
                to_user      TEXT NOT NULL,
                task_type    TEXT NOT NULL,
                subject      TEXT NOT NULL,
                body         TEXT NOT NULL,
                status       TEXT NOT NULL,
                result       TEXT,
                trace_id     TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_a2a_task_to ON a2a_tasks(to_binding, status);
            CREATE INDEX IF NOT EXISTS idx_a2a_task_from ON a2a_tasks(from_binding, status);

            CREATE TABLE IF NOT EXISTS a2a_task_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id       TEXT NOT NULL,
                status        TEXT NOT NULL,
                actor_binding TEXT NOT NULL,
                detail        TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES a2a_tasks(task_id)
            );

            CREATE TABLE IF NOT EXISTS a2a_messages (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id    TEXT NOT NULL UNIQUE,
                meeting_id    TEXT,
                from_binding  TEXT NOT NULL,
                to_binding    TEXT NOT NULL,
                task_id       TEXT,
                message_type  TEXT NOT NULL,
                body          TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                read_at       TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_a2a_message_to ON a2a_messages(to_binding, read_at);

            CREATE TABLE IF NOT EXISTS assistant_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT NOT NULL,
                trace_id    TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                user_id     TEXT NOT NULL,
                binding_id  TEXT,
                detail      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assistant_event_binding
                ON assistant_events(binding_id, id);

            CREATE TABLE IF NOT EXISTS assistant_visibility (
                user_id    TEXT PRIMARY KEY,
                level      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS meeting_members (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                meeting_id   TEXT NOT NULL,
                binding_id   TEXT NOT NULL,
                user_id      TEXT NOT NULL,
                scopes       TEXT NOT NULL,
                invited_by   TEXT NOT NULL,
                granted_at   TEXT NOT NULL,
                revoked_at   TEXT,
                UNIQUE(meeting_id, binding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_meeting_member_binding
                ON meeting_members(binding_id, revoked_at);
            CREATE INDEX IF NOT EXISTS idx_meeting_member_meeting
                ON meeting_members(meeting_id, revoked_at);

            CREATE TABLE IF NOT EXISTS a2a_artifacts (
                artifact_id  TEXT PRIMARY KEY,
                meeting_id   TEXT,
                task_id      TEXT,
                from_binding TEXT NOT NULL,
                to_binding   TEXT NOT NULL,
                art_type     TEXT NOT NULL,
                title        TEXT NOT NULL,
                size_bytes   INTEGER NOT NULL,
                sha256       TEXT NOT NULL,
                trace_id     TEXT NOT NULL,
                created_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_artifact_task ON a2a_artifacts(task_id);
            CREATE INDEX IF NOT EXISTS idx_artifact_to ON a2a_artifacts(to_binding);
            ",
        )
        .map_err(|e| format!("assistant db migration: {e}"))?;
        Ok(conn)
    }

    fn binding_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AssistantBinding> {
        let capabilities_s: String = row.get(5)?;
        let scopes_s: String = row.get(6)?;
        let capabilities = serde_json::from_str::<Vec<String>>(&capabilities_s).unwrap_or_default();
        Ok(AssistantBinding {
            binding_id: row.get(0)?,
            user_id: row.get(1)?,
            assistant_type: row.get(2)?,
            assistant_name: row.get(3)?,
            device_id: row.get(4)?,
            capabilities,
            scopes: split_csv(&scopes_s),
            status: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
            last_seen_at: row.get(11)?,
            revoked_at: row.get(12)?,
        })
    }

    const BINDING_COLS: &'static str =
        "binding_id,user_id,assistant_type,assistant_name,device_id,\
        capabilities,scopes,public_key,status,created_at,updated_at,last_seen_at,revoked_at";

    pub(crate) fn create_binding(&self, req: NewBinding) -> Result<AssistantBinding, String> {
        let user_id = sanitize_user_id(&req.user_id);
        // 助手类型/能力允许 Unicode（用户常用中文如「数据分析」）：
        // sanitize_id 是 ASCII-only，会把中文清成空串导致 400/能力静默丢失
        let assistant_type = sanitize_user_id(&req.assistant_type).to_lowercase();
        let device_id = if req.device_id.trim().is_empty() {
            "default".to_string()
        } else {
            sanitize_id(&req.device_id)
        };
        let assistant_name = if req.assistant_name.trim().is_empty() {
            format!("{user_id}-{assistant_type}")
        } else {
            sanitize_text(&req.assistant_name, 80)
        };
        if user_id.is_empty() || assistant_type.is_empty() {
            return Err("user_id / assistant_type 非法".to_string());
        }

        let capabilities = req
            .capabilities
            .iter()
            .map(|x| sanitize_user_id(x).to_lowercase())
            .filter(|x| !x.is_empty())
            .take(20)
            .collect::<Vec<_>>();
        let scopes = normalize_scopes(&req.scopes);
        let binding_id = format!("pag_{}", random_hex(12));
        let ts = now();
        let capabilities_json = serde_json::to_string(&capabilities)
            .map_err(|e| format!("serialize capabilities: {e}"))?;

        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        conn.execute(
            "INSERT INTO assistant_bindings \
             (binding_id,user_id,assistant_type,assistant_name,device_id,capabilities,scopes,\
              public_key,status,created_at,updated_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'active',?9,?9)",
            params![
                binding_id,
                user_id,
                assistant_type,
                assistant_name,
                device_id,
                capabilities_json,
                scopes.join(","),
                sanitize_text(&req.public_key, 512),
                ts
            ],
        )
        .map_err(|e| format!("create binding: {e}"))?;
        match self.get_binding_inner(&conn, &binding_id) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err("binding 创建后读取失败".to_string()),
            Err(e) => Err(format!("binding 创建后读取失败: {e}")),
        }
    }

    fn get_binding_inner(
        &self,
        conn: &Connection,
        binding_id: &str,
    ) -> rusqlite::Result<Option<AssistantBinding>> {
        conn.query_row(
            &format!(
                "SELECT {} FROM assistant_bindings WHERE binding_id=?1",
                Self::BINDING_COLS
            ),
            params![binding_id],
            Self::binding_from_row,
        )
        .optional()
    }

    pub(crate) fn get_binding(&self, binding_id: &str) -> Result<Option<AssistantBinding>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        self.get_binding_inner(&conn, binding_id)
            .map_err(|e| format!("get binding: {e}"))
    }

    pub(crate) fn list_bindings(&self, user_id: &str) -> Result<Vec<AssistantBinding>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT binding_id,user_id,assistant_type,assistant_name,device_id,capabilities,\
                 scopes,public_key,status,created_at,updated_at,last_seen_at,revoked_at \
                 FROM assistant_bindings WHERE user_id=?1 ORDER BY created_at DESC LIMIT 200",
            )
            .map_err(|e| format!("list bindings: {e}"))?;
        let rows = stmt
            .query_map(params![user_id], Self::binding_from_row)
            .map_err(|e| format!("list bindings: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(v) = row {
                out.push(v);
            }
        }
        Ok(out)
    }

    pub(crate) fn revoke_binding(
        &self,
        binding_id: &str,
        actor_user: &str,
    ) -> Result<Option<AssistantBinding>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let existing = self
            .get_binding_inner(&conn, binding_id)
            .map_err(|e| format!("get binding: {e}"))?;
        let Some(mut binding) = existing else {
            return Ok(None);
        };
        if binding.user_id != actor_user && actor_user != "admin" {
            return Err("无权撤销他人 binding".to_string());
        }
        if binding.status == "revoked" {
            return Ok(Some(binding));
        }
        let ts = now();
        conn.execute(
            "UPDATE assistant_bindings SET status='revoked', revoked_at=?2, updated_at=?2 \
             WHERE binding_id=?1",
            params![binding_id, ts],
        )
        .map_err(|e| format!("revoke binding: {e}"))?;
        conn.execute(
            "UPDATE assistant_tokens SET revoked_at=?2 WHERE binding_id=?1 AND revoked_at IS NULL",
            params![binding_id, ts],
        )
        .map_err(|e| format!("revoke tokens: {e}"))?;
        binding.status = "revoked".to_string();
        binding.revoked_at = Some(ts.clone());
        binding.updated_at = ts;
        Ok(Some(binding))
    }

    pub(crate) fn issue_token(
        &self,
        binding_id: &str,
        hours: i64,
    ) -> Result<(IssuedToken, AssistantBinding), String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let binding = self
            .get_binding_inner(&conn, binding_id)
            .map_err(|e| format!("get binding: {e}"))?
            .ok_or_else(|| "binding 不存在".to_string())?;
        if binding.status != "active" {
            return Err(format!("binding 状态不可发 token: {}", binding.status));
        }

        let token_id = format!("tok_{}", random_hex(8));
        let access_secret = random_hex(32);
        let refresh_secret = random_hex(32);
        let access_token = format!("pat_{token_id}_{access_secret}");
        let refresh_token = format!("prt_{token_id}_{refresh_secret}");
        let expires_at = expires(hours);
        let issued_at = now();
        conn.execute(
            "INSERT INTO assistant_tokens \
             (token_id,binding_id,token_hash,refresh_hash,scopes,issued_at,expires_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                token_id,
                binding_id,
                sha256_hex(&access_token),
                sha256_hex(&refresh_token),
                binding.scopes.join(","),
                issued_at,
                expires_at
            ],
        )
        .map_err(|e| format!("issue token: {e}"))?;
        Ok((
            IssuedToken {
                token_id,
                binding_id: binding.binding_id.clone(),
                access_token,
                refresh_token,
                scopes: binding.scopes.clone(),
                expires_at,
            },
            binding,
        ))
    }

    pub(crate) fn validate_token(
        &self,
        token: &str,
        required_scope: &str,
    ) -> Result<TokenAuth, String> {
        let token = token.trim();
        if token.is_empty() {
            return Err("缺少 assistant token".to_string());
        }
        let (prefix, rest) = token.split_once('_').unwrap_or(("", ""));
        if prefix != "pat" {
            return Err("token 类型错误".to_string());
        }
        let (_id, _secret) = rest.split_once('_').ok_or("token 格式错误")?;
        let hash = sha256_hex(token);
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let row = conn
            .query_row(
                "SELECT t.token_id,t.scopes,t.expires_at,t.revoked_at,\
                 b.binding_id,b.user_id,b.assistant_type,b.device_id,b.status \
                 FROM assistant_tokens t JOIN assistant_bindings b ON b.binding_id=t.binding_id \
                 WHERE t.token_hash=?1",
                params![hash],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, String>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("validate token: {e}"))?
            .ok_or("assistant token 无效")?;
        let (
            token_id,
            scopes_s,
            expires_at,
            revoked_at,
            binding_id,
            user_id,
            assistant_type,
            device_id,
            status,
        ) = row;
        if revoked_at.is_some() {
            return Err("assistant token 已撤销".to_string());
        }
        if status != "active" {
            return Err(format!("binding 状态不可用: {status}"));
        }
        if expires_at <= now() {
            return Err("assistant token 已过期".to_string());
        }
        let scopes = split_csv(&scopes_s);
        if !scopes.iter().any(|s| s == required_scope) {
            return Err(format!("缺少 scope: {required_scope}"));
        }
        Ok(TokenAuth {
            token_id,
            binding_id,
            user_id,
            assistant_type,
            device_id,
            scopes,
        })
    }

    pub(crate) fn revoke_token(&self, token: &str) -> Result<(), String> {
        let hash = sha256_hex(token.trim());
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let n = conn
            .execute(
                "UPDATE assistant_tokens SET revoked_at=?2 WHERE token_hash=?1 AND revoked_at IS NULL",
                params![hash, now()],
            )
            .map_err(|e| format!("revoke token: {e}"))?;
        if n == 0 {
            return Err("token 不存在或已撤销".to_string());
        }
        Ok(())
    }

    pub(crate) fn heartbeat(&self, binding_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let n = conn
            .execute(
                "UPDATE assistant_bindings SET last_seen_at=?2, updated_at=?2 WHERE binding_id=?1",
                params![binding_id, now()],
            )
            .map_err(|e| format!("heartbeat: {e}"))?;
        if n == 0 {
            return Err("binding 不存在".to_string());
        }
        Ok(())
    }

    /// Phase 1：refresh token 轮换。prt_ 验证通过后签发全新 token 对并撤销旧行
    /// （refresh 一次性使用，旧 access 随旧行一并失效）。
    pub(crate) fn refresh_access(
        &self,
        refresh_token: &str,
        hours: i64,
    ) -> Result<(IssuedToken, AssistantBinding), String> {
        let token = refresh_token.trim();
        if !token.starts_with("prt_") {
            return Err("token 类型错误（需 prt_ refresh token）".to_string());
        }
        let hash = sha256_hex(token);
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let row = conn
            .query_row(
                "SELECT t.token_id,t.scopes,t.expires_at,t.revoked_at,b.binding_id,b.status \
                 FROM assistant_tokens t JOIN assistant_bindings b ON b.binding_id=t.binding_id \
                 WHERE t.refresh_hash=?1",
                params![hash],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("refresh lookup: {e}"))?
            .ok_or("refresh token 无效".to_string())?;
        let (old_token_id, scopes_s, expires_at, revoked_at, binding_id, status) = row;
        if revoked_at.is_some() {
            return Err("refresh token 已撤销（可能已轮换过）".to_string());
        }
        if status != "active" {
            return Err(format!("binding 状态不可用: {status}"));
        }
        if expires_at <= now() {
            return Err("refresh token 已过期".to_string());
        }
        let binding = self
            .get_binding_inner(&conn, &binding_id)
            .map_err(|e| format!("get binding: {e}"))?
            .ok_or("binding 不存在".to_string())?;

        // 新 token 对
        let token_id = format!("tok_{}", random_hex(8));
        let access_token = format!("pat_{token_id}_{}", random_hex(32));
        let new_refresh = format!("prt_{token_id}_{}", random_hex(32));
        let new_expires = expires(hours);
        conn.execute(
            "INSERT INTO assistant_tokens \
             (token_id,binding_id,token_hash,refresh_hash,scopes,issued_at,expires_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                token_id,
                binding_id,
                sha256_hex(&access_token),
                sha256_hex(&new_refresh),
                scopes_s,
                now(),
                new_expires
            ],
        )
        .map_err(|e| format!("issue token: {e}"))?;
        // 旧行撤销（旧 access + 旧 refresh 同时失效）
        conn.execute(
            "UPDATE assistant_tokens SET revoked_at=?2 WHERE token_id=?1 AND revoked_at IS NULL",
            params![old_token_id, now()],
        )
        .map_err(|e| format!("revoke old token: {e}"))?;
        Ok((
            IssuedToken {
                token_id,
                binding_id: binding.binding_id.clone(),
                access_token,
                refresh_token: new_refresh,
                scopes: split_csv(&scopes_s),
                expires_at: new_expires,
            },
            binding,
        ))
    }

    /// Phase 1：通讯录助手摘要可见性。缺省 dept（仅同部门可见能力摘要）。
    pub(crate) fn get_visibility(&self, user_id: &str) -> Result<String, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let level = conn
            .query_row(
                "SELECT level FROM assistant_visibility WHERE user_id=?1",
                params![user_id],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| format!("get visibility: {e}"))?;
        Ok(level.unwrap_or_else(|| "dept".to_string()))
    }

    pub(crate) fn set_visibility(&self, user_id: &str, level: &str) -> Result<String, String> {
        let level = level.trim();
        if !matches!(level, "off" | "dept" | "company") {
            return Err(format!("非法可见性级别: {level}（允许 off/dept/company）"));
        }
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        conn.execute(
            "INSERT INTO assistant_visibility(user_id,level,updated_at) VALUES (?1,?2,?3) \
             ON CONFLICT(user_id) DO UPDATE SET level=excluded.level, updated_at=excluded.updated_at",
            params![user_id, level, now()],
        )
        .map_err(|e| format!("set visibility: {e}"))?;
        Ok(level.to_string())
    }

    /// Phase 1：一次性取全部用户的可见性设置（目录端点避免逐用户查询）。
    pub(crate) fn visibility_map(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare("SELECT user_id,level FROM assistant_visibility")
            .map_err(|e| format!("visibility map: {e}"))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| format!("visibility map: {e}"))?;
        let mut out = std::collections::HashMap::new();
        for row in rows {
            if let Ok((k, v)) = row {
                out.insert(k, v);
            }
        }
        Ok(out)
    }

    /// Phase 1：全量 active binding 摘要（通讯录目录用；可见性过滤在 handler 侧
    /// 结合请求者部门做，存储层只给原始数据）。
    pub(crate) fn active_summaries(
        &self,
    ) -> Result<Vec<(String, String, String, Vec<String>, Option<String>)>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT user_id,assistant_type,assistant_name,capabilities,last_seen_at \
                 FROM assistant_bindings WHERE status='active' ORDER BY user_id, assistant_type",
            )
            .map_err(|e| format!("list summaries: {e}"))?;
        let rows = stmt
            .query_map([], |r| {
                let caps_s: String = r.get(3)?;
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    serde_json::from_str::<Vec<String>>(&caps_s).unwrap_or_default(),
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(|e| format!("list summaries: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(v) = row {
                out.push(v);
            }
        }
        Ok(out)
    }

    // ── Phase 2 P2-1：会议成员（assistant binding 入会 + 临时 scope） ──

    /// 会议 scope 常量：授予入会助手的临时权限集（方案 §7.2）。
    pub(crate) fn meeting_scopes() -> Vec<String> {
        vec![
            "meeting:read".to_string(),
            "meeting:write".to_string(),
            "a2a:send:meeting".to_string(),
            "a2a:receive:meeting".to_string(),
        ]
    }

    /// 邀请 binding 入会（幂等：已在会且未撤销 → 更新 scopes；已撤销 → 重新授予）。
    /// 调用方须先完成：邀请人会议权限判定 + binding active 校验（handler 层）。
    pub(crate) fn meeting_invite(
        &self,
        meeting_id: &str,
        binding: &AssistantBinding,
        invited_by: &str,
    ) -> Result<(), String> {
        let scopes = Self::meeting_scopes().join(",");
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        conn.execute(
            "INSERT INTO meeting_members(meeting_id,binding_id,user_id,scopes,invited_by,granted_at) \
             VALUES (?1,?2,?3,?4,?5,?6) \
             ON CONFLICT(meeting_id,binding_id) DO UPDATE SET \
             scopes=excluded.scopes, invited_by=excluded.invited_by, \
             granted_at=excluded.granted_at, revoked_at=NULL",
            params![
                meeting_id,
                binding.binding_id,
                binding.user_id,
                scopes,
                invited_by,
                now()
            ],
        )
        .map_err(|e| format!("meeting invite: {e}"))?;
        Ok(())
    }

    /// 移除助手出会（撤销临时 scope；重复移除幂等）。
    pub(crate) fn meeting_remove(&self, meeting_id: &str, binding_id: &str) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let n = conn
            .execute(
                "UPDATE meeting_members SET revoked_at=?3 \
                 WHERE meeting_id=?1 AND binding_id=?2 AND revoked_at IS NULL",
                params![meeting_id, binding_id, now()],
            )
            .map_err(|e| format!("meeting remove: {e}"))?;
        Ok(n > 0)
    }

    /// 会议结束：批量撤销该会全部成员（幂等，可重复调用）。
    pub(crate) fn meeting_expire(&self, meeting_id: &str) -> Result<usize, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let n = conn
            .execute(
                "UPDATE meeting_members SET revoked_at=?2 \
                 WHERE meeting_id=?1 AND revoked_at IS NULL",
                params![meeting_id, now()],
            )
            .map_err(|e| format!("meeting expire: {e}"))?;
        Ok(n)
    }

    /// 某 binding 是否为该会有效成员（未撤销）。
    pub(crate) fn meeting_is_member(&self, meeting_id: &str, binding_id: &str) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let found = conn
            .query_row(
                "SELECT COUNT(*) FROM meeting_members \
                 WHERE meeting_id=?1 AND binding_id=?2 AND revoked_at IS NULL",
                params![meeting_id, binding_id],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| format!("meeting member check: {e}"))?;
        Ok(found > 0)
    }

    /// 会议有效成员列表（binding_id + user_id + 邀请人 + 授予时间）。
    pub(crate) fn meeting_members(
        &self,
        meeting_id: &str,
    ) -> Result<Vec<(String, String, String, String)>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT binding_id,user_id,invited_by,granted_at FROM meeting_members \
                 WHERE meeting_id=?1 AND revoked_at IS NULL ORDER BY granted_at",
            )
            .map_err(|e| format!("meeting members: {e}"))?;
        let rows = stmt
            .query_map(params![meeting_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| format!("meeting members: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(v) = row {
                out.push(v);
            }
        }
        Ok(out)
    }

    // ── Phase 3：artifact 存储（方案 §8.3，D8 拍板=本地受控目录 + 元数据/hash） ──

    /// P3 上限：单 artifact 50MB（大文件走 NAS 属 D8 后续演进，不进消息不进 memoria）。
    pub(crate) const ARTIFACT_MAX_BYTES: usize = 50 * 1024 * 1024;

    pub(crate) fn save_artifact(
        &self,
        from_binding: &str,
        to_binding: &str,
        meeting_id: Option<&str>,
        task_id: Option<&str>,
        art_type: &str,
        title: &str,
        data: &[u8],
    ) -> Result<(String, String, usize), String> {
        if data.is_empty() {
            return Err("artifact 内容为空".to_string());
        }
        if data.len() > Self::ARTIFACT_MAX_BYTES {
            return Err(format!("artifact 超限：{} bytes（上限 50MB）", data.len()));
        }
        let artifact_id = format!("art_{}", random_hex(12));
        let sha = sha256_hex_bytes(data);
        // 落盘（测试模式 artifacts_dir=None 跳过）
        if let Some(dir) = &self.artifacts_dir {
            let path = dir.join(&artifact_id);
            std::fs::write(&path, data).map_err(|e| format!("write artifact: {e}"))?;
        }
        let trace_id = format!("apf_{}", random_hex(10));
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        conn.execute(
            "INSERT INTO a2a_artifacts \
             (artifact_id,meeting_id,task_id,from_binding,to_binding,art_type,title,size_bytes,sha256,trace_id,created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                artifact_id,
                meeting_id,
                task_id,
                from_binding,
                to_binding,
                sanitize_id(art_type),
                sanitize_text(title, 200),
                data.len() as i64,
                sha,
                trace_id,
                now()
            ],
        )
        .map_err(|e| format!("save artifact: {e}"))?;
        Ok((artifact_id, sha, data.len()))
    }

    pub(crate) fn get_artifact(&self, artifact_id: &str) -> Result<Option<Artifact>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        conn.query_row(
            "SELECT artifact_id,ifnull(meeting_id,''),ifnull(task_id,''),from_binding,to_binding,\
             art_type,title,size_bytes,sha256,trace_id,created_at \
             FROM a2a_artifacts WHERE artifact_id=?1",
            params![artifact_id],
            |r| {
                Ok(Artifact {
                    artifact_id: r.get(0)?,
                    meeting_id: r.get(1)?,
                    task_id: r.get(2)?,
                    from_binding: r.get(3)?,
                    to_binding: r.get(4)?,
                    art_type: r.get(5)?,
                    title: r.get(6)?,
                    size_bytes: r.get(7)?,
                    sha256: r.get(8)?,
                    trace_id: r.get(9)?,
                    created_at: r.get(10)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("get artifact: {e}"))
    }

    /// artifact 内容读取（落盘模式从磁盘读并复核 sha256；测试模式返回空）。
    pub(crate) fn read_artifact_content(
        &self,
        artifact_id: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let Some(art) = self.get_artifact(artifact_id)? else {
            return Ok(None);
        };
        let Some(dir) = &self.artifacts_dir else {
            return Ok(Some(Vec::new()));
        };
        let path = dir.join(artifact_id);
        let data = std::fs::read(&path).map_err(|e| format!("read artifact: {e}"))?;
        if sha256_hex_bytes(&data) != art.sha256 {
            return Err(format!("artifact 完整性校验失败：{artifact_id}"));
        }
        Ok(Some(data))
    }

    /// 某任务的 artifact 列表（任务双方可见；handler 侧做权限判定）。
    pub(crate) fn artifacts_for_task(
        &self,
        task_id: &str,
    ) -> Result<Vec<Artifact>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT artifact_id,ifnull(meeting_id,''),ifnull(task_id,''),from_binding,to_binding,\
                 art_type,title,size_bytes,sha256,trace_id,created_at \
                 FROM a2a_artifacts WHERE task_id=?1 ORDER BY created_at",
            )
            .map_err(|e| format!("list artifacts: {e}"))?;
        let rows = stmt
            .query_map(params![task_id], Self::artifact_from_row)
            .map_err(|e| format!("list artifacts: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(v) = row {
                out.push(v);
            }
        }
        Ok(out)
    }

    fn artifact_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Artifact> {
        Ok(Artifact {
            artifact_id: r.get(0)?,
            meeting_id: r.get(1)?,
            task_id: r.get(2)?,
            from_binding: r.get(3)?,
            to_binding: r.get(4)?,
            art_type: r.get(5)?,
            title: r.get(6)?,
            size_bytes: r.get(7)?,
            sha256: r.get(8)?,
            trace_id: r.get(9)?,
            created_at: r.get(10)?,
        })
    }

    pub(crate) fn record_event(
        &self,
        event_type: &str,
        user_id: &str,
        binding_id: Option<&str>,
        detail: &str,
    ) -> Result<String, String> {
        let trace_id = format!("apf_{}", random_hex(10));
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        conn.execute(
            "INSERT INTO assistant_events(ts,trace_id,event_type,user_id,binding_id,detail) \
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![now(), trace_id, event_type, user_id, binding_id, detail],
        )
        .map_err(|e| format!("record event: {e}"))?;
        Ok(trace_id)
    }

    pub(crate) fn recent_events_for_user(
        &self,
        user_id: &str,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT ts,trace_id,event_type,user_id,ifnull(binding_id,''),detail \
                 FROM assistant_events WHERE user_id=?1 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(|e| format!("recent events: {e}"))?;
        let rows = stmt
            .query_map(params![user_id, limit as i64], |r| {
                Ok(serde_json::json!({
                    "ts": r.get::<_, String>(0)?,
                    "trace_id": r.get::<_, String>(1)?,
                    "event_type": r.get::<_, String>(2)?,
                    "user_id": r.get::<_, String>(3)?,
                    "binding_id": r.get::<_, String>(4)?,
                    "detail": r.get::<_, String>(5)?,
                }))
            })
            .map_err(|e| format!("recent events: {e}"))?;
        Ok(rows.filter_map(|x| x.ok()).collect())
    }

    fn task_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<A2aTask> {
        Ok(A2aTask {
            task_id: row.get(0)?,
            meeting_id: row.get(1)?,
            from_binding: row.get(2)?,
            from_user: row.get(3)?,
            to_binding: row.get(4)?,
            to_user: row.get(5)?,
            task_type: row.get(6)?,
            subject: row.get(7)?,
            body: row.get(8)?,
            status: row.get(9)?,
            result: row.get(10)?,
            trace_id: row.get(11)?,
            created_at: row.get(12)?,
            updated_at: row.get(13)?,
        })
    }

    pub(crate) fn create_task(
        &self,
        auth: &TokenAuth,
        target_binding: &str,
        meeting_id: Option<String>,
        task_type: &str,
        subject: &str,
        body: &str,
    ) -> Result<A2aTask, String> {
        let target = self
            .get_binding(target_binding)?
            .ok_or("目标 binding 不存在")?;
        if target.status != "active" {
            return Err("目标 binding 不可用".to_string());
        }
        if target.binding_id == auth.binding_id {
            return Err("不能向自己创建 A2A task".to_string());
        }
        let task_id = format!("task_{}", random_hex(10));
        let task_type_out = if sanitize_id(task_type).is_empty() {
            "generic".to_string()
        } else {
            sanitize_id(task_type)
        };
        let trace_id = self.record_event(
            "a2a.task.created",
            &auth.user_id,
            Some(&auth.binding_id),
            &format!("task={task_id} target={target_binding}"),
        )?;
        // 目标用户事件流同样可见“收到任务”，便于 Phase 1 通讯录/会议视图复用。
        self.record_event(
            "a2a.task.delivered",
            &target.user_id,
            Some(&target.binding_id),
            &format!("task={task_id} from={}", auth.binding_id),
        )?;
        let ts = now();
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        conn.execute(
            "INSERT INTO a2a_tasks \
             (task_id,meeting_id,from_binding,from_user,to_binding,to_user,task_type,subject,body,\
              status,result,trace_id,created_at,updated_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'queued',NULL,?10,?11,?11)",
            params![
                task_id,
                meeting_id,
                auth.binding_id,
                auth.user_id,
                target.binding_id,
                target.user_id,
                task_type_out,
                sanitize_text(subject, 160),
                sanitize_text(body, 8000),
                trace_id,
                ts.clone()
            ],
        )
        .map_err(|e| format!("create task: {e}"))?;
        conn.execute(
            "INSERT INTO a2a_task_events(task_id,status,actor_binding,detail,created_at) \
             VALUES (?1,'created',?2,?3,?4)",
            params![task_id, auth.binding_id, "A2A task created", ts],
        )
        .map_err(|e| format!("create task event: {e}"))?;
        match self.get_task_inner(&conn, &task_id) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err("task 创建后读取失败".to_string()),
            Err(e) => Err(format!("task 创建后读取失败: {e}")),
        }
    }

    fn get_task_inner(
        &self,
        conn: &Connection,
        task_id: &str,
    ) -> rusqlite::Result<Option<A2aTask>> {
        conn.query_row(
            "SELECT task_id,meeting_id,from_binding,from_user,to_binding,to_user,task_type,\
             subject,body,status,result,trace_id,created_at,updated_at \
             FROM a2a_tasks WHERE task_id=?1",
            params![task_id],
            Self::task_from_row,
        )
        .optional()
    }

    pub(crate) fn get_task(&self, task_id: &str) -> Result<Option<A2aTask>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        self.get_task_inner(&conn, task_id)
            .map_err(|e| format!("get task: {e}"))
    }

    pub(crate) fn update_task(
        &self,
        task_id: &str,
        actor_binding: &str,
        status: &str,
        result: Option<String>,
    ) -> Result<A2aTask, String> {
        let allowed = [
            "working",
            "input-required",
            "completed",
            "failed",
            "canceled",
        ];
        if !allowed.contains(&status) {
            return Err(format!("非法 task 状态: {status}"));
        }
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let task = self
            .get_task_inner(&conn, task_id)
            .map_err(|e| format!("get task: {e}"))?
            .ok_or("task 不存在")?;
        if task.from_binding != actor_binding && task.to_binding != actor_binding {
            return Err("无权更新该 task".to_string());
        }
        if ["completed", "failed", "canceled"].contains(&task.status.as_str()) {
            return Err(format!("task 已终态: {}", task.status));
        }
        let ts = now();
        conn.execute(
            "UPDATE a2a_tasks SET status=?2, result=COALESCE(?3,result), updated_at=?4 \
             WHERE task_id=?1",
            params![task_id, status, result, ts.clone()],
        )
        .map_err(|e| format!("update task: {e}"))?;
        conn.execute(
            "INSERT INTO a2a_task_events(task_id,status,actor_binding,detail,created_at) \
             VALUES (?1,?2,?3,?4,?5)",
            params![
                task_id,
                status,
                actor_binding,
                result.clone().unwrap_or_default(),
                ts
            ],
        )
        .map_err(|e| format!("update task event: {e}"))?;
        self.get_task_inner(&conn, task_id)
            .map_err(|e| format!("get task: {e}"))?
            .ok_or("task 更新后读取失败".to_string())
    }

    pub(crate) fn create_message(
        &self,
        auth: &TokenAuth,
        target_binding: &str,
        meeting_id: Option<String>,
        task_id: Option<String>,
        message_type: &str,
        body: &str,
    ) -> Result<A2aMessage, String> {
        let target = self
            .get_binding(target_binding)?
            .ok_or("目标 binding 不存在")?;
        if target.status != "active" {
            return Err("目标 binding 不可用".to_string());
        }
        if target.binding_id == auth.binding_id {
            return Err("不能给自己发 A2A message".to_string());
        }
        let message_id = format!("msg_{}", random_hex(10));
        let ts = now();
        let meeting_id_out = meeting_id.clone();
        let task_id_out = task_id.clone();
        let message_type_out = if sanitize_id(message_type).is_empty() {
            "text".to_string()
        } else {
            sanitize_id(message_type)
        };
        let body_out = sanitize_text(body, 8000);
        {
            let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
            conn.execute(
                "INSERT INTO a2a_messages \
                 (message_id,meeting_id,from_binding,to_binding,task_id,message_type,body,created_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    message_id,
                    meeting_id,
                    auth.binding_id,
                    target.binding_id,
                    task_id,
                    message_type_out,
                    body_out,
                    ts
                ],
            )
            .map_err(|e| format!("create message: {e}"))?;
        }
        self.record_event(
            "a2a.message.sent",
            &auth.user_id,
            Some(&auth.binding_id),
            &format!("message={message_id} target={target_binding}"),
        )?;
        // 收件方事件单独落一条：recent_events_for_user 按用户隔离后，
        // 目标用户仍能在自己的平台事件流里看到“收到了消息/任务”。
        self.record_event(
            "a2a.message.delivered",
            &target.user_id,
            Some(&target.binding_id),
            &format!("message={message_id} from={}", auth.binding_id),
        )?;
        Ok(A2aMessage {
            message_id,
            meeting_id: meeting_id_out,
            from_binding: auth.binding_id.clone(),
            to_binding: target.binding_id,
            task_id: task_id_out,
            message_type: message_type_out,
            body: body_out,
            created_at: ts,
        })
    }

    pub(crate) fn list_inbox(&self, binding_id: &str) -> Result<Vec<serde_json::Value>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT message_id,ifnull(meeting_id,''),from_binding,to_binding,ifnull(task_id,''),\
                 message_type,body,created_at,ifnull(read_at,'') \
                 FROM a2a_messages WHERE to_binding=?1 ORDER BY id DESC LIMIT 200",
            )
            .map_err(|e| format!("list inbox: {e}"))?;
        let rows = stmt
            .query_map(params![binding_id], |r| {
                Ok(serde_json::json!({
                    "message_id": r.get::<_, String>(0)?,
                    "meeting_id": r.get::<_, String>(1)?,
                    "from_binding": r.get::<_, String>(2)?,
                    "to_binding": r.get::<_, String>(3)?,
                    "task_id": r.get::<_, String>(4)?,
                    "message_type": r.get::<_, String>(5)?,
                    "body": r.get::<_, String>(6)?,
                    "created_at": r.get::<_, String>(7)?,
                    "read_at": r.get::<_, String>(8)?,
                }))
            })
            .map_err(|e| format!("list inbox: {e}"))?;
        Ok(rows.filter_map(|x| x.ok()).collect())
    }

    /// P2-3：inbox 增量查询——取 to_binding 的自 since_id（行 id，不含）之后的
    /// 新消息（按 id 升序，封顶 100），供 SSE/长轮询推送用。
    pub(crate) fn inbox_since(
        &self,
        binding_id: &str,
        since_id: i64,
    ) -> Result<Vec<(i64, serde_json::Value)>, String> {
        let conn = self.conn.lock().map_err(|e| format!("db lock: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT id,message_id,ifnull(meeting_id,''),from_binding,ifnull(task_id,''),\
                 message_type,body,created_at \
                 FROM a2a_messages WHERE to_binding=?1 AND id>?2 ORDER BY id ASC LIMIT 100",
            )
            .map_err(|e| format!("inbox since: {e}"))?;
        let rows = stmt
            .query_map(params![binding_id, since_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    serde_json::json!({
                        "message_id": r.get::<_, String>(1)?,
                        "meeting_id": r.get::<_, String>(2)?,
                        "from_binding": r.get::<_, String>(3)?,
                        "task_id": r.get::<_, String>(4)?,
                        "message_type": r.get::<_, String>(5)?,
                        "body": r.get::<_, String>(6)?,
                        "created_at": r.get::<_, String>(7)?,
                    }),
                ))
            })
            .map_err(|e| format!("inbox since: {e}"))?;
        Ok(rows.filter_map(|x| x.ok()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> AssistantPlatformStore {
        AssistantPlatformStore::open(Path::new(":memory:")).expect("open test store")
    }

    #[test]
    fn binding_token_scope_and_revoke() {
        let s = store();
        let b = s
            .create_binding(NewBinding {
                user_id: "zhangsan".into(),
                assistant_type: "workbuddy".into(),
                assistant_name: "张三助手".into(),
                device_id: "dev001".into(),
                capabilities: vec!["office.generate".into()],
                scopes: vec!["memory:write:self".into()],
                public_key: String::new(),
            })
            .expect("binding");
        assert!(b.scopes.contains(&"memory:write:self".to_string()));
        assert!(b.scopes.contains(&"assistant:heartbeat".to_string()));
        let (tok, _) = s.issue_token(&b.binding_id, 1).expect("token");
        let auth = s
            .validate_token(&tok.access_token, "memory:write:self")
            .expect("auth");
        assert_eq!(auth.user_id, "zhangsan");
        s.revoke_token(&tok.access_token).expect("revoke");
        assert!(s
            .validate_token(&tok.access_token, "memory:write:self")
            .is_err());
    }

    #[test]
    fn task_persistence_and_transition() {
        let s = store();
        let a = s
            .create_binding(NewBinding {
                user_id: "a".into(),
                assistant_type: "one".into(),
                assistant_name: String::new(),
                device_id: "d1".into(),
                capabilities: vec![],
                scopes: vec![],
                public_key: String::new(),
            })
            .unwrap();
        let b = s
            .create_binding(NewBinding {
                user_id: "b".into(),
                assistant_type: "two".into(),
                assistant_name: String::new(),
                device_id: "d2".into(),
                capabilities: vec![],
                scopes: vec![],
                public_key: String::new(),
            })
            .unwrap();
        let (ta, _) = s.issue_token(&a.binding_id, 1).unwrap();
        let auth = s.validate_token(&ta.access_token, "a2a:send").unwrap();
        let task = s
            .create_task(&auth, &b.binding_id, None, "analysis", "测试", "hello")
            .unwrap();
        let task2 = s
            .update_task(
                &task.task_id,
                &b.binding_id,
                "completed",
                Some("done".to_string()),
            )
            .unwrap();
        assert_eq!(task2.status, "completed");
        assert!(s
            .update_task(&task.task_id, &b.binding_id, "failed", None)
            .is_err());
        let events_a = s.recent_events_for_user("a", 100).unwrap();
        let events_b = s.recent_events_for_user("b", 100).unwrap();
        assert!(!events_a.is_empty());
        assert!(!events_b.is_empty());
        assert!(events_a
            .iter()
            .all(|e| e.get("user_id").and_then(|v| v.as_str()) == Some("a")));
    }

    #[test]
    fn unicode_user_id_kept_as_single_namespace_segment() {
        let s = store();
        let b = s
            .create_binding(NewBinding {
                user_id: "徐佳琰".into(),
                assistant_type: "workbuddy".into(),
                assistant_name: String::new(),
                device_id: "dev".into(),
                capabilities: vec![],
                scopes: vec![],
                public_key: String::new(),
            })
            .unwrap();
        assert_eq!(b.user_id, "徐佳琰");
        assert!(b.scopes.contains(&"assistant:heartbeat".to_string()));
        assert!(b.scopes.contains(&"memory:write:self".to_string()));
    }

    #[test]
    fn refresh_rotation_is_single_use() {
        let s = store();
        let b = s
            .create_binding(NewBinding {
                user_id: "r".into(),
                assistant_type: "workbuddy".into(),
                assistant_name: String::new(),
                device_id: "dev".into(),
                capabilities: vec![],
                scopes: vec![],
                public_key: String::new(),
            })
            .unwrap();
        let (t1, _) = s.issue_token(&b.binding_id, 1).unwrap();
        // 旧 access 有效
        assert!(s.validate_token(&t1.access_token, "assistant:heartbeat").is_ok());
        // 轮换：新对可用，旧 access + 旧 refresh 全部失效
        let (t2, _) = s.refresh_access(&t1.refresh_token, 1).unwrap();
        assert!(s.validate_token(&t2.access_token, "assistant:heartbeat").is_ok());
        assert!(s.validate_token(&t1.access_token, "assistant:heartbeat").is_err());
        // 旧 refresh 重放被拒（一次性）
        assert!(s.refresh_access(&t1.refresh_token, 1).is_err());
        // 新 refresh 可再轮换
        assert!(s.refresh_access(&t2.refresh_token, 1).is_ok());
        // 非 prt 前缀被拒
        assert!(s.refresh_access(&t2.access_token, 1).is_err());
    }

    #[test]
    fn visibility_default_dept_and_whitelist() {
        let s = store();
        assert_eq!(s.get_visibility("nobody").unwrap(), "dept");
        assert_eq!(s.set_visibility("u1", "company").unwrap(), "company");
        assert_eq!(s.get_visibility("u1").unwrap(), "company");
        assert!(s.set_visibility("u1", "everyone").is_err());
        let map = s.visibility_map().unwrap();
        assert_eq!(map.get("u1").map(|s| s.as_str()), Some("company"));
    }

    #[test]
    fn chinese_type_and_capabilities_survive() {
        let s = store();
        let b = s
            .create_binding(NewBinding {
                user_id: "徐佳琰".into(),
                assistant_type: "智浦助手".into(),
                assistant_name: String::new(),
                device_id: String::new(),
                capabilities: vec!["数据分析".into(), "PPT".into(), "!!".into()],
                scopes: vec![],
                public_key: String::new(),
            })
            .unwrap();
        assert_eq!(b.assistant_type, "智浦助手");
        assert!(b.capabilities.contains(&"数据分析".to_string()));
        assert!(b.capabilities.contains(&"ppt".to_string()));
        assert!(!b.capabilities.iter().any(|c| c.is_empty()));
        // 空名默认 = user_id-type（中文身份下可读）
        assert_eq!(b.assistant_name, "徐佳琰-智浦助手");
    }

    #[test]
    fn meeting_member_lifecycle() {
        let s = store();
        let mk = |u: &str| {
            s.create_binding(NewBinding {
                user_id: u.into(),
                assistant_type: "wb".into(),
                assistant_name: String::new(),
                device_id: "d".into(),
                capabilities: vec![],
                scopes: vec![],
                public_key: String::new(),
            })
            .unwrap()
        };
        let a = mk("a");
        let b = mk("b");
        // 邀请 a 入会；未邀请 b
        s.meeting_invite("meet_x", &a, "host").unwrap();
        assert!(s.meeting_is_member("meet_x", &a.binding_id).unwrap());
        assert!(!s.meeting_is_member("meet_x", &b.binding_id).unwrap());
        assert_eq!(s.meeting_members("meet_x").unwrap().len(), 1);
        // 幂等重邀
        s.meeting_invite("meet_x", &a, "host").unwrap();
        assert_eq!(s.meeting_members("meet_x").unwrap().len(), 1);
        // 移除后不可见；重复移除返回 false
        assert!(s.meeting_remove("meet_x", &a.binding_id).unwrap());
        assert!(!s.meeting_is_member("meet_x", &a.binding_id).unwrap());
        assert!(!s.meeting_remove("meet_x", &a.binding_id).unwrap());
        // 撤销后重邀 → 恢复成员（revoked_at 清空）
        s.meeting_invite("meet_x", &a, "host").unwrap();
        assert!(s.meeting_is_member("meet_x", &a.binding_id).unwrap());
        // 会议结束批量失效（a + 新邀 b 一并撤销；幂等二次返回 0）
        s.meeting_invite("meet_x", &b, "host").unwrap();
        assert_eq!(s.meeting_expire("meet_x").unwrap(), 2);
        assert_eq!(s.meeting_expire("meet_x").unwrap(), 0);
        assert!(!s.meeting_is_member("meet_x", &a.binding_id).unwrap());
        assert!(!s.meeting_is_member("meet_x", &b.binding_id).unwrap());
    }

    #[test]
    fn artifact_save_get_and_integrity() {
        // :memory: 测试模式：artifacts_dir=None 不落盘，只验 DB 元数据链路
        let s = store();
        let (id, sha, size) = s
            .save_artifact("b1", "b2", Some("m1"), Some("t1"), "pptx", "十月分析", b"hello artifact")
            .unwrap();
        assert!(id.starts_with("art_"));
        assert_eq!(size, 14);
        assert_eq!(sha.len(), 64);
        let art = s.get_artifact(&id).unwrap().unwrap();
        assert_eq!(art.from_binding, "b1");
        assert_eq!(art.to_binding, "b2");
        assert_eq!(art.task_id, "t1");
        assert_eq!(art.art_type, "pptx");
        assert_eq!(art.title, "十月分析");
        assert_eq!(art.sha256, sha);
        // 空/超限拒绝
        assert!(s.save_artifact("b1", "b2", None, None, "bin", "x", b"").is_err());
        let big = vec![0u8; AssistantPlatformStore::ARTIFACT_MAX_BYTES + 1];
        assert!(s.save_artifact("b1", "b2", None, None, "bin", "x", &big).is_err());
        // 列表
        let list = s.artifacts_for_task("t1").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].artifact_id, id);
        assert!(s.artifacts_for_task("t-none").unwrap().is_empty());
        // 测试模式内容读取返回空 Some（落盘校验由部署冒烟覆盖）
        assert!(s.read_artifact_content(&id).unwrap().is_some());
        assert!(s.get_artifact("art_none").unwrap().is_none());
    }
}
