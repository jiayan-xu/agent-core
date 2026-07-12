//! HarnessStore — 技能蒸馏引擎
//!
//! 从执行日志中提取成功模式，生成可复用的 Harness 模板。
//! 翻译自 agent-base/core/harness_store.py

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

/// 单条 Harness 记录（数据库行对应的 Rust 结构）
#[derive(Debug, Clone)]
pub struct Harness {
    pub id: i64,
    pub name: String,
    pub trigger_conditions: serde_json::Value,
    pub steps: serde_json::Value,
    pub verify_rule: String,
    pub confidence: f64,
    pub usage_count: i64,
    pub success_count: i64,
    pub consecutive_success: i64,
    pub is_active: bool,
}

/// HarnessStore — 管理模板的 CRUD、模糊匹配与日志提炼
pub struct HarnessStore {
    conn: Connection,
    db_path: String,
}

impl HarnessStore {
    /// 创建或打开存储
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("open db: {}", e))?;
        let db_path = path.to_string();
        let mut store = HarnessStore { conn, db_path };
        store.init_schema()?;
        Ok(store)
    }

    /// 返回数据库路径
    pub fn db_path(&self) -> String {
        self.db_path.clone()
    }

    /// 内存模式（用于测试）
    pub fn open_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| format!("open memory: {}", e))?;
        let mut store = HarnessStore { conn, db_path: String::new() };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS harnesses (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT NOT NULL,
                    trigger_conditions TEXT NOT NULL,
                    steps           TEXT NOT NULL,
                    verify_rule     TEXT DEFAULT '',
                    confidence      REAL DEFAULT 0.5,
                    usage_count     INTEGER DEFAULT 0,
                    success_count   INTEGER DEFAULT 0,
                    consecutive_success INTEGER DEFAULT 0,
                    last_used       REAL DEFAULT 0,
                    created_at      REAL DEFAULT 0,
                    updated_at      REAL DEFAULT 0,
                    is_active       INTEGER DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS chat_history (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id      TEXT NOT NULL,
                    namespace       TEXT NOT NULL DEFAULT 'default',
                    role            TEXT NOT NULL,
                    content         TEXT NOT NULL,
                    created_at      TEXT DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_history(session_id, namespace);",
            )
            .map_err(|e| format!("init schema: {}", e))?;
        Ok(())
    }

    // ── CRUD ───────────────────────────────────────

    /// 保存新 Harness 或更新已有记录
    pub fn save(
        &mut self,
        name: &str,
        trigger_conditions: &serde_json::Value,
        steps: &serde_json::Value,
        verify_rule: &str,
        harness_id: Option<i64>,
    ) -> Result<i64, String> {
        let now = now_secs();
        let conditions_str = serde_json::to_string(trigger_conditions)
            .map_err(|e| format!("serialize conditions: {}", e))?;
        let steps_str =
            serde_json::to_string(steps).map_err(|e| format!("serialize steps: {}", e))?;

        if let Some(id) = harness_id {
            self.conn
                .execute(
                    "UPDATE harnesses SET name=?1, trigger_conditions=?2, steps=?3,
                     verify_rule=?4, updated_at=?5 WHERE id=?6",
                    params![name, conditions_str, steps_str, verify_rule, now, id],
                )
                .map_err(|e| format!("update: {}", e))?;
            Ok(id)
        } else {
            self.conn
                .execute(
                    "INSERT INTO harnesses (name, trigger_conditions, steps, verify_rule,
                     confidence, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, 0.5, ?5, ?5)",
                    params![name, conditions_str, steps_str, verify_rule, now],
                )
                .map_err(|e| format!("insert: {}", e))?;
            Ok(self.conn.last_insert_rowid())
        }
    }

    /// 按 id 获取
    pub fn get(&self, harness_id: i64) -> Option<Harness> {
        self.conn
            .query_row(
                "SELECT * FROM harnesses WHERE id = ?1",
                params![harness_id],
                map_row,
            )
            .ok()
    }

    /// 列出所有激活的 Harness，按 confidence 降序
    pub fn list_all(&self, active_only: bool) -> Result<Vec<Harness>, String> {
        let sql = if active_only {
            "SELECT * FROM harnesses WHERE is_active = 1 ORDER BY confidence DESC"
        } else {
            "SELECT * FROM harnesses ORDER BY confidence DESC"
        };
        let mut stmt = self.conn.prepare(sql).map_err(|e| format!("prepare: {}", e))?;
        let rows = stmt
            .query_map([], map_row)
            .map_err(|e| format!("query: {}", e))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// 软删除
    pub fn deactivate(&mut self, harness_id: i64) -> bool {
        self.conn
            .execute("UPDATE harnesses SET is_active = 0 WHERE id = ?1", params![harness_id])
            .ok()
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// 激活（P2-3：危险/待审批模板经人工 / admin 批准后激活）
    pub fn activate(&mut self, harness_id: i64) -> bool {
        self.conn
            .execute("UPDATE harnesses SET is_active = 1 WHERE id = ?1", params![harness_id])
            .ok()
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    // ── 匹配算法 ───────────────────────────────────

    /// 根据 task_context 在所有激活的 Harness 中做模糊匹配
    pub fn match_harness(
        &self,
        task_context: &serde_json::Value,
        top_k: usize,
    ) -> Result<Vec<ScoredHarness>, String> {
        let context_obj = task_context.as_object().ok_or("context must be object")?;

        let mut stmt = self
            .conn
            .prepare(
                "SELECT * FROM harnesses
                 WHERE is_active = 1 AND confidence > 0.15
                 ORDER BY confidence * usage_count DESC",
            )
            .map_err(|e| format!("prepare: {}", e))?;

        let rows: Vec<Harness> = stmt
            .query_map([], map_row)
            .map_err(|e| format!("query: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        let mut scored: Vec<ScoredHarness> = rows
            .into_iter()
            .filter_map(|h| {
                let conditions = h.trigger_conditions.as_object()?;
                let match_score = compute_match_score(conditions, context_obj);
                if match_score <= 0.0 {
                    return None;
                }
                let weight = match_score * h.confidence * (h.usage_count as f64 + 1.0);
                Some(ScoredHarness {
                    harness: h,
                    match_score,
                    weight,
                })
            })
            .collect();

        scored.sort_by(|a, b| b.weight.partial_cmp(&a.weight).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);
        Ok(scored)
    }

    // ── 反馈与置信度演化 ──────────────────────────

    /// 记录一次执行结果，更新置信度
    pub fn record_usage(&mut self, harness_id: i64, success: bool) -> Result<UsageResult, String> {
        let h = self.get(harness_id).ok_or("harness not found")?;
        let now = now_secs();

        let mut new_confidence = h.confidence;
        let mut new_consecutive = h.consecutive_success;

        if success {
            new_confidence += 0.05;
            new_consecutive += 1;
            if new_consecutive >= 5 && new_consecutive % 5 == 0 {
                new_confidence += 0.1;
            }
        } else {
            new_confidence -= 0.15;
            new_consecutive = 0;
        }

        new_confidence = new_confidence.clamp(0.0, 1.0);
        let new_usage = h.usage_count + 1;
        let new_success = h.success_count + if success { 1 } else { 0 };

        self.conn
            .execute(
                "UPDATE harnesses SET confidence=?1, usage_count=?2, success_count=?3,
                 consecutive_success=?4, last_used=?5, updated_at=?5 WHERE id=?6",
                params![new_confidence, new_usage, new_success, new_consecutive, now, harness_id],
            )
            .map_err(|e| format!("update usage: {}", e))?;

        Ok(UsageResult {
            id: harness_id,
            confidence: new_confidence,
            usage_count: new_usage,
            success_count: new_success,
            consecutive_success: new_consecutive,
        })
    }

    // ── 日志提炼 ─────────────────────────────────────

    /// 从执行日志中提取模式生成 Harness
    /// P1-6 修复：使用 canonical JSON 序列化做去重，避免 key 顺序导致重复
    pub fn distill_from_logs(
        &mut self,
        logs: &[ExecutionLog],
        min_similar: usize,
    ) -> Result<Vec<i64>, String> {
        // 按 trigger_conditions 的 canonical JSON 摘要分组
        let mut groups: HashMap<String, Vec<&ExecutionLog>> = HashMap::new();
        for log in logs {
            if !log.success {
                continue;
            }
            // P1-6: canonical 序列化（key 排序后序列化）
            let key = canonical_json_string(&log.trigger_conditions);
            groups.entry(key).or_default().push(log);
        }

        let mut new_ids = Vec::new();

        for (key, group) in &groups {
            if group.len() < min_similar {
                continue;
            }

            // 用出现次数最多的 name
            let best_name = most_common(group.iter().map(|g| g.name.as_str()));

            let conditions: serde_json::Value =
                serde_json::from_str(key).unwrap_or(serde_json::Value::Null);

            // 合并所有 steps（去重）
            let mut seen_steps = std::collections::HashSet::new();
            let mut merged_steps: Vec<serde_json::Value> = Vec::new();
            for log in group {
                if let Some(arr) = log.steps.as_array() {
                    for step in arr {
                        // P1-6: canonical 序列化做去重
                        let step_str = canonical_json_string(step);
                        if seen_steps.insert(step_str) {
                            merged_steps.push(step.clone());
                        }
                    }
                }
            }

            // 用最常见的 verify_rule
            let best_rule = most_common(group.iter().map(|g| g.verify_rule.as_str()));

            // 检查是否已存在相同 conditions 的 harness（P1-6: 用 canonical key）
            let exists = self
                .conn
                .query_row(
                    "SELECT id FROM harnesses WHERE trigger_conditions = ?1 AND is_active = 1",
                    params![key],
                    |_| Ok(()),
                )
                .is_ok();
            if exists {
                continue;
            }

            let steps_val = serde_json::Value::Array(merged_steps.clone());
            let id = self.save(&best_name, &conditions, &steps_val, &best_rule, None)?;
            new_ids.push(id);

            // P2-3：危险模板永不自动激活 —— 含危险工具的蒸馏模板置为待审批（is_active=0），
            // 必须经人工 / admin 显式 activate 后方可参与匹配。
            let has_dangerous = merged_steps.iter().any(|step| {
                step.get("tool")
                    .and_then(|t| t.as_str())
                    .map(|t| crate::boundary::is_dangerous_tool(t))
                    .unwrap_or(false)
            });
            if has_dangerous {
                self.deactivate(id);
                tracing::warn!(
                    "蒸馏出的 Harness(id={}) 含危险工具，已置为待审批（不自动激活）",
                    id
                );
            }
        }

        Ok(new_ids)
    }
}

// ── 辅助类型 ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScoredHarness {
    pub harness: Harness,
    pub match_score: f64,
    pub weight: f64,
}

#[derive(Debug, Clone)]
pub struct UsageResult {
    pub id: i64,
    pub confidence: f64,
    pub usage_count: i64,
    pub success_count: i64,
    pub consecutive_success: i64,
}

#[derive(Debug, Clone)]
pub struct ExecutionLog {
    pub name: String,
    pub trigger_conditions: serde_json::Value,
    pub steps: serde_json::Value,
    pub verify_rule: String,
    pub success: bool,
}

// ── 内部函数 ──────────────────────────────────────

fn map_row(row: &rusqlite::Row) -> rusqlite::Result<Harness> {
    Ok(Harness {
        id: row.get(0)?,
        name: row.get(1)?,
        trigger_conditions: serde_json::from_str(&row.get::<_, String>(2)?)
            .unwrap_or(serde_json::Value::Null),
        steps: serde_json::from_str(&row.get::<_, String>(3)?)
            .unwrap_or(serde_json::Value::Null),
        verify_rule: row.get(4)?,
        confidence: row.get(5)?,
        usage_count: row.get(6)?,
        success_count: row.get(7)?,
        consecutive_success: row.get(8)?,
        is_active: row.get::<_, i32>(12)? != 0,
    })
}

pub fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// P2-4: 统一暴露 now_secs 供其他模块使用
pub use now_secs as current_timestamp;

/// 计算 trigger_conditions 与 context 的模糊匹配分数
#[allow(unused_assignments, unused_variables)]
    fn compute_match_score(
    conditions: &serde_json::Map<String, serde_json::Value>,
    context: &serde_json::Map<String, serde_json::Value>,
) -> f64 {
    if conditions.is_empty() {
        return 0.0;
    }

    let mut total = 0.0;
    let mut matched_keys = 0;

    for (key, cond_val) in conditions {
        let ctx_val = match context.get(key) {
            Some(v) => v,
            None => continue,
        };
        matched_keys += 1;

        let score = match (cond_val, ctx_val) {
            (serde_json::Value::String(c), serde_json::Value::String(t)) => {
                if c == t {
                    1.0
                } else if t.to_lowercase().contains(&c.to_lowercase()) {
                    0.7
                } else {
                    0.2
                }
            }
            _ => {
                if cond_val == ctx_val {
                    1.0
                } else {
                    0.2
                }
            }
        };
        total += score;
    }

    // 条件数归一化
    let normalized = if !conditions.is_empty() {
        total / conditions.len() as f64
    } else {
        0.0
    };

    // Bonus：context 比 conditions 更丰富说明匹配更精准
    let extra = (context.len() - conditions.len()).min(3) as f64;
    let bonus = (extra * 0.1).min(0.3);

    (normalized + bonus).min(1.0)
}

/// 从迭代器中找出出现次数最多的值
fn most_common<'a>(items: impl Iterator<Item = &'a str>) -> String {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(name, _)| name.to_string())
        .unwrap_or_default()
}

/// P1-6 修复：canonical JSON 序列化（key 排序后序列化）
/// 确保 {"a":1,"b":2} 和 {"b":2,"a":1} 生成相同的字符串
fn canonical_json_string(val: &serde_json::Value) -> String {
    canonicalize(val)
}

fn canonicalize(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts: Vec<String> = Vec::new();
            for k in keys {
                let v = &map[k];
                parts.push(format!("{:?}:{}", k, canonicalize(v)));
            }
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonicalize).collect();
            format!("[{}]", parts.join(","))
        }
        serde_json::Value::String(s) => format!("{:?}", s),
        other => other.to_string(),
    }
}

// ══════════════════════════════════════════════════════
// 测试
// ══════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> HarnessStore {
        HarnessStore::open_memory().unwrap()
    }

    #[test]
    fn test_save_and_get() {
        let mut store = test_store();
        let conditions = serde_json::json!({"tool": "query_plate"});
        let steps = serde_json::json!([{"tool": "query_plate", "args": {"plate": "test"}}]);

        let id = store.save("test_harness", &conditions, &steps, "", None).unwrap();
        assert!(id > 0);

        let h = store.get(id).unwrap();
        assert_eq!(h.name, "test_harness");
        assert_eq!(h.confidence, 0.5);
        assert!(h.is_active);
    }

    #[test]
    fn test_list_all() {
        let mut store = test_store();
        let c = serde_json::json!({"k": "v"});
        let s = serde_json::json!([]);

        store.save("a", &c, &s, "", None).unwrap();
        store.save("b", &c, &s, "", None).unwrap();

        let list = store.list_all(true).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_deactivate() {
        let mut store = test_store();
        let id = store
            .save("test", &serde_json::json!({}), &serde_json::json!([]), "", None)
            .unwrap();
        assert!(store.deactivate(id));
        assert!(!store.get(id).unwrap().is_active);
    }

    #[test]
    fn test_match_score_exact() {
        let conditions = serde_json::json!({"tool": "query_plate", "user": "admin"});
        let context = serde_json::json!({"tool": "query_plate", "user": "admin", "extra": "yes"});

        let c_obj = conditions.as_object().unwrap();
        let ctx_obj = context.as_object().unwrap();
        let score = compute_match_score(c_obj, ctx_obj);
        assert!(
            score > 0.9,
            "exact match should score high: {}",
            score
        );
    }

    #[test]
    fn test_match_score_partial() {
        let conditions = serde_json::json!({"tool": "query_plate"});
        let context = serde_json::json!({"tool": "query_plate for vehicle"});

        let score = compute_match_score(
            conditions.as_object().unwrap(),
            context.as_object().unwrap(),
        );
        assert!(
            score >= 0.7,
            "substring match should score >= 0.7: {}",
            score
        );
    }

    #[test]
    fn test_match_score_no_match() {
        let conditions = serde_json::json!({"tool": "query_plate"});
        let context = serde_json::json!({"tool": "send_email"});

        let score = compute_match_score(
            conditions.as_object().unwrap(),
            context.as_object().unwrap(),
        );
        assert!(score < 0.5, "mismatch should score low: {}", score);
    }

    #[test]
    fn test_harness_match_end_to_end() {
        let mut store = test_store();

        // 插入几个测试模板
        let c1 = serde_json::json!({"tool": "query_plate"});
        let s1 = serde_json::json!([{"tool": "query_plate", "args": {"plate": "auto"}}]);
        store.save("plate_query", &c1, &s1, "", None).unwrap();

        let c2 = serde_json::json!({"tool": "send_email"});
        let s2 = serde_json::json!([{"tool": "send_email", "args": {"to": "admin"}}]);
        store.save("send_email", &c2, &s2, "", None).unwrap();

        // 模拟车牌查询场景
        let context = serde_json::json!({"tool": "query_plate", "user": "admin"});
        let matches = store.match_harness(&context, 3).unwrap();

        assert!(!matches.is_empty(), "should find matches");
        assert_eq!(
            matches[0].harness.name, "plate_query",
            "plate_query should rank first"
        );
    }

    #[test]
    fn test_record_usage_success() {
        let mut store = test_store();
        let id = store
            .save("test", &serde_json::json!({}), &serde_json::json!([]), "", None)
            .unwrap();

        let r = store.record_usage(id, true).unwrap();
        assert!((r.confidence - 0.55).abs() < 0.001);
        assert_eq!(r.usage_count, 1);
        assert_eq!(r.success_count, 1);
    }

    #[test]
    fn test_record_usage_failure() {
        let mut store = test_store();
        let id = store
            .save("test", &serde_json::json!({}), &serde_json::json!([]), "", None)
            .unwrap();

        let r = store.record_usage(id, false).unwrap();
        assert!((r.confidence - 0.35).abs() < 0.001);
        assert_eq!(r.consecutive_success, 0);
    }

    #[test]
    fn test_record_usage_consecutive_bonus() {
        let mut store = test_store();
        let id = store
            .save("test", &serde_json::json!({}), &serde_json::json!([]), "", None)
            .unwrap();

        // 5 次连续成功 → 额外 +0.1
        for _ in 0..5 {
            store.record_usage(id, true).unwrap();
        }

        let h = store.get(id).unwrap();
        assert!((h.confidence - (0.5 + 5.0 * 0.05 + 0.1)).abs() < 0.001);
    }

    #[test]
    fn test_distill_from_logs() {
        let mut store = test_store();

        // 3 条相似的成功记录
        let logs: Vec<ExecutionLog> = (0..3)
            .map(|i| ExecutionLog {
                name: format!("check_plate_{}", i),
                trigger_conditions: serde_json::json!({"tool": "query_plate"}),
                steps: serde_json::json!([{"tool": "query_plate", "args": {"plate": "test"}}]),
                verify_rule: String::new(),
                success: true,
            })
            .collect();

        let new_ids = store.distill_from_logs(&logs, 3).unwrap();
        assert_eq!(new_ids.len(), 1, "should distill 1 new harness");

        let h = store.get(new_ids[0]).unwrap();
        assert!(h.name.contains("check_plate"), "name should be derived from logs");
    }

    #[test]
    fn test_distill_requires_min_similar() {
        let mut store = test_store();

        // 只有 2 条，不满足 min_similar=3
        let logs: Vec<ExecutionLog> = (0..2)
            .map(|_| ExecutionLog {
                name: "test".to_string(),
                trigger_conditions: serde_json::json!({"tool": "query"}),
                steps: serde_json::json!([]),
                verify_rule: String::new(),
                success: true,
            })
            .collect();

        let new_ids = store.distill_from_logs(&logs, 3).unwrap();
        assert!(new_ids.is_empty(), "should not distill with <3 logs");
    }

    #[test]
    fn test_distill_skips_failures() {
        let mut store = test_store();

        let logs: Vec<ExecutionLog> = (0..3)
            .map(|i| ExecutionLog {
                name: "fail".to_string(),
                trigger_conditions: serde_json::json!({"tool": "write_db"}),
                steps: serde_json::json!([]),
                verify_rule: String::new(),
                success: i == 0, // only 1 success
            })
            .collect();

        let new_ids = store.distill_from_logs(&logs, 3).unwrap();
        assert!(new_ids.is_empty(), "should skip failures");
    }

    #[test]
    fn test_confidence_clamping() {
        let mut store = test_store();
        let id = store
            .save("test", &serde_json::json!({}), &serde_json::json!([]), "", None)
            .unwrap();

        // 连续失败 → 不应低于 0
        for _ in 0..10 {
            store.record_usage(id, false).unwrap();
        }
        let h = store.get(id).unwrap();
        assert!(h.confidence >= 0.0, "confidence should not go below 0");
    }

    #[test]
    fn test_distill_dangerous_template_not_auto_activated() {
        let mut store = test_store();
        // 3 次成功、相同触发、但步骤含危险工具 delete_entrance_record
        let logs: Vec<ExecutionLog> = (0..3)
            .map(|_| ExecutionLog {
                name: "danger".to_string(),
                trigger_conditions: serde_json::json!({"tool": "danger"}),
                steps: serde_json::json!([
                    {"tool": "delete_entrance_record", "args": {"id": 1}}
                ]),
                verify_rule: String::new(),
                success: true,
            })
            .collect();

        let new_ids = store.distill_from_logs(&logs, 3).unwrap();
        assert_eq!(new_ids.len(), 1, "应蒸馏出 1 个模板");
        let h = store.get(new_ids[0]).unwrap();
        // P2-3：危险模板不得自动激活，必须待审批
        assert!(!h.is_active, "危险模板不应自动激活（is_active 应为 false）");
        // 确认其不在「已激活」列表中
        let active = store.list_all(true).unwrap();
        assert!(!active.iter().any(|x| x.id == h.id), "危险模板不应出现在激活列表");
    }

    #[test]
    fn test_distill_safe_template_auto_activated() {
        let mut store = test_store();
        // 3 次成功、步骤仅含只读工具（安全）
        let logs: Vec<ExecutionLog> = (0..3)
            .map(|_| ExecutionLog {
                name: "safe".to_string(),
                trigger_conditions: serde_json::json!({"tool": "safe"}),
                steps: serde_json::json!([
                    {"tool": "query_plate", "args": {"plate": "沪A12345"}}
                ]),
                verify_rule: String::new(),
                success: true,
            })
            .collect();

        let new_ids = store.distill_from_logs(&logs, 3).unwrap();
        assert_eq!(new_ids.len(), 1);
        let h = store.get(new_ids[0]).unwrap();
        assert!(h.is_active, "安全模板应自动激活");
    }

    #[test]
    fn test_activate_toggles_is_active() {
        let mut store = test_store();
        let id = store
            .save("test", &serde_json::json!({}), &serde_json::json!([]), "", None)
            .unwrap();
        store.deactivate(id);
        assert!(!store.get(id).unwrap().is_active);
        assert!(store.activate(id), "activate 应返回 true");
        assert!(store.get(id).unwrap().is_active, "activate 后应为 active");
    }
}
