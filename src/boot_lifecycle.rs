//! Phase A (OpenClaw 吸收): 启动生命周期记录 + 崩溃循环 safe_mode。
//!
//! 思路来自 OpenClaw `gateway-boot-lifecycle`（SQLite 记启动 + 阈值判定 + channel 抑制），
//! 但关键差异：OpenClaw 把退避/防抖**委托给 systemd/launchd**，应用层无 backoff；
//! agent-core 无此假设，故 safe_mode 以**本运行时自实现的闩锁**实现——
//! 一旦阈值触发即进入 safe_mode，抑制危险/未分类/外发工具的自动执行，
//! 直到人工解除（删除 `agent_core_boot.db` 或后续 reset 端点）。

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

/// 不干净启动阈值：窗口内累计 >= 此值即进入 safe_mode。
const UNCLEAN_BOOT_THRESHOLD: u32 = 3;
/// 统计窗口：最近 5 分钟内。
const BOOT_WINDOW_MS: i64 = 5 * 60_000;

fn db_path() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_default();
    cwd.join("agent_core_boot.db")
}

fn open() -> Option<Connection> {
    match Connection::open(db_path()) {
        Ok(c) => {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS boot_lifecycle (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    startup_at   INTEGER NOT NULL,
                    completed_at INTEGER,
                    failed       INTEGER NOT NULL DEFAULT 0
                );",
            );
            Some(c)
        }
        Err(e) => {
            tracing::error!("[boot] open db failed: {}", e);
            None
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 记录一次启动，返回启动行 id（用于稍后标记完成/失败）。
fn record_startup() -> Option<i64> {
    let c = open()?;
    let now = now_ms();
    c.execute(
        "INSERT INTO boot_lifecycle (startup_at, completed_at, failed) VALUES (?1, NULL, 0)",
        params![now],
    )
    .ok()?;
    Some(c.last_insert_rowid())
}

/// 标记某次启动为健康完成。
fn mark_completed(id: i64) {
    if let Some(c) = open() {
        let _ = c.execute(
            "UPDATE boot_lifecycle SET completed_at = ?1 WHERE id = ?2",
            params![now_ms(), id],
        );
    }
}

/// 标记某次启动为失败（异常退出路径用；当前未接线，保留以备 panic hook）。
#[allow(dead_code)]
fn mark_failed(id: i64) {
    if let Some(c) = open() {
        let _ = c.execute(
            "UPDATE boot_lifecycle SET failed = 1 WHERE id = ?1",
            params![id],
        );
    }
}

/// 统计窗口内「不干净启动」数量（排除当前正在进行的这一次）。
fn count_unclean_boots(exclude_id: i64) -> u32 {
    let c = match open() {
        Some(c) => c,
        None => return 0,
    };
    let window_start = now_ms() - BOOT_WINDOW_MS;
    let count: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM boot_lifecycle
             WHERE id != ?1 AND startup_at >= ?2
               AND (completed_at IS NULL OR failed = 1)",
            params![exclude_id, window_start],
            |r| r.get(0),
        )
        .unwrap_or(0);
    count as u32
}

/// Phase A 入口：记录启动 → 统计历史不干净启动 → 返回 (启动id, 是否进入 safe_mode)。
///
/// 在 `build_agent` 开头调用：记录当前启动（completed_at=NULL），再统计窗口内
/// 历史不干净启动（排除当前这一次），达阈值即判定 safe_mode。
pub fn enter_phase_a() -> (Option<i64>, bool) {
    let id = record_startup();
    let unclean = count_unclean_boots(id.unwrap_or(0));
    let safe = unclean >= UNCLEAN_BOOT_THRESHOLD;
    if safe {
        tracing::warn!(
            "[boot] safe_mode ENGAGED: {} unclean boots in window (threshold {})",
            unclean,
            UNCLEAN_BOOT_THRESHOLD
        );
    }
    (id, safe)
}

/// 标记当前启动健康完成（`build_agent` 成功返回前调用）。
/// 成功启动会被标记 completed，不再计入「不干净」；若 build_agent 中途出错返回 Err，
/// 本次启动保持 completed_at=NULL，下次启动会把它算作不干净。
pub fn mark_healthy(id: Option<i64>) {
    if let Some(i) = id {
        mark_completed(i);
    }
}

/// 纯查询：当前不干净启动数（供运维/健康检查使用，不记录启动）。
pub fn unclean_boot_count() -> u32 {
    count_unclean_boots(0)
}
