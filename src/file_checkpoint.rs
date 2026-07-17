//! 文件级 checkpoint（Grok Build 吸收 · Phase A2）
//!
//! 在 **WRITE / dangerous 类工具执行前**，对其 `path` / `file` / `dir` 等参数指向的
//! **已存在本地文件**做快照；工具执行失败时自动回滚到快照（best-effort）。
//!
//! 设计约束（与 A1 沙箱一致）：
//! - **best-effort**：任何快照/回滚失败都只 `warn`/`info`，**绝不阻断**工具执行。
//! - 只快照绝对路径且已存在的常规文件，避免对管道/设备/网络路径下手。
//! - 快照存放在隔离目录（默认 `temp_dir()/agent-core-file-checkpoints`，可用
//!   `AGENT_FILE_CHECKPOINT_DIR` 覆盖），与业务目录解耦。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// 工具参数中视为「路径类」的键（不区分大小写）
const PATH_KEYS: &[&str] = &[
    "path",
    "file",
    "dir",
    "src",
    "source",
    "dest",
    "target",
    "output",
    "in_file",
    "out_file",
    "file_path",
    "filename",
];

#[derive(Clone)]
struct SnapshotMeta {
    original: PathBuf,
    snapshot: PathBuf,
}

static STORE_ROOT: OnceLock<PathBuf> = OnceLock::new();
static INDEX: OnceLock<Mutex<HashMap<String, SnapshotMeta>>> = OnceLock::new();

fn store_root() -> &'static PathBuf {
    STORE_ROOT.get_or_init(|| {
        if let Ok(v) = std::env::var("AGENT_FILE_CHECKPOINT_DIR") {
            if !v.is_empty() {
                return PathBuf::from(v);
            }
        }
        std::env::temp_dir().join("agent-core-file-checkpoints")
    })
}

fn index() -> &'static Mutex<HashMap<String, SnapshotMeta>> {
    // 确保 store_root 已初始化
    let _ = store_root();
    INDEX.get_or_init(|| Mutex::new(HashMap::new()))
}

fn gen_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("fc-{}-{:x}", std::process::id(), nanos)
}

/// 从工具参数中抽取「路径类键 + 绝对路径 + 已存在常规文件」的本地路径
pub fn extract_existing_paths(args: &serde_json::Value) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(obj) = args.as_object() {
        for (k, v) in obj {
            if !PATH_KEYS.iter().any(|p| k.eq_ignore_ascii_case(p)) {
                continue;
            }
            if let Some(s) = v.as_str() {
                let p = PathBuf::from(s);
                if p.is_absolute() && p.is_file() {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// 对单个已存在文件做快照，返回 snapshot id（失败返回 None）
pub fn snapshot_file(original: &Path) -> Option<String> {
    let root = store_root();
    if let Err(e) = std::fs::create_dir_all(root) {
        tracing::warn!("file_checkpoint: 创建快照目录 {:?} 失败: {}", root, e);
        return None;
    }
    let id = gen_id();
    let ext = original
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let snap = root.join(format!("{}.{}", id, ext));
    if let Err(e) = std::fs::copy(original, &snap) {
        tracing::warn!(
            "file_checkpoint: 快照 {:?} 失败: {}",
            original.display(),
            e
        );
        return None;
    }
    let meta = SnapshotMeta {
        original: original.to_path_buf(),
        snapshot: snap,
    };
    index()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id.clone(), meta);
    tracing::debug!(
        "file_checkpoint: 已快照 {} -> {} ({})",
        original.display(),
        id,
        ext
    );
    Some(id)
}

/// 对一个工具的参数批量快照（仅已存在文件），返回 snapshot id 列表
pub fn snapshot_args(args: &serde_json::Value) -> Vec<String> {
    let mut ids = Vec::new();
    for p in extract_existing_paths(args) {
        if let Some(id) = snapshot_file(&p) {
            ids.push(id);
        }
    }
    ids
}

/// 回滚单个快照到原路径，成功返回 true
pub fn restore(id: &str) -> bool {
    let meta = {
        let g = index().lock().unwrap_or_else(|p| p.into_inner());
        g.get(id).cloned()
    };
    if let Some(m) = meta {
        if let Err(e) = std::fs::copy(&m.snapshot, &m.original) {
            tracing::warn!(
                "file_checkpoint: 回滚 {} -> {:?} 失败: {}",
                id,
                m.original.display(),
                e
            );
            return false;
        }
        tracing::info!(
            "file_checkpoint: 已回滚 {} -> {}",
            id,
            m.original.display()
        );
        true
    } else {
        tracing::warn!("file_checkpoint: 未找到快照 {}", id);
        false
    }
}

/// 批量回滚（best-effort，逐个尝试）
pub fn restore_many(ids: &[String]) {
    for id in ids {
        restore(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("fc-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn extract_paths_picks_existing_abs_files() {
        let dir = std::env::temp_dir().join("fc-test");
        let _ = std::fs::create_dir_all(&dir);
        let exist = write_tmp("exist.txt", "hello");
        let args = serde_json::json!({
            "path": exist.to_string_lossy(),
            "dir": "/nonexistent/xyz",
            "content": "not a path",
            "target": "relative/file.txt",
        });
        let paths = extract_existing_paths(&args);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], exist);
    }

    #[test]
    fn snapshot_and_restore_roundtrip() {
        let f = write_tmp("rt.txt", "original");
        let id = snapshot_file(&f).expect("snapshot should succeed");
        // 篡改原文件
        std::fs::write(&f, "modified").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "modified");
        // 回滚
        assert!(restore(&id));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "original");
    }

    #[test]
    fn restore_unknown_id_is_false() {
        assert!(!restore("fc-nope"));
    }

    #[test]
    fn snapshot_args_only_existing() {
        let f = write_tmp("sa.txt", "data");
        let args = serde_json::json!({
            "file": f.to_string_lossy(),
            "output": "/no/such/file",
        });
        let ids = snapshot_args(&args);
        assert_eq!(ids.len(), 1);
    }
}
