//! HY3 1.3 收口：记忆自进化生产证据审计
//!
//! 把生产流量中每次 `consolidate` 触发的 LLM 级 `memory_evolve` 落结构化审计日志
//! （`data/evolution_audit.jsonl`），使「记忆自进化在生产中持续运行且达标」可被持续证明，
//! 而非仅依赖 memoria 的 `evolution_log` 表或一次性人工文档。
//! 同时在启动处记录 G1 二进制版本（证明运行实例与 canonical 对齐），供复验。
//!
//! 设计纪律：
//! - 本模块**纯本地落盘**，不依赖 memoria 重建，零网络/零 LLM，绝不进 call_tool_routed 热路径。
//! - 写入失败仅 warn，不影响主链路（自进化优先级高于审计）。
//! - 审计文件落在 agent-core 工作目录 `data/`，不硬编码绝对路径，符合隐私/可移植约定。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// 一条自进化审计事件（JSONL 一行）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionAuditEntry {
    /// RFC3339 时间戳
    pub ts: String,
    /// 命名空间（自进化发生的 ns）；`__boot__` 表示启动复验快照
    pub namespace: String,
    /// 本轮演化的记忆条数（evolved_context 写入数）
    pub evolved: u64,
    /// 演化所用模型（来自 config.llm.model）
    pub model: String,
    /// 变更类型（如 context_update / g1_binary_aligned）
    pub change_type: String,
    /// G1：运行二进制版本（CARGO_PKG_VERSION，配合 git 工作树干净 = 对齐 canonical）
    pub binary_version: String,
    /// 可选备注
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// 自进化审计器：包装一个 JSONL 文件，线程安全追加。
pub struct EvolutionAuditor {
    path: PathBuf,
    binary_version: String,
    lock: Mutex<()>,
}

impl EvolutionAuditor {
    pub fn new<P: AsRef<Path>>(path: P, binary_version: String) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            binary_version,
            lock: Mutex::new(()),
        }
    }

    /// 默认路径：`<cwd>/data/evolution_audit.jsonl`
    pub fn default_path() -> PathBuf {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data")
            .join("evolution_audit.jsonl")
    }

    fn append(&self, entry: &EvolutionAuditEntry) {
        let line = match serde_json::to_string(entry) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(target: "agent.evolve_audit", "审计序列化失败: {}", e);
                return;
            }
        };
        let _g = self.lock.lock().unwrap();
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                let _ = f.write_all(line.as_bytes());
                let _ = f.write_all(b"\n");
            }
            Err(e) => {
                tracing::warn!(target: "agent.evolve_audit", "审计落盘失败: {}", e);
            }
        }
    }

    /// 记录一次自进化事件（evolved==0 时跳过，避免噪声）
    pub fn record(&self, namespace: &str, evolved: u64, model: &str, change_type: &str) {
        if evolved == 0 {
            return;
        }
        self.append(&EvolutionAuditEntry {
            ts: chrono::Utc::now().to_rfc3339(),
            namespace: namespace.to_string(),
            evolved,
            model: model.to_string(),
            change_type: change_type.to_string(),
            binary_version: self.binary_version.clone(),
            note: None,
        });
    }

    /// 启动复验快照：记录 G1 二进制版本（证明运行实例与 canonical 对齐）
    pub fn record_boot(&self) {
        self.append(&EvolutionAuditEntry {
            ts: chrono::Utc::now().to_rfc3339(),
            namespace: "__boot__".to_string(),
            evolved: 0,
            model: "system".to_string(),
            change_type: "g1_binary_aligned".to_string(),
            binary_version: self.binary_version.clone(),
            note: Some("G1: running binary version recorded at boot".into()),
        });
    }

    /// 读取全部审计条目（供复验/查询；损坏行跳过）
    pub fn load_entries(&self) -> Vec<EvolutionAuditEntry> {
        match std::fs::read_to_string(&self.path) {
            Ok(txt) => txt
                .lines()
                .filter_map(|l| serde_json::from_str::<EvolutionAuditEntry>(l).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("evolve_audit_{}_{}.jsonl", std::process::id(), name))
    }

    #[test]
    fn appends_and_loads_entries() {
        let p = tmp_path("a");
        let _ = std::fs::remove_file(&p);
        {
            let au = EvolutionAuditor::new(&p, "0.4.0-test".into());
            au.record("agent_x", 3, "flash", "context_update");
            au.record("agent_x", 0, "flash", "context_update"); // 跳过
            au.record_boot();
        }
        let au = EvolutionAuditor::new(&p, "0.4.0-test".into());
        let entries = au.load_entries();
        assert_eq!(entries.len(), 2); // 1 evolve + 1 boot
        let evolve = entries.iter().find(|e| e.namespace == "agent_x").unwrap();
        assert_eq!(evolve.evolved, 3);
        assert_eq!(evolve.binary_version, "0.4.0-test");
        let _ = std::fs::remove_file(&p);
    }
}
