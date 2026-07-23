//! 技能库（skill library）—— HY3 1.3+ 大项之一（最自包含，优先落地）
//!
//! 定位：可复用技能（prompt 模板 / 工具组合 / 子 agent 配方）的注册表。
//! agent 按任务语义检索并注入，作为 RoutedLlm 候选池与工具选择的补充能力源。
//!
//! 本文件为**最小骨架**：仅定义 Skill 结构 + SkillRegistry trait + InMemory 实现，
//! 暂未接入路由/工具选择热路径（后续里程碑再接线，保持小步合入）。
//! 存储后端：先用 InMemory 跑通逻辑与单测；MemoriaBackedSkillRegistry 在存储层就绪后补。
//!
//! 版本/回滚（2026-07-22 补齐）：register 自动递增 version 并写入历史；rollback(id)
//! 回退到上一版本。注册表用 `RwLock` 内部可变性，故 `&self` 即可 register/rollback，
//! 运行时经 `Arc<dyn SkillRegistry>` 也可调用（修复 P0-1「启动后无法 register」根因）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};

/// 一个可复用技能
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub id: String,
    pub name: String,
    /// 一句话说明技能做什么（同时用于检索排序）
    pub description: String,
    /// 触发关键词（任务文本命中即视为相关）
    pub trigger_keywords: Vec<String>,
    /// 技能体：prompt 模板或工具/子 agent 规格（JSON 字符串，由使用者解释）
    pub body: String,
    /// 版本号（每次 register 覆盖自动 +1；可 rollback 到历史版本）
    #[serde(default)]
    pub version: u32,
}

/// 技能注册表抽象
/// 加 `Send + Sync` 超约束：使 `Arc<dyn SkillRegistry + Send + Sync>` 可跨线程持有
/// （AgentCore 的 skill_registry 字段需满足 Send+Sync）。
pub trait SkillRegistry: Send + Sync {
    /// 列出全部已注册技能
    fn list(&self) -> Vec<Skill>;
    /// 按 id 取技能
    fn get(&self, id: &str) -> Option<Skill>;
    /// 按任务文本检索相关技能（关键词重叠打分，降序返回至多 top_k）
    fn search_by_task(&self, task: &str, top_k: usize) -> Vec<Skill>;
    /// 注册/覆盖一个技能（自动递增版本并写入历史）
    fn register(&self, skill: Skill) -> Result<(), String>;
    /// 删除技能（连同版本历史）
    fn unregister(&self, id: &str) -> Result<(), String>;
    /// 回退某技能到上一版本（仅 1 个版本时报错）。返回回退后的技能。
    fn rollback(&self, id: &str) -> Result<Skill, String>;
    /// 当前版本号
    fn version_of(&self, id: &str) -> Option<u32>;
    /// 全部历史版本（按时间升序，含当前）
    fn list_versions(&self, id: &str) -> Vec<Skill>;
}

/// 内存版注册表（测试 / 单进程默认）
#[derive(Debug, Default)]
pub struct InMemorySkillRegistry {
    skills: RwLock<Vec<Skill>>,
    /// 每 id 的版本历史（按注册时间升序；末项为当前版本）
    history: RwLock<HashMap<String, Vec<Skill>>>,
}

impl InMemorySkillRegistry {
    /// 空注册表（测试 / 自定义加载用）。生产开闸请用 `new_with_defaults`。
    pub fn new() -> Self {
        Self {
            skills: RwLock::new(Vec::new()),
            history: RwLock::new(HashMap::new()),
        }
    }

    /// 生产用：内置与 agent 真实工具/能力对应的技能，使 `features.skill_library=true`
    /// 时 `search_by_task` 真正命中、`render_skill_block` 真正注入「## 可用技能」。
    /// 此前 `new()` 为空表 + `Arc<dyn>` 启动后无法 `register`，导致开闸=空转（P0-1）。
    /// 后续可改为从 toml / Memoria 加载；此处为可验证的最小内置集。
    pub fn new_with_defaults() -> Self {
        let s = Self::new();
        s.seed_defaults();
        s
    }

    fn seed_defaults(&self) {
        let defaults: &[(&str, &str, &str, &[&str])] = &[
            (
                "sql",
                "SQL 查询",
                "编写与执行 SQL 查询（配合 execute_sql 工具）",
                &["sql", "查询", "数据库", "select", "表"],
            ),
            (
                "rust",
                "Rust 并发",
                "Rust 并发与安全代码生成（锁/通道/异步）",
                &["rust", "并发", "锁", "tokio", "异步"],
            ),
            (
                "regex",
                "正则表达式",
                "正则表达式构造与边界处理",
                &["正则", "regex", "模式匹配"],
            ),
            (
                "plate",
                "车牌匹配",
                "车牌号模糊匹配（配合 fuzzy_match_plate 工具）",
                &["车牌", "plate", "车牌号"],
            ),
        ];
        for (id, name, desc, kws) in defaults {
            let _ = self.register(Skill {
                id: id.to_string(),
                name: name.to_string(),
                description: desc.to_string(),
                trigger_keywords: kws.iter().map(|s| s.to_string()).collect(),
                body: String::new(),
                version: 1,
            });
        }
    }
}

impl SkillRegistry for InMemorySkillRegistry {
    fn list(&self) -> Vec<Skill> {
        self.skills.read().unwrap().clone()
    }

    fn get(&self, id: &str) -> Option<Skill> {
        self.skills
            .read()
            .unwrap()
            .iter()
            .find(|s| s.id == id)
            .cloned()
    }

    fn search_by_task(&self, task: &str, top_k: usize) -> Vec<Skill> {
        let task_low = task.to_lowercase();
        // 在 guard 作用域内克隆成自有 Skill，避免 guard 生命周期外仍持有借用
        let scored: Vec<(usize, Skill)> = {
            let skills = self.skills.read().unwrap();
            skills
                .iter()
                .filter_map(|s| {
                    let hits = s
                        .trigger_keywords
                        .iter()
                        .filter(|kw| task_low.contains(&kw.to_lowercase()))
                        .count();
                    if hits > 0 {
                        Some((hits, s.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };
        let mut scored = scored;
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        scored
            .into_iter()
            .take(top_k)
            .map(|(_, s)| s)
            .collect()
    }

    fn register(&self, skill: Skill) -> Result<(), String> {
        if skill.id.is_empty() {
            return Err("skill id 不能为空".to_string());
        }
        // 计算下一版本号（基于当前版本 +1；首次为 1），再原子写入 skills + history
        let new_version = {
            let skills = self.skills.read().unwrap();
            match skills.iter().find(|s| s.id == skill.id) {
                Some(existing) => existing.version + 1,
                None => 1,
            }
        };
        let mut sk = skill;
        sk.version = new_version;
        {
            let mut skills = self.skills.write().unwrap();
            if let Some(slot) = skills.iter_mut().find(|s| s.id == sk.id) {
                *slot = sk.clone();
            } else {
                skills.push(sk.clone());
            }
        }
        {
            let mut hist = self.history.write().unwrap();
            hist.entry(sk.id.clone()).or_default().push(sk);
        }
        Ok(())
    }

    fn unregister(&self, id: &str) -> Result<(), String> {
        let mut skills = self.skills.write().unwrap();
        let before = skills.len();
        skills.retain(|s| s.id != id);
        if skills.len() == before {
            return Err(format!("skill {} 不存在", id));
        }
        drop(skills);
        self.history.write().unwrap().remove(id);
        Ok(())
    }

    fn rollback(&self, id: &str) -> Result<Skill, String> {
        let restored = {
            let mut hist = self.history.write().unwrap();
            let entry = hist
                .get_mut(id)
                .ok_or_else(|| format!("skill {} 无版本历史", id))?;
            if entry.len() < 2 {
                return Err(format!("skill {} 仅 1 个版本，无法回退", id));
            }
            entry.pop(); // 移除当前版本
            entry.last().cloned().unwrap()
        };
        {
            let mut skills = self.skills.write().unwrap();
            if let Some(slot) = skills.iter_mut().find(|s| s.id == id) {
                *slot = restored.clone();
            } else {
                skills.push(restored.clone());
            }
        }
        Ok(restored)
    }

    fn version_of(&self, id: &str) -> Option<u32> {
        self.skills
            .read()
            .unwrap()
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.version)
    }

    fn list_versions(&self, id: &str) -> Vec<Skill> {
        self.history
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default()
    }
}

/// 持久化形状（落盘用）：skills 当前快照 + 每 id 的版本历史
#[derive(Debug, Serialize, Deserialize)]
struct PersistShape {
    skills: Vec<Skill>,
    history: HashMap<String, Vec<Skill>>,
}

impl InMemorySkillRegistry {
    /// 导出当前全部状态（skills + 版本历史），供持久化包装落盘
    pub fn export_state(&self) -> (Vec<Skill>, HashMap<String, Vec<Skill>>) {
        (
            self.skills.read().unwrap().clone(),
            self.history.read().unwrap().clone(),
        )
    }

    /// 从导出状态整体恢复（覆盖当前内存）。用于启动时加载持久化文件。
    pub fn import_state(&self, skills: Vec<Skill>, history: HashMap<String, Vec<Skill>>) {
        *self.skills.write().unwrap() = skills;
        *self.history.write().unwrap() = history;
    }
}

/// 文件持久化的技能注册表：包装 `InMemorySkillRegistry`，每次写操作后整体落盘 JSON。
/// 启动从文件加载（缺失/损坏则回退 `new_with_defaults` 并立即落盘），进程重启不丢
/// 运行时注册的技能，跨进程可共享同一文件。满足 `SkillRegistry + Send + Sync`，
/// 可直接替换 `InMemorySkillRegistry` 作为 `Arc<dyn SkillRegistry>` 实现。
pub struct FileBackedSkillRegistry {
    inner: InMemorySkillRegistry,
    path: PathBuf,
    flush_lock: Mutex<()>,
}

impl FileBackedSkillRegistry {
    /// 默认持久化路径：agent-core 工作目录下的 `skill_library.json`
    /// （不硬编码绝对路径，符合隐私/可移植约定）。
    pub fn default_path() -> PathBuf {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("skill_library.json")
    }

    /// 从文件加载；文件缺失/损坏则回退 `new_with_defaults` 并立即落盘。
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let inner = if path.exists() {
            match std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| serde_json::from_str::<PersistShape>(&t).ok())
            {
                Some(shape) => {
                    let reg = InMemorySkillRegistry::new();
                    reg.import_state(shape.skills, shape.history);
                    reg
                }
                None => InMemorySkillRegistry::new_with_defaults(),
            }
        } else {
            InMemorySkillRegistry::new_with_defaults()
        };
        let me = Self {
            inner,
            path,
            flush_lock: Mutex::new(()),
        };
        me.flush()?;
        Ok(me)
    }

    fn flush(&self) -> std::io::Result<()> {
        let _g = self.flush_lock.lock().unwrap();
        let (skills, history) = self.inner.export_state();
        let shape = PersistShape { skills, history };
        let txt = serde_json::to_string_pretty(&shape)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&self.path, txt)
    }
}

impl SkillRegistry for FileBackedSkillRegistry {
    fn list(&self) -> Vec<Skill> {
        self.inner.list()
    }
    fn get(&self, id: &str) -> Option<Skill> {
        self.inner.get(id)
    }
    fn search_by_task(&self, task: &str, top_k: usize) -> Vec<Skill> {
        self.inner.search_by_task(task, top_k)
    }
    fn register(&self, skill: Skill) -> Result<(), String> {
        let r = self.inner.register(skill);
        if r.is_ok() {
            if let Err(e) = self.flush() {
                tracing::warn!(target: "agent.skill", "技能库持久化失败: {}", e);
            }
        }
        r
    }
    fn unregister(&self, id: &str) -> Result<(), String> {
        let r = self.inner.unregister(id);
        if r.is_ok() {
            if let Err(e) = self.flush() {
                tracing::warn!(target: "agent.skill", "技能库持久化失败: {}", e);
            }
        }
        r
    }
    fn rollback(&self, id: &str) -> Result<Skill, String> {
        let r = self.inner.rollback(id);
        if r.is_ok() {
            if let Err(e) = self.flush() {
                tracing::warn!(target: "agent.skill", "技能库持久化失败: {}", e);
            }
        }
        r
    }
    fn version_of(&self, id: &str) -> Option<u32> {
        self.inner.version_of(id)
    }
    fn list_versions(&self, id: &str) -> Vec<Skill> {
        self.inner.list_versions(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(id: &str, kws: &[&str]) -> Skill {
        Skill {
            id: id.to_string(),
            name: id.to_string(),
            description: String::new(),
            trigger_keywords: kws.iter().map(|s| s.to_string()).collect(),
            body: String::new(),
            version: 1,
        }
    }

    #[test]
    fn register_and_search() {
        let reg = InMemorySkillRegistry::new();
        reg.register(sk("sql", &["sql", "数据库", "查询"])).unwrap();
        reg.register(sk("rust", &["rust", "并发", "队列"])).unwrap();
        let r = reg.search_by_task("帮我写一段 sql 查询", 5);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "sql");
        let none = reg.search_by_task("今天天气", 5);
        assert!(none.is_empty());
    }

    #[test]
    fn unregister_missing_errors() {
        let reg = InMemorySkillRegistry::new();
        assert!(reg.unregister("nope").is_err());
    }

    #[test]
    fn seeded_registry_finds_sql() {
        // P0-1 修复验证：new_with_defaults 必须预置内置技能，使开闸后真正命中注入
        let reg = InMemorySkillRegistry::new_with_defaults();
        let r = reg.search_by_task("帮我写一段 sql 查询", 5);
        assert!(!r.is_empty(), "seeded registry 应命中 sql 技能");
        assert_eq!(r[0].id, "sql");
        assert_eq!(reg.version_of("sql"), Some(1));
        // 无关任务仍应无命中（不污染 prompt）
        assert!(reg.search_by_task("今天天气怎么样", 5).is_empty());
    }

    #[test]
    fn version_increments_on_reregister() {
        let reg = InMemorySkillRegistry::new();
        reg.register(sk("sql", &["sql"])).unwrap();
        assert_eq!(reg.version_of("sql"), Some(1));
        let mut v2 = sk("sql", &["sql", "查询"]);
        v2.body = "改进版".into();
        reg.register(v2).unwrap();
        assert_eq!(reg.version_of("sql"), Some(2));
        assert_eq!(reg.list_versions("sql").len(), 2);
        // 当前版本应为 v2 的 body
        assert_eq!(reg.get("sql").unwrap().body, "改进版");
    }

    #[test]
    fn rollback_restores_previous_version() {
        let reg = InMemorySkillRegistry::new();
        let mut v1 = sk("sql", &["sql"]);
        v1.body = "v1".into();
        reg.register(v1).unwrap();
        let mut v2 = sk("sql", &["sql"]);
        v2.body = "v2".into();
        reg.register(v2).unwrap();
        let restored = reg.rollback("sql").unwrap();
        assert_eq!(restored.version, 1);
        assert_eq!(restored.body, "v1");
        assert_eq!(reg.version_of("sql"), Some(1));
        assert_eq!(reg.get("sql").unwrap().body, "v1");
        assert_eq!(reg.list_versions("sql").len(), 1);
    }

    #[test]
    fn rollback_single_version_errors() {
        let reg = InMemorySkillRegistry::new();
        reg.register(sk("sql", &["sql"])).unwrap();
        assert!(reg.rollback("sql").is_err());
        assert!(reg.rollback("nope").is_err());
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    fn sk(id: &str, kws: &[&str]) -> Skill {
        Skill {
            id: id.to_string(),
            name: id.to_string(),
            description: String::new(),
            trigger_keywords: kws.iter().map(|s| s.to_string()).collect(),
            body: String::new(),
            version: 1,
        }
    }

    #[test]
    fn file_backed_persists_register_across_restart() {
        let p = std::env::temp_dir().join(format!("skill_persist_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        {
            let reg = FileBackedSkillRegistry::load_or_default(&p).unwrap();
            // 用非内置 seed 的 id（"mydb"），避免与内置 sql/rust/regex/plate seed 版本冲突
            reg.register(sk("mydb", &["mydb"])).unwrap();
            let mut v2 = sk("mydb", &["mydb"]);
            v2.body = "v2".into();
            reg.register(v2).unwrap();
        }
        {
            let reg = FileBackedSkillRegistry::load_or_default(&p).unwrap();
            assert_eq!(reg.version_of("mydb"), Some(2));
            assert_eq!(reg.get("mydb").unwrap().body, "v2");
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn file_backed_persists_rollback_across_restart() {
        let p = std::env::temp_dir().join(format!("skill_rollback_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        {
            let reg = FileBackedSkillRegistry::load_or_default(&p).unwrap();
            let mut v1 = sk("x", &["x"]);
            v1.body = "a".into();
            reg.register(v1).unwrap();
            let mut v2 = sk("x", &["x"]);
            v2.body = "b".into();
            reg.register(v2).unwrap();
            reg.rollback("x").unwrap();
        }
        {
            let reg = FileBackedSkillRegistry::load_or_default(&p).unwrap();
            assert_eq!(reg.get("x").unwrap().body, "a");
            assert_eq!(reg.version_of("x"), Some(1));
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn file_backed_corrupt_file_falls_back_to_defaults() {
        let p = std::env::temp_dir().join(format!("skill_corrupt_{}.json", std::process::id()));
        let _ = std::fs::write(&p, "not valid json {{{");
        let reg = FileBackedSkillRegistry::load_or_default(&p).unwrap();
        // 损坏文件 → 回退默认 seed（sql 技能应可用）
        assert!(!reg.search_by_task("sql 查询", 3).is_empty());
        let _ = std::fs::remove_file(&p);
    }
}
