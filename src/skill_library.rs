//! 技能库（skill library）—— HY3 1.3+ 大项之一（最自包含，优先落地）
//!
//! 定位：可复用技能（prompt 模板 / 工具组合 / 子 agent 配方）的注册表。
//! agent 按任务语义检索并注入，作为 RoutedLlm 候选池与工具选择的补充能力源。
//!
//! 本文件为**最小骨架**：仅定义 Skill 结构 + SkillRegistry trait + InMemory 实现，
//! 暂未接入路由/工具选择热路径（后续里程碑再接线，保持小步合入）。
//! 存储后端：先用 InMemory 跑通逻辑与单测；MemoriaBackedSkillRegistry 在存储层就绪后补。

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
    /// 版本号（自进化时递增）
    #[serde(default)]
    pub version: u32,
}

/// 技能注册表抽象
pub trait SkillRegistry {
    /// 列出全部已注册技能
    fn list(&self) -> Vec<Skill>;
    /// 按 id 取技能
    fn get(&self, id: &str) -> Option<Skill>;
    /// 按任务文本检索相关技能（关键词重叠打分，降序返回至多 top_k）
    fn search_by_task(&self, task: &str, top_k: usize) -> Vec<Skill>;
    /// 注册/覆盖一个技能
    fn register(&mut self, skill: Skill) -> Result<(), String>;
    /// 删除技能
    fn unregister(&mut self, id: &str) -> Result<(), String>;
}

/// 内存版注册表（测试 / 单进程默认）
#[derive(Debug, Default)]
pub struct InMemorySkillRegistry {
    skills: Vec<Skill>,
}

impl InMemorySkillRegistry {
    pub fn new() -> Self {
        Self { skills: Vec::new() }
    }
}

impl SkillRegistry for InMemorySkillRegistry {
    fn list(&self) -> Vec<Skill> {
        self.skills.clone()
    }

    fn get(&self, id: &str) -> Option<Skill> {
        self.skills.iter().find(|s| s.id == id).cloned()
    }

    fn search_by_task(&self, task: &str, top_k: usize) -> Vec<Skill> {
        let task_low = task.to_lowercase();
        let mut scored: Vec<(usize, &Skill)> = self
            .skills
            .iter()
            .filter_map(|s| {
                let hits = s
                    .trigger_keywords
                    .iter()
                    .filter(|kw| task_low.contains(&kw.to_lowercase()))
                    .count();
                if hits > 0 {
                    Some((hits, s))
                } else {
                    None
                }
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        scored
            .into_iter()
            .take(top_k)
            .map(|(_, s)| s.clone())
            .collect()
    }

    fn register(&mut self, skill: Skill) -> Result<(), String> {
        if skill.id.is_empty() {
            return Err("skill id 不能为空".to_string());
        }
        if let Some(existing) = self.skills.iter_mut().find(|s| s.id == skill.id) {
            *existing = skill;
        } else {
            self.skills.push(skill);
        }
        Ok(())
    }

    fn unregister(&mut self, id: &str) -> Result<(), String> {
        let before = self.skills.len();
        self.skills.retain(|s| s.id != id);
        if self.skills.len() == before {
            return Err(format!("skill {} 不存在", id));
        }
        Ok(())
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
        let mut reg = InMemorySkillRegistry::new();
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
        let mut reg = InMemorySkillRegistry::new();
        assert!(reg.unregister("nope").is_err());
    }
}
