//! HY3 1.3 三大项热路径接线 —— 共享渲染/判定辅助（纯函数，便于单测）。
//!
//! 重要纪律：本文件及其余 1.3 接线代码全部默认 **OFF**（由 `AgentConfig.features`
//! 与 agent.toml `[features]` 控制）。在 G1–G4 硬门未全绿、且各 DoD（单测绿 /
//! 热路径接线 / live 冒烟 / 可回滚开关）未全部满足前，生产必须保持全 false。
//! 「接了线但默认不启用」≠「已开闸」。

use crate::skill_library::SkillRegistry;

/// 把技能库检索到的相关技能渲染成可注入 system prompt 的块。
/// 纯函数：无需构造 AgentCore，直接喂一个 registry 即可单测。
/// 无命中返回 None（调用方据此跳过注入，零 prompt 膨胀）。
pub fn render_skill_block(reg: &dyn SkillRegistry, task: &str, top_k: usize) -> Option<String> {
    let skills = reg.search_by_task(task, top_k);
    if skills.is_empty() {
        return None;
    }
    let mut s = String::from(
        "\n\n## 可用技能（技能库检索）\n以下技能与当前任务相关，可优先套用其方法：\n",
    );
    for sk in &skills {
        s.push_str(&format!("- [{}] {}：{}\n", sk.id, sk.name, sk.description));
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skill_library::{InMemorySkillRegistry, Skill};

    fn sk(id: &str, kws: &[&str], desc: &str) -> Skill {
        Skill {
            id: id.to_string(),
            name: id.to_string(),
            description: desc.to_string(),
            trigger_keywords: kws.iter().map(|s| s.to_string()).collect(),
            body: String::new(),
            version: 1,
        }
    }

    #[test]
    fn renders_when_match() {
        let mut reg = InMemorySkillRegistry::new();
        reg.register(sk("sql", &["sql", "查询"], "编写与优化 SQL 查询")).unwrap();
        let block = render_skill_block(&reg, "帮我写一段 sql 查询", 3);
        let b = block.expect("应渲染技能块");
        assert!(b.contains("[sql]"));
        assert!(b.contains("编写与优化 SQL 查询"));
    }

    #[test]
    fn none_when_no_match() {
        let reg = InMemorySkillRegistry::new();
        assert!(render_skill_block(&reg, "今天天气怎么样", 3).is_none());
    }
}
