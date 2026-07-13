//! 多租户 Namespace 模型 — user / project / dept 三层独立命名空间
//!
//! 设计：
//! - 三层层级：Dept (部门) > Project (项目) > User (用户)
//! - 每层可注册父子关系，权限沿层级向下继承
//! - NamespaceRegistry 管理所有注册关系 + 查询 API
//! - 存储 key 为完整路径（含祖先），如 `/dept/运营部/project/固废平台`

use std::collections::HashMap;

/// 命名空间层级
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NsLevel {
    /// 部门（顶层）
    Dept,
    /// 项目（中层）
    Project,
    /// 用户（叶子层）
    User,
}

impl NsLevel {
    /// 层级数值：Dept=3, Project=2, User=1
    pub fn rank(&self) -> u8 {
        match self {
            NsLevel::Dept => 3,
            NsLevel::Project => 2,
            NsLevel::User => 1,
        }
    }

    pub fn lower(&self) -> Option<NsLevel> {
        match self {
            NsLevel::Dept => Some(NsLevel::Project),
            NsLevel::Project => Some(NsLevel::User),
            NsLevel::User => None,
        }
    }

    pub fn higher(&self) -> Option<NsLevel> {
        match self {
            NsLevel::Dept => None,
            NsLevel::Project => Some(NsLevel::Dept),
            NsLevel::User => Some(NsLevel::Project),
        }
    }
}

impl std::fmt::Display for NsLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NsLevel::Dept => write!(f, "dept"),
            NsLevel::Project => write!(f, "project"),
            NsLevel::User => write!(f, "user"),
        }
    }
}

/// 命名空间标识 — 单层级，如 Dept("运营部")、Project("固废平台")
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Namespace {
    pub level: NsLevel,
    pub id: String,
}

impl Namespace {
    pub fn new(level: NsLevel, id: &str) -> Self {
        Namespace {
            level,
            id: id.to_string(),
        }
    }

    pub fn dept(id: &str) -> Self {
        Namespace::new(NsLevel::Dept, id)
    }
    pub fn project(id: &str) -> Self {
        Namespace::new(NsLevel::Project, id)
    }
    pub fn user(id: &str) -> Self {
        Namespace::new(NsLevel::User, id)
    }

    /// 本地路径：/dept/{id}、/project/{id}、/user/{id}
    pub fn to_path(&self) -> String {
        format!("/{}/{}", self.level, self.id)
    }

    /// 从路径的最后一个层级解析 Namespace
    pub fn from_path(path: &str) -> Option<Self> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if parts.len() >= 2 && parts.len() % 2 == 0 {
            let level = match parts[parts.len() - 2] {
                "dept" => NsLevel::Dept,
                "project" => NsLevel::Project,
                "user" => NsLevel::User,
                _ => return None,
            };
            Some(Namespace {
                level,
                id: parts[parts.len() - 1].to_string(),
            })
        } else {
            None
        }
    }

    /// 扁平化 namespace 标识（用于 Memoria search 的 namespace 字段），不含前导 /
    pub fn to_memoria_ns(&self, parent_full_path: &str) -> String {
        let local = self.to_path().trim_start_matches('/').to_string();
        if parent_full_path.is_empty() {
            local
        } else {
            format!(
                "{}/{}",
                parent_full_path
                    .trim_start_matches('/')
                    .trim_end_matches('/'),
                local
            )
        }
    }
}

/// 命名空间注册表 — 管理所有已注册的 namespace 及其关系
pub struct NamespaceRegistry {
    /// 完整路径 → NsEntry（key 如 `/dept/运营部/project/固废平台`）
    namespaces: HashMap<String, NsEntry>,
    /// 父完整路径 → 子完整路径列表
    children_index: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct NsEntry {
    ns: Namespace,
    /// 父节点的完整路径（如 `/dept/运营部`）
    parent_full_path: Option<String>,
}

impl NamespaceRegistry {
    pub fn new() -> Self {
        NamespaceRegistry {
            namespaces: HashMap::new(),
            children_index: HashMap::new(),
        }
    }

    /// 注册一个 namespace
    ///
    /// `parent_full_path` 是父节点的完整路径（如 `/dept/运营部`），
    /// 由之前的 register() 返回。父节点必须已存在。
    ///
    /// 返回新节点的完整路径（如 `/dept/运营部/project/固废平台`）。
    pub fn register(
        &mut self,
        ns: Namespace,
        parent_full_path: Option<&str>,
    ) -> Result<String, String> {
        // 计算完整路径
        let full_path = match parent_full_path {
            Some(pp) => {
                let parent = self
                    .namespaces
                    .get(pp)
                    .ok_or_else(|| format!("父 namespace 不存在: {}", pp))?;

                // 校验层级关系
                match parent.ns.level {
                    NsLevel::Dept => {
                        if ns.level != NsLevel::Project {
                            return Err(format!("Dept 下只能注册 Project，不能注册 {}", ns.level));
                        }
                    }
                    NsLevel::Project => {
                        if ns.level != NsLevel::User {
                            return Err(format!("Project 下只能注册 User，不能注册 {}", ns.level));
                        }
                    }
                    NsLevel::User => {
                        return Err("User 不能作为父 namespace".to_string());
                    }
                }

                format!("{}{}", pp.trim_end_matches('/'), ns.to_path())
            }
            None => {
                if ns.level != NsLevel::Dept {
                    return Err(format!(
                        "只有 Dept 级别可以不指定父 namespace，{} 需要父 namespace",
                        ns.level
                    ));
                }
                ns.to_path()
            }
        };

        if self.namespaces.contains_key(&full_path) {
            return Err(format!("namespace 已存在: {}", full_path));
        }

        let parent_owned = parent_full_path.map(|s| s.trim_end_matches('/').to_string());

        self.namespaces.insert(
            full_path.clone(),
            NsEntry {
                ns: ns.clone(),
                parent_full_path: parent_owned.clone(),
            },
        );

        if let Some(ref pp) = parent_owned {
            self.children_index
                .entry(pp.clone())
                .or_default()
                .push(full_path.clone());
        }

        Ok(full_path)
    }

    /// 批量注册（方便测试和启动时初始化）
    pub fn register_batch(
        &mut self,
        entries: Vec<(Namespace, Option<String>)>,
    ) -> Result<Vec<String>, String> {
        let mut results = Vec::new();
        for (ns, parent) in entries {
            results.push(self.register(ns, parent.as_deref())?);
        }
        Ok(results)
    }

    /// 判断 target 是否在 scope 的作用域内（scope 是完整路径）
    pub fn contains(&self, scope: &str, target: &str) -> bool {
        if scope == target {
            return true;
        }
        if target.starts_with(scope) {
            let rest = &target[scope.len()..];
            if rest.starts_with('/') {
                return true;
            }
        }
        false
    }

    /// 获取指定完整路径的所有祖先（从近到远，不含自身）
    pub fn ancestors(&self, full_path: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = full_path.to_string();
        loop {
            if let Some(entry) = self.namespaces.get(&current) {
                match &entry.parent_full_path {
                    Some(parent) => {
                        result.push(parent.clone());
                        current = parent.clone();
                    }
                    None => break,
                }
            } else {
                break;
            }
        }
        result
    }

    /// 获取指定完整路径的直接子级
    pub fn children(&self, full_path: &str) -> Vec<String> {
        self.children_index
            .get(full_path)
            .cloned()
            .unwrap_or_default()
    }

    /// 获取指定完整路径的所有后代（递归）
    pub fn descendants(&self, full_path: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut stack: Vec<String> = self.children(full_path);
        while let Some(child) = stack.pop() {
            result.push(child.clone());
            stack.extend(self.children(&child));
        }
        result
    }

    /// 已注册的 namespace 数量
    pub fn count(&self) -> usize {
        self.namespaces.len()
    }

    /// 列出所有已注册的完整路径
    pub fn list_all(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.namespaces.keys().cloned().collect();
        keys.sort();
        keys
    }

    pub fn exists(&self, full_path: &str) -> bool {
        self.namespaces.contains_key(full_path)
    }

    /// 按层级过滤
    pub fn list_by_level(&self, level: &NsLevel) -> Vec<String> {
        self.namespaces
            .iter()
            .filter(|(_, entry)| entry.ns.level == *level)
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// 获取某个节点下所有指定层级的后代路径
    pub fn descendants_by_level(&self, root: &str, level: &NsLevel) -> Vec<String> {
        self.descendants(root)
            .into_iter()
            .filter(|path| {
                self.namespaces
                    .get(path)
                    .map(|e| e.ns.level == *level)
                    .unwrap_or(false)
            })
            .collect()
    }
}

impl Default for NamespaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 构建完整的 Memoria namespace 标识
///
/// 格式：agent/{agent_id}/{ns_flat_path}
pub fn build_memoria_ns(agent_id: &str, ns_full_path: &str) -> String {
    let flat = ns_full_path.trim_start_matches('/');
    format!("agent/{}/{}", agent_id, flat)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── NsLevel ──

    #[test]
    fn test_ns_level_rank() {
        assert!(NsLevel::Dept.rank() > NsLevel::Project.rank());
        assert!(NsLevel::Project.rank() > NsLevel::User.rank());
    }

    #[test]
    fn test_ns_level_lower() {
        assert_eq!(NsLevel::Dept.lower(), Some(NsLevel::Project));
        assert_eq!(NsLevel::Project.lower(), Some(NsLevel::User));
        assert_eq!(NsLevel::User.lower(), None);
    }

    #[test]
    fn test_ns_level_higher() {
        assert_eq!(NsLevel::Dept.higher(), None);
        assert_eq!(NsLevel::Project.higher(), Some(NsLevel::Dept));
        assert_eq!(NsLevel::User.higher(), Some(NsLevel::Project));
    }

    // ── Namespace ──

    #[test]
    fn test_namespace_construction() {
        let ns = Namespace::dept("运营部");
        assert_eq!(ns.level, NsLevel::Dept);
        assert_eq!(ns.id, "运营部");
    }

    #[test]
    fn test_namespace_to_path() {
        assert_eq!(Namespace::dept("运营部").to_path(), "/dept/运营部");
        assert_eq!(
            Namespace::project("固废平台").to_path(),
            "/project/固废平台"
        );
        assert_eq!(Namespace::user("张三").to_path(), "/user/张三");
    }

    #[test]
    fn test_namespace_from_path() {
        let ns = Namespace::from_path("/dept/运营部").unwrap();
        assert_eq!(ns.level, NsLevel::Dept);
        assert_eq!(ns.id, "运营部");

        let ns = Namespace::from_path("/dept/运营部/project/固废平台").unwrap();
        assert_eq!(ns.level, NsLevel::Project);
        assert_eq!(ns.id, "固废平台");

        assert!(Namespace::from_path("invalid").is_none());
    }

    #[test]
    fn test_namespace_to_memoria_ns() {
        let user = Namespace::user("张三");
        assert_eq!(
            user.to_memoria_ns("/dept/运营部/project/固废平台"),
            "dept/运营部/project/固废平台/user/张三"
        );
        let dept = Namespace::dept("运营部");
        assert_eq!(dept.to_memoria_ns(""), "dept/运营部");
    }

    // ── NamespaceRegistry ──

    #[test]
    fn test_register_dept() {
        let mut reg = NamespaceRegistry::new();
        let path = reg.register(Namespace::dept("运营部"), None).unwrap();
        assert_eq!(path, "/dept/运营部");
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_dept_must_be_root() {
        let mut reg = NamespaceRegistry::new();
        let err = reg
            .register(Namespace::project("固废平台"), None)
            .unwrap_err();
        assert!(err.contains("需要父 namespace"));
    }

    #[test]
    fn test_child_validation() {
        let mut reg = NamespaceRegistry::new();
        reg.register(Namespace::dept("运营部"), None).unwrap();

        reg.register(Namespace::project("固废平台"), Some("/dept/运营部"))
            .unwrap();

        let err = reg
            .register(Namespace::user("张三"), Some("/dept/运营部"))
            .unwrap_err();
        assert!(err.contains("Dept 下只能注册 Project"));
    }

    #[test]
    fn test_full_hierarchy() {
        let mut reg = NamespaceRegistry::new();
        let dept = reg.register(Namespace::dept("运营部"), None).unwrap();
        let proj = reg
            .register(Namespace::project("固废平台"), Some(&dept))
            .unwrap();
        reg.register(Namespace::user("张三"), Some(&proj)).unwrap();

        assert_eq!(reg.count(), 3);
        assert_eq!(proj, "/dept/运营部/project/固废平台");
    }

    #[test]
    fn test_duplicate() {
        let mut reg = NamespaceRegistry::new();
        reg.register(Namespace::dept("运营部"), None).unwrap();
        let err = reg.register(Namespace::dept("运营部"), None).unwrap_err();
        assert!(err.contains("已存在"));
    }

    #[test]
    fn test_missing_parent() {
        let mut reg = NamespaceRegistry::new();
        let err = reg
            .register(Namespace::project("固废平台"), Some("/dept/不存在"))
            .unwrap_err();
        assert!(err.contains("父 namespace 不存在"));
    }

    #[test]
    fn test_contains() {
        let mut reg = NamespaceRegistry::new();
        let d = reg.register(Namespace::dept("运营部"), None).unwrap();
        let p = reg
            .register(Namespace::project("固废平台"), Some(&d))
            .unwrap();
        let u = reg.register(Namespace::user("张三"), Some(&p)).unwrap();

        assert!(reg.contains(&d, &p));
        assert!(reg.contains(&d, &u));
        assert!(reg.contains(&p, &u));
        assert!(reg.contains(&u, &u));
        assert!(!reg.contains(&d, "/dept/技术部"));
        assert!(!reg.contains(&p, "/dept/运营部/project/智慧交通"));
    }

    #[test]
    fn test_ancestors() {
        let mut reg = NamespaceRegistry::new();
        let d = reg.register(Namespace::dept("运营部"), None).unwrap();
        let p = reg
            .register(Namespace::project("固废平台"), Some(&d))
            .unwrap();
        let u = reg.register(Namespace::user("张三"), Some(&p)).unwrap();

        let ancestors = reg.ancestors(&u);
        assert_eq!(ancestors.len(), 2);
        assert_eq!(ancestors[0], p);
        assert_eq!(ancestors[1], d);
    }

    #[test]
    fn test_children_and_descendants() {
        let mut reg = NamespaceRegistry::new();
        let d = reg.register(Namespace::dept("运营部"), None).unwrap();
        let p1 = reg
            .register(Namespace::project("固废平台"), Some(&d))
            .unwrap();
        let p2 = reg
            .register(Namespace::project("智慧交通"), Some(&d))
            .unwrap();
        reg.register(Namespace::user("张三"), Some(&p1)).unwrap();
        reg.register(Namespace::user("李四"), Some(&p1)).unwrap();

        let children = reg.children(&d);
        assert_eq!(children.len(), 2);
        assert!(children.contains(&p1));
        assert!(children.contains(&p2));

        let descendants = reg.descendants(&d);
        assert_eq!(descendants.len(), 4);
    }

    #[test]
    fn test_list_by_level() {
        let mut reg = NamespaceRegistry::new();
        reg.register(Namespace::dept("运营部"), None).unwrap();
        reg.register(Namespace::dept("技术部"), None).unwrap();
        let d = reg.list_all().first().unwrap().clone();
        reg.register(Namespace::project("固废平台"), Some(&d))
            .unwrap();

        assert_eq!(reg.list_by_level(&NsLevel::Dept).len(), 2);
        assert_eq!(reg.list_by_level(&NsLevel::Project).len(), 1);
        assert_eq!(reg.list_by_level(&NsLevel::User).len(), 0);
    }

    #[test]
    fn test_descendants_by_level() {
        let mut reg = NamespaceRegistry::new();
        let d = reg.register(Namespace::dept("运营部"), None).unwrap();
        let p = reg
            .register(Namespace::project("固废平台"), Some(&d))
            .unwrap();
        reg.register(Namespace::user("张三"), Some(&p)).unwrap();
        reg.register(Namespace::user("李四"), Some(&p)).unwrap();

        let users = reg.descendants_by_level(&d, &NsLevel::User);
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_build_memoria_ns() {
        let ns = build_memoria_ns("agent-001", "/dept/运营部/project/固废平台");
        assert_eq!(ns, "agent/agent-001/dept/运营部/project/固废平台");
    }

    #[test]
    fn test_register_batch() {
        let mut reg = NamespaceRegistry::new();
        let result = reg.register_batch(vec![
            (Namespace::dept("运营部"), None),
            (
                Namespace::project("固废平台"),
                Some("/dept/运营部".to_string()),
            ),
            (
                Namespace::user("张三"),
                Some("/dept/运营部/project/固废平台".to_string()),
            ),
        ]);
        assert!(result.is_ok());
        assert_eq!(reg.count(), 3);
    }
}
