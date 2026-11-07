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

// ═══════════════════════════════════════════════════════════════════════════
// D0 命名空间分流修复（2026-11-06，方案 tech-docs/2026-11-06_D0-命名空间分流缺陷修复方案_v1.1.md）
//
// 单一决策入口 resolve_memory_ns：落库 NS 只由认证身份（NsCaller）+ persona 归属
// 决定，session_id 永远只做会话隔离（R1）。策略配置驱动，legacy = 旧行为秒级回滚。
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

/// NS 解析策略：`identity` = 认证身份路由（新）；`legacy` = 旧行为（session_id 推导，回滚用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NsPolicy {
    Identity,
    Legacy,
}

/// `[namespace]` 配置块（agent.toml）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NamespaceConfig {
    pub policy: NsPolicy,
    pub user_prefix: String,
    pub main_ns: String,
    pub quarantine_ns: String,
    pub reject_unattributed: bool,
    /// 只读封存名单：任何调用方（含 admin）不得写入；读不受限（D3）
    pub write_deny_ns: Vec<String>,
    /// P0-0 观测开关：每次解析写 ns_audit 结构化日志
    pub log_origin: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        NamespaceConfig {
            policy: NsPolicy::Identity,
            user_prefix: "agent".to_string(),
            main_ns: "agent/xujiayan".to_string(),
            quarantine_ns: "agent/_unattributed".to_string(),
            reject_unattributed: false,
            write_deny_ns: vec![
                "agent/user".to_string(),
                "agent/user/user/user".to_string(),
            ],
            log_origin: true,
        }
    }
}

impl NamespaceConfig {
    /// 生效策略：环境变量 `NAMESPACE_POLICY=legacy|identity` 覆盖 toml（回滚杠杆）
    pub fn effective_policy(&self) -> NsPolicy {
        match std::env::var("NAMESPACE_POLICY").ok().as_deref().map(str::trim) {
            Some("legacy") => NsPolicy::Legacy,
            Some("identity") => NsPolicy::Identity,
            _ => self.policy,
        }
    }

    pub fn is_write_denied(&self, ns: &str) -> bool {
        self.write_deny_ns.iter().any(|d| d == ns)
    }
}

/// 认证后的请求调用方（agent-core `authenticate` 解析结果；System 内部任务传 None）
#[derive(Debug, Clone)]
pub struct NsCaller {
    /// authenticate 解析的身份（登录态 = 真实 user_id；legacy = 随机安装ID）
    pub user_id: String,
    /// memoria 反查授权
    pub allowed_ns: Vec<String>,
    /// 仅 x-user-tag（无 x-agent-id）的 legacy 安装身份（D4：不建 NS）
    pub from_usertag: bool,
}

/// NS 决策来源（审计用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsOrigin {
    ExplicitAllowed,
    System,
    Persona,
    IdentityAdmin,
    Identity,
    Quarantine,
    /// policy=legacy 回滚路径（旧行为，不参与身份判定）
    Legacy,
}

impl std::fmt::Display for NsOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NsOrigin::ExplicitAllowed => "ExplicitAllowed",
            NsOrigin::System => "System",
            NsOrigin::Persona => "Persona",
            NsOrigin::IdentityAdmin => "IdentityAdmin",
            NsOrigin::Identity => "Identity",
            NsOrigin::Quarantine => "Quarantine",
            NsOrigin::Legacy => "Legacy",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone)]
pub struct NsDecision {
    pub ns: String,
    pub origin: NsOrigin,
}

#[derive(Debug)]
pub enum NsError {
    /// 显式 ns 未获授权（R4）
    Forbidden(String),
    /// 命中只读封存黑名单（D3）
    WriteDenied(String),
    /// 无身份且 reject_unattributed=true
    NoIdentity,
}

impl std::fmt::Display for NsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NsError::Forbidden(ns) => write!(f, "namespace 未授权: {}", ns),
            NsError::WriteDenied(ns) => write!(f, "namespace 只读封存: {}", ns),
            NsError::NoIdentity => write!(f, "无认证身份且策略拒绝无归属写入"),
        }
    }
}

/// 授权判定：target == granted，或 target 是 granted 的**子级**（仅子树向下；禁止祖先方向，R4/D3）
pub fn ns_grants_access(allowed_ns: &[String], target: &str) -> bool {
    allowed_ns
        .iter()
        .any(|g| g == target || target.starts_with(&format!("{}/", g)))
}

fn caller_is_admin(caller: &NsCaller) -> bool {
    caller.user_id == "admin" || caller.allowed_ns.iter().any(|s| s == "*")
}

/// 记忆 NS 单一决策入口（D0 修复核心）。
///
/// 决策优先级：显式(校验后) > System > 本人 persona > admin 主库 > 认证 user_id > 拒绝/隔离。
///
/// - `caller`: Request 身份（chat 三入口绑定）；`None` = 服务内部任务（tick/oncall，R6）
/// - `persona`: 会话绑定的 persona `(memory_namespace, owner_user_id)`
/// - `explicit`: 客户端显式传入的 namespace（必须过授权校验）。
///   ⚠️ 当前生产调用方 `caller_ns` 恒传 None——chat 链路的显式 namespace 参数由
///   memoria 侧 `check_ns_access` 强制执行（web_api 各路由）；本分支为防御纵深 +
///   后续入口接线预留（OCR round2 low，备忘）
pub fn resolve_memory_ns(
    cfg: &NamespaceConfig,
    caller: Option<&NsCaller>,
    persona: Option<(&str, &str)>,
    explicit: Option<&str>,
) -> Result<NsDecision, NsError> {
    // 0) 显式 ns：黑名单 → 授权（仅 ==/子级；admin/System 信任）→ ExplicitAllowed
    if let Some(ns) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        if cfg.is_write_denied(ns) {
            return Err(NsError::WriteDenied(ns.to_string()));
        }
        let ok = match caller {
            None => true,
            Some(c) => caller_is_admin(c) || ns_grants_access(&c.allowed_ns, ns),
        };
        return if ok {
            Ok(NsDecision {
                ns: ns.to_string(),
                origin: NsOrigin::ExplicitAllowed,
            })
        } else {
            Err(NsError::Forbidden(ns.to_string()))
        };
    }
    // System（R6）：persona 绑定 → persona ns；否则隔离区（保护主库纯净；origin=System 可审计）
    let Some(c) = caller else {
        return Ok(match persona {
            Some((ns, _)) if !ns.trim().is_empty() => NsDecision {
                ns: ns.to_string(),
                origin: NsOrigin::System,
            },
            _ => NsDecision {
                ns: cfg.quarantine_ns.clone(),
                origin: NsOrigin::System,
            },
        });
    };
    // persona：owner 严格相等（与 chat_inner 绑定处同规则，D1）
    if let Some((ns, owner)) = persona {
        if !ns.trim().is_empty() && owner == c.user_id {
            return Ok(NsDecision {
                ns: ns.to_string(),
                origin: NsOrigin::Persona,
            });
        }
    }
    // admin（D2）：先于 Identity —— user_id="admin" 不得新建 agent/admin
    if caller_is_admin(c) {
        return Ok(NsDecision {
            ns: cfg.main_ns.clone(),
            origin: NsOrigin::IdentityAdmin,
        });
    }
    // Identity（R1/D4）：真实登录用户；排除默认身份 "user" 与 legacy 安装ID
    if !c.from_usertag && !c.user_id.is_empty() && c.user_id != "user" {
        let ns = format!("{}/{}", cfg.user_prefix, c.user_id);
        if cfg.is_write_denied(&ns) {
            return Err(NsError::WriteDenied(ns));
        }
        return Ok(NsDecision {
            ns,
            origin: NsOrigin::Identity,
        });
    }
    // 无身份 / legacy 安装ID / 默认身份（R2，§14-2 拍板：隔离）
    if cfg.reject_unattributed {
        return Err(NsError::NoIdentity);
    }
    Ok(NsDecision {
        ns: cfg.quarantine_ns.clone(),
        origin: NsOrigin::Quarantine,
    })
}

/// 无身份会话的写调用是否应被拒绝（2026-11-07）。
///
/// 抽成纯函数以便单测覆盖 `call_tool_routed` 的判定分支：
/// 只有「开关打开 + 错误确为 NoIdentity + 工具非只读」三者同时成立才拒绝；
/// 只读工具、其它 NsError、开关关闭时一律放行/走隔离区兜底（fail-open 保持旧行为）。
pub fn should_reject_unattributed(
    cfg: &NamespaceConfig,
    no_identity: bool,
    tool_is_read_only: bool,
) -> bool {
    cfg.reject_unattributed && no_identity && !tool_is_read_only
}

#[cfg(test)]
mod ns_resolver_tests {
    use super::*;

    fn cfg() -> NamespaceConfig {
        NamespaceConfig::default()
    }

    fn caller(user_id: &str, allowed: &[&str]) -> NsCaller {
        NsCaller {
            user_id: user_id.to_string(),
            allowed_ns: allowed.iter().map(|s| s.to_string()).collect(),
            from_usertag: false,
        }
    }

    #[test]
    fn explicit_allowed_for_granted_user() {
        let c = caller("u_x", &["agent/u_x"]);
        let d = resolve_memory_ns(&cfg(), Some(&c), None, Some("agent/u_x/sub")).unwrap();
        assert_eq!((d.ns.as_str(), d.origin), ("agent/u_x/sub", NsOrigin::ExplicitAllowed));
    }

    #[test]
    fn explicit_forbidden_without_grant() {
        let c = caller("u_x", &["agent/u_x"]);
        assert!(matches!(
            resolve_memory_ns(&cfg(), Some(&c), None, Some("agent/xujiayan")),
            Err(NsError::Forbidden(_))
        ));
    }

    #[test]
    fn explicit_deny_list_blocks_even_admin() {
        let c = caller("admin", &["*"]);
        assert!(matches!(
            resolve_memory_ns(&cfg(), Some(&c), None, Some("agent/user")),
            Err(NsError::WriteDenied(_))
        ));
    }

    #[test]
    fn system_with_persona_uses_persona_ns() {
        let d = resolve_memory_ns(&cfg(), None, Some(("agent/xujiayan", "pai")), None).unwrap();
        assert_eq!((d.ns.as_str(), d.origin), ("agent/xujiayan", NsOrigin::System));
    }

    #[test]
    fn system_without_persona_goes_quarantine() {
        let d = resolve_memory_ns(&cfg(), None, None, None).unwrap();
        assert_eq!((d.ns.as_str(), d.origin), ("agent/_unattributed", NsOrigin::System));
    }

    #[test]
    fn persona_owner_match() {
        let c = caller("user", &[]);
        let d = resolve_memory_ns(&cfg(), Some(&c), Some(("agent/xujiayan", "user")), None).unwrap();
        assert_eq!((d.ns.as_str(), d.origin), ("agent/xujiayan", NsOrigin::Persona));
    }

    #[test]
    fn persona_owner_mismatch_falls_through() {
        let c = caller("u_x", &["agent/u_x"]);
        let d = resolve_memory_ns(&cfg(), Some(&c), Some(("agent/xujiayan", "user")), None).unwrap();
        assert_eq!(d.origin, NsOrigin::Identity);
        assert_eq!(d.ns, "agent/u_x");
    }

    #[test]
    fn admin_role_uses_main_ns() {
        let c = caller("admin", &["*"]);
        let d = resolve_memory_ns(&cfg(), Some(&c), None, None).unwrap();
        assert_eq!((d.ns.as_str(), d.origin), ("agent/xujiayan", NsOrigin::IdentityAdmin));
    }

    #[test]
    fn admin_literal_user_id_never_creates_agent_admin() {
        let c = caller("admin", &[]);
        let d = resolve_memory_ns(&cfg(), Some(&c), None, None).unwrap();
        assert_eq!(d.ns, "agent/xujiayan");
    }

    #[test]
    fn identity_resolves_single_layer() {
        let c = caller("许有康_u_e864p91o736d", &["agent/许有康_u_e864p91o736d"]);
        let d = resolve_memory_ns(&cfg(), Some(&c), None, None).unwrap();
        assert_eq!(d.ns, "agent/许有康_u_e864p91o736d");
        assert_eq!(d.origin, NsOrigin::Identity);
    }

    #[test]
    fn legacy_usertag_quarantines() {
        let mut c = caller("install-abc123", &[]);
        c.from_usertag = true;
        let d = resolve_memory_ns(&cfg(), Some(&c), None, None).unwrap();
        assert_eq!(d.origin, NsOrigin::Quarantine);
    }

    #[test]
    fn default_identity_user_quarantines() {
        let c = caller("user", &[]);
        let d = resolve_memory_ns(&cfg(), Some(&c), None, None).unwrap();
        assert_eq!(d.origin, NsOrigin::Quarantine);
    }

    #[test]
    fn reject_unattributed_errors() {
        let mut c = cfg();
        c.reject_unattributed = true;
        let caller = caller("user", &[]);
        assert!(matches!(
            resolve_memory_ns(&c, Some(&caller), None, None),
            Err(NsError::NoIdentity)
        ));
    }

    #[test]
    fn grants_access_child_only_not_ancestor() {
        let allowed = vec!["agent/u_x".to_string()];
        assert!(ns_grants_access(&allowed, "agent/u_x"));
        assert!(ns_grants_access(&allowed, "agent/u_x/sub"));
        // 祖先方向必须拒绝（D3：普通账号不得借父级写入共享桶）
        assert!(!ns_grants_access(&allowed, "agent"));
    }

    /// 2026-11-07：reject_unattributed 判定矩阵——确保开关真正生效且不误伤读/其它错误
    #[test]
    fn unattributed_write_reject_decision() {
        let mut c = cfg();
        // 默认 false：即便无身份 + 写工具也不拒绝（生产现状，行为不变）
        assert!(!should_reject_unattributed(&c, true, false));
        c.reject_unattributed = true;
        assert!(should_reject_unattributed(&c, true, false)); // 无身份写 → 拒
        assert!(!should_reject_unattributed(&c, true, true)); // 只读工具 → 放行
        assert!(!should_reject_unattributed(&c, false, false)); // 其它 NsError → 隔离区兜底
    }

    #[test]
    fn default_config_values() {
        let c = NamespaceConfig::default();
        // 仅断言 toml 解析值；effective_policy() 读进程环境变量 NAMESPACE_POLICY，
        // 回滚 shell 中可能被置 legacy，不作测试输入（OCR round2 low）。
        assert_eq!(c.policy, NsPolicy::Identity);
        assert!(c.is_write_denied("agent/user"));
        assert!(c.is_write_denied("agent/user/user/user"));
        assert!(!c.is_write_denied("agent/xujiayan"));
    }
}
