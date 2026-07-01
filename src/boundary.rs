//! ComplianceBoundary — 7 条红线
//!
//! 从 Python agent-base/core/boundary.py 翻译为 Rust。
//! 每条红线是一个独立模块，组合在 ComplianceBoundary 中统一检查。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ── 基本类型 ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionLevel {
    Read,
    Write,
    Dangerous,
    Admin,
}

impl PermissionLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "read" => PermissionLevel::Read,
            "write" => PermissionLevel::Write,
            "dangerous" => PermissionLevel::Dangerous,
            "admin" => PermissionLevel::Admin,
            _ => PermissionLevel::Read,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PermissionLevel::Read => "read",
            PermissionLevel::Write => "write",
            PermissionLevel::Dangerous => "dangerous",
            PermissionLevel::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlockLevel {
    Red,    // 不可绕过
    Yellow, // 需要确认
}

#[derive(Debug, Clone)]
pub struct ToolCheck {
    pub allow: bool,
    pub level: Option<BlockLevel>,
    pub reason: String,
}

impl ToolCheck {
    pub fn allow() -> Self {
        ToolCheck { allow: true, level: None, reason: String::new() }
    }
    pub fn red(reason: &str) -> Self {
        ToolCheck { allow: false, level: Some(BlockLevel::Red), reason: reason.to_string() }
    }
    pub fn yellow(reason: &str) -> Self {
        ToolCheck { allow: false, level: Some(BlockLevel::Yellow), reason: reason.to_string() }
    }
}

// ══════════════════════════════════════════════════════
// 第一条：权限递减红线
// ══════════════════════════════════════════════════════

/// 权限链：子代权限永远不超过父代
pub struct PermissionChain {
    chain: HashMap<String, PermissionLevel>,
}

impl PermissionChain {
    pub fn new() -> Self {
        PermissionChain { chain: HashMap::new() }
    }

    /// 注册 Agent 权限，返回最终权限等级
    pub fn register(
        &mut self,
        agent_id: &str,
        parent_id: Option<&str>,
        parent_permission: PermissionLevel,
    ) -> PermissionLevel {
        let level = match parent_id.and_then(|pid| self.chain.get(pid)) {
            Some(parent_level) => parent_level.min(&parent_permission).clone(),
            None => parent_permission,
        };
        self.chain.insert(agent_id.to_string(), level.clone());
        level
    }

    /// 检查是否有提权行为
    pub fn check_escalation(&self, agent_id: &str, requested: &PermissionLevel) -> bool {
        self.chain
            .get(agent_id)
            .map(|current| requested <= current)
            .unwrap_or(false)
    }
}

// ══════════════════════════════════════════════════════
// 第二条：代码与执行隔离红线
// ══════════════════════════════════════════════════════

pub struct ExecutionSandbox;

impl ExecutionSandbox {
    const REQUIRES_SANDBOX: &'static [&'static str] = &[
        "exec_code", "exec_shell", "exec_sql_raw", "exec_python", "run_script",
    ];
    const REQUIRES_REVIEW: &'static [&'static str] = &[
        "delete_", "batch_", "shutdown_",
    ];

    pub fn check(tool_name: &str) -> ToolCheck {
        for pattern in Self::REQUIRES_SANDBOX {
            if tool_name == *pattern || tool_name.starts_with(pattern) {
                return ToolCheck::red(&format!("{} 必须在沙箱中执行", tool_name));
            }
        }
        for pattern in Self::REQUIRES_REVIEW {
            if tool_name.starts_with(pattern) {
                return ToolCheck::yellow(&format!("{} 需要人工审核", tool_name));
            }
        }
        ToolCheck::allow()
    }
}

// ══════════════════════════════════════════════════════
// 第三条：进化边界红线（治理层不可修改）
// ══════════════════════════════════════════════════════

pub struct GovernanceGuard;

impl GovernanceGuard {
    const GOVERNANCE_TOOLS: &'static [&'static str] = &[
        "modify_router_rules", "modify_permission_logic",
        "modify_kill_switch", "modify_alert_rules",
        "modify_audit_module", "modify_agent_key",
        "modify_boundary_config", "modify_red_lines",
        "disable_safety_check", "bypass_approval",
    ];

    pub fn is_governance(tool_name: &str) -> bool {
        Self::GOVERNANCE_TOOLS.contains(&tool_name)
            || tool_name.starts_with("modify_")
            || tool_name.starts_with("disable_")
            || tool_name.starts_with("bypass_")
    }
}

// ══════════════════════════════════════════════════════
// 第四条：数据出域红线
// ══════════════════════════════════════════════════════

pub struct DataExfiltrationGuard;

impl DataExfiltrationGuard {
    const EXPORT_TOOLS: &'static [&'static str] = &[
        "export_data", "send_email", "api_push", "webhook_send",
        "upload_file", "share_report",
    ];

    pub fn check_export(tool_name: &str) -> ToolCheck {
        if Self::EXPORT_TOOLS.contains(&tool_name) {
            return ToolCheck::red(&format!("{} 涉及数据外发，需要管理员审批", tool_name));
        }
        ToolCheck::allow()
    }

    pub fn check_cross_ns(namespaces: &[String]) -> ToolCheck {
        // 去重
        let mut unique: Vec<&str> = namespaces.iter().map(|s| s.as_str()).collect();
        unique.sort();
        unique.dedup();
        if unique.len() > 1 {
            return ToolCheck::red(&format!("跨 {} 个 namespace 聚合数据需要审批", unique.len()));
        }
        ToolCheck::allow()
    }
}

// ══════════════════════════════════════════════════════
// 第五条：全局终止红线（Kill Switch）
// ══════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub enum KillState {
    Running,
    SoftStop,   // L1：可恢复
    HardStop,   // L2：需人工恢复
    Killed,     // L3：物理终止
}

pub struct KillSwitch {
    state: Mutex<KillState>,
}

impl KillSwitch {
    pub fn new() -> Self {
        KillSwitch { state: Mutex::new(KillState::Running) }
    }

    pub fn trigger(&self, level: u32, reason: &str) {
        let new_state = match level {
            1 => KillState::SoftStop,
            2 => KillState::HardStop,
            3 => KillState::Killed,
            _ => KillState::SoftStop,
        };
        let mut state = self.state.lock().unwrap();
        *state = new_state;
        tracing::warn!("[KILL] L{} 熔断触发: {}", level, reason);
    }

    pub fn is_alive(&self) -> bool {
        *self.state.lock().unwrap() == KillState::Running
    }

    pub fn state(&self) -> KillState {
        self.state.lock().unwrap().clone()
    }
}

// ══════════════════════════════════════════════════════
// 第六条：身份唯一性（补充红线）
// ══════════════════════════════════════════════════════

/// 身份守卫：每个 Agent 必须有唯一可验证身份。
/// 实际实现依赖 Memoria 的 agent_registry 表（SHA-256 badge_token）。
/// 此处为编译期标记 trait。
pub trait IdentityGuard: Send + Sync {
    fn agent_id(&self) -> &str;
    fn namespace(&self) -> &str;
    fn verify_token(&self, token: &str) -> bool;
}

// ══════════════════════════════════════════════════════
// 第七条：供应链准入红线
// ══════════════════════════════════════════════════════

pub struct SupplyChainGuard {
    whitelist: Option<Vec<String>>,
}

impl SupplyChainGuard {
    pub fn new(whitelist: Option<Vec<String>>) -> Self {
        SupplyChainGuard { whitelist }
    }

    pub fn check_skill(&self, skill_name: &str, source: &str) -> ToolCheck {
        // 白名单检查
        if let Some(ref list) = self.whitelist {
            if !list.contains(&skill_name.to_string()) {
                return ToolCheck::yellow(&format!("技能 {} 不在白名单中", skill_name));
            }
        }
        // 来源检查
        if source != "local" && source != "builtin" {
            return ToolCheck::red(&format!("技能来源 {} 未通过安全审查", source));
        }
        ToolCheck::allow()
    }
}

// ══════════════════════════════════════════════════════
// 综合边界检查器
// ══════════════════════════════════════════════════════

pub struct ComplianceBoundary {
    pub perm_chain: Mutex<PermissionChain>,
    pub supply_chain: SupplyChainGuard,
    kill_switch: KillSwitch,
}

impl ComplianceBoundary {
    pub fn new(whitelist: Option<Vec<String>>) -> Self {
        ComplianceBoundary {
            perm_chain: Mutex::new(PermissionChain::new()),
            supply_chain: SupplyChainGuard::new(whitelist),
            kill_switch: KillSwitch::new(),
        }
    }

    /// 综合检查一次 tool 调用，按优先级顺序执行 7 条红线
    pub fn check_tool(
        &self,
        tool_name: &str,
        args: &serde_json::Value,
        agent_id: &str,
        user_role: &str,
        parent_permission: &PermissionLevel,
        namespaces: Option<&[String]>,
    ) -> ToolCheck {
        // ── ⑤ 全局终止：最优先 ──
        if !self.kill_switch.is_alive() {
            return ToolCheck::red(&format!("系统已终止（{:?}），拒绝所有操作", self.kill_switch.state()));
        }

        // ── ③ 进化边界：不可修改治理层 ──
        if GovernanceGuard::is_governance(tool_name) {
            self.kill_switch.trigger(2, &format!("试图修改治理层: {}", tool_name));
            return ToolCheck::red(&format!("红线：{} 属于治理层，Agent 不可修改", tool_name));
        }

        // ── ② 代码与执行隔离 ──
        let sandbox = ExecutionSandbox::check(tool_name);
        if !sandbox.allow {
            return sandbox;
        }

        // ── ⑦ 供应链准入：白名单 ──
        let sc = self.supply_chain.check_skill(tool_name, "local");
        if !sc.allow {
            return sc;
        }

        // ── ④ 数据出域 ──
        let export = DataExfiltrationGuard::check_export(tool_name);
        if !export.allow {
            return export;
        }

        if let Some(ns) = namespaces {
            let cross = DataExfiltrationGuard::check_cross_ns(ns);
            if !cross.allow {
                return cross;
            }
        }

        // ── ① 权限递减（使用 user_role + parent_permission）──
        let role_base = match user_role {
            "admin" => PermissionLevel::Admin,
            "guard" => PermissionLevel::Read,
            "shower" => PermissionLevel::Read,
            _ => PermissionLevel::Write, // manage / user 默认 Write
        };

        // parent_permission 限制：子代权限不能超过父代
        let effective_max = role_base.min(parent_permission.clone());

        let level = classify_skill(tool_name);
        if level == "unknown" {
            return ToolCheck::allow();
        }

        let requested = PermissionLevel::from_str(level);

        // 检查参数安全性（SQL 注入 / 路径穿越）
        if let Some(obj) = args.as_object() {
            for (key, val) in obj {
                if val.is_string() {
                    let s = val.as_str().unwrap_or("");
                    // SQL 注入检测
                    if s.contains("' --") || s.contains("';") || s.to_uppercase().contains(" UNION ") {
                        return ToolCheck::red(&format!("参数安全检查：{} 含可疑 SQL 内容", key));
                    }
                    // 路径穿越检测
                    if s.contains("../") || s.contains("..\\") {
                        return ToolCheck::red(&format!("参数安全检查：{} 含路径穿越", key));
                    }
                }
            }
        }

        // 权限逐级检查：当前授予权限 >= 角色基础 >= 工具要求
        if !self.perm_chain.lock().unwrap().check_escalation(agent_id, &requested) {
            return ToolCheck::yellow(&format!(
                "权限递减：{} 需要 {}，但当前 Agent 权限不足", tool_name, requested.as_str()
            ));
        }

        if &requested > &effective_max {
            return ToolCheck::yellow(&format!(
                "权限递减：{} 需要 {}，但用户角色 {} 最高 {}",
                tool_name, requested.as_str(), user_role, effective_max.as_str()
            ));
        }

        // ── 正常放行 ──
        ToolCheck::allow()
    }

    pub fn kill_switch(&self) -> &KillSwitch {
        &self.kill_switch
    }
}

/// 技能分类（简化版，从 Python GUFEI_CLASSIFICATION 翻译）
fn classify_skill(tool_name: &str) -> &'static str {
    let read_tools = [
        "query_plate", "query_sql", "search_memory",
        "check_status", "get_statistics", "validate_data",
        "detect_anomaly", "get_context", "check_media",
        "review_data", "diagnose_system", "archive_ocr",
        "query_archive_log", "system_ops", "code_reader",
        "summarize_url", "read_docx", "read_xlsx",
    ];
    let write_tools = [
        "fill_excel_log", "update_whitelist", "archive_manifest",
        "manage_whitelist", "manage_holiday", "generate_month_log",
        "archive_operate", "organize_folders",
    ];
    let dangerous_tools = [
        "delete_entrance_record", "batch_update_whitelist",
        "shutdown_agent", "batch_delete_memories",
    ];

    if read_tools.contains(&tool_name) { return "read"; }
    if write_tools.contains(&tool_name) { return "write"; }
    if dangerous_tools.contains(&tool_name) { return "dangerous"; }
    "unknown"
}

// ══════════════════════════════════════════════════════
// 测试
// ══════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_chain() {
        let mut chain = PermissionChain::new();
        let level = chain.register("child", Some("parent"), PermissionLevel::Read);
        assert_eq!(level, PermissionLevel::Read);
        assert!(chain.check_escalation("child", &PermissionLevel::Read));
        assert!(!chain.check_escalation("child", &PermissionLevel::Write));
    }

    #[test]
    fn test_permission_descent() {
        let mut chain = PermissionChain::new();
        chain.register("admin", None, PermissionLevel::Admin);
        chain.register("dept-head", Some("admin"), PermissionLevel::Write);
        chain.register("staff", Some("dept-head"), PermissionLevel::Read);

        // staff 不能使用 write 工具
        assert!(!chain.check_escalation("staff", &PermissionLevel::Write));
        // dept-head 可以
        assert!(chain.check_escalation("dept-head", &PermissionLevel::Write));
    }

    #[test]
    fn test_execution_sandbox() {
        let r = ExecutionSandbox::check("exec_shell");
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));

        let r = ExecutionSandbox::check("query_plate");
        assert!(r.allow);
    }

    #[test]
    fn test_governance_guard() {
        assert!(GovernanceGuard::is_governance("modify_permission_logic"));
        assert!(GovernanceGuard::is_governance("disable_safety_check"));
        assert!(!GovernanceGuard::is_governance("query_plate"));
    }

    #[test]
    fn test_data_exfiltration() {
        let r = DataExfiltrationGuard::check_export("send_email");
        assert!(!r.allow);

        let r = DataExfiltrationGuard::check_export("query_plate");
        assert!(r.allow);

        let r = DataExfiltrationGuard::check_cross_ns(&[
            "dept/finance".to_string(),
            "dept/ops".to_string(),
        ]);
        assert!(!r.allow);
    }

    #[test]
    fn test_kill_switch() {
        let ks = KillSwitch::new();
        assert!(ks.is_alive());

        ks.trigger(3, "test");
        assert!(!ks.is_alive());
        assert_eq!(ks.state(), KillState::Killed);
    }

    #[test]
    fn test_supply_chain() {
        let guard = SupplyChainGuard::new(Some(vec!["query_sql".to_string()]));
        assert!(guard.check_skill("query_sql", "local").allow);
        assert!(!guard.check_skill("query_plate", "local").allow);

        let guard = SupplyChainGuard::new(None);
        assert!(guard.check_skill("anything", "local").allow);
    }

    #[test]
    fn test_compliance_boundary_full() {
        let mut boundary = ComplianceBoundary::new(None);

        // 注册 test-agent 的权限
        boundary.perm_chain.lock().unwrap()
            .register("test-agent", None, PermissionLevel::Write);

        // 正常工具应该放行
        let r = boundary.check_tool("query_plate", &serde_json::json!({}),
                                    "test-agent", "user", &PermissionLevel::Write, None);
        assert!(r.allow, "query_plate 应放行: {:?}", r);

        // 治理工具应拦截
        let r = boundary.check_tool("modify_red_lines", &serde_json::json!({}),
                                    "test-agent", "user", &PermissionLevel::Write, None);
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));
    }

    #[test]
    fn test_boundary_with_whitelist() {
        let mut boundary = ComplianceBoundary::new(Some(vec!["query_sql".to_string()]));

        // 注册权限
        boundary.perm_chain.lock().unwrap()
            .register("test-agent", None, PermissionLevel::Write);

        // 在白名单中
        let r = boundary.check_tool("query_sql", &serde_json::json!({}),
                                    "test-agent", "user", &PermissionLevel::Write, None);
        assert!(r.allow, "query_sql 应在白名单中: {:?}", r);

        // 不在白名单中
        let r = boundary.check_tool("query_plate", &serde_json::json!({}),
                                    "test-agent", "user", &PermissionLevel::Write, None);
        assert!(!r.allow, "query_plate 应被白名单拦截: {:?}", r);
    }

    #[test]
    fn test_kill_switch_blocks_all() {
        let mut boundary = ComplianceBoundary::new(None);
        boundary.perm_chain.lock().unwrap()
            .register("test-agent", None, PermissionLevel::Write);
        boundary.kill_switch().trigger(3, "emergency");

        let r = boundary.check_tool("query_plate", &serde_json::json!({}),
                                    "test-agent", "user", &PermissionLevel::Write, None);
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));
    }
}
