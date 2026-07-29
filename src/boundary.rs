//! ComplianceBoundary — 7 条红线
//!
//! 从 Python agent-base/core/boundary.py 翻译为 Rust。
//! 每条红线是一个独立模块，组合在 ComplianceBoundary 中统一检查。

pub mod prompt_injection;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

// ── 安全锁辅助函数（锁中毒时优雅降级，不 panic）──

/// 安全获取 KillState 锁，中毒时假定 Running
fn lock_state(mutex: &Mutex<KillState>) -> KillState {
    match mutex.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            tracing::error!("KillState Mutex 中毒，降级为 Running");
            KillState::Running
        }
    }
}

/// 安全获取 ToolClassifier 锁并执行操作
fn with_classifier<F, R>(mutex: &Mutex<ToolClassifier>, default: R, f: F) -> R
where
    F: FnOnce(&ToolClassifier) -> R,
{
    match mutex.lock() {
        Ok(guard) => f(&guard),
        Err(_) => {
            tracing::error!("ToolClassifier Mutex 中毒，使用默认值");
            default
        }
    }
}

/// C1a: 危险工具精确集（堵漏判的最后一道闸）。
/// agent-core 内置 + memoria 路由危险工具（经 self.mcp 调用，权限归 memoria permissions.rs）。
/// 实现时按真实工具名 grep 确认（无 memory_forget/memory_delete 等），仅收录已核实存在者。
const HARD_DANGEROUS: &[&str] = &[
    // agent-core 内置危险工具
    "delete_entrance_record",
    "shutdown_agent",
    "batch_delete_memories",
    "delete_record",
    "shutdown_server",
    // 本仓沙箱写文件：必须走黄线/审批，禁止当普通 write 静默落盘
    "local_fs_write",
    // 白名单/改码写：无论分类器如何，强制危险地板 → L2 黄线
    "sync_whitelist_plates",
    "manage_whitelist",
    "edit_code",
    // memoria 路由危险工具（写操作 / 演化 / 身份）
    "memory_merge",
    "memory_dedup_chain",
    "memory_evolve",
    "memory_evolve_auto",
    "evolution_rollback",
    "agent_revoke",
    "register_agent",
];

// ── SQL 只读校验（P1-6 修复）──
// query_sql 等工具归为 read 级，但 read 权限不应等同于"可执行任意 SQL"。
// 这里做**正向** SELECT-only 校验：语句必须以 SELECT/WITH/EXPLAIN/PRAGMA 开头，
// 且不得包含任何写/DDL 关键字（INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/...）。

/// 去除 SQL 中的注释与字符串字面量，避免关键字出现在注释/字符串内误判
fn normalize_sql_for_check(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut in_block = false;
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_block {
            if c == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                in_block = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if in_single {
            if c == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if c == '-' && i + 1 < chars.len() && chars[i + 1] == '-' {
            // 跳过整行注释
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            in_block = true;
            i += 2;
            continue;
        }
        if c == '\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = true;
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out.to_lowercase()
}

/// 整词匹配关键字
fn contains_word(haystack: &str, word: &str) -> bool {
    for w in haystack.split_whitespace() {
        // 去掉尾随标点后再比较（如 "delete;" / "delete"）
        let cleaned: String = w
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if cleaned == word {
            return true;
        }
    }
    false
}

/// 正向校验 SQL 为只读语句
fn is_select_only(sql: &str) -> bool {
    // 防御：只读查询不需要语句分隔符 `;`。直接拒绝含 `;` 的入参，
    // 彻底阻断 `SELECT ...;DELETE ...` 拼接绕过（B1 修复）。
    if sql.contains(';') {
        return false;
    }
    let norm = normalize_sql_for_check(sql);
    let first = norm.split_whitespace().next().unwrap_or("");
    let starts_ok = matches!(first, "select" | "with" | "explain" | "pragma");
    let forbidden = [
        "insert", "update", "delete", "drop", "alter", "create", "truncate", "attach", "replace",
        "merge", "grant", "revoke", "vacuum",
    ];
    let no_write = !forbidden.iter().any(|kw| contains_word(&norm, kw));
    starts_ok && no_write
}

/// 是否为 SQL 执行类工具的查询参数（需要 SELECT-only 校验）
fn is_sql_query_param(tool_name: &str, key: &str) -> bool {
    let key = key.to_lowercase();
    let is_sql_tool =
        tool_name == "query_sql" || tool_name.starts_with("query_") || tool_name.contains("sql");
    let is_sql_arg = matches!(key.as_str(), "query" | "sql" | "statement" | "sql_text");
    is_sql_tool && is_sql_arg
}

/// 安全获取 PermissionChain 锁并执行操作
pub fn with_perm_chain<F, R>(mutex: &Mutex<PermissionChain>, default: R, f: F) -> R
where
    F: FnOnce(&PermissionChain) -> R,
{
    match mutex.lock() {
        Ok(guard) => f(&guard),
        Err(_) => {
            tracing::error!("PermissionChain Mutex 中毒，使用默认值");
            default
        }
    }
}

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
        ToolCheck {
            allow: true,
            level: None,
            reason: String::new(),
        }
    }
    pub fn red(reason: &str) -> Self {
        ToolCheck {
            allow: false,
            level: Some(BlockLevel::Red),
            reason: reason.to_string(),
        }
    }
    pub fn yellow(reason: &str) -> Self {
        ToolCheck {
            allow: false,
            level: Some(BlockLevel::Yellow),
            reason: reason.to_string(),
        }
    }
    /// 放行但附带说明（如"已在沙箱内执行"），reason 仅作审计记录
    pub fn allow_note(reason: &str) -> Self {
        ToolCheck {
            allow: true,
            level: None,
            reason: reason.to_string(),
        }
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
        PermissionChain {
            chain: HashMap::new(),
        }
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

/// 沙箱启用开关（进程级，默认启用）。未启用时任何 require-sandbox 的工具一律红闸硬拦，
/// 避免"门控被架空"——这正是此前 `exec_*` 只有门控、无实现时的语义漏洞。
static SANDBOX_ENABLED: AtomicBool = AtomicBool::new(true);

pub struct ExecutionSandbox;

impl ExecutionSandbox {
    const REQUIRES_SANDBOX: &'static [&'static str] = &[
        "exec_code",
        "exec_shell",
        "exec_sql_raw",
        "exec_python",
        "run_script",
        "local_fs_read",
        "local_fs_write",
        "local_fs_list",
        "local_fs_stat",
    ];
    const REQUIRES_REVIEW: &'static [&'static str] = &["delete_", "batch_", "shutdown_"];

    /// 设置沙箱启用状态（main 启动时按配置调用；默认 true）
    pub fn set_enabled(v: bool) {
        SANDBOX_ENABLED.store(v, Ordering::SeqCst);
    }

    pub fn is_enabled() -> bool {
        SANDBOX_ENABLED.load(Ordering::SeqCst)
    }

    /// 检查工具是否需在沙箱内执行。
    /// - `path`：可选的文件路径参数，命中敏感 deny 列表或越出严格沙箱根时红闸拦截。
    /// - 沙箱未启用 → 任何 require-sandbox 工具硬拦（绝不裸跑）。
    pub fn check(tool_name: &str, path: Option<&Path>) -> ToolCheck {
        let requires = Self::REQUIRES_SANDBOX
            .iter()
            .any(|p| tool_name == *p || tool_name.starts_with(p));
        if requires {
            if !Self::is_enabled() {
                return ToolCheck::red(&format!(
                    "{} 必须在沙箱中执行，但沙箱未启用（拒绝裸跑）",
                    tool_name
                ));
            }
            if let Some(p) = path {
                if let Some(reason) = Self::path_violation(p) {
                    return ToolCheck::red(&format!("{} 沙箱路径门闸：{}", tool_name, reason));
                }
                // 若配置了严格沙箱根，越界即拦（未配置则仅 deny 列表生效，避免误伤合法读盘）
                if let Some(root) = crate::sandbox::resolve_sandbox_root() {
                    if !Self::under_root(p, &root) {
                        return ToolCheck::red(&format!(
                            "{} 试图访问沙箱根 {:?} 之外的路径 {:?}",
                            tool_name,
                            root,
                            p
                        ));
                    }
                }
            }
            return ToolCheck::allow_note(&format!("{} 已在沙箱内执行", tool_name));
        }
        for pattern in Self::REQUIRES_REVIEW {
            if tool_name.starts_with(pattern) {
                return ToolCheck::yellow(&format!("{} 需要人工审核", tool_name));
            }
        }
        ToolCheck::allow()
    }

    /// 敏感路径组件 / 文件名（命中即视为越界，沙箱内也禁读）
    const DENY_COMPONENTS: &'static [&'static str] =
        &[".ssh", ".gnupg", ".aws", ".azure", ".config/gcloud"];
    const DENY_FILENAMES: &'static [&'static str] = &[
        "id_ed25519",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519.pub",
        "credentials",
        "gserviceaccount.json",
    ];

    /// 返回命中敏感路径的原因（用于红闸 reason），无违规则 None
    fn path_violation(p: &Path) -> Option<String> {
        let norm = normalize(p);
        for comp in Self::DENY_COMPONENTS {
            let want = std::ffi::OsStr::new(*comp);
            if norm.components().any(|c| c.as_os_str() == want) {
                return Some(format!("命中敏感目录组件 {}", comp));
            }
        }
        if let Some(name) = norm.file_name() {
            let n = name.to_string_lossy().to_lowercase();
            if Self::DENY_FILENAMES.contains(&n.as_str()) || n.ends_with(".pem") || n.ends_with(".key")
            {
                return Some(format!("命中敏感文件 {}", n));
            }
        }
        None
    }

    fn under_root(p: &Path, root: &Path) -> bool {
        normalize(p).starts_with(normalize(root))
    }
}

/// 把路径规范化为绝对、去 `..` 的形式（存在则 canonicalize，否则按 cwd 拼接后清理）
fn normalize(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    abs.canonicalize().unwrap_or_else(|_| {
        let mut out = PathBuf::new();
        for c in abs.components() {
            match c {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::CurDir => {}
                other => out.push(other.as_os_str()),
            }
        }
        out
    })
}

/// 参数级路径穿越检测（修复 C7）。
///
/// 原实现仅 `contains("../") || contains("..\\")`，可被 URL 编码（`%2e%2e%2f`、
/// `%2e%2e%5c`、`..%2f`）绕过。这里先对常见编码做一次反转义，再判定。
/// 注意：真正的文件系统路径访问走 `extract_path_arg` → `ExecutionSandbox::check`
/// → `normalize()` 规范化 + 前缀比对，本函数仅作为参数层的纵深防御补充。
fn has_path_traversal(s: &str) -> bool {
    if s.contains("../") || s.contains("..\\") {
        return true;
    }
    // 反转义常见百分号编码后再判定（大小写不敏感）
    let dec = s
        .replace("%2e", ".")
        .replace("%2f", "/")
        .replace("%5c", "\\")
        .to_lowercase();
    dec.contains("../") || dec.contains("..\\") || dec.contains("%2e%2e")
}

/// 从工具参数中抽取显式文件路径参数做门闸（命令型参数 command/code/sql 不含路径，不抽）
fn extract_path_arg(args: &serde_json::Value) -> Option<&Path> {
    const KEYS: &[&str] = &[
        "path",
        "file",
        "file_path",
        "filepath",
        "dir",
        "directory",
        "target",
    ];
    if let Some(obj) = args.as_object() {
        for k in KEYS {
            if let Some(v) = obj.get(*k) {
                if let Some(s) = v.as_str() {
                    return Some(Path::new(s));
                }
            }
        }
    }
    None
}

// ══════════════════════════════════════════════════════
// 第三条：进化边界红线（治理层不可修改）
// ══════════════════════════════════════════════════════

pub struct GovernanceGuard;

impl GovernanceGuard {
    const GOVERNANCE_TOOLS: &'static [&'static str] = &[
        "modify_router_rules",
        "modify_permission_logic",
        "modify_kill_switch",
        "modify_alert_rules",
        "modify_audit_module",
        "modify_agent_key",
        "modify_boundary_config",
        "modify_red_lines",
        "disable_safety_check",
        "bypass_approval",
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
        "export_data",
        "send_email",
        "api_push",
        "webhook_send",
        "upload_file",
        "share_report",
    ];
    const EXPORT_PREFIXES: &'static [&'static str] = &[
        "export_", "send_", "upload_", "push_", "webhook_", "exfil", "share_",
    ];

    pub fn check_export(tool_name: &str) -> ToolCheck {
        if Self::EXPORT_TOOLS.contains(&tool_name)
            || Self::EXPORT_PREFIXES
                .iter()
                .any(|p| tool_name.starts_with(p))
        {
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
            return ToolCheck::red(&format!(
                "跨 {} 个 namespace 聚合数据需要审批",
                unique.len()
            ));
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
    SoftStop, // L1：可恢复
    HardStop, // L2：需人工恢复
    Killed,   // L3：物理终止
}

/// KillSwitch 熔断器（带 hook 回调）
pub struct KillSwitch {
    state: Mutex<KillState>,
    on_trigger: Mutex<Vec<Box<dyn Fn(u32, &str) + Send + Sync>>>,
}

impl KillSwitch {
    pub fn new() -> Self {
        KillSwitch {
            state: Mutex::new(KillState::Running),
            on_trigger: Mutex::new(Vec::new()),
        }
    }

    /// 注册熔断回调（Python 版 hook 兼容）
    pub fn on_trigger<F>(&self, hook: F)
    where
        F: Fn(u32, &str) + Send + Sync + 'static,
    {
        if let Ok(mut hooks) = self.on_trigger.lock() {
            hooks.push(Box::new(hook));
        }
    }

    pub fn trigger(&self, level: u32, reason: &str) {
        let new_state = match level {
            1 => KillState::SoftStop,
            2 => KillState::HardStop,
            3 => KillState::Killed,
            _ => KillState::SoftStop,
        };
        match self.state.lock() {
            Ok(mut state) => {
                *state = new_state;
            }
            Err(_) => {
                tracing::error!("KillState Mutex 中毒，跳过状态更新");
            }
        }
        tracing::warn!("[KILL] L{} 熔断触发: {}", level, reason);
        // 执行所有注册的 hook 回调
        if let Ok(hooks) = self.on_trigger.lock() {
            for hook in hooks.iter() {
                hook(level, reason);
            }
        }
    }

    pub fn state(&self) -> KillState {
        lock_state(&self.state)
    }

    pub fn is_alive(&self) -> bool {
        lock_state(&self.state) == KillState::Running
    }
}

// ══════════════════════════════════════════════════════
// 第六条：身份唯一性（补充红线）
// ══════════════════════════════════════════════════════

/// 身份守卫：每个 Agent 必须有唯一可验证身份
pub trait IdentityGuard: Send + Sync {
    fn agent_id(&self) -> &str;
    fn namespace(&self) -> &str;
    fn verify_token(&self, token: &str) -> bool;
}

// ══════════════════════════════════════════════════════
// 第七条：供应链准入红线
// ══════════════════════════════════════════════════════
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
    pub classifier: Mutex<ToolClassifier>,
    /// 审批管理器（P2-D 接入 check_tool）
    pub approval_manager: crate::approval::ApprovalManager,
    /// Phase A (OpenClaw 吸收): 崩溃循环 safe_mode 闩锁。
    /// 进入后抑制危险/未分类/外发工具的自动执行，直至人工解除。
    /// 用 Arc<AtomicBool> 以支持 &self 下切换，且可与主流程共享同一标志。
    pub safe_mode: Arc<AtomicBool>,
}

impl ComplianceBoundary {
    pub fn new(whitelist: Option<Vec<String>>) -> Self {
        ComplianceBoundary {
            perm_chain: Mutex::new(PermissionChain::new()),
            supply_chain: SupplyChainGuard::new(whitelist),
            kill_switch: KillSwitch::new(),
            classifier: Mutex::new(ToolClassifier::new()),
            approval_manager: crate::approval::ApprovalManager::new(),
            safe_mode: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Phase A: 设置/清除 safe_mode 闩锁（&self 即可，因内部用 AtomicBool）。
    pub fn set_safe_mode(&self, on: bool) {
        self.safe_mode.store(on, Ordering::SeqCst);
    }

    /// Phase A: 读取当前 safe_mode 状态。
    pub fn is_safe_mode(&self) -> bool {
        self.safe_mode.load(Ordering::SeqCst)
    }

    /// 注册工具分类（运行时动态添加）
    pub fn register_tool(&self, tool_name: &str, level: &str) {
        match self.classifier.lock() {
            Ok(mut c) => c.register(tool_name, level),
            Err(_) => tracing::error!("ToolClassifier Mutex 中毒，跳过注册"),
        }
    }

    /// 从 MCP 工具列表批量学习分类
    pub fn learn_tools(&self, tools: &[(String, String)]) {
        match self.classifier.lock() {
            Ok(mut c) => c.register_from_tools(tools),
            Err(_) => tracing::error!("ToolClassifier Mutex 中毒，跳过学习"),
        }
    }

    /// C1a: 危险工具硬地板（精确集 ∪ 名称启发式）。
    ///
    /// 修正（评审 P0）：**不依赖分类器**——若工具被 `learn_tools` 误登为 `read`/`write`，
    /// 分类器返回的就是 `read`/`write`，抓不到误登。地板以 `HARD_DANGEROUS` 精确集与
    /// 破坏数据类前缀兜底，确保危险工具无论分类器如何都进入黄线（审批闸）。
    /// 既有 `is_dangerous_tool`（蒸馏门，空分类器版）保持不变，避免回归。
    pub fn is_dangerous_floor(&self, name: &str) -> bool {
        if HARD_DANGEROUS.contains(&name) {
            return true;
        }
        let l = name.to_lowercase();
        l.starts_with("delete_")
            || l.starts_with("batch_delete")
            || l.starts_with("shutdown_")
            || l.starts_with("drop_")
            || l.starts_with("truncate_")
            || l.starts_with("purge_")
            || l.starts_with("destroy_")
            || l.starts_with("wipe_")
            || l.starts_with("format_")
            || l.starts_with("reset_")
            || l.starts_with("revoke_")
            || l.starts_with("ban_")
            || l.starts_with("kill_")
            || l.starts_with("rm_")
    }

    /// C1c: 精简治理守卫（审批后执行前重跑）。
    ///
    /// 仅含「失败即红」的底线：kill_switch / safe_mode / 治理层 / 沙箱 / 出域 / SQL·路径参数。
    /// 刻意跳过：供应链白名单（已批准=信任静态白名单）、权限链、黄线重弹，
    /// 以及「跨 namespace 聚合」守卫（该守卫已在 `check_tool` 前置阶段触发审批，
    /// 一旦 ADMIN 批准即视为已授权，执行侧不再重复拦截——避免已批准项被自身守卫死锁）。
    /// 与 `call_tool_routed` 已有的 kill_switch 守卫重复，属 defense-in-depth（执行侧再卡一道）。
    pub fn hard_guards_only(
        &self,
        tool_name: &str,
        args: &serde_json::Value,
        _namespaces: Option<&[String]>,
    ) -> Option<ToolCheck> {
        if !self.kill_switch.is_alive() {
            return Some(ToolCheck::red("系统已终止，拒绝所有操作"));
        }
        if self.is_safe_mode() {
            let level = with_classifier(&self.classifier, "unknown", |c| c.classify(tool_name));
            let is_export = !DataExfiltrationGuard::check_export(tool_name).allow;
            if level == "dangerous" || level == "unknown" || is_export {
                return Some(ToolCheck::red(&format!(
                    "safe_mode 激活：抑制危险/未分类/外发工具 {}（需人工介入解除）",
                    tool_name
                )));
            }
        }
        if GovernanceGuard::is_governance(tool_name) {
            return Some(ToolCheck::red(&format!("红线：{} 属于治理层，Agent 不可修改", tool_name)));
        }
        let sandbox = ExecutionSandbox::check(tool_name, extract_path_arg(args));
        if !sandbox.allow {
            return Some(sandbox);
        }
        // 跳过 supply_chain（已批准=信任静态白名单）
        let export = DataExfiltrationGuard::check_export(tool_name);
        if !export.allow {
            return Some(export);
        }
        // 注：跨 namespace 聚合守卫已在前置 check_tool 触发审批，批准后不再重检（见函数文档）。
        if let Some(obj) = args.as_object() {
            for (key, val) in obj {
                if let Some(s) = val.as_str() {
                    let s_upper = s.to_uppercase();
                    if s.contains("' --")
                        || s.contains("';")
                        || s_upper.contains(" UNION ")
                        || s_upper.contains(" OR 1=1")
                        || s_upper.contains(" AND 1=1")
                        || s_upper.contains("DROP TABLE")
                        || s_upper.contains("INSERT INTO")
                        || s_upper.contains("DELETE FROM")
                        || (s_upper.contains("UPDATE ") && s_upper.contains("SET "))
                    {
                        return Some(ToolCheck::red(&format!("参数安全检查：{} 含可疑 SQL 内容", key)));
                    }
                    if has_path_traversal(s) {
                        return Some(ToolCheck::red(&format!("参数安全检查：{} 含路径穿越", key)));
                    }
                    if is_sql_query_param(tool_name, key) && !is_select_only(s) {
                        return Some(ToolCheck::red(&format!(
                            "参数安全检查：{} 必须是只读 SELECT 语句",
                            key
                        )));
                    }
                }
            }
        }
        None
    }

    /// 综合检查一次 tool 调用，按优先级顺序执行 7 条红线
    #[tracing::instrument(skip(self, args, parent_permission), fields(tool_name = %tool_name, agent_id = %agent_id, user_role))]
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
            return ToolCheck::red(&format!(
                "系统已终止（{:?}），拒绝所有操作",
                self.kill_switch.state()
            ));
        }

        // ── Phase A: safe_mode（崩溃循环后进入）──
        // 抑制危险/未分类/外发工具的「自动执行」，仅保留健康探针与运维 RPC。
        // 控制面（HTTP/WS）照常拉起，运维可连接诊断；危险操作需人工介入解除 safe_mode。
        if self.is_safe_mode() {
            let level = with_classifier(&self.classifier, "unknown", |c| c.classify(tool_name));
            let is_export = !DataExfiltrationGuard::check_export(tool_name).allow;
            if level == "dangerous" || level == "unknown" || is_export {
                return ToolCheck::red(&format!(
                    "safe_mode 激活：抑制危险/未分类/外发工具 {}（需人工介入解除）",
                    tool_name
                ));
            }
        }

        // ── ③ 进化边界：不可修改治理层 ──
        if GovernanceGuard::is_governance(tool_name) {
            self.kill_switch
                .trigger(2, &format!("试图修改治理层: {}", tool_name));
            return ToolCheck::red(&format!("红线：{} 属于治理层，Agent 不可修改", tool_name));
        }

        // ── ② 代码与执行隔离 ──
        let sandbox = ExecutionSandbox::check(tool_name, extract_path_arg(args));
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

        // ── ⑨ 审批检查：dangerous 级别工具需要审批（P2-D 接入）──
        // C1b: 已否决（短 TTL）→ 红闸；已批准（精确 op_hash，TTL 1h）→ 直接放行不弹黄线。
        // C1a: 危险地板（精确集 ∪ 启发式）与分类器 dangerous 一并触发黄线。
        if crate::approval::is_rejected_sync(&self.approval_manager, tool_name, agent_id) {
            return ToolCheck::red("该工具此前已被否决，须重新提交审批");
        }
        if !crate::approval::is_approved_sync(&self.approval_manager, tool_name, args, agent_id) {
            let tool_level = with_classifier(&self.classifier, "read".to_string(), |c| {
                c.classify(tool_name).to_string()
            });
            if tool_level == "dangerous" || self.is_dangerous_floor(tool_name) {
                return ToolCheck::yellow(&format!("{} 需要审批，请等待审批人确认", tool_name));
            }
            // 固废整理/归档写操作：非 dry_run 时走黄线（可控写改）
            if needs_dept_ops_write_approval(tool_name, args) {
                return ToolCheck::yellow(&format!(
                    "{} 会改动现场文件，请确认后执行（可先 dry_run=true 预览）",
                    tool_name
                ));
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

        let level = with_classifier(&self.classifier, "unknown", |c| c.classify(tool_name));
        if level == "unknown" {
            // P1-7 修复：unknown 工具不再直接放行，改为黄线需确认
            return ToolCheck::yellow(&format!("工具 {} 未分类，需要确认后执行", tool_name));
        }

        let requested = PermissionLevel::from_str(level);

        // 检查参数安全性（SQL 注入 / 路径穿越）
        if let Some(obj) = args.as_object() {
            for (key, val) in obj {
                if val.is_string() {
                    let s = val.as_str().unwrap_or("");
                    // SQL 注入检测（P2-7 增强）
                    let s_upper = s.to_uppercase();
                    if s.contains("' --")
                        || s.contains("';")
                        || s_upper.contains(" UNION ")
                        || s_upper.contains(" OR 1=1")
                        || s_upper.contains(" AND 1=1")
                        || s_upper.contains("DROP TABLE")
                        || s_upper.contains("INSERT INTO")
                        || s_upper.contains("DELETE FROM")
                        || s_upper.contains("UPDATE ") && s_upper.contains("SET ")
                    {
                        return ToolCheck::red(&format!("参数安全检查：{} 含可疑 SQL 内容", key));
                    }
                    // 路径穿越检测
                    if has_path_traversal(s) {
                        return ToolCheck::red(&format!("参数安全检查：{} 含路径穿越", key));
                    }
                    // P1-6 修复：SQL 只读强制（正向 SELECT-only 校验，替代仅靠负向 blocklist）
                    if is_sql_query_param(tool_name, key) && !is_select_only(s) {
                        return ToolCheck::red(&format!(
                            "参数安全检查：{} 必须是只读 SELECT 语句（禁止 INSERT/UPDATE/DELETE/DROP/ALTER 等写操作）",
                            key
                        ));
                    }
                }
            }
        }

        // 权限逐级检查：当前授予权限 >= 角色基础 >= 工具要求
        if !with_perm_chain(&self.perm_chain, false, |c| {
            c.check_escalation(agent_id, &requested)
        }) {
            return ToolCheck::yellow(&format!(
                "权限递减：{} 需要 {}，但当前 Agent 权限不足",
                tool_name,
                requested.as_str()
            ));
        }

        if &requested > &effective_max {
            return ToolCheck::yellow(&format!(
                "权限递减：{} 需要 {}，但用户角色 {} 最高 {}",
                tool_name,
                requested.as_str(),
                user_role,
                effective_max.as_str()
            ));
        }

        // ── 正常放行 ──
        ToolCheck::allow()
    }

    pub fn kill_switch(&self) -> &KillSwitch {
        &self.kill_switch
    }
}

/// 工具分类器（P1-7 修复：配置驱动 + 自动学习）
///
/// 保留内置默认分类，同时支持运行时动态注册和从 MCP tools/list 自动学习。
/// 新工具不再因 unknown 而绕过权限检查。
pub struct ToolClassifier {
    read_tools: std::collections::HashSet<String>,
    write_tools: std::collections::HashSet<String>,
    dangerous_tools: std::collections::HashSet<String>,
    unknown_tools: std::collections::HashSet<String>,
}

impl ToolClassifier {
    pub fn new() -> Self {
        let mut c = ToolClassifier {
            read_tools: std::collections::HashSet::new(),
            write_tools: std::collections::HashSet::new(),
            dangerous_tools: std::collections::HashSet::new(),
            unknown_tools: std::collections::HashSet::new(),
        };
        // 内置默认分类（保留原有列表）
        for t in [
            "query_plate",
            "query_sql",
            "search_memory",
            "check_status",
            "get_statistics",
            "validate_data",
            "detect_anomaly",
            "get_context",
            "check_media",
            "review_data",
            "diagnose_system",
            "archive_ocr",
            "query_archive_log",
            "system_ops",
            "code_reader",
            "verify_code",
            "summarize_url",
            "read_docx",
            "read_xlsx",
            // 真实 MCP 工具名（dashboard stdio skills）兜底，避免首轮 learn 前被误判
            "execute_sql",
            "fuzzy_match_plate",
            "fuzzy_match_indicator",
            // Memoria 只读：前缀 memory_ 不在 query_/search_/get_ 启发式内，必须显式列入
            "memory_search",
            "memory_search_v2",
            "memory_recall",
            "memory_profile",
            "memory_context",
            "memory_user_prefs",
            "memory_recent_decisions",
            "memory_health",
            "memory_quota_status",
            "dream_state_get",
            "db_stats",
            "audit_query",
            "entity_search",
            "memory_graph",
        ] {
            c.read_tools.insert(t.to_string());
        }
        for t in [
            "fill_excel_log",
            "update_whitelist",
            "archive_manifest",
            "manage_whitelist",
            "manage_holiday",
            "generate_month_log",
            "archive_operate",
            "organize_folders",
            "edit_code",
            // PR4 Phase A 演化：写回 evolved_context / 回滚演化（Memoria 哑存储写操作）
            "memory_evolve",
            "evolution_rollback",
            // Memoria 常规写入（非删库级危险）
            "memory_remember",
            "memory",
            "memory_observe",
            "dream_state_update",
            "entity_upsert",
            "entity_add_mention",
            "entity_add_edge",
        ] {
            c.write_tools.insert(t.to_string());
        }
        for t in [
            "local_fs_read",
            "local_fs_list",
            "local_fs_stat",
        ] {
            c.read_tools.insert(t.to_string());
        }
        for t in [
            "delete_entrance_record",
            "batch_update_whitelist",
            "shutdown_agent",
            "batch_delete_memories",
            "memory_merge",
            "memory_decay",
            "memory_import",
            "memory_export",
            "local_fs_write",
            "sync_whitelist_plates",
            "manage_whitelist",
            "edit_code",
        ] {
            c.dangerous_tools.insert(t.to_string());
        }
        c
    }

    /// 注册工具到指定权限级别
    pub fn register(&mut self, tool_name: &str, level: &str) {
        match level {
            "read" => {
                self.read_tools.insert(tool_name.to_string());
            }
            "write" => {
                self.write_tools.insert(tool_name.to_string());
            }
            "dangerous" => {
                self.dangerous_tools.insert(tool_name.to_string());
            }
            _ => {
                self.unknown_tools.insert(tool_name.to_string());
            }
        }
    }

    /// 批量注册（从 MCP tools/list 结果中自动学习分类）
    pub fn register_from_tools(&mut self, tools: &[(String, String)]) {
        for (name, _desc) in tools {
            // Memoria 具名工具：优先精确分类，避免 memory_* 落入 unknown 黄线
            if let Some(level) = classify_memoria_tool(name) {
                self.register(name, level);
                continue;
            }
            // 运维状态查询工具：纯只读，直接归 read，避免被 unknown 黄线触发「执行」确认闸
            if name == "system_ops" {
                self.register(name, "read");
                continue;
            }
            if name == "verify_code" || name == "code_reader" {
                self.register(name, "read");
                continue;
            }
            if name == "edit_code" {
                self.register(name, "write");
                continue;
            }
            if name == "local_fs_read" || name == "local_fs_list" || name == "local_fs_stat" {
                self.register(name, "read");
                continue;
            }
            if name == "local_fs_write" {
                self.register(name, "dangerous");
                continue;
            }
            let lower = name.to_lowercase();
            // SQL 查询类工具（execute_sql / query_* 等，仅 SELECT）一律按只读处理，
            // 排除明显的写操作前缀（update_/insert_/delete_/create_）
            let is_sql_read = lower.contains("sql")
                && !lower.starts_with("update")
                && !lower.starts_with("insert")
                && !lower.starts_with("delete")
                && !lower.starts_with("create");
            if name.starts_with("query_")
                || name.starts_with("search_")
                || name.starts_with("get_")
                || name.starts_with("check_")
                || name.starts_with("read_")
                || name.starts_with("list_")
                || name.starts_with("fuzzy_match_")
                || name.starts_with("match_")
                || name.starts_with("review_")
                || name.starts_with("diagnose_")
                || name.starts_with("explain_")
                || name.starts_with("validate_")
                || name.starts_with("cross_")
                || is_sql_read
            {
                self.read_tools.insert(name.clone());
            } else if name.starts_with("delete_")
                || name.starts_with("batch_delete")
                || name.starts_with("shutdown_")
            {
                self.dangerous_tools.insert(name.clone());
            } else if !self.read_tools.contains(name) && !self.dangerous_tools.contains(name) {
                // P0-4：未知工具不再默认当 write 放行，先标记为 unknown，由 check_tool 走黄线确认
                self.unknown_tools.insert(name.clone());
            }
        }
    }

    pub fn classify(&self, tool_name: &str) -> &'static str {
        // 具名 Memoria/编排工具优先（避免仅靠 HashSet 内置表漏网 → unknown 黄线）
        if let Some(level) = classify_memoria_tool(tool_name) {
            return level;
        }
        if self.read_tools.contains(tool_name) {
            return "read";
        }
        if self.write_tools.contains(tool_name) {
            return "write";
        }
        if self.dangerous_tools.contains(tool_name) {
            return "dangerous";
        }
        if self.unknown_tools.contains(tool_name) {
            return "unknown";
        }
        "unknown"
    }
}

/// 固废部门写文件类工具：非 dry_run 时需要人工确认（HumanInLoop 黄线）。
fn needs_dept_ops_write_approval(tool_name: &str, args: &serde_json::Value) -> bool {
    const OPS_WRITE: &[&str] = &[
        "organize_folders",
        "archive_operate",
        "archive_manifest",
        "create_archive",
        "archive_ops",
        "edit_code",
    ];
    if !OPS_WRITE.iter().any(|t| *t == tool_name) {
        return false;
    }
    // dry_run=true → 只预览，不拦
    if args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return false;
    }
    // action=preview/status/list 等只读子命令不拦
    if let Some(action) = args.get("action").and_then(|v| v.as_str()) {
        let a = action.to_ascii_lowercase();
        if matches!(
            a.as_str(),
            "preview" | "status" | "list" | "check" | "dry_run" | "query"
        ) {
            return false;
        }
    }
    true
}

/// 判断工具是否「危险」（落入红线/高危前缀）。
///
/// 用于蒸馏质量门控（P2-3）：含危险工具的 Harness 模板绝不自动激活，
/// 必须经人工 / admin 批准 `activate`。同时覆盖内置危险清单与
/// `delete_` / `batch_delete` / `shutdown_` 高危前缀。
pub fn is_dangerous_tool(name: &str) -> bool {
    let lower = name.to_lowercase();
    if lower.starts_with("delete_")
        || lower.starts_with("batch_delete")
        || lower.starts_with("shutdown_")
    {
        return true;
    }
    ToolClassifier::new().classify(name) == "dangerous"
}

/// Memoria MCP 工具分级（精确名）。`None` = 非具名 Memoria 工具，走通用前缀启发式。
fn classify_memoria_tool(name: &str) -> Option<&'static str> {
    match name {
        // ── 只读检索 / 状态 ──
        "memory_search"
        | "memory_search_v2"
        | "memory_recall"
        | "memory_profile"
        | "memory_context"
        | "memory_user_prefs"
        | "memory_recent_decisions"
        | "memory_health"
        | "memory_quota_status"
        | "memory_fetch_unconsolidated"
        | "memory_backup_list"
        | "memory_dedup_chain"
        | "memory_graph"
        | "dream_state_get"
        | "db_stats"
        | "audit_query"
        | "entity_search"
        | "get_allowed_ns"
        | "agent_list"
        | "system_status"
        | "skill_market_list_installed"
        | "skill_market_search"
        | "skill_market_info"
        | "auto_route" => Some("read"),
        // ── 常规写 / 编排（Write 权限即可，不进人工审批台）──
        "memory_remember"
        | "memory"
        | "memory_observe"
        | "dream_state_update"
        | "memory_evolve"
        | "memory_evolve_auto"
        | "evolution_rollback"
        | "entity_upsert"
        | "entity_add_mention"
        | "entity_add_edge"
        | "a2a_send"
        | "a2a_recv"
        | "cross_agent_query"
        | "continue_task"
        | "reasonix_dispatch"
        | "register_agent"
        | "register_user"
        | "login_user"
        | "skill_market_publish"
        | "skill_market_install"
        | "memory_backup" => Some("write"),
        // ── 危险 / 破坏性（仍走 dashboard-admin）──
        "memory_merge"
        | "memory_decay"
        | "memory_import"
        | "memory_export"
        | "memory_maintenance_normalize"
        | "memory_migration_manifest"
        | "batch_delete_memories"
        | "agent_revoke"
        | "agent_registry_cleanup" => Some("dangerous"),
        _ => None,
    }
}

/// 判断工具是否「纯只读」——可不经用户确认直接自动执行。
///
/// 与 `ToolClassifier::register_from_tools` 的只读判定保持一致的前缀逻辑：
/// 仅 `query_` / `search_` / `get_` / `check_` / `read_` / `list_` / `fuzzy_match_` /
/// `match_` / `review_` / `diagnose_` / `explain_` / `validate_` / `cross_` 前缀，
/// 以及仅 SELECT 的 SQL 工具判为只读；另含具名 Memoria 只读工具。
///
/// 命中写/危险前缀（`delete_` / `batch_delete` / `shutdown_` / `update_` / `insert_` /
/// `create_`）或无法判定为只读的工具一律返回 `false`，走确认闸 / 黄线确认，
/// 符合 P0-4「未知工具不默认放行」的安全姿态。
///
/// 注意：这里用前缀启发式而非 `ToolClassifier::new()` 实例——后者是空分类器，
/// 不含 `register_from_tools` 学到的前缀，会把 `query_today` 之类误判为 unknown。
pub fn is_read_only_tool(name: &str) -> bool {
    if matches!(classify_memoria_tool(name), Some("read")) {
        return true;
    }
    if matches!(classify_memoria_tool(name), Some("write") | Some("dangerous")) {
        return false;
    }
    let lower = name.to_lowercase();
    // 写 / 危险前缀：永远需要确认，绝不自动执行
    if lower.starts_with("delete_")
        || lower.starts_with("batch_delete")
        || lower.starts_with("shutdown_")
        || lower.starts_with("update_")
        || lower.starts_with("insert_")
        || lower.starts_with("create_")
    {
        return false;
    }
    lower.starts_with("query_")
        || lower.starts_with("search_")
        || lower.starts_with("get_")
        || lower.starts_with("check_")
        || lower.starts_with("read_")
        || lower.starts_with("list_")
        || lower.starts_with("fuzzy_match_")
        || lower.starts_with("match_")
        || lower.starts_with("review_")
        || lower.starts_with("diagnose_")
        || lower.starts_with("explain_")
        || lower.starts_with("validate_")
        || lower.starts_with("cross_")
        || (lower.contains("sql")
            && !lower.starts_with("update")
            && !lower.starts_with("insert")
            && !lower.starts_with("delete")
            && !lower.starts_with("create"))
}

#[cfg(test)]
mod read_only_tests {
    use super::*;

    #[test]
    fn read_only_prefixes_accepted() {
        for t in [
            "query_today",
            "query_yesterday",
            "query_system_status",
            "explain_anomaly",
            "search_memory",
            "get_statistics",
            "check_status",
            "list_vehicles",
            "fuzzy_match_plate",
            "execute_sql",
            "memory_recall",
            "memory_search",
            "memory_profile",
            "memory_context",
        ] {
            assert!(is_read_only_tool(t), "应为只读: {}", t);
        }
    }

    #[test]
    fn memoria_tools_classified() {
        let c = ToolClassifier::new();
        assert_eq!(c.classify("memory_recall"), "read");
        assert_eq!(c.classify("memory_search_v2"), "read");
        assert_eq!(c.classify("auto_route"), "read");
        assert_eq!(c.classify("cross_agent_query"), "write");
        assert_eq!(c.classify("reasonix_dispatch"), "write");
        assert_eq!(c.classify("continue_task"), "write");
        assert_eq!(c.classify("system_status"), "read");
        assert_eq!(c.classify("memory_remember"), "write");
        assert_eq!(c.classify("memory_merge"), "dangerous");
        assert!(is_read_only_tool("auto_route"));
        assert!(!is_read_only_tool("cross_agent_query"));
        assert!(!is_read_only_tool("memory_remember"));
        assert!(!is_read_only_tool("memory_merge"));
    }

    #[test]
    fn write_and_dangerous_rejected() {
        for t in [
            "delete_entrance_record",
            "update_whitelist",
            "insert_log",
            "create_report",
            "batch_delete_memories",
            "shutdown_agent",
            "fill_excel_log",
            "memory_remember",
        ] {
            assert!(!is_read_only_tool(t), "不应为只读: {}", t);
        }
    }
}

// ══════════════════════════════════════════════════════
// 第八条：任务确认红线
// ══════════════════════════════════════════════════════

/// 任务确认守卫：判断用户消息是否需要先复述确认
///
/// 简单查询（查车牌、查数据等）直接执行，
/// 复杂任务（写文档、做分析、改数据等）需要先确认理解。
pub struct TaskConfirmationGate;

impl TaskConfirmationGate {
    /// 判断用户消息是否需要先确认理解
    pub fn requires_confirmation(message: &str) -> bool {
        let trimmed = message.trim();

        // 确认/否定/元词 → 不是新任务
        let meta_words = [
            "对", "是", "确认", "行", "好", "可以", "不对", "改", "补充", "继续", "停", "结束",
        ];
        if meta_words.contains(&trimmed) {
            return false;
        }

        // 自然语言疑问句 / 查询意图 → 直接执行，不需要确认
        // 覆盖「昨天进了多少车」「X 是多少」「查一下…」等不以“查/看/搜”开头的问法。
        let query_signals = [
            "多少",
            "几",
            "什么",
            "怎么",
            "如何",
            "为何",
            "何时",
            "哪些",
            "哪辆",
            "吗",
            "？",
            "?",
            "查",
            "看",
            "搜",
            "统计",
            "查询",
            "列表",
            "明细",
            "排行",
            "top",
            "TOP",
            "count",
            "Count",
            "有几",
            "是否",
            "有没有",
        ];
        if query_signals.iter().any(|s| trimmed.contains(s)) {
            return false;
        }

        // 以查询前缀开头 → 直接执行，不需要确认
        let query_prefixes = [
            "查",
            "查一下",
            "查询",
            "看看",
            "搜一搜",
            "搜",
            "帮我看",
            "帮我查",
        ];
        if query_prefixes.iter().any(|p| trimmed.starts_with(p)) {
            return false;
        }

        // 短消息（<4 字）且无任务关键词 → 简单回应
        if trimmed.chars().count() < 4 {
            return false;
        }

        // 任务类关键词 → 需要确认
        let task_keywords = [
            "帮我",
            "写",
            "做",
            "分析",
            "整理",
            "设计",
            "方案",
            "报告",
            "文档",
            "总结",
            "规划",
            "开发",
            "实现",
            "创建",
            "生成",
            "修改",
            "更新",
            "重构",
            "调整",
            "给我",
            "出一份",
            "做一个",
            "搞一个",
        ];
        task_keywords.iter().any(|k| trimmed.contains(k))
    }

    /// 话题切换检测：判断用户输入是否与当前任务上下文相关
    ///
    /// 如果输入很短或不含任务中的关键词，可能是切换话题。
    /// 支持中文（用 2-char 滑动窗口提取关键词）。
    pub fn detect_topic_switch(message: &str, current_task: &str) -> bool {
        let msg = message.trim();
        // 元命令 → 不是切换
        let meta = [
            "对",
            "是",
            "确认",
            "行",
            "好",
            "可以",
            "继续",
            "停",
            "结束",
            "先这样",
        ];
        if meta.contains(&msg) {
            return false;
        }
        // 输入太短 → 可能是切换
        if msg.chars().count() < 5 {
            return true;
        }
        // 从任务中提取 2-char 关键词（中文滑动窗口）
        let task_chars: Vec<char> = current_task.trim().chars().collect();
        let mut task_tokens: Vec<String> = Vec::new();
        for w in task_chars.windows(2) {
            let token: String = w.iter().collect();
            if !task_tokens.contains(&token) {
                task_tokens.push(token);
            }
        }
        // 也处理英文/混合文本的分词
        for w in current_task
            .split_whitespace()
            .filter(|w| w.chars().count() >= 2)
        {
            if !task_tokens.contains(&w.to_string()) {
                task_tokens.push(w.to_string());
            }
        }
        if task_tokens.is_empty() {
            return false;
        }
        !task_tokens.iter().any(|t| msg.contains(t.as_str()))
    }
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
    fn dept_ops_write_needs_approval_unless_dry_run() {
        assert!(needs_dept_ops_write_approval(
            "organize_folders",
            &serde_json::json!({})
        ));
        assert!(!needs_dept_ops_write_approval(
            "organize_folders",
            &serde_json::json!({"dry_run": true})
        ));
        assert!(!needs_dept_ops_write_approval(
            "query_today",
            &serde_json::json!({})
        ));
        assert!(!needs_dept_ops_write_approval(
            "edit_code",
            &serde_json::json!({"dry_run": true})
        ));
        assert!(needs_dept_ops_write_approval(
            "edit_code",
            &serde_json::json!({"filepath": "x.py", "instructions": "fix"})
        ));
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
        use std::path::Path;

        // 沙箱默认启用
        ExecutionSandbox::set_enabled(true);

        // exec_* 在沙箱内放行（不再"永被硬拦但无实现"）
        let r = ExecutionSandbox::check("exec_shell", None);
        assert!(r.allow);

        // 非执行类工具不受沙箱门控
        let r = ExecutionSandbox::check("query_plate", None);
        assert!(r.allow);

        // 沙箱未启用 → 任何 require-sandbox 工具硬拦（绝不裸跑）
        ExecutionSandbox::set_enabled(false);
        let r = ExecutionSandbox::check("exec_shell", None);
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));
        ExecutionSandbox::set_enabled(true);

        // 路径门闸：命中 .ssh 敏感目录 → 红闸
        let r = ExecutionSandbox::check(
            "exec_shell",
            Some(Path::new("C:/test/.ssh/id_ed25519")),
        );
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));

        // 路径门闸：工作区内路径允许
        let r = ExecutionSandbox::check("exec_shell", Some(Path::new("C:/workspace/script.py")));
        assert!(r.allow);

        // REVIEW 类仍走黄线
        let r = ExecutionSandbox::check("delete_user", None);
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Yellow));
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
        boundary
            .perm_chain
            .lock()
            .unwrap()
            .register("test-agent", None, PermissionLevel::Write);

        // 正常工具应该放行
        let r = boundary.check_tool(
            "query_plate",
            &serde_json::json!({}),
            "test-agent",
            "user",
            &PermissionLevel::Write,
            None,
        );
        assert!(r.allow, "query_plate 应放行: {:?}", r);

        // 治理工具应拦截
        let r = boundary.check_tool(
            "modify_red_lines",
            &serde_json::json!({}),
            "test-agent",
            "user",
            &PermissionLevel::Write,
            None,
        );
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));
    }

    #[test]
    fn test_boundary_with_whitelist() {
        let mut boundary = ComplianceBoundary::new(Some(vec!["query_sql".to_string()]));

        // 注册权限
        boundary
            .perm_chain
            .lock()
            .unwrap()
            .register("test-agent", None, PermissionLevel::Write);

        // 在白名单中
        let r = boundary.check_tool(
            "query_sql",
            &serde_json::json!({}),
            "test-agent",
            "user",
            &PermissionLevel::Write,
            None,
        );
        assert!(r.allow, "query_sql 应在白名单中: {:?}", r);

        // 不在白名单中
        let r = boundary.check_tool(
            "query_plate",
            &serde_json::json!({}),
            "test-agent",
            "user",
            &PermissionLevel::Write,
            None,
        );
        assert!(!r.allow, "query_plate 应被白名单拦截: {:?}", r);
    }

    #[test]
    fn test_task_confirmation_simple_query() {
        // 简单查询 → 不需要确认
        assert!(!TaskConfirmationGate::requires_confirmation(
            "查一下京A12345"
        ));
        assert!(!TaskConfirmationGate::requires_confirmation(
            "查询昨天的车辆数据"
        ));
        assert!(!TaskConfirmationGate::requires_confirmation(
            "看看白名单有没有这个企业"
        ));
    }

    #[test]
    fn test_task_confirmation_meta_words() {
        // 元词 → 不是新任务
        assert!(!TaskConfirmationGate::requires_confirmation("对"));
        assert!(!TaskConfirmationGate::requires_confirmation("确认"));
        assert!(!TaskConfirmationGate::requires_confirmation("继续"));
    }

    #[test]
    fn test_task_confirmation_task_request() {
        // 任务类请求 → 需要确认
        assert!(TaskConfirmationGate::requires_confirmation(
            "帮我分析上个月的车辆数据"
        ));
        assert!(TaskConfirmationGate::requires_confirmation(
            "写一份固废分析报告"
        ));
        assert!(TaskConfirmationGate::requires_confirmation(
            "整理一下这个月的入厂记录"
        ));
    }

    #[test]
    fn test_topic_switch_detection() {
        // 相关输入 → 非切换
        assert!(!TaskConfirmationGate::detect_topic_switch(
            "看看车辆数据的趋势",
            "分析上个月车辆入厂数据"
        ));
        // 无关输入 → 切换
        assert!(TaskConfirmationGate::detect_topic_switch(
            "今天天气怎么样",
            "分析上个月车辆入厂数据"
        ));
        // 元命令 → 非切换
        assert!(!TaskConfirmationGate::detect_topic_switch(
            "继续",
            "分析数据"
        ));
        // 太短 → 可能是切换
        assert!(TaskConfirmationGate::detect_topic_switch("哦", "分析数据"));
    }

    #[test]
    fn test_kill_switch_blocks_all() {
        let mut boundary = ComplianceBoundary::new(None);
        boundary
            .perm_chain
            .lock()
            .unwrap()
            .register("test-agent", None, PermissionLevel::Write);
        boundary.kill_switch().trigger(3, "emergency");

        let r = boundary.check_tool(
            "query_plate",
            &serde_json::json!({}),
            "test-agent",
            "user",
            &PermissionLevel::Write,
            None,
        );
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));
    }

    // ── C1a: 危险工具硬地板 ──

    #[test]
    fn test_dangerous_floor_direct() {
        let b = ComplianceBoundary::new(None);
        // 精确集 + 破坏数据类前缀
        assert!(b.is_dangerous_floor("delete_record"));
        assert!(b.is_dangerous_floor("batch_delete_memories"));
        assert!(b.is_dangerous_floor("shutdown_agent"));
        assert!(b.is_dangerous_floor("memory_merge"));
        assert!(b.is_dangerous_floor("drop_table_x"));
        assert!(b.is_dangerous_floor("purge_cache"));
        // 非危险
        assert!(!b.is_dangerous_floor("query_plate"));
        assert!(!b.is_dangerous_floor("update_profile"));
        assert!(!b.is_dangerous_floor("send_email")); // 出域走另一道闸，不在地板
    }

    #[test]
    fn test_floor_catches_misclassified_dangerous() {
        // 模拟误登：delete_record 被 learn 成 write（本应 dangerous），
        // 分类器返回 write → 不会触发 unknown 黄线，但地板仍须拦成黄线（审批闸）。
        let mut boundary = ComplianceBoundary::new(None);
        boundary
            .perm_chain
            .lock()
            .unwrap()
            .register("test-agent", None, PermissionLevel::Admin);
        boundary.register_tool("delete_record", "write");

        let r = boundary.check_tool(
            "delete_record",
            &serde_json::json!({"id": 1}),
            "test-agent",
            "admin",
            &PermissionLevel::Admin,
            None,
        );
        assert_eq!(
            r.level,
            Some(BlockLevel::Yellow),
            "误登为 write 的危险工具仍须被地板拦成黄线（需审批）: {:?}",
            r
        );

        // 只读工具不应触发
        let r2 = boundary.check_tool(
            "query_plate",
            &serde_json::json!({}),
            "test-agent",
            "admin",
            &PermissionLevel::Admin,
            None,
        );
        assert!(r2.allow, "query_plate 应放行: {:?}", r2);
    }
}
