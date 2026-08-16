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
    "sync_exception_correction",
    // P0-1 场景沙箱提交：影子变更落生产，强制审批闸
    "scenario_commit",
    // 双轨：受控写（无论分类器如何，强制危险地板 → L2 黄线）
    "cw_write", // 轨一：受控改库写
    "repo_ws_write", // 轨二：白名单仓写
    "repo_ws_diff", // 轨二：白名单仓改动
    "controlled_db_write", // dashboard 受控写执行器（参数化落库，backend）
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
        // fsutil 源路径类工具（office-tools/skills/）：目录枚举/文件查找/移动/删除会访问任意路径，
        // 必须过沙箱敏感目录 deny(.ssh/.gnupg/.aws/.azure/.config/gcloud) 与沙箱根越界检查，防止枚举敏感文件元数据
        "list_dir",
        "find_files",
        "file_info",
        "move_file",
        "delete_path",
        // officecli 文档引擎读类工具（officecli_mcp_bridge.py）：接受 file 路径读取文档内容，
        // 必须过沙箱敏感目录 deny 与沙箱根越界检查，防止读出 .ssh/.gnupg/.aws 等敏感文件内容
        "officecli_read",
        "officecli_validate",
        "officecli_issues",
        "officecli_query",
        "officecli_render",
        // officecli 写类工具也接受输入 file/template 路径（PDF 导出源、merge 模板），
        // 同样需过沙箱门闸，防经 PDF/merge 路径读敏感文件
        "officecli_pdf",
        "officecli_merge",
        "officecli_create",
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
    /// - `paths`：所有文件路径参数，逐个命中敏感 deny 列表或越出严格沙箱根时红闸拦截。
    /// - 沙箱未启用 → 任何 require-sandbox 工具硬拦（绝不裸跑）。
    pub fn check(tool_name: &str, paths: &[PathBuf]) -> ToolCheck {
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
            for p in paths {
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

/// repo_ws 写/改工具的文件内容（`content`）与路径（`path`）由 `resolve_safe_path` 负责路径安全，
/// 不应在通用参数安检中按 SQL 注入 / 路径穿越拦截（否则写入含 "../" 或 "UPDATE ... SET" 的文件内容会被误杀）。
fn is_repo_ws_payload(tool_name: &str, key: &str) -> bool {
    matches!(tool_name, "repo_ws_write" | "repo_ws_diff")
        && (key == "content" || key == "path")
}

/// 从工具参数中抽取显式文件路径参数做门闸（命令型参数 command/code/sql 不含路径，不抽）
/// 提取 args 中所有路径类参数（path/file/file_path/filepath/dir/directory/target/src/dst/paths）。
/// 返回全部匹配路径，使 move_file 的 src+dst 都能过沙箱门闸（而非只查第一个）；数组值（如
/// `paths: [...]`）逐元素展开，避免数组/glob 路径被静默忽略而绕过 path_violation/under_root。
fn extract_path_arg(tool_name: &str, args: &serde_json::Value) -> Vec<PathBuf> {
    const KEYS: &[&str] = &[
        "path",
        "paths", // 数组形式的多路径参数（如 find 的 paths 列表），逐元素展开
        "file",
        "file_path",
        "filepath",
        "dir",
        "directory",
        "target",
        "src", // move_file 的源路径参数（fsutil 源），用于沙箱敏感目录门闸
        "dst", // move_file 的目标路径参数，同样需过沙箱门闸
        "template", // officecli_merge 的模板源路径，需过沙箱门闸防读敏感文件
        "output",   // officecli_create/pdf 等的输出写目标，沙箱根越界检查约束写位置
    ];
    // officecli 写类工具的 `output` 若是裸文件名（无目录分隔、非绝对、非 drive-relative、非 `.`/`..`），
    // 由 bridge 锚定到 office-tools/_out/ 固定目录，不是 agent 可控的真实文件路径；此时若按 process cwd
    // 拼接再去过沙箱根越界检查，会校验一个与 bridge 实际写入目标不同的路径（语义错位）。故严格裸名跳过
    // 门闸，仅对含目录分隔/绝对/drive-relative/穿越形式的 output 按真实路径继续门闸。
    //
    // 注意：drive-relative（如 Windows `C:out.pdf`，无 `/`/`\` 且 is_absolute()==false）不是裸名——
    // Python os.path.join(_out, "C:out.pdf") 会保留 C: 前缀逃逸 _out/，必须按真实路径门闸。
    let bridge_anchored_out = matches!(tool_name, "officecli_create" | "officecli_pdf" | "officecli_merge");
    let mut out = Vec::new();
    if let Some(obj) = args.as_object() {
        for k in KEYS {
            let Some(v) = obj.get(*k) else { continue };
            // 标量：直接取其字符串
            if let Some(s) = v.as_str() {
                if bridge_anchored_out && *k == "output" {
                    let pb = PathBuf::from(s);
                    let is_bare = !s.contains('/')
                        && !s.contains('\\')
                        && !s.contains(':') // 排除 drive-relative（C:out.pdf）
                        && s != "."
                        && s != ".."
                        && !pb.is_absolute();
                    if is_bare {
                        continue; // 严格裸名由 bridge 锚定，跳过门闸
                    }
                }
                out.push(PathBuf::from(s));
            }
            // 数组（如 paths: [...]）：逐元素展开提取字符串路径
            if let Some(arr) = v.as_array() {
                for el in arr {
                    if let Some(s) = el.as_str() {
                        out.push(PathBuf::from(s));
                    }
                }
            }
        }
    }
    out
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

    /// 权威分类器是否把工具判为 read。
    /// 与 bootstrap 的 `is_safe` 谓词同一口径；分类器不可用/返回 unknown 时
    /// 一律 false（fail-closed），不回退前缀启发式。
    /// 注意：分类器自身不再把 `cross_*` 按前缀自动归 read（见 register_from_tools），
    /// 已知只读 cross 工具必须显式注册。
    pub fn classifier_says_read(&self, tool_name: &str) -> bool {
        with_classifier(&self.classifier, ToolClass::Unknown, |c| c.classify_typed(tool_name))
            == ToolClass::Read
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
        let sandbox = ExecutionSandbox::check(tool_name, &extract_path_arg(tool_name, args));
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
                    // repo_ws 写/改工具的 content/path：路径安全由 resolve_safe_path 负责，
                    // 不按 SQL 注入 / 路径穿越拦截，避免误杀含 "../" 或 "UPDATE SET" 的文件内容。
                    if !is_repo_ws_payload(tool_name, key) {
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
        let sandbox = ExecutionSandbox::check(tool_name, &extract_path_arg(tool_name, args));
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
            // 本 check_tool 分支逻辑为 HARD_DANGEROUS 工具（manage_whitelist / sync_whitelist_plates）
            // 的 dangerous-floor 早退——一律返回黄线，与参数内容无关。危险工具在 LLM 工具循环的
            // 审批门禁由 agent.rs 对每次工具调用都走本 check_tool 保证；正常用户成员查询由
            // agent.rs 确定性预路由（try_preroute 内 extract_whitelist_membership_query →
            // call_tool_routed）天然免审批，不依赖本分支的豁免。此处不留 query 豁免，避免外部
            // MCP handler 的 query 存在未察觉副作用或 query_oplog 泄漏全量操作日志时，构成对
            // 危险地板的静默绕过。正常查询体验不受影响（预路由已覆盖）。
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
                    let s_upper = s.to_uppercase();
                    // repo_ws 写/改工具的 content/path：路径安全由 resolve_safe_path 负责，
                    // 不按 SQL 注入 / 路径穿越拦截，避免误杀含 "../" 或 "UPDATE SET" 的文件内容。
                    if !is_repo_ws_payload(tool_name, key) {
                        // SQL 注入检测（P2-7 增强）
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
                            return ToolCheck::red(&format!("参数安全检查：{} 含可疑 SQL 内容", key));
                        }
                        // 路径穿越检测
                        if has_path_traversal(s) {
                            return ToolCheck::red(&format!("参数安全检查：{} 含路径穿越", key));
                        }
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

/// 工具权限分类（类型化标签，避免调用方与字符串字面量比较）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ToolClass {
    Read,
    Write,
    Dangerous,
    Unknown,
}

/// 显式允许为只读的 `cross_*` 工具。
/// 这是 classifier 与 `is_read_only_tool` 共用的唯一白名单，避免两个安全门漂移。
pub(crate) const EXPLICIT_READ_CROSS_TOOLS: &[&str] = &["cross_validate"];

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
            "cw_select", // 轨一：受控改库只读查询（SELECT-only）
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
            // 真实 MCP 工具名（dashboard stdio skills）兜底，避免首轮 learn 前被误判
            "execute_sql",
            "fuzzy_match_plate",
            "fuzzy_match_indicator",
            // P0 权限评审 2026-08-05：只读问数/查询类此前漏分类，导致
            // 「7月装修垃圾进了多少」等纯查询被 nl_query 判"未分类"要求审批。
            // 全部为只读（nl_query 自带白名单表/字段防注入）。
            "nl_query",
            "query_entrance",
            "query_whitelist",
            "query_daily_stats",
            "query_monthly_stats",
            "query_indicators",
            "query_today",
            "query_yesterday",
            "query_vehicle",
            "query_system_status",
            "query_chart",
            "get_project_context",
            "get_schema",
            "render_query_chart",
            // 只读诊断/分析/报告类（P0 权限评审同批补全，均不写生产）
            "data_analysis",
            "explain_anomaly",
            "diagnose_data_gap",
            "diagnose_discrepancy",
            "check_media_files",
            "analyze_manifest_anomaly",
            "predict_vehicle_flow",
            "review_data",
            "generate_report",
            "summarize_url",
            // OfficeCLI 文档引擎只读能力（officecli 源）：读/查/校验/健康/渲染
            "officecli_read",
            "officecli_query",
            "officecli_validate",
            "officecli_issues",
            "officecli_render",
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
            // fsutil 源只读底座（office-tools/skills/ 动态扫描）：文件系统/URL 只读查询
            "list_dir",
            "find_files",
            "file_info",
        ] {
            c.read_tools.insert(t.to_string());
        }
        // cross_* 的只读白名单唯一来源（与 is_read_only_tool 共用 const）
        for t in EXPLICIT_READ_CROSS_TOOLS {
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
            "repo_ws_diff", // 轨二：白名单仓改动（应用 diff，本质写；危险地板由 HARD_DANGEROUS 兜底）
            // OfficeCLI 文档引擎写能力（officecli 源）：建文档/模板合并/PDF 导出（产出到 _out/，非破坏性）
            "officecli_create",
            "officecli_merge",
            "officecli_pdf",
            // P0-1 场景沙箱：写生命周期（创建/加变更/提交/丢弃；commit 强制审批）
            "scenario_create",
            "scenario_add_change",
            "scenario_commit",
            "scenario_discard",
        ] {
            c.write_tools.insert(t.to_string());
        }
        for t in [
            "local_fs_read",
            "local_fs_list",
            "local_fs_stat",
            "repo_ws_read",  // 轨二：白名单仓只读
            "repo_ws_list",  // 轨二：白名单仓列目录（只读）
            "repo_ws_stat",  // 轨二：白名单仓文件元数据（只读）
            // P0-1 场景沙箱：只读推演（基线+影子叠加，绝不写生产）
            "scenario_list",
            "scenario_get",
            "scenario_view",
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
            "sync_exception_correction",
            // fsutil 源破坏性操作（office-tools/skills/）：移动/改名可覆盖，删除破坏数据，均明确归危险触发审批
            "move_file",
            "delete_path",
        ] {
            c.dangerous_tools.insert(t.to_string());
        }
        c
    }

    /// 注册工具到指定权限级别
    pub fn register(&mut self, tool_name: &str, level: &str) {
        // 存储侧统一小写：classify 用 lowercase lookup，避免动态注册的大小写漂移
        let key = tool_name.to_lowercase();
        match level {
            "read" => {
                self.read_tools.insert(key);
            }
            "write" => {
                self.write_tools.insert(key);
            }
            "dangerous" => {
                self.dangerous_tools.insert(key);
            }
            _ => {
                self.unknown_tools.insert(key);
            }
        }
    }

    /// 批量注册（从 MCP tools/list 结果中自动学习分类）
    pub fn register_from_tools(&mut self, tools: &[(String, String)]) {
        for (name, _desc) in tools {
            // Memoria 具名工具：优先精确分类，避免 memory_* 落入 unknown 黄线
            if let Some(level) = classify_memoria_tool(&name.to_lowercase()) {
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
            if name == "sync_exception_correction" {
                self.register(name, "dangerous");
                continue;
            }
            if name == "manage_samples" {
                // sync 写由 needs_dept_ops_write_approval 按 action 黄线；list/stats 可走 write 分类后被 action 放行
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
            // 双轨工具：显式归类，避免落 unknown 黄线
            if name == "cw_select" {
                self.register(name, "read");
                continue;
            }
            if name == "repo_ws_read" || name == "repo_ws_list" || name == "repo_ws_stat" {
                self.register(name, "read");
                continue;
            }
            if name == "repo_ws_diff" {
                self.register(name, "write");
                continue;
            }
            let lower = name.to_lowercase();
            // SQL 查询类工具（execute_sql / query_* 等，仅 SELECT）一律按只读处理，
            // 排除明显的写操作前缀（update_/insert_/delete_/create_）
            // ⚠️ `cross_*` **不再**按前缀自动归 read：该前缀在历史上过宽
            // （cross_agent_query 实际可写，由 classify_memoria_tool 显式归 write）。
            // 只读 cross 工具（如 cross_validate）必须走内置/显式注册白名单。
            let is_sql_read = lower.contains("sql")
                && !lower.starts_with("update")
                && !lower.starts_with("insert")
                && !lower.starts_with("delete")
                && !lower.starts_with("create")
                && !lower.starts_with("cross_");
            if lower.starts_with("query_")
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
                || is_sql_read
            {
                self.read_tools.insert(lower);
            } else if lower.starts_with("delete_")
                || lower.starts_with("batch_delete")
                || lower.starts_with("shutdown_")
            {
                self.dangerous_tools.insert(lower.clone());
            } else if !self.read_tools.contains(&lower) && !self.dangerous_tools.contains(&lower)
            {
                // P0-4：未知工具不再默认当 write 放行，先标记为 unknown，由 check_tool 走黄线确认
                self.unknown_tools.insert(lower);
            }
        }
    }

    pub fn classify(&self, tool_name: &str) -> &'static str {
        // 快路径：存储侧已 canonical 小写，常见小写工具名直接精确命中，零额外分配。
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
        // 慢路径：混合大小写的 MCP 工具名，lowercase 后与 canonical 存储对齐。
        let key = tool_name.to_lowercase();
        if let Some(level) = classify_memoria_tool(&key) {
            return level;
        }
        if self.read_tools.contains(&key) {
            return "read";
        }
        if self.write_tools.contains(&key) {
            return "write";
        }
        if self.dangerous_tools.contains(&key) {
            return "dangerous";
        }
        if self.unknown_tools.contains(&key) {
            return "unknown";
        }
        "unknown"
    }

    /// 类型化分类：把字符串标签收敛为 `ToolClass`。
    /// 遇到未知标签显式告警并按 Unknown 处理——调用方不会静默回退到更宽的
    /// 启发式，bootstrap/并行只读门只会更严格（fail-closed）。
    pub fn classify_typed(&self, tool_name: &str) -> ToolClass {
        match self.classify(tool_name) {
            "read" => ToolClass::Read,
            "write" => ToolClass::Write,
            "dangerous" => ToolClass::Dangerous,
            "unknown" => ToolClass::Unknown,
            other => {
                tracing::warn!(target = "boundary.classifier", tool = %tool_name,
                    label = %other, "ToolClassifier 返回未知标签，按 Unknown 处理");
                ToolClass::Unknown
            }
        }
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
        "manage_samples",
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
    // action=preview/status/list/stats 等只读子命令不拦
    if let Some(action) = args.get("action").and_then(|v| v.as_str()) {
        let a = action.to_ascii_lowercase();
        if matches!(
            a.as_str(),
            "preview" | "status" | "list" | "check" | "dry_run" | "query" | "stats"
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
/// `match_` / `review_` / `diagnose_` / `explain_` / `validate_` 前缀，
/// 以及仅 SELECT 的 SQL 工具判为只读；另含具名 Memoria 只读工具。
/// **`cross_*` 不按前缀自动归只读**：该前缀历史上过宽（cross_agent_query 实际可写），
/// 仅显式列入只读白名单的 `cross_validate` 放行，其余 cross 工具 fail-closed。
///
/// 命中写/危险前缀（`delete_` / `batch_delete` / `shutdown_` / `update_` / `insert_` /
/// `create_`）或无法判定为只读的工具一律返回 `false`，走确认闸 / 黄线确认，
/// 符合 P0-4「未知工具不默认放行」的安全姿态。
///
/// 注意：这里用前缀启发式而非 `ToolClassifier::new()` 实例——后者是空分类器，
/// 不含 `register_from_tools` 学到的前缀，会把 `query_today` 之类误判为 unknown。
pub fn is_read_only_tool(name: &str) -> bool {
    let lower = name.to_lowercase();
    if matches!(classify_memoria_tool(&lower), Some("read")) {
        return true;
    }
    if matches!(classify_memoria_tool(&lower), Some("write") | Some("dangerous")) {
        return false;
    }
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
    if EXPLICIT_READ_CROSS_TOOLS.iter().any(|t| lower == *t) {
        return true;
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
        || (lower.contains("sql")
            && !lower.starts_with("update")
            && !lower.starts_with("insert")
            && !lower.starts_with("delete")
            && !lower.starts_with("create")
            && !lower.starts_with("cross_"))
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
        // cross_* 不再按前缀自动归只读；仅显式只读白名单 cross_validate 放行
        assert!(is_read_only_tool("cross_validate"));
        assert!(!is_read_only_tool("cross_unknown_thing"));
    }

    #[test]
    fn generic_cross_prefix_is_not_auto_read() {
        // 回归锁：register_from_tools 不得把未知 cross_* 按前缀自动归 read；
        // 已知只读 cross_validate 走内置显式白名单，跨 agent 写能力走 classify_memoria_tool。
        let mut c = ToolClassifier::new();
        c.register_from_tools(&[
            ("cross_unknown_thing".to_string(), String::new()),
            ("cross_validate".to_string(), String::new()),
        ]);
        assert_eq!(c.classify_typed("cross_unknown_thing"), ToolClass::Unknown);
        assert_eq!(c.classify_typed("cross_sql_select"), ToolClass::Unknown);
        assert!(!is_read_only_tool("cross_sql_select"));
        assert_eq!(c.classify_typed("cross_validate"), ToolClass::Read);
        // 大小写漂移在两个只读门之间保持一致
        assert!(is_read_only_tool("Cross_validate"));
        assert_eq!(c.classify_typed("Cross_validate"), ToolClass::Read);
        assert_eq!(c.classify_typed("cross_agent_query"), ToolClass::Write);
        // 动态注册的混合大小写工具也按统一 canonical case 存储/查询
        let mut d = ToolClassifier::new();
        d.register("Query_Plate", "read");
        assert_eq!(d.classify_typed("query_plate"), ToolClass::Read);
        assert_eq!(d.classify_typed("QUERY_PLATE"), ToolClass::Read);
        // register_from_tools 的混合大小写前缀判定也必须与 is_read_only_tool 一致
        let mut e = ToolClassifier::new();
        e.register_from_tools(&[("Query_User".to_string(), String::new())]);
        assert_eq!(e.classify_typed("query_user"), ToolClass::Read);
        assert!(is_read_only_tool("Query_User"));
    }

    #[test]
    fn classifier_says_read_is_fail_closed_for_unknown() {
        let boundary = ComplianceBoundary::new(None);
        boundary.learn_tools(&[("cross_unknown_thing".to_string(), String::new())]);
        assert!(!boundary.classifier_says_read("cross_unknown_thing"));
        assert!(boundary.classifier_says_read("cross_validate"));
    }

    #[test]
    fn repo_ws_and_cw_tools_classified() {
        let c = ToolClassifier::new();
        // 轨一只读
        assert_eq!(c.classify("cw_select"), "read");
        // 轨二只读
        assert_eq!(c.classify("repo_ws_read"), "read");
        assert_eq!(c.classify("repo_ws_list"), "read");
        assert_eq!(c.classify("repo_ws_stat"), "read");
        // 轨二写：语义归 write（危险地板由 HARD_DANGEROUS 独立兜底，不依赖分类器）
        assert_eq!(c.classify("repo_ws_diff"), "write");
        // 危险地板独立于分类器
        assert!(HARD_DANGEROUS.contains(&"repo_ws_diff"));
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
        assert!(needs_dept_ops_write_approval(
            "manage_samples",
            &serde_json::json!({"action": "sync"})
        ));
        assert!(!needs_dept_ops_write_approval(
            "manage_samples",
            &serde_json::json!({"action": "list"})
        ));
        assert!(!needs_dept_ops_write_approval(
            "manage_samples",
            &serde_json::json!({"action": "stats"})
        ));
        assert!(!needs_dept_ops_write_approval(
            "manage_samples",
            &serde_json::json!({"action": "sync", "dry_run": true})
        ));
    }

    /// 受控写注册表内每个工具必须能被审批地板拦住（HARD_DANGEROUS 或 dept_ops 黄线）。
    /// 防止「进了注册表却可静默落盘」。
    #[test]
    fn controlled_writes_are_approval_gated() {
        for spec in crate::controlled_write::CONTROLLED_WRITES {
            let hard = HARD_DANGEROUS.contains(&spec.tool);
            let dept = needs_dept_ops_write_approval(spec.tool, &serde_json::json!({}))
                || needs_dept_ops_write_approval(
                    spec.tool,
                    &serde_json::json!({"action": "sync"}),
                );
            assert!(
                hard || dept,
                "受控写工具 {} 未挂审批地板（既非 HARD_DANGEROUS 也不走 dept_ops 黄线）",
                spec.tool
            );
        }
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
        use std::path::PathBuf;

        // 沙箱默认启用
        ExecutionSandbox::set_enabled(true);

        // exec_* 在沙箱内放行（不再"永被硬拦但无实现"）
        let r = ExecutionSandbox::check("exec_shell", &[]);
        assert!(r.allow);

        // 非执行类工具不受沙箱门控
        let r = ExecutionSandbox::check("query_plate", &[]);
        assert!(r.allow);

        // 沙箱未启用 → 任何 require-sandbox 工具硬拦（绝不裸跑）
        ExecutionSandbox::set_enabled(false);
        let r = ExecutionSandbox::check("exec_shell", &[]);
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));
        ExecutionSandbox::set_enabled(true);

        // 路径门闸：命中 .ssh 敏感目录 → 红闸
        let r = ExecutionSandbox::check(
            "exec_shell",
            &[PathBuf::from("C:/test/.ssh/id_ed25519")],
        );
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Red));

        // 路径门闸：工作区内路径允许
        let r = ExecutionSandbox::check("exec_shell", &[PathBuf::from("C:/workspace/script.py")]);
        assert!(r.allow);

        // REVIEW 类仍走黄线
        let r = ExecutionSandbox::check("delete_user", &[]);
        assert!(!r.allow);
        assert_eq!(r.level, Some(BlockLevel::Yellow));

        // 多路径门闸：move_file 安全 src + 恶意 dst（.ssh）→ 红闸（第二个路径触发）
        let r = ExecutionSandbox::check(
            "move_file",
            &[
                PathBuf::from("C:/workspace/a.txt"),
                PathBuf::from("C:/test/.ssh/id_ed25519"),
            ],
        );
        assert!(!r.allow, "move_file 恶意 dst 应触发沙箱门闸");
        assert_eq!(r.level, Some(BlockLevel::Red));

        // officecli_pdf 敏感 file + 合法 output → 红闸（源路径触发）
        let r = ExecutionSandbox::check(
            "officecli_pdf",
            &[
                PathBuf::from("C:/test/.ssh/id_ed25519"),
                PathBuf::from("C:/workspace/out.pdf"),
            ],
        );
        assert!(!r.allow, "officecli_pdf 敏感 file 应触发沙箱门闸");
        assert_eq!(r.level, Some(BlockLevel::Red));

        // 多路径都为安全路径 → 放行
        let r = ExecutionSandbox::check(
            "move_file",
            &[
                PathBuf::from("C:/workspace/a.txt"),
                PathBuf::from("C:/workspace/b.txt"),
            ],
        );
        assert!(r.allow, "move_file 全安全路径应放行");
    }

    #[test]
    fn test_officecli_bare_output_skips_root_gate() {
        // officecli 写类工具的裸文件名 output 由 bridge 锚定到 _out/，不应按 cwd 拼接去过沙箱根越界
        // 检查（否则门闸校验的路径与实际写入目标不一致，语义错位）。
        let bare_args = serde_json::json!({"file": "C:/workspace/tpl.docx", "output": "out.docx"});
        let paths = extract_path_arg("officecli_pdf", &bare_args);
        // 裸名 output 跳过门闸，只剩真实的 file 路径被提取
        assert_eq!(paths.len(), 1, "裸名 output 不应进入门闸路径集合");
        assert_eq!(paths[0], PathBuf::from("C:/workspace/tpl.docx"));

        // 带目录分隔的 output 仍按真实路径提取并过门闸
        let abs_args = serde_json::json!({"file": "C:/workspace/tpl.docx", "output": "C:/test/.ssh/id_ed25519"});
        let paths = extract_path_arg("officecli_pdf", &abs_args);
        assert_eq!(paths.len(), 2, "含路径的 output 应进入门闸路径集合");
        let r = ExecutionSandbox::check("officecli_pdf", &paths);
        assert!(!r.allow, "敏感 output 路径应触发沙箱门闸");
        assert_eq!(r.level, Some(BlockLevel::Red));

        // 非写类工具（officecli_query）的 output 不适用裸名豁免，仍按原逻辑提取
        let q_args = serde_json::json!({"output": "x.docx"});
        let paths = extract_path_arg("officecli_query", &q_args);
        assert_eq!(paths.len(), 1, "非写类工具 output 仍提取");

        // drive-relative（Windows C:out.pdf，无 /\\ 且 is_absolute()==false）不是裸名，必须按真实路径门闸
        let rel_args = serde_json::json!({"file": "C:/workspace/tpl.docx", "output": "C:out.pdf"});
        let paths = extract_path_arg("officecli_pdf", &rel_args);
        assert_eq!(paths.len(), 2, "drive-relative output 不豁免，应进入门闸");
        assert_eq!(paths[1], PathBuf::from("C:out.pdf"));

        // `..` / `.` 不是裸名，必须按真实路径门闸（防 os.path.join(_out, "..") 逃逸 _out）
        let dotdot_args = serde_json::json!({"output": ".."});
        let paths = extract_path_arg("officecli_pdf", &dotdot_args);
        assert_eq!(paths.len(), 1, "`..` 不豁免，应进入门闸");
        assert_eq!(paths[0], PathBuf::from(".."));

        // paths 数组参数逐元素展开，避免数组路径绕过门闸
        let arr_args = serde_json::json!({"paths": ["C:/workspace/a.txt", "C:/test/.ssh/id_ed25519"]});
        let paths = extract_path_arg("find_files", &arr_args);
        assert_eq!(paths.len(), 2, "paths 数组应逐元素展开");
        let r = ExecutionSandbox::check("find_files", &paths);
        assert!(!r.allow, "paths 数组中的敏感路径应触发沙箱门闸");
        assert_eq!(r.level, Some(BlockLevel::Red));
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
    fn test_read_tools_no_approval_needed() {
        // P0 权限评审 2026-08-05：只读问数/查询/诊断类必须归 read，不得走审批
        let b = ComplianceBoundary::new(None);
        let c = b.classifier.lock().unwrap();
        for t in [
            "nl_query",
            "query_entrance",
            "query_whitelist",
            "query_daily_stats",
            "query_monthly_stats",
            "query_indicators",
            "query_today",
            "query_yesterday",
            "query_vehicle",
            "query_system_status",
            "query_chart",
            "get_project_context",
            "get_schema",
            "render_query_chart",
            "cross_validate",
            "data_analysis",
            "explain_anomaly",
            "diagnose_data_gap",
            "diagnose_discrepancy",
            "check_media_files",
            "analyze_manifest_anomaly",
            "predict_vehicle_flow",
            // P2b：officecli 文档引擎只读能力
            "officecli_read",
            "officecli_query",
            "officecli_validate",
            "officecli_issues",
            "officecli_render",
        ] {
            assert_eq!(c.classify(t), "read", "{t} 应分类为 read（纯查询，不得审批）");
        }
    }

    #[test]
    fn test_officecli_write_tools_classified_write() {
        // P2b：officecli 写类工具（create/merge/pdf）产出到 _out/，应分类为 write 需审批
        let b = ComplianceBoundary::new(None);
        let c = b.classifier.lock().unwrap();
        for t in ["officecli_create", "officecli_merge", "officecli_pdf"] {
            assert_eq!(c.classify(t), "write", "{t} 应分类为 write（产出文件，需写权限）");
        }
    }

    #[test]
    fn test_fsutil_tools_classification() {
        // P2b：fsutil 源工具分类——只读底座(read) / 破坏性写(write/dangerous)，
        // 与 dept_ops 提示文本保持一致，避免 LLM 按提示调用却被 enforcement 拦截。
        let b = ComplianceBoundary::new(None);
        let c = b.classifier.lock().unwrap();
        for t in ["list_dir", "find_files", "file_info", "summarize_url", "data_analysis"] {
            assert_eq!(c.classify(t), "read", "{t} 应分类为 read（文件系统/URL 只读查询）");
        }
        assert_eq!(c.classify("move_file"), "dangerous", "move_file 应分类为 dangerous（移动可覆盖，需审批）");
        assert_eq!(c.classify("delete_path"), "dangerous", "delete_path 应分类为 dangerous（删除，危险地板）");
    }

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
        // P0-1 场景沙箱：commit 落生产必须走危险地板（审批闸）；只读推演不在地板
        assert!(b.is_dangerous_floor("scenario_commit"));
        assert!(!b.is_dangerous_floor("scenario_view"));
        assert!(!b.is_dangerous_floor("scenario_list"));
        assert!(!b.is_dangerous_floor("scenario_get"));
    }

    #[test]
    fn test_scenario_tool_classification() {
        let b = ComplianceBoundary::new(None);
        let mut classifier = b.classifier.lock().unwrap();
        // 读工具白名单
        for t in ["scenario_list", "scenario_get", "scenario_view"] {
            assert!(classifier.read_tools.contains(t), "{t} 应在 read_tools");
        }
        // 写工具（生命周期）
        for t in ["scenario_create", "scenario_add_change", "scenario_commit", "scenario_discard"] {
            assert!(classifier.write_tools.contains(t), "{t} 应在 write_tools");
        }
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

    #[test]
    fn test_whitelist_dangerous_tools_require_approval() {
        // 断言 check_tool 的 dangerous-floor 行为：HARD_DANGEROUS 工具（manage_whitelist /
        // sync_whitelist_plates）无论 query/写动作一概走审批闸，与参数内容无关。
        // 它不驱动 agent.rs 的 LLM tool-loop/预路由路径（豁免移除的实际生效点）；该路径由
        // agent.rs 的 try_preroute/成员查询测试独立覆盖。此处仅验证边界层保证。
        // （精简：避免与生产注释重复、硬编码 agent.rs 内部符号导致漂移。）
        let mut boundary = ComplianceBoundary::new(None);
        boundary
            .perm_chain
            .lock()
            .unwrap()
            .register("test-agent", None, PermissionLevel::Admin);
        // 两工具显式注册为 "read"，使断言【只依赖 HARD_DANGEROUS 地板】产生拦截——
        // 不依赖默认分类表把 manage_whitelist 标为 write（该值是检查顺序 read→write→dangerous
        // 的产物，未来分类表调整不使本测试脆失败）。地板被移除则 check_tool 对 read 放行，
        // 断言失败（已实证移出 HARD_DANGEROUS → FAILED，非空通过）。
        boundary.register_tool("manage_whitelist", "read");
        boundary.register_tool("sync_whitelist_plates", "read");

        // ①-⑯ 十六个 near-identical check_tool+Yellow 块折叠为统一表驱动（含纯查询/写动作/
        // 嵌套/缺参/空值/越界代表形状），单一保证「HARD_DANGEROUS 工具一律审批（与参数内容
        // 无关）」，消除重复样板。
        let dangerous_shapes: Vec<(&str, serde_json::Value, &str)> = vec![
            // ① manage_whitelist query（纯查询，无写参数）
            ("manage_whitelist", serde_json::json!({"action": "query", "plate": "苏B12345"}), "纯 query"),
            // ② query 携带写参数（confirmed）
            ("manage_whitelist", serde_json::json!({"action": "query", "plate": "苏B12345", "confirmed": true}), "query 带 confirmed"),
            // ③ add 写动作
            ("manage_whitelist", serde_json::json!({"action": "add", "plate": "苏B12345", "waste_type": "装修垃圾"}), "add 写动作"),
            // ④ query_oplog 纯查询（带 limit 分页）
            ("sync_whitelist_plates", serde_json::json!({"action": "query_oplog", "limit": 50}), "query_oplog"),
            // ⑤ update_company 写动作
            ("sync_whitelist_plates", serde_json::json!({"action": "update_company", "plate": "苏B12345", "company_name": "佳士能"}), "update_company"),
            // ⑥ query 携带写参数（effective_date）
            ("manage_whitelist", serde_json::json!({"action": "query", "plate": "苏B12345", "effective_date": "2026-08-01"}), "query 带 effective_date"),
            // ⑦ query_oplog 携带 plates 数组
            ("sync_whitelist_plates", serde_json::json!({"action": "query_oplog", "plates": ["苏B12345", "皖NB7691"]}), "query_oplog 带 plates"),
            // ⑧ 未知 action（fail-closed）
            ("manage_whitelist", serde_json::json!({"action": "export", "plate": "苏B12345"}), "未知 action"),
            // ⑨ query 携带嵌套对象写参数（filters.company_name）
            ("manage_whitelist", serde_json::json!({"action": "query", "plate": "苏B12345", "filters": {"company_name": "佳士能"}}), "嵌套写参数"),
            // ⑩ query_oplog 携带 plate
            ("sync_whitelist_plates", serde_json::json!({"action": "query_oplog", "plate": "苏B12345"}), "query_oplog 携带 plate"),
            // ⑪ query 携带嵌套写意图于允许键值（plate 是对象）
            ("manage_whitelist", serde_json::json!({"action": "query", "plate": {"confirmed": true}}), "plate 为对象"),
            // ⑫ query 携带 limit 为负
            ("manage_whitelist", serde_json::json!({"action": "query", "plate": "苏B12345", "limit": -1}), "limit 为负"),
            // ⑬ 缺必备参数（query 无 plate）
            ("manage_whitelist", serde_json::json!({"action": "query"}), "缺 plate"),
            // ⑭ query_oplog 缺 limit
            ("sync_whitelist_plates", serde_json::json!({"action": "query_oplog"}), "缺 limit"),
            // ⑮ query 带空车牌
            ("manage_whitelist", serde_json::json!({"action": "query", "plate": "  "}), "空车牌"),
            // ⑯ limit 超上限（>1000）
            ("manage_whitelist", serde_json::json!({"action": "query", "plate": "苏B12345", "limit": 1001}), "limit 超上限"),
        ];
        for (tool, args, label) in dangerous_shapes {
            let r = boundary.check_tool(
                tool,
                &args,
                "test-agent",
                "admin",
                &PermissionLevel::Admin,
                None,
            );
            assert!(
                !r.allow,
                "{label} 应被拦截（dangerous 一律审批，allow 必须为 false）: {:?}",
                r
            );
            // 该不变式是「HARD_DANGEROUS 工具无论参数一概拦截（需审批）」，由 !r.allow 表达。
            // 具体级别钉死 Yellow 会脆——若未来加固为 Red（硬拦截）或更高优先级守卫
            // （沙箱/导出/供应链）扩展到这些工具，安全姿态等同或更强，但 Yellow 断言会失败。
            // （断言不变式而非具体色。）
            assert!(
                r.level.is_some(),
                "{label} 拦截须带级别（决定后续审批流程）: {:?}",
                r
            );
            // 仅 !r.allow + level.is_some() 无法证明【审批门禁】触发——前置守卫（沙箱/供应链/导出/
            // 安全模式）若未来拦截这些形状也会满足断言，测试会静默不再测到 HARD_DANGEROUS 审批闸
            // 本体。→ 钉紧 reason 须含 approval gate 专属片段「需要审批」（boundary.rs:915 的 reason
            // 恒含「需要审批，请等待审批人确认」）。注意不能用更宽的「审批」——数据外发守卫
            // （「需要管理员审批」）、跨 ns 守卫（「跨 N namespace 聚合数据需要审批」）、否决同步
            // 守卫（「须重新提交审批」）都含「审批」但非本闸，「审批」会让断言在这些守卫将来覆盖
            // 到这些工具时误测主题漂移。用「需要审批」精确指纹（不含于「需要管理员审批」）。
            assert!(
                r.reason.contains("需要审批"),
                "{label} 拦截原因须表明是【HARD_DANGEROUS 审批闸】而非其他守卫，实际: {:?}",
                r
            );
        }
    }
}
