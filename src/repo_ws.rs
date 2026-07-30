//! 双轨·轨二：本机白名单仓库编辑（repo_ws_read / write / list / stat / diff）。
//!
//! **权限生存线（P0）**：
//! - 默认关闭：须显式 `AGENT_REPO_WS=1` 才暴露/可调用
//! - 路径必须落在 `AGENT_REPO_WS_ROOTS` 白名单仓内（默认 agent-core / dashboard）
//! - `repo_ws_write` / `repo_ws_diff` 为危险写：走 L2 审批黄线 + `confirmed=true`
//! - 写前自动快照（复用 `file_checkpoint`），失败可回滚；写后独立回读校验

use std::fs;
use std::path::{Path, PathBuf};

use crate::llm::{ToolDef, ToolDefFunction};

pub const TOOL_READ: &str = "repo_ws_read";
pub const TOOL_WRITE: &str = "repo_ws_write";
pub const TOOL_LIST: &str = "repo_ws_list";
pub const TOOL_STAT: &str = "repo_ws_stat";
pub const TOOL_DIFF: &str = "repo_ws_diff";

const MAX_READ_BYTES: u64 = 256 * 1024;
const MAX_WRITE_BYTES: usize = 512 * 1024;
const MAX_LIST_ENTRIES: usize = 500;

pub fn is_repo_ws_tool(name: &str) -> bool {
    matches!(
        name,
        TOOL_READ | TOOL_WRITE | TOOL_LIST | TOOL_STAT | TOOL_DIFF
    )
}

/// 功能总闸：默认关闭。
pub fn is_enabled() -> bool {
    matches!(
        std::env::var("AGENT_REPO_WS").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

pub fn repo_roots() -> Vec<PathBuf> {
    // 默认相对当前工作目录（agent-core 运行时 cwd），避免硬编码本机用户名绝对路径。
    // 调用方（agent-core）通常以自身目录为 cwd：`./`=agent-core，`../dashboard`=兄弟仓。
    let raw = std::env::var("AGENT_REPO_WS_ROOTS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "./;../dashboard".to_string());
    let mut roots = Vec::new();
    for s in raw.split(';') {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        let c = canonicalize_best_effort(Path::new(s));
        // P1 修复：fail-closed —— 危险根（系统目录 / 用户主目录等）直接剔除，
        // 绝不纳入白名单。此前 assert_safe_repo_root 定义却全仓无调用（死代码）。
        match assert_safe_repo_root(&c) {
            Ok(()) => roots.push(c),
            Err(e) => {
                eprintln!("[repo_ws] 拒绝将危险路径加入白名单仓库根，已跳过: {}", e);
            }
        }
    }
    roots
}

fn canonicalize_best_effort(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

/// 拒绝把仓库根设到危险位置（系统目录 / 用户主目录本身等）。
pub fn assert_safe_repo_root(root: &Path) -> Result<(), String> {
    let c = canonicalize_best_effort(root);
    let s = c.to_string_lossy().to_lowercase();
    let forbidden_exact = [
        r"c:\",
        r"c:/",
        "/",
        r"c:\windows",
        r"c:\windows\system32",
        r"c:\program files",
        r"c:\program files (x86)",
    ];
    for f in forbidden_exact {
        if s == f || s.trim_end_matches(['/', '\\']) == f.trim_end_matches(['/', '\\']) {
            return Err(format!("仓库根禁止使用系统路径: {:?}", c));
        }
    }
    if s.contains(r"\windows\system32") || s.contains("/etc") || s.contains("/usr") {
        return Err(format!("仓库根禁止落在系统目录内: {:?}", c));
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        let home_c = canonicalize_best_effort(Path::new(&home));
        if c == home_c {
            return Err("仓库根禁止直接设为用户主目录，请使用其子目录".into());
        }
    }
    Ok(())
}

/// 校验路径是否落在任一白名单仓根下（已规范化后传入）。
pub fn owns_resolved_path(resolved: &Path) -> bool {
    let target = canonicalize_best_effort(resolved);
    repo_roots()
        .iter()
        .any(|r| is_under_root(&target, r))
}

fn is_under_root(path: &Path, root: &Path) -> bool {
    let path_l = path.to_string_lossy().to_lowercase();
    let root_l = root.to_string_lossy().to_lowercase();
    if path_l == root_l {
        return true;
    }
    let sep = std::path::MAIN_SEPARATOR;
    path_l.starts_with(&format!("{}{}", root_l, sep)) || path_l.starts_with(&(root_l + "/"))
}

fn sensitive_path_reason(p: &Path) -> Option<String> {
    let deny_comp = [".ssh", ".gnupg", ".aws", ".git"];
    for c in p.components() {
        let s = c.as_os_str().to_string_lossy();
        if deny_comp.iter().any(|d| s.eq_ignore_ascii_case(d)) {
            return Some(format!("组件 {}", s));
        }
    }
    if let Some(name) = p.file_name() {
        let n = name.to_string_lossy().to_lowercase();
        if n.ends_with(".pem")
            || n.ends_with(".key")
            || n == "id_rsa"
            || n == "credentials"
            || n == ".env"
        {
            return Some(format!("文件 {}", n));
        }
    }
    None
}

/// 将用户路径解析到某白名单仓内绝对路径；拒绝越界与敏感组件。
pub fn resolve_safe_path(user_path: &str) -> Result<PathBuf, String> {
    let raw = user_path.trim();
    if raw.is_empty() {
        return Err("path 不能为空".into());
    }
    if raw.contains('\0') {
        return Err("path 含非法字符".into());
    }
    for root in repo_roots() {
        let candidate = if Path::new(raw).is_absolute() {
            PathBuf::from(raw)
        } else {
            root.join(raw)
        };
        let resolved = if candidate.exists() {
            canonicalize_best_effort(&candidate)
        } else {
            // P2 修复：先判定将落在哪个白名单根下，越界则跳到下一根，
            // 绝不在此创建任何目录（避免越界副作用）。目录创建仅留给确认后的写路径。
            let parent = candidate
                .parent()
                .ok_or_else(|| "无效路径".to_string())?;
            let parent_c = canonicalize_best_effort(parent);
            let filename = candidate
                .file_name()
                .ok_or_else(|| "无效文件名".to_string())?;
            let would_resolved = parent_c.join(filename);
            if !is_under_root(&would_resolved, &root) {
                continue;
            }
            would_resolved
        };
        if is_under_root(&resolved, &root) {
            if let Some(reason) = sensitive_path_reason(&resolved) {
                return Err(format!("敏感路径拒绝: {}", reason));
            }
            return Ok(resolved);
        }
    }
    Err(format!(
        "路径越出所有白名单仓库根: {:?}（AGENT_REPO_WS_ROOTS = {:?}）",
        raw,
        repo_roots()
    ))
}

pub fn tool_defs() -> Vec<ToolDef> {
    let path_prop = serde_json::json!({
        "type": "string",
        "description": "相对白名单仓根的路径，或仓内绝对路径"
    });
    vec![
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_READ.into(),
                description: "读取白名单仓库内文本文件（上限 256KB）。路径须在 AGENT_REPO_WS_ROOTS 内。"
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": { "path": path_prop },
                    "required": ["path"]
                }),
            },
        },
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_WRITE.into(),
                description: "写入白名单仓库内文本文件（上限 512KB，dangerous）。须 AGENT_REPO_WS=1 + 人工审批 + confirmed=true；写前自动快照，写后回读校验。"
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": path_prop,
                        "content": { "type": "string", "description": "要写入的全文" },
                        "confirmed": { "type": "boolean", "description": "二次确认，true 才落盘" }
                    },
                    "required": ["path", "content"]
                }),
            },
        },
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_LIST.into(),
                description: "列出白名单仓库内目录条目（最多 500）。".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "目录路径，默认 ." }
                    }
                }),
            },
        },
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_STAT.into(),
                description: "查看白名单仓库内文件/目录元信息。".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": { "path": path_prop },
                    "required": ["path"]
                }),
            },
        },
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_DIFF.into(),
                description: "（受控写）对白名单仓库文件做受控改动并预览 diff（dangerous）。须 AGENT_REPO_WS=1 + 审批 + confirmed=true；写前自动快照，落盘后回读校验。"
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": path_prop,
                        "content": { "type": "string", "description": "改动后的全文" },
                        "confirmed": { "type": "boolean", "description": "二次确认，true 才落盘" }
                    },
                    "required": ["path", "content"]
                }),
            },
        },
    ]
}

pub fn system_hint() -> &'static str {
    "\n\n## 本机白名单仓库编辑（轨二，默认关闭）\n\
     - 仅当运维设置 `AGENT_REPO_WS=1` 时可用：`repo_ws_read` / `repo_ws_write` / `repo_ws_list` / `repo_ws_stat` / `repo_ws_diff`\n\
     - 严格限制在 `AGENT_REPO_WS_ROOTS`（默认 agent-core / dashboard）白名单仓内\n\
     - `repo_ws_write` / `repo_ws_diff` 属危险写，须人工审批且 confirmed=true；写前自动快照，写后回读校验\n"
}

/// 执行仓库工具，返回 JSON 字符串。写操作（write/diff）须 confirmed=true。
pub fn execute(tool_name: &str, args: &serde_json::Value) -> Result<String, String> {
    if !is_enabled() {
        return Err("repo_ws 未启用（须设置 AGENT_REPO_WS=1；权限生存线默认关闭）".into());
    }
    match tool_name {
        TOOL_READ => {
            let path = args.get("path").and_then(|v| v.as_str()).ok_or("缺少 path")?;
            let p = resolve_safe_path(path)?;
            if !p.is_file() {
                return Err(format!("不是文件或不存在: {:?}", p));
            }
            let meta = fs::metadata(&p).map_err(|e| e.to_string())?;
            if meta.len() > MAX_READ_BYTES {
                return Err(format!("文件过大 {} bytes（上限 {}）", meta.len(), MAX_READ_BYTES));
            }
            let content = fs::read_to_string(&p).map_err(|e| format!("读取失败: {}", e))?;
            Ok(serde_json::json!({
                "success": true,
                "path": p.to_string_lossy(),
                "bytes": content.len(),
                "content": content,
            })
            .to_string())
        }
        TOOL_WRITE | TOOL_DIFF => {
            let confirmed = args
                .get("confirmed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let path = args.get("path").and_then(|v| v.as_str()).ok_or("缺少 path")?;
            let content = args.get("content").and_then(|v| v.as_str()).ok_or("缺少 content")?;
            if content.len() > MAX_WRITE_BYTES {
                return Err(format!("内容过大 {} bytes（上限 {}）", content.len(), MAX_WRITE_BYTES));
            }
            let p = resolve_safe_path(path)?;
            if !confirmed {
                return Ok(serde_json::json!({
                    "success": false,
                    "require_confirm": true,
                    "path": p.to_string_lossy(),
                    "bytes": content.len(),
                    "message": format!(
                        "⚠️ 即将写入白名单仓库文件 {:?}（{} bytes）。须人工审批通过且 confirmed=true 后执行。",
                        p, content.len()
                    ),
                })
                .to_string());
            }
            // P2 修复：仅在确认写、且路径已落在白名单内后，才创建缺失的父目录
            // （resolve_safe_path 不再越界预建目录）。
            if let Some(parent) = p.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
                }
            }
            // 写前快照（复用 file_checkpoint，失败可回滚）
            let snap_ids = if p.is_file() {
                let args_abs = serde_json::json!({ "path": p.to_string_lossy() });
                crate::file_checkpoint::snapshot_args(&args_abs)
            } else {
                Vec::new()
            };
            match fs::write(&p, content) {
                Ok(()) => {
                    let readback = fs::read_to_string(&p).unwrap_or_default();
                    let verify = crate::controlled_write::verify_file_writeback(
                        &p.to_string_lossy(),
                        content,
                        &readback,
                    );
                    Ok(serde_json::json!({
                        "success": true,
                        "path": p.to_string_lossy(),
                        "bytes": content.len(),
                        "verify": verify.detail_text(),
                        "verify_pass": verify.is_pass(),
                    })
                    .to_string())
                }
                Err(e) => {
                    if !snap_ids.is_empty() {
                        crate::file_checkpoint::restore_many(&snap_ids);
                    }
                    Err(format!("写入失败: {}", e))
                }
            }
        }
        TOOL_LIST => {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            let p = resolve_safe_path(path)?;
            if !p.is_dir() {
                return Err(format!("不是目录: {:?}", p));
            }
            let mut entries = Vec::new();
            let rd = fs::read_dir(&p).map_err(|e| e.to_string())?;
            for ent in rd.take(MAX_LIST_ENTRIES) {
                let ent = ent.map_err(|e| e.to_string())?;
                let name = ent.file_name().to_string_lossy().to_string();
                let ty = if ent.path().is_dir() { "dir" } else { "file" };
                entries.push(serde_json::json!({ "name": name, "type": ty }));
            }
            Ok(serde_json::json!({
                "success": true,
                "path": p.to_string_lossy(),
                "count": entries.len(),
                "entries": entries,
            })
            .to_string())
        }
        TOOL_STAT => {
            let path = args.get("path").and_then(|v| v.as_str()).ok_or("缺少 path")?;
            let p = resolve_safe_path(path)?;
            let meta = fs::metadata(&p).map_err(|e| format!("stat 失败: {}", e))?;
            Ok(serde_json::json!({
                "success": true,
                "path": p.to_string_lossy(),
                "is_file": meta.is_file(),
                "is_dir": meta.is_dir(),
                "len": meta.len(),
            })
            .to_string())
        }
        _ => Err(format!("未知 repo_ws 工具: {}", tool_name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_roots<F: FnOnce()>(f: F) {
        let _g = LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("agent-core-repo-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("AGENT_REPO_WS", "1");
        std::env::set_var("AGENT_REPO_WS_ROOTS", &dir);
        f();
        let _ = fs::remove_dir_all(&dir);
        std::env::remove_var("AGENT_REPO_WS_ROOTS");
        std::env::remove_var("AGENT_REPO_WS");
    }

    #[test]
    fn disabled_by_default() {
        let _g = LOCK.lock().unwrap();
        std::env::remove_var("AGENT_REPO_WS");
        assert!(execute(TOOL_READ, &serde_json::json!({"path": "x.txt"})).is_err());
    }

    #[test]
    fn escapes_rejected() {
        with_temp_roots(|| {
            // 尝试跳出临时根到系统目录
            #[cfg(windows)]
            let escape = "C:/Windows/System32/drivers/etc/hosts";
            #[cfg(not(windows))]
            let escape = "/etc/passwd";
            assert!(execute(TOOL_READ, &serde_json::json!({"path": escape})).is_err());
        });
    }

    #[test]
    fn write_requires_confirm_then_roundtrip() {
        with_temp_roots(|| {
            let preview = execute(
                TOOL_WRITE,
                &serde_json::json!({"path": "hello.txt", "content": "repo content"}),
            )
            .unwrap();
            assert!(preview.contains("require_confirm"));

            let w = execute(
                TOOL_WRITE,
                &serde_json::json!({
                    "path": "hello.txt",
                    "content": "repo content",
                    "confirmed": true
                }),
            )
            .unwrap();
            assert!(w.contains("\"success\":true"));
            assert!(w.contains("verify_pass"));

            let r = execute(TOOL_READ, &serde_json::json!({"path": "hello.txt"})).unwrap();
            assert!(r.contains("repo content"));
        });
    }

    #[test]
    fn roots_have_defaults() {
        let _g = LOCK.lock().unwrap();
        std::env::remove_var("AGENT_REPO_WS_ROOTS");
        let roots = repo_roots();
        assert!(!roots.is_empty());
    }
}
