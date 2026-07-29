//! 本仓本地沙箱文件系统工具（WorkBuddy 代码/文件铁轨最小可用）。
//!
//! **权限生存线（P0）**：
//! - 默认关闭：须显式 `AGENT_LOCAL_FS=1` 才暴露/可调用
//! - `local_fs_write` 为 dangerous：走 L2 审批黄线；且须 `confirmed=true`
//! - 路径必须落在 `AGENT_SANDBOX_ROOT`；禁止把系统盘/用户主目录当沙箱根
//! - 调用路径必须经过 boundary hard_guards（见 `call_tool_routed`）

use std::fs;
use std::path::{Path, PathBuf};

use crate::llm::{ToolDef, ToolDefFunction};

pub const TOOL_READ: &str = "local_fs_read";
pub const TOOL_WRITE: &str = "local_fs_write";
pub const TOOL_LIST: &str = "local_fs_list";
pub const TOOL_STAT: &str = "local_fs_stat";

const MAX_READ_BYTES: u64 = 256 * 1024;
const MAX_WRITE_BYTES: usize = 512 * 1024;
const MAX_LIST_ENTRIES: usize = 500;

pub fn is_local_fs_tool(name: &str) -> bool {
    matches!(
        name,
        TOOL_READ | TOOL_WRITE | TOOL_LIST | TOOL_STAT
    )
}

/// 功能总闸：默认关闭。只有显式开启才允许暴露工具与执行。
pub fn is_enabled() -> bool {
    matches!(
        std::env::var("AGENT_LOCAL_FS").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

/// 拒绝把沙箱根设到危险位置（系统目录 / 用户主目录本身等）。
pub fn assert_safe_sandbox_root(root: &Path) -> Result<(), String> {
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
            return Err(format!("沙箱根禁止使用系统路径: {:?}", c));
        }
    }
    if s.contains(r"\windows\system32") || s.contains("/etc") || s.contains("/usr") {
        return Err(format!("沙箱根禁止落在系统目录内: {:?}", c));
    }
    // 禁止直接等于用户主目录（允许其下的子目录 sandbox）
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        let home_c = canonicalize_best_effort(Path::new(&home));
        if c == home_c {
            return Err("沙箱根禁止直接设为用户主目录，请使用其子目录".into());
        }
    }
    Ok(())
}

/// 确保沙箱根存在：优先环境变量 / 已 init；否则 `cwd/sandbox_workspace`。
pub fn ensure_sandbox_root() -> Result<PathBuf, String> {
    if !is_enabled() {
        return Err("local_fs 未启用（须设置 AGENT_LOCAL_FS=1）".into());
    }
    if let Some(root) = crate::sandbox::resolve_sandbox_root() {
        assert_safe_sandbox_root(&root)?;
        fs::create_dir_all(&root).map_err(|e| format!("创建沙箱根失败: {}", e))?;
        return Ok(canonicalize_best_effort(&root));
    }
    let default = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("sandbox_workspace");
    assert_safe_sandbox_root(&default)?;
    fs::create_dir_all(&default).map_err(|e| format!("创建默认沙箱根失败: {}", e))?;
    std::env::set_var("AGENT_SANDBOX_ROOT", &default);
    Ok(canonicalize_best_effort(&default))
}

fn canonicalize_best_effort(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

/// 将用户路径解析到沙箱内绝对路径；拒绝越界与敏感组件。
pub fn resolve_safe_path(user_path: &str) -> Result<PathBuf, String> {
    let root = ensure_sandbox_root()?;
    let raw = user_path.trim();
    if raw.is_empty() {
        return Err("path 不能为空".into());
    }
    if raw.contains('\0') {
        return Err("path 含非法字符".into());
    }
    let candidate = {
        let p = PathBuf::from(raw);
        if p.is_absolute() {
            p
        } else {
            root.join(p)
        }
    };

    // 对尚不存在的文件：规范化父目录再拼接文件名
    let resolved = if candidate.exists() {
        canonicalize_best_effort(&candidate)
    } else {
        let parent = candidate
            .parent()
            .ok_or_else(|| "无效路径".to_string())?;
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
        }
        let parent_c = canonicalize_best_effort(parent);
        match candidate.file_name() {
            Some(name) => parent_c.join(name),
            None => return Err("无效文件名".into()),
        }
    };

    if !is_under_root(&resolved, &root) {
        return Err(format!(
            "路径越出沙箱根 {:?}: {:?}",
            root, resolved
        ));
    }
    if let Some(reason) = sensitive_path_reason(&resolved) {
        return Err(format!("敏感路径拒绝: {}", reason));
    }
    Ok(resolved)
}

fn is_under_root(path: &Path, root: &Path) -> bool {
    let path_l = path.to_string_lossy().to_lowercase();
    let root_l = root.to_string_lossy().to_lowercase();
    if path_l == root_l {
        return true;
    }
    let sep = std::path::MAIN_SEPARATOR;
    path_l.starts_with(&format!("{}{}", root_l, sep))
        || path_l.starts_with(&(root_l + "/"))
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

pub fn tool_defs() -> Vec<ToolDef> {
    let path_prop = serde_json::json!({
        "type": "string",
        "description": "相对沙箱根的路径，或沙箱内的绝对路径"
    });
    vec![
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_READ.into(),
                description: "读取沙箱内文本文件（上限 256KB）。路径相对 AGENT_SANDBOX_ROOT。"
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
                description: "写入沙箱内文本文件（上限 512KB，dangerous）。须 AGENT_LOCAL_FS=1 + 人工审批 + confirmed=true；写后自动回读校验。"
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
                description: "列出沙箱内目录条目（最多 500）。".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "目录路径，默认 ."
                        }
                    }
                }),
            },
        },
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_STAT.into(),
                description: "查看沙箱内文件/目录元信息。".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": { "path": path_prop },
                    "required": ["path"]
                }),
            },
        },
    ]
}

pub fn system_hint() -> &'static str {
    "\n\n## 本地沙箱文件（本仓内置，默认关闭）\n\
     - 仅当运维设置 `AGENT_LOCAL_FS=1` 时可用：`local_fs_read` / `local_fs_write` / `local_fs_list` / `local_fs_stat`\n\
     - 严格限制在 `AGENT_SANDBOX_ROOT`；`local_fs_write` 属危险写，须人工审批且 `confirmed=true`\n\
     - 大仓改码仍走 `code_reader`/`edit_code`/`verify_code`（同样受审批纪律约束）\n"
}

/// 执行本地 FS 工具，返回 JSON 字符串。
pub fn execute(tool_name: &str, args: &serde_json::Value) -> Result<String, String> {
    if !is_enabled() {
        return Err("local_fs 未启用（须设置 AGENT_LOCAL_FS=1；权限生存线默认关闭）".into());
    }
    match tool_name {
        TOOL_READ => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("缺少 path")?;
            let p = resolve_safe_path(path)?;
            if !p.is_file() {
                return Err(format!("不是文件或不存在: {:?}", p));
            }
            let meta = fs::metadata(&p).map_err(|e| e.to_string())?;
            if meta.len() > MAX_READ_BYTES {
                return Err(format!(
                    "文件过大 {} bytes（上限 {}）",
                    meta.len(),
                    MAX_READ_BYTES
                ));
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
        TOOL_WRITE => {
            // 二次确认：无 confirmed=true 只返回预览，禁止静默落盘
            let confirmed = args
                .get("confirmed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("缺少 path")?;
            let content = args
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or("缺少 content")?;
            if content.len() > MAX_WRITE_BYTES {
                return Err(format!(
                    "内容过大 {} bytes（上限 {}）",
                    content.len(),
                    MAX_WRITE_BYTES
                ));
            }
            let p = resolve_safe_path(path)?;
            if !confirmed {
                return Ok(serde_json::json!({
                    "success": false,
                    "require_confirm": true,
                    "path": p.to_string_lossy(),
                    "bytes": content.len(),
                    "message": format!(
                        "⚠️ 即将写入沙箱文件 {:?}（{} bytes）。须人工审批通过且 confirmed=true 后执行。",
                        p, content.len()
                    ),
                })
                .to_string());
            }
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
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("缺少 path")?;
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
        _ => Err(format!("未知 local_fs 工具: {}", tool_name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_sandbox<F: FnOnce(&Path)>(f: F) {
        let _g = LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "agent-core-fs-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("AGENT_LOCAL_FS", "1");
        std::env::set_var("AGENT_SANDBOX_ROOT", &dir);
        f(&dir);
        let _ = fs::remove_dir_all(&dir);
        std::env::remove_var("AGENT_SANDBOX_ROOT");
        std::env::remove_var("AGENT_LOCAL_FS");
    }

    #[test]
    fn disabled_by_default() {
        let _g = LOCK.lock().unwrap();
        std::env::remove_var("AGENT_LOCAL_FS");
        let err = execute(
            TOOL_READ,
            &serde_json::json!({"path": "x.txt"}),
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("未启用"));
    }

    #[test]
    fn write_requires_confirm_then_roundtrip() {
        with_temp_sandbox(|root| {
            let preview = execute(
                TOOL_WRITE,
                &serde_json::json!({"path": "hello.txt", "content": "你好 WorkBuddy"}),
            )
            .unwrap();
            assert!(preview.contains("require_confirm"));
            assert!(!root.join("hello.txt").exists());

            let w = execute(
                TOOL_WRITE,
                &serde_json::json!({
                    "path": "hello.txt",
                    "content": "你好 WorkBuddy",
                    "confirmed": true
                }),
            )
            .unwrap();
            assert!(w.contains("\"success\":true"));
            assert!(w.contains("verify_pass"));
            let r = execute(TOOL_READ, &serde_json::json!({"path": "hello.txt"})).unwrap();
            assert!(r.contains("你好 WorkBuddy"));
            assert!(root.join("hello.txt").is_file());
        });
    }

    #[test]
    fn rejects_escape() {
        with_temp_sandbox(|_| {
            #[cfg(windows)]
            let escape = "C:/Windows/System32/drivers/etc/hosts";
            #[cfg(not(windows))]
            let escape = "/etc/passwd";
            let err2 = execute(TOOL_READ, &serde_json::json!({"path": escape}));
            assert!(err2.is_err());
        });
    }
}
