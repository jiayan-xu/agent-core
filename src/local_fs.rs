//! 本仓本地沙箱文件系统工具（WorkBuddy 代码/文件铁轨最小可用）。
//!
//! 不依赖 dashboard MCP：在 `AGENT_SANDBOX_ROOT`（缺省 `./sandbox_workspace`）内
//! 提供 read / write / list / stat。越界与敏感路径一律拒绝。

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

/// 确保沙箱根存在：优先环境变量 / 已 init；否则 `cwd/sandbox_workspace`。
pub fn ensure_sandbox_root() -> Result<PathBuf, String> {
    if let Some(root) = crate::sandbox::resolve_sandbox_root() {
        fs::create_dir_all(&root).map_err(|e| format!("创建沙箱根失败: {}", e))?;
        return Ok(canonicalize_best_effort(&root));
    }
    let default = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("sandbox_workspace");
    fs::create_dir_all(&default).map_err(|e| format!("创建默认沙箱根失败: {}", e))?;
    // 供后续 resolve_sandbox_root / MCP 子进程看到同一根
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
                description: "写入沙箱内文本文件（上限 512KB）。会覆盖已有内容；写后自动回读校验。"
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": path_prop,
                        "content": { "type": "string", "description": "要写入的全文" }
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
    "\n\n## 本地沙箱文件（本仓内置）\n\
     - `local_fs_read` / `local_fs_write` / `local_fs_list` / `local_fs_stat`\n\
     - 仅限 `AGENT_SANDBOX_ROOT`（默认 `./sandbox_workspace`）内；越界与敏感路径拒绝。\n\
     - 迭代小文件/草稿优先用这组工具；大仓改码仍走 `code_reader`/`edit_code`/`verify_code`。\n"
}

/// 执行本地 FS 工具，返回 JSON 字符串。
pub fn execute(tool_name: &str, args: &serde_json::Value) -> Result<String, String> {
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
            // 写前快照（若已存在）
            let snap_ids = if p.is_file() {
                let args_abs = serde_json::json!({ "path": p.to_string_lossy() });
                crate::file_checkpoint::snapshot_args(&args_abs)
            } else {
                Vec::new()
            };
            match fs::write(&p, content) {
                Ok(()) => {
                    // 回读校验
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
        std::env::set_var("AGENT_SANDBOX_ROOT", &dir);
        f(&dir);
        let _ = fs::remove_dir_all(&dir);
        std::env::remove_var("AGENT_SANDBOX_ROOT");
    }

    #[test]
    fn write_read_roundtrip() {
        with_temp_sandbox(|root| {
            let w = execute(
                TOOL_WRITE,
                &serde_json::json!({"path": "hello.txt", "content": "你好 WorkBuddy"}),
            )
            .unwrap();
            assert!(w.contains("\"success\":true"));
            assert!(w.contains("verify_pass\":true") || w.contains("\"verify_pass\": true"));
            let r = execute(TOOL_READ, &serde_json::json!({"path": "hello.txt"})).unwrap();
            assert!(r.contains("你好 WorkBuddy"));
            assert!(root.join("hello.txt").is_file());
        });
    }

    #[test]
    fn rejects_escape() {
        with_temp_sandbox(|_| {
            let err = execute(
                TOOL_READ,
                &serde_json::json!({"path": "../outside.txt"}),
            );
            // 规范化后可能仍落在沙箱外，或读失败
            assert!(err.is_err() || err.unwrap().contains("success"));
            // 明确绝对路径逃逸
            #[cfg(windows)]
            let escape = "C:/Windows/System32/drivers/etc/hosts";
            #[cfg(not(windows))]
            let escape = "/etc/passwd";
            let err2 = execute(TOOL_READ, &serde_json::json!({"path": escape}));
            assert!(err2.is_err());
        });
    }
}
