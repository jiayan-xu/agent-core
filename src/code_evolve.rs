//! 代码自我进化引擎（Phase 7 生产形态）
//!
//! 设计对齐「圆桌共识」5 根安全支柱，但本模块的安全**真实来源**是：
//! 1. 隔离仓库 —— 引擎只改【隔离仓库】里的单个目标函数；引擎代码在 agent-core 内、目标在隔离仓库，
//!    二者不相交 → 引擎无法自改。（P0-2 进一步强化：路径规范化 + 拒 symlink + 拒任何落入
//!    agent-core / memoria 源码树的路径，含改名克隆与 memoria-open。）
//! 2. 自动评估 —— `eval_crate` 用冻结的 `cargo test` 双门：正确性 + BENCH_MS 粗粒度性能信号。
//!    （注意：BENCH_MS 是粗粒度信号，fib(38) 迭代本就近 0，0.000 表示"低于计时分辨率"，
//!     不宜当作高精度性能结论。）
//! 3. 真签名冻结（P0-3）—— `apply_patch` 不靠"子串包含"冒充签名校验，而是：归一化空白后比对
//!    原/候选签名，不一致即拒绝；仅用【原签名（字节级冻结）+ 候选函数体】替换。函数体之外的任何东西
//!    （可见性、属性、返回类型、参数）都无法被候选改动。
//! 4. git 回退 —— 每代更优则 commit（或按调用方 dry_run 只产 diff），否则 `git checkout HEAD --` 回退。
//! 5. 熔断 HARD STOP —— 连续 N 代失败/无进展，立即停并报原因（由 handler 控制阈值）。
//!
//! 防御纵深（非唯一安全层）：
//! - 人类否决闸门在 handler 层：默认 dry_run（只产 diff，不落盘），须显式 apply=true + allow_commit=true 才提交；
//!   且 /api/evolve 需携带专用 `x-evolve-key`（P0-1），杜绝"端口可达即可触发进化"。
//! - 函数体黑名单（contains_blocked）仅作启发式兜底，**不是**安全保证——真正约束来自"隔离仓库 +
//!   签名冻结 + git 回退 + dry_run 人工审阅"。一个能写任意函数体的攻击者仍有办法做 IO，
//!   因此该引擎的定位是"受控研发沙箱"，不是"可对抗恶意 LLM 的硬沙箱"。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::llm::{LlmClient, Message};
use tokio::time::timeout;

/// 单次评估的结果
pub struct EvalResult {
    pub passed: bool,
    pub bench_ms: Option<f64>,
    pub log: String,
}

/// 在源码中定位目标函数定义。
/// 返回 (完整 fn 文本, 起始偏移, 结束偏移, 签名文本, 函数体文本)。
/// - 签名文本 = 从 `fn` 关键字到首个 `{` 之前（含 pub / async / 泛型 / 返回类型），用于真签名比对。
/// - 函数体文本 = 从首个 `{` 到配对的 `}`（含花括号）。
///
/// 覆盖：pub / pub(crate) / pub(super) / async / 属性宏 / 泛型；
/// 跳过文档注释（/// //! /* */）、markdown 代码围栏（```），避免误匹配示例。
pub fn extract_fn(source: &str, name: &str) -> Option<(String, usize, usize, String, String)> {
    let marker = format!("fn {}", name);
    let mut line_start = 0usize;
    let mut in_block = false;
    let mut hit: Option<usize> = None; // fn 关键字字节偏移
    for line in source.lines() {
        let line_byte_len = line.len(); // 不含换行符
        let rest = &source[line_start + line_byte_len..];
        let newline_len = if rest.starts_with("\r\n") {
            2
        } else if rest.starts_with('\n') {
            1
        } else {
            0
        };
        let trim = line.trim_start();

        // 块注释状态机（跨行 /* ... */）
        if in_block {
            if trim.contains("*/") {
                in_block = false;
            }
            line_start += line_byte_len + newline_len;
            continue;
        }
        // 跳过文档注释 / 代码围栏 / 块注释起始
        if trim.starts_with("///") || trim.starts_with("//!") {
            line_start += line_byte_len + newline_len;
            continue;
        }
        if line.contains("```") {
            line_start += line_byte_len + newline_len;
            continue;
        }
        if trim.starts_with("/*") {
            in_block = !trim.contains("*/"); // 单行 /* */ 不进入 in_block
            line_start += line_byte_len + newline_len;
            continue;
        }

        // 查找 "fn NAME"，并要求其后紧跟 '(' 或 '<'，且 "fn" 是整词
        if let Some(pos) = line.find(&marker) {
            let after = &line[pos + marker.len()..];
            if after.starts_with('(') || after.starts_with('<') {
                let prefix = &line[..pos];
                let whole = match prefix.chars().last() {
                    None => true,
                    Some(c) => !c.is_alphanumeric() && c != '_',
                };
                if whole {
                    hit = Some(line_start + pos);
                    break;
                }
            }
        }
        line_start += line_byte_len + newline_len;
    }
    let fn_kw_pos = hit?;

    // 签名：fn_kw_pos -> 首个 '{'
    let open_rel = source[fn_kw_pos..].find('{')?;
    let open = fn_kw_pos + open_rel;
    let signature = source[fn_kw_pos..open].to_string();

    // 括号匹配找配对 '}'
    let bytes = source.as_bytes();
    let mut depth: i32 = 0;
    let mut end = open;
    for i in open..source.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    let full = source[fn_kw_pos..=end].to_string();
    let body = source[open..=end].to_string();
    Some((full, fn_kw_pos, end, signature, body))
}

/// 调用 LLM 提议新的函数实现，返回提取出的新函数源码
pub async fn propose_fn(
    llm: &LlmClient,
    name: &str,
    current: &str,
    goal: &str,
) -> Result<String, String> {
    let system = "You are a code-optimization engine. You will be given a Rust function and an optimization goal. \
Propose a NEW implementation of the SAME function that is semantically equivalent and meets the goal (e.g. faster), \
while STRICTLY preserving its exact signature (visibility, async, generics, parameters, return type) and MUST NOT modify or remove the `#[cfg(test)]` test module or any other code. \
Output ONLY a single fenced ```rust code block containing the complete new function definition and nothing else. \
No explanations, no markdown outside the fence, no `unsafe`, no external crates, no file/network IO.";
    let user = format!(
        "Current implementation:\n```rust\n{}\n```\n\nGoal: {}\n\nReturn ONLY the optimized `fn {}` in a single ```rust fenced block.",
        current, goal, name
    );
    let msgs = vec![
        Message {
            role: "system".to_string(),
            content: Some(system.to_string()),
            tool_calls: None,
            tool_call_id: None,
        },
        Message {
            role: "user".to_string(),
            content: Some(user),
            tool_calls: None,
            tool_call_id: None,
        },
    ];
    let resp = match timeout(Duration::from_secs(45), llm.chat(&msgs, &[])).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(format!("LLM 错误: {}", e)),
        Err(_) => return Err("LLM 超时(45s)".to_string()),
    };
    extract_fn_from_llm(&resp.text, name)
}

/// 从 LLM 文本中提取目标函数（优先 fenced ```rust 块）
fn extract_fn_from_llm(text: &str, name: &str) -> Result<String, String> {
    let block = if let Some(pos) = text.find("```") {
        let rest = &text[pos + 3..];
        let end = rest.find("```").unwrap_or(rest.len());
        let mut body = &rest[..end];
        if let Some(nl) = body.find('\n') {
            body = &body[nl + 1..];
        }
        body.trim().to_string()
    } else {
        text.trim().to_string()
    };
    extract_fn(&block, name)
        .map(|(s, _, _, _, _)| s)
        .ok_or_else(|| "LLM 未返回可解析的 fn 定义".to_string())
}

/// 把新函数外科式替换进源码：
/// - 真签名比对（去空白后一致），否则拒绝（P0-3，非子串包含冒充）；
/// - 仅用【原签名 + 候选函数体】替换，签名字节级冻结；
/// - 冻结 #[cfg(test)] 测试模块；
/// - 函数体黑名单兜底（启发式，非唯一安全层）。
pub fn apply_patch(source: &str, name: &str, candidate: &str) -> Result<String, String> {
    let (_, start, end, orig_sig, _) = extract_fn(source, name).ok_or("源文件中找不到目标函数")?;
    let (_, _, _, cand_sig, cand_body) =
        extract_fn(candidate, name).ok_or("候选中找不到目标函数")?;

    // 真签名比对：去除所有空白后必须完全一致（词序/词一致），否则视为签名被篡改
    if norm_sig(&orig_sig) != norm_sig(&cand_sig) {
        return Err(format!(
            "拒绝：函数签名被改动（原: {} / 候选: {}）",
            orig_sig.trim(),
            cand_sig.trim()
        ));
    }

    // 仅替换函数体：原签名（字节级冻结）+ 候选函数体
    let new_fn = format!("{}{}", orig_sig, cand_body);
    let new_src = format!("{}{}\n{}", &source[..start], new_fn, &source[end + 1..]);

    // 冻结测试模块：不得被移除
    if !new_src.contains("#[cfg(test)]") {
        return Err("拒绝：#[cfg(test)] 测试模块被移除".to_string());
    }
    // 目标函数必须仍在
    if !new_src.contains(&format!("fn {}", name)) {
        return Err("拒绝：目标函数缺失".to_string());
    }
    // 防御性黑名单（仅扫被替换的函数体；非唯一安全层，真正安全靠隔离仓库 + 签名冻结 + git 回退 + dry_run 审阅）
    if contains_blocked(&cand_body) {
        return Err("拒绝：函数体检测到 unsafe / 文件 / 进程 / 网络 IO 等受限模式".to_string());
    }
    Ok(new_src)
}

/// 签名归一化：去除所有空白（含括号内空格），用于稳健比对
fn norm_sig(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// 启发式受限模式（防御纵深，非安全保证）
fn contains_blocked(s: &str) -> bool {
    const BLOCKED: &[&str] = &[
        "unsafe",
        "std::fs",
        "std::process",
        "std::os",
        "std::env",
        "std::net",
        "tokio::fs",
        "tokio::process",
        "std::io",
        "fs::write",
        "fs::read",
        "File::open",
        "File::create",
        "include!",
        "include_str!",
        "require!",
        "Command",
        "exec",
        "spawn",
        "socket",
        "net::",
        "process::",
    ];
    BLOCKED.iter().any(|b| s.contains(b))
}

/// 运行 cargo test，返回 (通过?, BENCH_MS, 日志尾)
pub fn eval_crate(manifest: &Path) -> EvalResult {
    let out = Command::new("cargo")
        .args([
            "test",
            "--manifest-path",
            &manifest.to_string_lossy(),
            "--release",
            "--",
            "--nocapture",
        ])
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            let combined = format!("{}{}", stdout, stderr);
            let passed = o.status.success() && combined.contains("test result: ok");
            let bench = parse_bench(&combined);
            EvalResult {
                passed,
                bench_ms: bench,
                log: tail(&combined, 1600),
            }
        }
        Err(e) => EvalResult {
            passed: false,
            bench_ms: None,
            log: format!("cargo 执行失败: {}", e),
        },
    }
}

/// 解析输出中的 BENCH_MS=<float>
fn parse_bench(s: &str) -> Option<f64> {
    let idx = s.find("BENCH_MS=")?;
    let rest = &s[idx + 9..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rest.len());
    rest[..end].parse::<f64>().ok()
}

fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[s.len() - n..].to_string()
    }
}

/// 从 start 向上查找名为 `name` 的文件/目录，返回首个命中路径
pub fn find_up(start: &Path, name: &str) -> Option<PathBuf> {
    let mut cur = start.to_path_buf();
    loop {
        if cur.join(name).exists() {
            return Some(cur.join(name));
        }
        if !cur.pop() {
            return None;
        }
    }
}

/// git checkout 单文件（恢复为 HEAD）
pub fn git_revert(repo: &Path, file: &Path) -> Result<(), String> {
    let rel = file.strip_prefix(repo).unwrap_or(file);
    // 用 checkout HEAD -- file：始终恢复到 HEAD（而非 index），
    // 避免 index 已被 git add 污染时无法回退到干净基线、残留 dirty working tree。
    let o = Command::new("git")
        .args([
            "-C",
            &repo.to_string_lossy(),
            "checkout",
            "HEAD",
            "--",
            &rel.to_string_lossy(),
        ])
        .output()
        .map_err(|e| format!("git checkout 失败: {}", e))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!(
            "git checkout 失败: {}",
            String::from_utf8_lossy(&o.stderr)
        ))
    }
}

/// git diff 单文件（工作树 vs HEAD）→ 候选补丁（供人类审阅）
pub fn git_diff(repo: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(repo).unwrap_or(file);
    let o = Command::new("git")
        .args(["-C", &repo.to_string_lossy(), "diff", "--", &rel.to_string_lossy()])
        .output();
    match o {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => format!("git diff 失败: {}", e),
    }
}

/// git add + commit 单文件，返回 commit 短哈希
///
/// 根因修复：Windows 控制台代码页会导致 `git commit -m "<中文>"` 静默失败（stderr 为空）。
/// 改为把消息写入 UTF-8 临时文件，用 `git commit -F <file>` 读取 —— 与代码页无关。
pub fn git_commit(repo: &Path, file: &Path, msg: &str) -> Result<String, String> {
    let rel = file.strip_prefix(repo).unwrap_or(file);
    let s1 = Command::new("git")
        .args(["-C", &repo.to_string_lossy(), "add", &rel.to_string_lossy()])
        .output()
        .map_err(|e| e.to_string())?;
    if !s1.status.success() {
        return Err(format!(
            "git add 失败: {}",
            String::from_utf8_lossy(&s1.stderr)
        ));
    }
    let msg_path = repo.join(".evo_commit_msg");
    std::fs::write(&msg_path, msg).map_err(|e| format!("写 commit 消息失败: {}", e))?;
    let s2 = Command::new("git")
        .args([
            "-C",
            &repo.to_string_lossy(),
            "commit",
            "-F",
            &msg_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&msg_path);
    let s2 = match s2 {
        Ok(o) => o,
        Err(e) => return Err(e),
    };
    if !s2.status.success() {
        return Err(format!(
            "git commit 失败: {}",
            String::from_utf8_lossy(&s2.stderr)
        ));
    }
    let h = Command::new("git")
        .args(["-C", &repo.to_string_lossy(), "rev-parse", "--short", "HEAD"])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&h.stdout).trim().to_string())
}

/// 取用户主目录（用于推导受保护根，避免硬编码用户名）
fn home_dir() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .ok()
        .or_else(|| std::env::var("HOME").ok())
        .map(PathBuf::from)
}

/// P0-2：把目标路径规范化并校验它确实落在隔离仓库，而非 agent-core / memoria 源码树。
/// 返回规范化后的绝对路径；任何不满足都返回 Err（fail-closed）：
/// 1. 解析 symlink / `..` / 大小写，得到真实路径；
/// 2. 拒绝符号链接本身（防 TOCTOU / 软链指向核心仓）；
/// 3. 拒绝任何路径组件（小写）以 "agent-core" 或 "memoria" 开头（覆盖改名克隆、memoria-open 等）；
/// 4. 拒绝规范化后落在 agent-core 可执行文件所在 crate 根，或其已知 memoria 根下的任何文件。
pub fn resolve_isolated_target(target: &str) -> Result<PathBuf, String> {
    let p = Path::new(target);
    // 符号链接本身一律拒绝
    if let Ok(meta) = std::fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return Err("拒绝：目标为符号链接（防指向核心仓）".to_string());
        }
    }
    let canon = p
        .canonicalize()
        .map_err(|e| format!("目标路径无法解析: {}", e))?;

    // 3) 组件级拦截（覆盖改名克隆 / memoria-open）
    for comp in canon.components() {
        if let std::path::Component::Normal(s) = comp {
            let c = s.to_string_lossy().to_lowercase();
            if c.starts_with("agent-core") || c.starts_with("memoria") {
                return Err(format!("拒绝：路径落入受保护源码树（组件 {}）", c));
            }
        }
    }

    // 4) 根级拦截
    let mut forbidden: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        // agent-core.exe 位于 <crate>/target/release/agent-core.exe → 上溯三层到 crate 根
        if let Some(crate_root) = exe
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
        {
            if let Ok(c) = crate_root.canonicalize() {
                forbidden.push(c);
            }
        }
    }
    if let Some(home) = home_dir() {
        for sub in ["memoria", "memoria-open"] {
            let mp = home.join(".qclaw").join("workspace").join(sub);
            if let Ok(c) = mp.canonicalize() {
                forbidden.push(c);
            }
        }
    }
    for f in &forbidden {
        if canon.starts_with(f) {
            return Err(format!("拒绝：目标落入受保护根 {}", f.display()));
        }
    }
    Ok(canon)
}
