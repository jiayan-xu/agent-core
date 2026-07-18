//! 白龙马 Phase C 吸收 — 条件式本地资源门控（local-resources-scanner 精华）
//!
//! 机制来源：白龙马 `src/local-resources-scanner.js` + `desktop-scanner.js`。
//! 代码事实（非宣传）：
//!   - 启动扫描一次本机「自有资源」只读元数据（ssh config 别名 / 公私钥**对名** /
//!     known_hosts 去重 host / git 全局 [user]），注入 system prompt，
//!     让 agent 在收到模糊任务（"上服务器"、"提交一下"）时先扫环境再问凭据。
//!   - 文档 §3 第4条：白龙马「资源感知」是**条件式**的——仅消息命中规则才门控注入，
//!     不是每次请求恒在（这点对齐我们的降泄露面诉求）。
//!
//! 安全红线（与白龙马代码事实一致，P0 合规）：
//!   - **绝不读私钥文件内容**（只收集 `.pub` 成对存在的**文件名**）。
//!   - **绝不读 known_hosts 指纹**（只提取 host 名，跳过 `|` 开头的 hashed 行）。
//!   - **绝不硬编码绝对路径**（home 用 `USERPROFILE` / `HOME` 环境变量）。
//!   - 不扫描桌面文件（agent-core 是后端服务，桌面扫描由 PFAiX 前端负责，见文档 §8）。
//!
//! 与白龙马的偏差（合理收敛）：
//!   - 白龙马 `desktop-scanner` 扫描用户桌面，我方**不吸收**（agent-core 不面向用户桌面）。
//!   - 白龙马无条件把资源块拼进每次 runTurn 的 extraContext；我方改为**仅消息命中规则时**
//!     才注入（条件式门控），零常态 prompt 膨胀、零泄露面。

use std::path::Path;
use std::sync::{Arc, Mutex};

/// 单个 SSH Host 别名解析结果（来自 `~/.ssh/config`，不含任何凭据）
#[derive(Clone, Debug, Default)]
pub struct SshHost {
    pub aliases: Vec<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<String>,
}

/// git 全局身份（来自 `~/.gitconfig` [user]，公开身份，非私密）
#[derive(Clone, Debug, Default)]
pub struct GitUser {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// 启动扫描得到的本机资源只读快照（全部为元数据，无任何私钥内容/指纹）
#[derive(Clone, Debug, Default)]
pub struct LocalResourceSnapshot {
    pub ssh_hosts: Vec<SshHost>,
    pub ssh_keys: Vec<String>,    // 仅密钥**对名**（如 id_ed25519），内容从未读取
    pub known_hosts: Vec<String>, // 去重后的 host 名，不含指纹
    pub git_user: Option<GitUser>,
}

/// 消息规则命中关键词（中英）——命中才把资源块注入 system prompt
const HIT_KEYWORDS: &[&str] = &[
    "ssh", "服务器", "部署", "deploy", "提交", "commit", "git", "仓库", "主机", "host",
    "连接", "登录", "推送", "push", "上服务器", "pull", "clone", "origin", "remote",
];

/// 判断用户消息是否命中资源相关规则（条件式门控的开关）
pub fn resource_hit(message: &str) -> bool {
    let m = message.to_lowercase();
    HIT_KEYWORDS.iter().any(|k| m.contains(k))
}

/// 解析 `~/.ssh/config`：提取 Host 块别名 / HostName / User / Port，跳过通配规则
fn scan_ssh_config(ssh_dir: &Path) -> Vec<SshHost> {
    let text = match std::fs::read_to_string(ssh_dir.join("config")) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut hosts: Vec<SshHost> = Vec::new();
    let mut current: Option<SshHost> = None;
    for raw in text.split('\n') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(m) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let key = m.0.trim().to_lowercase();
        let value = m.1.trim().to_string();
        if key == "host" {
            if let Some(c) = current.take() {
                hosts.push(c);
            }
            // 跳过通配 Host * / Host *.example（默认规则，非具体目标）
            let names: Vec<String> = value
                .split_whitespace()
                .filter(|n| !n.contains('*') && !n.contains('?'))
                .map(|s| s.to_string())
                .collect();
            current = if names.is_empty() { None } else { Some(SshHost { aliases: names, ..Default::default() }) };
        } else if let Some(c) = current.as_mut() {
            match key.as_str() {
                "hostname" => c.hostname = Some(value),
                "user" => c.user = Some(value),
                "port" => c.port = Some(value),
                _ => {}
            }
        }
    }
    if let Some(c) = current.take() {
        hosts.push(c);
    }
    hosts
}

/// 扫描 `~/.ssh/` 下「公私钥成对存在」的密钥**文件名**（绝不读内容）
fn scan_ssh_keys(ssh_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(ssh_dir) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for e in entries.flatten() {
        if let Ok(meta) = e.metadata() {
            if meta.is_file() {
                names.push(e.file_name().to_string_lossy().to_string());
            }
        }
    }
    let pub_set: std::collections::HashSet<String> =
        names.iter().filter(|n| n.ends_with(".pub")).cloned().collect();
    let mut keys: Vec<String> = names
        .into_iter()
        .filter(|n| !n.ends_with(".pub") && pub_set.contains(&format!("{}.pub", n)))
        .collect();
    keys.sort();
    keys
}

/// 解析 `~/.ssh/known_hosts`：提取每行首个 host，去重，跳过 `|` 开头的 hashed 行（不可逆）
fn scan_known_hosts(ssh_dir: &Path) -> Vec<String> {
    let text = match std::fs::read_to_string(ssh_dir.join("known_hosts")) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for raw in text.split('\n') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('|') {
            continue;
        }
        let first = line.split_whitespace().next().unwrap_or("");
        if first.is_empty() {
            continue;
        }
        // 一行可能逗号分隔多个 host：foo.com,1.2.3.4
        for h in first.split(',') {
            let cleaned = h.trim_start_matches('[').trim_end_matches(']').split(':').next().unwrap_or("").to_string();
            if !cleaned.is_empty() {
                hosts.insert(cleaned);
            }
        }
    }
    hosts.into_iter().collect()
}

/// 解析 `~/.gitconfig` [user] 的 name / email（公开 git 身份，非私密）
fn scan_git_global(home: &Path) -> Option<GitUser> {
    let text = std::fs::read_to_string(home.join(".gitconfig")).ok()?;
    let mut result = GitUser::default();
    let mut section: Option<String> = None;
    for raw in text.split('\n') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(sec) = line.trim().strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = Some(sec.to_lowercase());
            continue;
        }
        if section.as_deref() != Some("user") {
            continue;
        }
        let Some(kv) = line.split_once('=') else { continue };
        let k = kv.0.trim().to_lowercase();
        let v = kv.1.trim().to_string();
        match k.as_str() {
            "name" => result.name = Some(v),
            "email" => result.email = Some(v),
            _ => {}
        }
    }
    if result.name.is_some() || result.email.is_some() {
        Some(result)
    } else {
        None
    }
}

/// 启动时扫描一次本机资源只读元数据。无 home / 无 .ssh 时返回空快照（不报错）。
pub fn scan_local_resources() -> LocalResourceSnapshot {
    // home：Windows 用 USERPROFILE，posix 用 HOME。绝不硬编码 C:/Users/user（P0 红线）。
    let home = match std::env::var("USERPROFILE").ok().filter(|s| !s.is_empty()) {
        Some(h) => h,
        None => match std::env::var("HOME").ok().filter(|s| !s.is_empty()) {
            Some(h) => h,
            None => {
                tracing::warn!(target: "resources", "未找到 USERPROFILE/HOME，跳过本地资源扫描");
                return LocalResourceSnapshot::default();
            }
        },
    };
    let home_path = Path::new(&home);
    let ssh_dir = home_path.join(".ssh");
    let mut snap = LocalResourceSnapshot::default();
    if ssh_dir.exists() {
        snap.ssh_hosts = scan_ssh_config(&ssh_dir);
        snap.ssh_keys = scan_ssh_keys(&ssh_dir);
        snap.known_hosts = scan_known_hosts(&ssh_dir);
    }
    snap.git_user = scan_git_global(home_path);
    tracing::info!(
        target: "resources",
        ssh_hosts = snap.ssh_hosts.len(),
        ssh_keys = snap.ssh_keys.len(),
        known_hosts = snap.known_hosts.len(),
        git_user = snap.git_user.is_some(),
        "本地资源快照扫描完成（只读元数据）"
    );
    snap
}

/// 条件式门控：仅当用户消息命中资源规则、且确实存在可注入资源时才返回文本块。
/// 返回 None = 不注入（零常态泄露面 / 零 prompt 膨胀）。
pub fn resource_block_for(message: &str, snap: &LocalResourceSnapshot) -> Option<String> {
    if !resource_hit(message) {
        return None;
    }
    let mut lines: Vec<String> = vec![
        "## Local Resources Snapshot".to_string(),
        "(Scanned once at startup from the user's filesystem — read-only metadata. \
         Use these directly; do not ask the user for credentials, host addresses, or git \
         identity already listed below.)"
            .to_string(),
    ];

    if !snap.ssh_keys.is_empty() || !snap.ssh_hosts.is_empty() || !snap.known_hosts.is_empty() {
        let mut sub = vec!["### SSH".to_string()];
        if !snap.ssh_keys.is_empty() {
            sub.push(format!(
                "- Keys: {} (passwordless login set up — try ssh directly before asking for credentials)",
                snap.ssh_keys.join(", ")
            ));
        }
        if !snap.ssh_hosts.is_empty() {
            let shown = snap.ssh_hosts.iter().take(20).map(|h| {
                let aliases = h.aliases.join(" / ");
                let target = h.hostname.clone().unwrap_or_else(|| "(no HostName)".to_string());
                let user_part = h.user.as_ref().map(|u| format!(" as {}", u)).unwrap_or_default();
                let port_part = h
                    .port
                    .as_ref()
                    .filter(|p| *p != "22")
                    .map(|p| format!(":{}", p))
                    .unwrap_or_default();
                format!("  · {} → {}{}{}", aliases, target, port_part, user_part)
            });
            let more = if snap.ssh_hosts.len() > 20 {
                format!("\n  · ... ({} more)", snap.ssh_hosts.len() - 20)
            } else {
                String::new()
            };
            sub.push(format!(
                "- ~/.ssh/config aliases ({}):\n{}{}",
                snap.ssh_hosts.len(),
                shown.collect::<Vec<_>>().join("\n"),
                more
            ));
        }
        if !snap.known_hosts.is_empty() {
            let shown = snap.known_hosts.iter().take(30).cloned().collect::<Vec<_>>().join(", ");
            let more = if snap.known_hosts.len() > 30 {
                format!(" ... ({} total)", snap.known_hosts.len())
            } else {
                String::new()
            };
            sub.push(format!(
                "- Hosts previously connected ({}): {}{}",
                snap.known_hosts.len(),
                shown,
                more
            ));
        }
        lines.push(sub.join("\n"));
    }

    if let Some(g) = &snap.git_user {
        let mut parts = Vec::new();
        if let Some(n) = &g.name {
            parts.push(n.clone());
        }
        if let Some(e) = &g.email {
            parts.push(format!("<{}>", e));
        }
        if !parts.is_empty() {
            lines.push("### Git".to_string());
            lines.push(format!("- Global identity: {}", parts.join(" ")));
        }
    }

    // 无任何可注入资源时不注入（例如命中关键词但本机无 ssh/git 配置）
    if lines.len() <= 2 {
        return None;
    }
    Some(lines.join("\n\n"))
}

/// 共享的资源快照句柄（AppState 与 AgentCore 持有同一 Arc）
pub type SharedResourceSnapshot = Arc<Mutex<LocalResourceSnapshot>>;
