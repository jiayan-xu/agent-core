//! 服务编排（P2，2026-10-22）：托管本机常驻服务的启停与保活。
//!
//! # 为什么需要它
//! 此前「谁负责拉起/保活本机服务」由 PowerShell 托盘（`start_both_tray.ps1`）承担，
//! 结果是托盘成了一个服务注册表：每加一个服务就要改脚本 + 加一项 UI，越滚越大，
//! 且托盘是 GUI 进程，依赖登录桌面，崩溃即全体失管。本模块把这层职责上移到
//! agent-core（常驻 Rust 服务），托盘退化为纯状态面板。
//!
//! # 与 `sandbox::Job Object` 的语义差异（关键，别搞混）
//! `sandbox.rs` 是 **kill-on-job-close**：agent-core 退出时把 MCP 子进程一起清掉，用于
//! 防孤儿。服务编排要的恰恰相反——**agent-core 重启/升级时被管服务必须继续跑**，
//! 否则编排层一升级就把生产服务全带走，比托盘的脆弱性更糟。因此：
//! - 子进程用 `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP` 启动；
//! - **绝不**把服务进程交给 [`crate::sandbox`] 的 Job Object。
//!
//! # 状态模型
//! **进程存活 ≠ 服务可用**。判定以「端口监听 + 可选 HTTP 健康路径」为准
//! （对齐托盘 E4 口径：ox 必须看 `/healthz`，nvr 旧构建 `/health` 返回 404 需
//! `fallback_port`）。进程句柄只用于优雅停机，不作为可用性依据——进程假死时
//! 端口探测能发现，而 `Child::try_wait` 不能。
//!
//! # 配置
//! 落 `agent.toml` 的 `[[services]]` 表（该文件已 gitignore，可写本机路径）。

use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// 子进程脱离父进程控制台：agent-core 退出/重启后服务继续跑。
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x0000_0008;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn default_expect() -> u16 {
    200
}
fn default_stop_timeout() -> u64 {
    10
}
fn default_restart_policy() -> String {
    "on-failure".to_string()
}

/// 单个被管服务的配置（`[[services]]` 表）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// 唯一短名，API 用它定位服务（如 `dashboard`）。
    pub key: String,
    /// 显示名（UI/日志用）。
    #[serde(default)]
    pub name: String,
    pub port: u16,
    /// HTTP 健康路径（如 `/health`）。空串则只做端口探测。
    #[serde(default)]
    pub health: String,
    /// 期望的 HTTP 状态码。
    #[serde(default = "default_expect")]
    pub expect: u16,
    /// 健康路径返回 404 时回退为「端口在听即正常」（nvr 旧构建场景）。
    #[serde(default)]
    pub fallback_port: bool,
    /// 可执行文件绝对路径。
    pub exe: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// 工作目录。
    #[serde(default)]
    pub cwd: String,
    /// 启动前置校验：该路径不存在则不启动（防配置写错后疯狂重试）。
    #[serde(default)]
    pub require_path: String,
    /// 停机等待上限（秒）。
    #[serde(default = "default_stop_timeout")]
    pub stop_timeout_sec: u64,
    /// 保活策略：`off` / `on-failure`（默认）/ `always`。
    #[serde(default = "default_restart_policy")]
    pub restart: String,
    /// 优雅停机接口（POST）。空串则直接 TerminateProcess。
    #[serde(default)]
    pub stop_path: String,
    /// 本服务专属环境变量。
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// 对外暴露的服务状态快照。
#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    pub key: String,
    pub name: String,
    pub port: u16,
    /// 可用性（端口 + 健康路径），这是唯一可信的「在跑」判据。
    pub running: bool,
    /// 本模块拉起的进程 pid（跨代/外部启动时为 None）。
    pub pid: Option<u32>,
    /// 本模块拉起且进程仍存活。
    pub managed_alive: bool,
    pub uptime_sec: u64,
    pub fail_count: u32,
    pub last_error: String,
    pub restart: String,
}

/// 单服务的运行时状态。
#[derive(Default)]
struct Runtime {
    child: Option<Child>,
    started_at: Option<Instant>,
    fail_count: u32,
    last_error: String,
}

/// 服务编排器。克隆成本低（内部 Arc），可放进 `AppState` 共享。
#[derive(Clone)]
pub struct ServiceManager {
    configs: Vec<ServiceConfig>,
    rt: std::sync::Arc<Mutex<HashMap<String, Runtime>>>,
    http: reqwest::Client,
}

impl ServiceManager {
    pub fn new(configs: Vec<ServiceConfig>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            // 健康探测只打本机回环，禁跳转、禁代理
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            configs,
            rt: std::sync::Arc::new(Mutex::new(HashMap::new())),
            http,
        }
    }

    /// 配置里的服务数量（0 表示编排未启用，热路径应零行为变化）。
    pub fn len(&self) -> usize {
        self.configs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    fn cfg(&self, key: &str) -> Option<&ServiceConfig> {
        self.configs.iter().find(|c| c.key == key)
    }

    /// 端口是否在监听。同步、无 IO 阻塞风险（connect_timeout 200ms）。
    fn port_open(&self, port: u16) -> bool {
        use std::net::{SocketAddr, TcpStream};
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
    }

    /// 可用性判定：端口 + 健康路径（含 fallback_port 语义）。
    async fn probe(&self, c: &ServiceConfig) -> bool {
        if !self.port_open(c.port) {
            return false;
        }
        if c.health.is_empty() {
            return true;
        }
        let url = format!("http://127.0.0.1:{}{}", c.port, c.health);
        match self.http.get(&url).send().await {
            Ok(r) => {
                if r.status().as_u16() == c.expect {
                    return true;
                }
                // 404 且配置允许回退：端口在听即认为在跑（老版本健康路径未实现）
                c.fallback_port && r.status().as_u16() == 404
            }
            // 端口在听但 HTTP 栈异常：只有显式 fallback 才认定正常
            Err(_) => c.fallback_port && self.port_open(c.port),
        }
    }

    /// 启动一个服务。已在跑则直接返回其外部 pid 语义（不重复起）。
    pub async fn start(&self, key: &str) -> Result<String, String> {
        let c = self.cfg(key).ok_or_else(|| format!("未知服务: {key}"))?;
        if self.probe(c).await {
            return Ok(format!("{} 已在运行（端口 {}）", c.name, c.port));
        }
        if !c.require_path.is_empty() && !Path::new(&c.require_path).exists() {
            return Err(format!("前置文件不存在: {}", c.require_path));
        }

        let mut cmd = Command::new(&c.exe);
        cmd.args(&c.args);
        if !c.cwd.is_empty() {
            cmd.current_dir(&c.cwd);
        }
        for (k, v) in &c.env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);

        let child = cmd
            .spawn()
            .map_err(|e| format!("启动 {} 失败: {e}", c.name))?;
        let pid = child.id();

        {
            let mut rt = self.rt.lock().await;
            let slot = rt.entry(key.to_string()).or_default();
            slot.child = Some(child);
            slot.started_at = Some(Instant::now());
            slot.last_error.clear();
        }

        // 等端口就绪（最多 20s）：就绪才算启动成功，避免「假成功」后保活狂重试
        for _ in 0..40 {
            if self.probe(c).await {
                return Ok(format!("{} 已启动 pid={pid}", c.name));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let msg = format!("{} 启动后 20s 内端口 {} 未就绪", c.name, c.port);
        let mut rt = self.rt.lock().await;
        if let Some(slot) = rt.get_mut(key) {
            slot.last_error = msg.clone();
            slot.fail_count = slot.fail_count.saturating_add(1);
        }
        Err(msg)
    }

    /// 停止一个服务：优先走优雅停机接口，再退化为终止进程，最后按端口兜底。
    pub async fn stop(&self, key: &str) -> Result<String, String> {
        let c = self.cfg(key).ok_or_else(|| format!("未知服务: {key}"))?;

        // 1) 优雅停机（如 nvr_dl_service 的 /shutdown 需要先 DPSDK_Logout）
        if !c.stop_path.is_empty() {
            let url = format!("http://127.0.0.1:{}{}", c.port, c.stop_path);
            let _ = self.http.post(&url).send().await;
        }

        // 2) 终止本模块拉起的进程
        let mut killed = 0usize;
        {
            let mut rt = self.rt.lock().await;
            if let Some(slot) = rt.get_mut(key) {
                if let Some(mut ch) = slot.child.take() {
                    // 先给它优雅退出的机会
                    let deadline = Instant::now() + Duration::from_secs(c.stop_timeout_sec);
                    loop {
                        match ch.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) => {
                                if Instant::now() >= deadline {
                                    let _ = ch.kill();
                                    let _ = ch.wait();
                                    killed += 1;
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(300)).await;
                            }
                            Err(_) => break,
                        }
                    }
                }
                slot.started_at = None;
            }
        }

        // 3) 端口兜底：跨代/外部启动的进程本模块没有句柄，只能等它自己退；
        //    这里不做「按端口杀任意进程」——误杀代价太高（可能杀掉占同端口的别的东西）。
        for _ in 0..(c.stop_timeout_sec * 2) {
            if !self.port_open(c.port) {
                return Ok(format!("{} 已停止（终止 {killed} 个进程）", c.name));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!(
            "{} 端口 {} 仍被占用（可能由外部进程监听，未强杀）",
            c.name, c.port
        ))
    }

    /// 重启。
    pub async fn restart(&self, key: &str) -> Result<String, String> {
        let _ = self.stop(key).await;
        self.start(key).await
    }

    /// 全量状态快照。
    ///
    /// 注意：`probe` 是异步 IO，**不能**在持有状态锁时 await（会钉住整个表）。
    /// 故先持锁收集运行时字段、立即释放，再逐个做网络探测。
    pub async fn status(&self) -> Vec<ServiceStatus> {
        let mut rows = Vec::with_capacity(self.configs.len());
        {
            let mut rt = self.rt.lock().await;
            for c in &self.configs {
                let (pid, alive, uptime, fails, err) = match rt.get_mut(&c.key) {
                    Some(s) => {
                        // try_wait 需要 &mut Child；这里持有的是 &mut HashMap，正好可用。
                        // 比 OpenProcess 探活更准：能立刻回收僵尸句柄。
                        let alive = s
                            .child
                            .as_mut()
                            .map(|ch| matches!(ch.try_wait(), Ok(None)))
                            .unwrap_or(false);
                        (
                            s.child.as_ref().map(|ch| ch.id()),
                            alive,
                            s.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                            s.fail_count,
                            s.last_error.clone(),
                        )
                    }
                    None => (None, false, 0, 0, String::new()),
                };
                rows.push((c.clone(), pid, alive, uptime, fails, err));
            }
        }
        let mut out = Vec::with_capacity(rows.len());
        for (c, pid, alive, uptime, fails, err) in rows {
            out.push(ServiceStatus {
                key: c.key.clone(),
                name: if c.name.is_empty() {
                    c.key.clone()
                } else {
                    c.name.clone()
                },
                port: c.port,
                running: self.probe(&c).await,
                pid,
                managed_alive: alive,
                uptime_sec: uptime,
                fail_count: fails,
                last_error: err,
                restart: c.restart.clone(),
            });
        }
        out
    }

    /// 保活一轮：对 `restart != "off"` 且探测失败的服务的按策略拉起。
    /// 返回本轮执行的动作（供日志/审计）。
    pub async fn tick(&self) -> Vec<String> {
        let mut actions = Vec::new();
        for c in &self.configs {
            if c.restart == "off" {
                continue;
            }
            if self.probe(c).await {
                let mut rt = self.rt.lock().await;
                if let Some(slot) = rt.get_mut(&c.key) {
                    slot.fail_count = 0;
                }
                continue;
            }
            // 累计失败次数；on-failure 要求 ≥2 次才动手（对齐托盘防抖语义）
            let fails = {
                let mut rt = self.rt.lock().await;
                let slot = rt.entry(c.key.clone()).or_default();
                slot.fail_count = slot.fail_count.saturating_add(1);
                slot.fail_count
            };
            if c.restart == "on-failure" && fails < 2 {
                continue;
            }
            match self.start(&c.key).await {
                Ok(m) => actions.push(format!("[保活] {m}")),
                Err(e) => actions.push(format!("[保活失败] {e}")),
            }
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(key: &str, port: u16) -> ServiceConfig {
        ServiceConfig {
            key: key.into(),
            name: key.into(),
            port,
            health: String::new(),
            expect: 200,
            fallback_port: false,
            exe: "noop".into(),
            args: vec![],
            cwd: String::new(),
            require_path: String::new(),
            stop_timeout_sec: 1,
            restart: "off".into(),
            stop_path: String::new(),
            env: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn empty_manager_is_inert() {
        let m = ServiceManager::new(vec![]);
        assert!(m.is_empty());
        assert!(m.tick().await.is_empty());
        assert!(m.status().await.is_empty());
    }

    #[tokio::test]
    async fn unknown_key_errors() {
        let m = ServiceManager::new(vec![cfg("a", 1)]);
        assert!(m.start("nope").await.is_err());
        assert!(m.stop("nope").await.is_err());
        assert!(m.restart("nope").await.is_err());
    }

    #[tokio::test]
    async fn missing_require_path_refuses_start() {
        let mut c = cfg("x", 59999);
        c.exe = "definitely-not-exists-xyz".into();
        c.require_path = "C:/definitely/not/here/xyz.exe".into();
        let m = ServiceManager::new(vec![c]);
        let e = m.start("x").await.unwrap_err();
        assert!(e.contains("前置文件不存在"), "unexpected: {e}");
    }

    #[tokio::test]
    async fn status_reports_down_for_closed_port() {
        let m = ServiceManager::new(vec![cfg("dead", 59998)]);
        let s = m.status().await;
        assert_eq!(s.len(), 1);
        assert!(!s[0].running);
        assert_eq!(s[0].pid, None);
    }

    #[tokio::test]
    async fn tick_skips_off_policy() {
        let m = ServiceManager::new(vec![cfg("off", 59997)]); // restart="off"
        assert!(m.tick().await.is_empty());
    }
}
