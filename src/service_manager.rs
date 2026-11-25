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
/// 脱离父进程所在的 Job Object。
///
/// **这是「agent-core 重启，被管服务继续跑」这条承诺的技术前提**。
/// 实测教训（2026-10-22）：仅用 DETACHED_PROCESS 时，若 agent-core 自身处在某个
/// Job 里（CodeBuddy/托盘/服务包装器创建的都可能），子进程会**默认继承同一个 Job**，
/// 那么父进程被 kill 时 Job 关闭 → 被管服务被一起收走。
/// 当天 emb(:8778) 就这样被带走了两次，进而拖慢 memoria /health 触发上层误判。
///
/// 注意：若 Job 未设 `JOB_OBJECT_LIMIT_BREAKAWAY_OK`，带此标志会 CreateProcess 失败
/// （拒绝访问），故调用处必须能回退到不带该标志。
#[cfg(windows)]
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

fn default_expect() -> u16 {
    200
}
fn default_stop_timeout() -> u64 {
    10
}
fn default_restart_policy() -> String {
    "on-failure".to_string()
}
fn default_true() -> bool {
    true
}
fn default_probe_timeout() -> u64 {
    3
}
fn default_keepalive_fails() -> u32 {
    4
}
fn default_slow_confirm() -> u64 {
    10
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
    /// 可执行文件绝对路径（`task_name` 非空时可留空）。
    #[serde(default)]
    pub exe: String,
    /// 计划任务名（非空 = 该服务由 Windows 计划任务驱动，用 `schtasks` 启停）。
    ///
    /// 为什么需要两种类型：本机 `a2a`(A2A Bridge) 历史上是 `svc-a2a-bridge` 计划任务
    /// 拉起的，没有可直接 spawn 的 exe 路径。硬塞进 process 模型会起不来。
    /// 注意 `schtasks /end` 只结束任务、**不保证杀掉已运行进程**，故 stop 仍保留端口兜底。
    #[serde(default)]
    pub task_name: String,
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
    /// 端口仍被占用时，是否按端口找 PID 强杀（默认 true）。
    ///
    /// 必要性：迁移前启动的实例、跨代遗留实例都没有本模块的 `Child` 句柄，
    /// 不按端口杀就永远停不掉 → `restart` 会退化成「假成功」。
    /// agent-core 以 LocalSystem 运行，权限足以终止托盘/普通令牌杀不掉的外部实例。
    /// 保守场景可置 false（此时 stop 只会等待端口自然释放）。
    #[serde(default = "default_true")]
    pub kill_by_port: bool,
    /// 本服务专属环境变量。
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// 单次健康探测的超时（秒）。默认 3。
    ///
    /// 为什么需要（2026-11-25）：此前写死 3 秒且挂在全局 reqwest client 上，
    /// 所有服务共用同一个判据。dashboard 的 `/health` 要走 WMI 扫全机进程再探
    /// 各端口，机器忙时经常超过 3 秒，「进程活着但应答慢」被当成「进程卡死」——
    /// 2026-11-25 10:48 与 11-23 两次把活进程树杀重启，同事页面无故瞬断。
    /// 改为按服务配置，配合 [`Self::slow_confirm_sec`] 区分「慢」与「死」。
    /// 注意：该值同时作用于 `start()` 里「拉起后等就绪」的轮询探测（40 轮），
    /// 配置过大会把一次启动的等待时间按比例放大，请保持在个位数秒。
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout_sec: u64,
    /// `on-failure` 策略下连续失败多少轮才考虑动手。默认 4。
    ///
    /// 为什么需要（2026-11-25）：此前写死 2 轮，30s 周期下只有 60s 观察窗，
    /// 撞上机器繁忙的探测慢就可能误杀；放宽为可配置阈值（默认 4 轮 = 120s）
    /// 给慢服务更多恢复机会。`always` 策略不受此项影响（失败即动手）。
    #[serde(default = "default_keepalive_fails")]
    pub keepalive_fails: u32,
    /// 「慢确认」超时（秒）。默认 10。
    ///
    /// 为什么需要（2026-11-25）：超过宽限期、探测失败、准备树杀旧进程前，
    /// 先用这个更长的超时再探一次——成功则说明服务只是慢不是死，
    /// 不杀不重启。这是 2026-11-25 10:48「活进程被树杀」事故的直接对策。
    #[serde(default = "default_slow_confirm")]
    pub slow_confirm_sec: u64,
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
    /// 停机接口客户端（`stop_path` POST）：保留改动前的 3s 超时，stop() 行为不变。
    http: reqwest::Client,
    /// 健康探测客户端：client 级不设超时，逐请求超时按服务配置落实（2026-11-25）。
    probe_http: reqwest::Client,
}

impl ServiceManager {
    pub fn new(configs: Vec<ServiceConfig>) -> Self {
        // 停机用：维持改动前的 3s 全局超时（stop_path 不参与保活判据，行为不动）。
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            // 健康探测只打本机回环，禁跳转、禁代理
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        // 探测用：**不设** client 级超时——改动前所有服务共用一个 3s 判据，
        // 「进程活着但应答慢」与「进程卡死」区分不了（2026-11-25 误杀根因）。
        // 每个服务的超时 = ServiceConfig::probe_timeout_sec，由 probe_with_timeout
        // 用 tokio::time::timeout 逐请求落实。
        let probe_http = reqwest::Client::builder()
            // 健康探测只打本机回环，禁跳转、禁代理
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            configs,
            rt: std::sync::Arc::new(Mutex::new(HashMap::new())),
            http,
            probe_http,
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
    /// HTTP 阶段超时取该服务配置的 `probe_timeout_sec`。
    async fn probe(&self, c: &ServiceConfig) -> bool {
        self.probe_with_timeout(c, c.probe_timeout_sec).await
    }

    /// 同 [`probe`](Self::probe)，但 HTTP 超时由调用方给定（慢确认用更长的超时）。
    ///
    /// 超时与传输错误走同一 fallback 分支，成功判据（状态码 / fallback_port）
    /// 与改动前逐字一致——只是「多久算超时」从全局 3s 变成按服务配置。
    async fn probe_with_timeout(&self, c: &ServiceConfig, timeout_sec: u64) -> bool {
        if !self.port_open(c.port) {
            return false;
        }
        if c.health.is_empty() {
            return true;
        }
        let url = format!("http://127.0.0.1:{}{}", c.port, c.health);
        // client 级不设超时，逐请求用 tokio::time::timeout 落实「这个服务的」超时
        // （2026-11-25：reqwest 的 client timeout 是全局的，无法按服务区分
        // 「进程活着但应答慢」与「进程卡死」，正是误杀根因）。
        let send = self.probe_http.get(&url).send();
        // 下限 1 秒：配置误写 0 时，带 health 路径的探测会「立即超时」恒失败
        // （有慢确认兜底不会误杀，但每轮都要白等一次慢确认）。
        let res = match tokio::time::timeout(Duration::from_secs(timeout_sec.max(1)), send).await {
            Ok(r) => r,
            // 超时与传输错误同语义：只有显式 fallback 才认定正常
            Err(_) => return c.fallback_port && self.port_open(c.port),
        };
        match res {
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

    /// 「慢确认」探测：用服务配置的 `slow_confirm_sec` 超时再探一次。
    ///
    /// 与 [`probe`](Self::probe) 的成功判据完全相同，只是超时更长——
    /// 树杀旧进程前的最后一道闸（2026-11-25：区分「活着但慢」与「卡死」）。
    async fn slow_confirm(&self, c: &ServiceConfig) -> bool {
        self.probe_with_timeout(c, c.slow_confirm_sec).await
    }

    /// 启动一个服务。已在跑则直接返回其外部 pid 语义（不重复起）。
    pub async fn start(&self, key: &str) -> Result<String, String> {
        let c = self.cfg(key).ok_or_else(|| format!("未知服务: {key}"))?;
        if self.probe(c).await {
            return Ok(format!("{} 已在运行（端口 {}）", c.name, c.port));
        }

        // ── 慢确认（2026-11-25）：探测失败不等于进程卡死 ──
        // 探测失败有三种可能：真卡死、还没起来、**活着但应答慢**。
        // dashboard 的 /health 要走 WMI 扫全机进程，机器忙时经常超过 3s——
        // 2026-11-25 10:48 与 11-23 两次，活进程因此被树杀重启、同事页面瞬断。
        // 所以探测失败后一律先用更长的 slow_confirm_sec 再探一次：成功则说明
        // 服务只是慢不是死，不杀不重启也不重复拉起；失败才落到下方原有逻辑。
        //
        // 为什么不限「手里有存活句柄」：本模块拉起的进程之外还有外部实例
        // （如旧看护脚本拉起的 memoria），它们没有句柄——探测超时若不拦，
        // 下方会直接再 spawn 一个重复进程。端口没开时 slow_confirm 立即返回
        // false，不会拖慢真正宕机时的拉起。
        //
        // 句柄在慢确认期间仍留在槽里（不 take）：成功路径天然没有
        // 「取出来又放回」的并发窗口，下方原有实现一字未改。
        if self.slow_confirm(c).await {
            // 慢确认成功：进程活着只是慢，不杀不重启，清零该服务失败计数
            {
                let mut rt = self.rt.lock().await;
                if let Some(slot) = rt.get_mut(key) {
                    slot.fail_count = 0;
                }
            }
            tracing::warn!(
                target: "agent.services",
                "服务 {} 探测超时但 {} 秒内慢确认成功，不重启",
                c.name, c.slow_confirm_sec
            );
            return Ok(format!(
                "{} 探测超时但 {} 秒内慢确认成功，不重启",
                c.name, c.slow_confirm_sec
            ));
        }

        // 修复泄漏（2026-11-03）：probe 失败但旧子进程可能还活着（卡死但占 CPU、
        // 不再监听端口）。此前走到下面直接覆盖 slot.child，把活句柄丢成孤儿——
        // 保活每轮重启就漏一个 pythonw，数天累积数十个。这里先树杀旧进程并
        // 回收句柄，再拉新。
        //
        // 宽限期：刚拉起还没来得及绑端口的服务是「慢启动」不是「卡死」，直接树杀
        // 会造成杀/起死循环（2026-11-03 二审意见）。超过 120s 仍探测失败才动手。
        {
            let (old, fresh) = {
                let mut rt = self.rt.lock().await;
                match rt.get_mut(key) {
                    Some(s) => {
                        // 宽限期只在「有活句柄且未超时」时生效：保护慢启动进程；
                        // spawn 失败残留的孤儿 started_at（child=None）不受保护，
                        // 否则无进程可管却拒绝重启（2026-11-03 三审）
                        let fresh = s.child.is_some()
                            && s.started_at
                                .map(|t| t.elapsed() < Duration::from_secs(120))
                                .unwrap_or(false);
                        // 宽限期内不下手：句柄留在 slot，慢启动进程不失去管理
                        // （三审 HIGH 修：此前 take 后早退把句柄丢成孤儿）
                        if fresh {
                            (None, true)
                        } else {
                            (s.child.take(), false)
                        }
                    }
                    None => (None, false),
                }
            };
            if fresh {
                return Ok(format!("{} 启动宽限期内（<120s），暂不重启", c.name));
            }
            if let Some(mut old) = old {
                // try_wait 出错视为存活未知：仍尝试树杀（对已退出 pid 是无害空操作）
                let alive_or_unknown = !matches!(old.try_wait(), Ok(Some(_)));
                if alive_or_unknown {
                    let pid = old.id();
                    tracing::warn!(
                        target: "agent.services",
                        "服务 {} 探测失败但旧进程(pid={})存活或状态未知，树杀后重启",
                        c.name, pid
                    );
                    let task = tokio::task::spawn_blocking(move || {
                        crate::mcp_client::kill_pid(pid);
                        let _ = old.wait();
                    });
                    // kill_pid 失败（无权限/进程顽固）时 old.wait() 可能永不返回：
                    // 必须给 start() 出口，否则 tick 全量保活循环被卡死（三审）
                    if tokio::time::timeout(Duration::from_secs(10), task)
                        .await
                        .is_err()
                    {
                        tracing::warn!(
                            target: "agent.services",
                            "服务 {} 树杀后句柄回收超时（进程可能未被终止）",
                            c.name
                        );
                    }
                }
            }
        }

        // ── 计划任务型：用 schtasks /run 拉起 ──
        if !c.task_name.is_empty() {
            let out = Command::new("schtasks")
                .args(["/run", "/tn", &c.task_name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| format!("schtasks /run {} 失败: {e}", c.task_name))?;
            if !out.success() {
                return Err(format!(
                    "schtasks /run {} 返回非零（任务不存在或无权限？）",
                    c.task_name
                ));
            }
            for _ in 0..40 {
                if self.probe(c).await {
                    return Ok(format!("{} 已启动（计划任务 {}）", c.name, c.task_name));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            return Err(format!(
                "{} 计划任务已触发，但 20s 内端口 {} 未就绪",
                c.name, c.port
            ));
        }

        if !c.require_path.is_empty() && !Path::new(&c.require_path).exists() {
            return Err(format!("前置文件不存在: {}", c.require_path));
        }
        if c.exe.is_empty() {
            return Err(format!("{} 未配置 exe 也未配置 task_name", c.name));
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
        {
            // 先尝试脱离父 Job（保证 agent-core 重启不带走被管服务）；
            // 若当前 Job 未允许 BREAKAWAY，CreateProcess 会失败，下面回退重试。
            cmd.creation_flags(
                DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
                    | CREATE_BREAKAWAY_FROM_JOB,
            );
        }

        let mut child = match cmd.spawn() {
            Ok(ch) => ch,
            Err(first_err) => {
                #[cfg(windows)]
                {
                    tracing::warn!(
                        target: "agent.services",
                        "启动 {} 时无法脱离父 Job（{}），回退为普通脱离模式——\
                         若 agent-core 被强杀，该服务可能被一起收走",
                        c.name, first_err
                    );
                    // 回退：重建命令（Command 不能复用），去掉 BREAKAWAY
                    let mut c2 = Command::new(&c.exe);
                    c2.args(&c.args);
                    if !c.cwd.is_empty() {
                        c2.current_dir(&c.cwd);
                    }
                    for (k, v) in &c.env {
                        c2.env(k, v);
                    }
                    c2.stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    c2.creation_flags(
                        DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
                    );
                    c2.spawn()
                        .map_err(|e| format!("启动 {} 失败: {e}", c.name))?
                }
                #[cfg(not(windows))]
                {
                    return Err(format!("启动 {} 失败: {first_err}", c.name));
                }
            }
        };
        let pid = child.id();
        // 多余实例（duplicate 分支）的树杀 pid：须在锁块前捕获——锁块会以
        // Option::take 方式处置 child，之后不可再直用（三审借用修正）
        let dup_pid = pid;
        let mut child_opt = Some(child);

        let surplus = {
            let mut rt = self.rt.lock().await;
            let slot = rt.entry(key.to_string()).or_default();
            if slot.child.is_some() {
                // 并发 start 已登记活句柄（HTTP/tick/restart 三入口并发）：
                // 终止本次多余实例而不是覆盖，避免造出孤儿
                // （2026-11-03 二审：check-then-act 竞态补丁）
                child_opt.take()
            } else {
                slot.child = child_opt.take();
                slot.started_at = Some(Instant::now());
                slot.last_error.clear();
                None
            }
        };
        if let Some(mut dup) = surplus {
            // 锁下只做判定，阻塞的杀+回收放锁外（三审：wait 持全局锁会卡全部
            // start/stop/status）。树杀 kill_pid：多余实例同样带 worker 子进程，
            // 只杀本体会留孤儿；句柄在手 pid 不会被复用。
            let task = tokio::task::spawn_blocking(move || {
                crate::mcp_client::kill_pid(dup_pid);
                let _ = dup.wait();
            });
            let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
            return Ok(format!("{} 已由并发启动拉起（本次多余实例已终止）", c.name));
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

        // 0) 计划任务型：先结束任务。注意 schtasks /end 只结束任务实例，
        //    不保证杀掉已运行的进程，故后面仍要等端口释放。
        if !c.task_name.is_empty() {
            let _ = Command::new("schtasks")
                .args(["/end", "/tn", &c.task_name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }

        // 1) 优雅停机（如 nvr_dl_service 的 /shutdown 需要先 DPSDK_Logout）
        if !c.stop_path.is_empty() {
            let url = format!("http://127.0.0.1:{}{}", c.port, c.stop_path);
            let _ = self.http.post(&url).send().await;
        }

        // 2) 终止本模块拉起的进程：先取出句柄并释放 rt 锁——阻塞的 taskkill/wait
        //    不能持有全局服务表锁（会卡住并发的 start/stop/status，2026-11-03 审查意见；
        //    与 start() 的「取句柄-放锁-再杀」模式保持一致）
        let mut killed = 0usize;
        let victim = {
            let mut rt = self.rt.lock().await;
            rt.get_mut(key).and_then(|slot| {
                slot.started_at = None;
                slot.child.take()
            })
        };
        if let Some(mut ch) = victim {
            // 先给它优雅退出的机会（锁外执行阻塞操作）
            let deadline = Instant::now() + Duration::from_secs(c.stop_timeout_sec);
            loop {
                match ch.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            // 树杀（taskkill /T /F）：pythonw 服务（dashboard/ox
                            // 等）常带 worker 子进程，只 kill 本体会把 worker
                            // 留成孤儿（2026-11-03 事故来源之一）。阻塞操作
                            // 放 spawn_blocking，避免占住执行器 worker。
                            let vpid = ch.id();
                            let task = tokio::task::spawn_blocking(move || {
                                crate::mcp_client::kill_pid(vpid);
                                let _ = ch.wait();
                            });
                            if let Err(je) = task.await {
                                tracing::warn!(
                                    target: "agent.services",
                                    "服务 {} 树杀阻塞任务未完成: {je}",
                                    c.name
                                );
                            }
                            killed += 1;
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    Err(_) => break,
                }
            }
        }

        // 3) 端口兜底：本模块没有句柄的实例（跨代/外部/迁移前的老进程）只能等；
        //    等不到就按端口找 PID 强杀。**这一步需要权限**——agent-core 以 LocalSystem
        //    运行，能杀掉托盘/普通令牌杀不掉的外部实例（这正是迁移后 restart 假成功
        //    的根因：老实例无句柄 → stop 杀不掉 → start 发现端口在听 → 报「已在运行」）。
        //    这些端口都是专用服务端口，误杀风险可控；可用 kill_by_port=false 关闭。
        for _ in 0..(c.stop_timeout_sec * 2) {
            if !self.port_open(c.port) {
                return Ok(format!("{} 已停止（终止 {killed} 个进程）", c.name));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if c.kill_by_port {
            // 并发 start 已登记新句柄 = 端口监听者是新拉起的实例，不能按端口强杀
            // （2026-11-03 三审：stop-vs-start check-then-act 窗口，netstat 复核
            // 只能发现监听者变化、发现不了合法新实例）
            let new_child_registered = {
                let rt = self.rt.lock().await;
                rt.get(key).map(|s| s.child.is_some()).unwrap_or(false)
            };
            if new_child_registered {
                return Err(format!(
                    "{} 检测到并发 start 已拉起新实例，跳过按端口强杀",
                    c.name
                ));
            }
            if let Some(pid) = Self::find_pid_by_port(c.port) {
                // netstat 快照可能过期（监听者刚退出/pid 被复用）：/T 树杀的误伤
                // 半径大，动手前复核一次监听者没变（2026-11-03 二审意见）。
                // 三种结局分开处理（三审）：监听者退出=stop 已生效，不该误报。
                match Self::find_pid_by_port(c.port) {
                    None if !self.port_open(c.port) => {
                        return Ok(format!("{} 已停止（监听者已退出）", c.name));
                    }
                    None => {
                        return Err(format!(
                            "{} 端口 {} 监听者复核失败（netstat 异常？），本轮不强杀",
                            c.name, c.port
                        ));
                    }
                    Some(cur) if cur != pid => {
                        return Err(format!(
                            "{} 端口 {} 的监听者已变化（原 pid={pid}），本轮不强杀",
                            c.name, c.port
                        ));
                    }
                    _ => {}
                }
                // 复用 kill_pid（taskkill /T /F 树杀）：监听者可能带 worker 子进程，
                // 不带 /T 会把子进程留成孤儿。阻塞操作放 spawn_blocking（三审）。
                let _ = tokio::task::spawn_blocking(move || {
                    crate::mcp_client::kill_pid(pid);
                })
                .await;
                tracing::warn!(
                    target: "agent.services",
                    "服务 {} 无句柄，已按端口 {} 强杀 PID={}",
                    c.name, c.port, pid
                );
                for _ in 0..10 {
                    if !self.port_open(c.port) {
                        return Ok(format!("{} 已停止（按端口强杀 PID={pid}）", c.name));
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
        Err(format!(
            "{} 端口 {} 仍被占用（kill_by_port={}，未能终止监听者）",
            c.name, c.port, c.kill_by_port
        ))
    }

    /// 解析 `netstat -ano` 找监听指定端口的 PID。
    ///
    /// 不用 `GetExtendedTcpTable`（要更多 FFI 与 unsafe），netstat 足够且可读性好。
    fn find_pid_by_port(port: u16) -> Option<u32> {
        let out = Command::new("netstat").args(["-ano"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let needle = format!(":{port}");
        for line in text.lines() {
            if !line.contains("LISTENING") {
                continue;
            }
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            // 本地地址列形如 0.0.0.0:8080 / [::]:8080 / 127.0.0.1:9753
            let local = cols[1];
            if !local.ends_with(&needle) {
                continue;
            }
            if let Ok(pid) = cols[cols.len() - 1].parse::<u32>() {
                return Some(pid);
            }
        }
        None
    }

    /// 重启。
    ///
    /// 注意：**stop 失败必须直接返回错误**。早期版本写成 `let _ = self.stop(...)`
    /// 忽略失败，导致「老实例无句柄、杀不掉 → 端口还在 → start 探测到就在跑 →
    /// 返回『已在运行』」的**假成功**（2026-10-22 实测：调 ox restart 返回 ok=true
    /// 但其实什么都没重启）。这种假成功比报错更糟，因为它会让人以为操作生效了。
    pub async fn restart(&self, key: &str) -> Result<String, String> {
        if let Err(e) = self.stop(key).await {
            return Err(format!("重启中止（停止阶段失败）: {e}"));
        }
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
            // 累计失败次数；on-failure 达到 keepalive_fails 轮才动手（默认 4 轮）
            let fails = {
                let mut rt = self.rt.lock().await;
                let slot = rt.entry(c.key.clone()).or_default();
                slot.fail_count = slot.fail_count.saturating_add(1);
                slot.fail_count
            };
            if c.restart == "on-failure" && fails < c.keepalive_fails {
                // 被防抖挡住：留一条可检索日志，事后能区分「在防抖」与「漏保活」
                tracing::info!(
                    target: "agent.services",
                    "服务 {} 保活防抖中：连续失败 {} 轮 < 阈值 {}，本轮不动手",
                    c.name, fails, c.keepalive_fails
                );
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
            task_name: String::new(),
            args: vec![],
            cwd: String::new(),
            require_path: String::new(),
            stop_timeout_sec: 1,
            restart: "off".into(),
            stop_path: String::new(),
            kill_by_port: true,
            env: HashMap::new(),
            probe_timeout_sec: 3,
            keepalive_fails: 4,
            slow_confirm_sec: 10,
        }
    }

    /// 最小假 HTTP 服务：读到请求后等 `delay` 再回 200。
    /// `port`=0 表示由系统分配。返回 (实际端口, 接受循环句柄)。
    async fn spawn_fake_http(port: u16, delay: Duration) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap_or_else(|e| panic!("绑假服务端口 {port} 失败: {e}"));
        let actual = listener.local_addr().expect("读本地地址").port();
        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                // 每连接一个任务：慢应答不能堵住接受循环（真实服务也是这样）
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    tokio::time::sleep(delay).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        (actual, handle)
    }

    /// 预留一个「此刻无人监听」的端口：绑上拿到端口号后立刻放开。
    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("绑临时端口");
        let port = l.local_addr().expect("读本地地址").port();
        drop(l);
        port
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

    /// 阈值防抖：on-failure 连续失败未达 keepalive_fails 时不动手。
    /// 端口无人监听 + exe 不存在 → 第 4 轮动手必然失败，动作带「保活失败」。
    #[tokio::test]
    async fn tick_debounces_until_keepalive_fails_threshold() {
        let mut c = cfg("deb", closed_port());
        c.restart = "on-failure".into();
        c.keepalive_fails = 4;
        c.exe = "definitely-not-exists-xyz".into();
        let m = ServiceManager::new(vec![c]);

        for i in 1..=3 {
            let actions = m.tick().await;
            assert!(
                actions.is_empty(),
                "第 {i} 轮应被防抖挡住，实际动作: {actions:?}"
            );
            let st = m.status().await;
            assert_eq!(
                st[0].fail_count, i,
                "第 {i} 轮后 fail_count 应累计到 {i}"
            );
        }

        let actions = m.tick().await;
        assert_eq!(actions.len(), 1, "第 4 轮应动手，实际: {actions:?}");
        assert!(
            actions[0].contains("[保活失败]"),
            "第 4 轮动作应为保活失败，实际: {}",
            actions[0]
        );
    }

    /// 慢确认成功：应答延迟 1.5s 超过 1s 探测超时，但落在 5s 慢确认内。
    #[tokio::test]
    async fn slow_confirm_succeeds_when_probe_times_out() {
        let (port, _server) = spawn_fake_http(0, Duration::from_millis(1500)).await;
        let mut c = cfg("slow", port);
        c.health = "/health".into();
        c.probe_timeout_sec = 1;
        c.slow_confirm_sec = 5;
        let probe_cfg = c.clone();
        let m = ServiceManager::new(vec![c]);

        assert!(!m.probe(&probe_cfg).await, "1s 探测应超时判失败");
        assert!(m.slow_confirm(&probe_cfg).await, "5s 慢确认应成功");
    }

    /// 慢确认失败：应答延迟 1.5s 超过 1s 慢确认超时，且不得等满应答时间。
    #[tokio::test]
    async fn slow_confirm_fails_when_response_exceeds_timeout() {
        let (port, _server) = spawn_fake_http(0, Duration::from_millis(1500)).await;
        let mut c = cfg("slowfail", port);
        c.health = "/health".into();
        c.probe_timeout_sec = 1;
        c.slow_confirm_sec = 1;
        let probe_cfg = c.clone();
        let m = ServiceManager::new(vec![c]);

        let t0 = Instant::now();
        assert!(
            !m.slow_confirm(&probe_cfg).await,
            "1.5s 应答超过 1s 慢确认，应判失败"
        );
        let elapsed = t0.elapsed();
        // 余量放宽到 1.9s（应答 1.5s）：若实现等满了应答，上面那条断言会先失败，
        // 这里只拦「明显超时后才返回」的回归，避免高负载机器上因调度抖动误报。
        assert!(
            elapsed < Duration::from_millis(1900),
            "应在约 1s 超时返回，不得等满 1.5s 应答，实际耗时 {elapsed:?}"
        );
    }

    /// 外部实例（本模块手里没有句柄，如旧看护脚本拉起的 memoria）慢但在运行：
    /// start() 不得再拉一个重复进程，应慢确认成功后直接返回。
    #[tokio::test]
    async fn start_does_not_spawn_duplicate_for_slow_external_instance() {
        let (port, _server) = spawn_fake_http(0, Duration::from_millis(1500)).await;
        let mut c = cfg("ext", port);
        c.health = "/health".into();
        c.probe_timeout_sec = 1;
        c.slow_confirm_sec = 5;
        // exe 指向不存在的路径：若没被慢确认拦住，下面会走到启动失败分支返回 Err
        c.exe = "definitely-not-exists-xyz".into();
        let m = ServiceManager::new(vec![c]);

        let msg = m
            .start("ext")
            .await
            .expect("慢确认成功应返回 Ok，不得尝试启动");
        assert!(msg.contains("慢确认"), "unexpected: {msg}");
        let st = m.status().await;
        assert!(st[0].pid.is_none(), "不应拉起新进程");
        assert_eq!(st[0].fail_count, 0, "慢确认成功应清零失败计数");
    }
}
