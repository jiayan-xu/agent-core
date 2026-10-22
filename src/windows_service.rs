//! Windows 服务支持（P2 阶段3，2026-10-22）：让 agent-core 由 SCM 托管。
//!
//! # 为什么必须做
//! P2 把「服务编排」职责搬进 agent-core 后，agent-core 自身若仍由 GUI 托盘拉起，
//! 编排层就是个单点：托盘崩溃 / 未登录桌面 / 被误杀 → 整条编排链失效，所有被管
//! 服务失去保活。SCM（服务控制管理器）提供**开机自启 + 崩溃重启 + 无桌面依赖**。
//!
//! # 不引入外部 wrapper
//! 不用 WinSW / NSSM（本机未安装，也不联网拉包），直接调 SCM API：
//! `StartServiceCtrlDispatcherW` + `RegisterServiceCtrlHandlerExW` + `SetServiceStatus`，
//! 依赖 `windows-sys`（本地 registry 缓存已有）。
//!
//! # 四种运行形态（同一个 exe）
//! - `agent-core.exe --install-service`    安装为自启服务（**需管理员**）
//! - `agent-core.exe --uninstall-service`  卸载（**需管理员**）
//! - 由 SCM 拉起（无控制台）→ dispatcher 成功 → 走服务分支
//! - 普通命令行 → dispatcher 返回 1063（非服务环境）→ 保持原行为，零变化
//!
//! # 关键坑：工作目录
//! SCM 启动服务的 cwd 是 `C:\Windows\System32`，而 `config_path()` 依赖 cwd 找
//! `agent.toml`。不处理的话服务会读不到配置、甚至凭空造出一份默认配置。
//! 故 `service_main` 一进来就把 cwd 切到 exe 所在目录。

use std::ffi::OsStr;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{GetLastError, ERROR_SERVICE_DOES_NOT_EXIST};
use windows_sys::Win32::System::Services::*;

/// 在 GUI 子系统（release 构建的 `windows_subsystem = "windows"`，无控制台）下，
/// `println!` 写 stdout 失败会 **panic**，导致 install 注册完服务后立刻异常退出、
/// 脚本拿到非零退出码后提前中止（2026-10-22 实测踩到两次）。
/// 这里统一用忽略错误的写入：有控制台就能看到，没有也不会 panic。
macro_rules! emit {
    ($($arg:tt)*) => {{
        let _ = writeln!(std::io::stdout(), $($arg)*);
        let _ = std::io::stdout().flush();
        tracing::info!($($arg)*);
    }};
}

pub(crate) const SVC_NAME: &str = "agent-core";
const SVC_DISPLAY: &str = "agent-core (PFAiX 编排引擎)";
const SVC_DESC: &str =
    "PFAiX 平台编排引擎：HTTP :9753 + 本机服务启停与保活。由 SCM 托管，开机自启、崩溃重启。";

/// 服务状态句柄（RegisterServiceCtrlHandlerExW 返回）。
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
/// 停止请求标志：控制处理器置位，主循环与 axum graceful shutdown 读取。
static STOP_REQ: AtomicBool = AtomicBool::new(false);

/// 是否已收到停止请求（供 bootstrap 的 graceful shutdown 读取）。
pub(crate) fn stop_requested() -> bool {
    STOP_REQ.load(Ordering::SeqCst)
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn set_status(state: u32, exit_code: u32, wait_hint_ms: u32) {
    let h = STATUS_HANDLE.load(Ordering::SeqCst);
    if h == 0 {
        return;
    }
    let accepted = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        0
    };
    let mut st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };
    unsafe {
        SetServiceStatus(h as SERVICE_STATUS_HANDLE, &mut st);
    }
}

/// SCM 控制处理器：STOP / SHUTDOWN 置标志；INTERROGATE 直接回 OK。
unsafe extern "system" fn ctrl_handler(
    ctrl: u32,
    _evt_type: u32,
    _evt_data: *mut core::ffi::c_void,
    _ctx: *mut core::ffi::c_void,
) -> u32 {
    match ctrl {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP_REQ.store(true, Ordering::SeqCst);
            // 告诉 SCM：正在停，给 10 秒。随后主循环会优雅关停 axum。
            set_status(SERVICE_STOP_PENDING, 0, 10_000);
        }
        _ => {}
    }
    0 // NO_ERROR
}

/// 服务主体：由 dispatcher 在 SCM 给予的服务线程上调用。
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(SVC_NAME);
    let h = RegisterServiceCtrlHandlerExW(
        name.as_ptr(),
        Some(ctrl_handler),
        std::ptr::null_mut(),
    );
    if h == 0 {
        return; // 拿不到状态句柄，SCM 会自行判失败
    }
    STATUS_HANDLE.store(h as isize, Ordering::SeqCst);
    set_status(SERVICE_START_PENDING, 0, 30_000);

    // ★★ 关键：定位 agent.toml，不能只按 exe 目录。
    //
    // 两个事实叠加会出大事：SCM 启动服务的 cwd 是 C:\Windows\System32；而本项目的
    // exe 位于 `<repo>/target/release/`，agent.toml 却在 `<repo>/`（上一层）。
    // 若只 set_current_dir(exe.parent())，`config_path()` 会去 target/release 找
    // agent.toml，找不到就**凭空创建一份默认配置**——实测（2026-10-22）服务起来后
    // `/api/services` 返回 enabled=false，生产配置里的 [[services]] / llm /
    // mcp_source / personas **全部丢失**，却因为环境变量仍注入而看起来「健康」，
    // 属于极难察觉的降级。
    //
    // 故：从 exe 目录向上最多 4 级，找到含 agent.toml 的目录就切过去。
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent().map(|p| p.to_path_buf());
        let mut hops = 0;
        while let Some(dir) = cur {
            if dir.join("agent.toml").exists() {
                let _ = std::env::set_current_dir(&dir);
                emit!("agent.toml 定位成功: {}", dir.display());
                break;
            }
            hops += 1;
            if hops >= 4 {
                emit!("! 向上 {hops} 级仍未找到 agent.toml，将使用默认配置（功能会降级）");
                break;
            }
            cur = dir.parent().map(|p| p.to_path_buf());
        }
    }

    // 复用与命令行模式完全相同的启动路径，避免两套逻辑漂移
    let config = crate::config::load_or_create_config();
    let path = crate::config::config_path();
    let metrics = std::sync::Arc::new(agent_core::metrics::MetricsRegistry::new());
    let server_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    crate::bootstrap::spawn_server(config, path, server_ready.clone(), metrics);

    // 等端口就绪（最多 60s）。失败也继续跑——/health 会暴露问题，好过服务直接不启动。
    let deadline = Instant::now() + Duration::from_secs(60);
    while !server_ready.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    set_status(SERVICE_RUNNING, 0, 0);

    // 常驻直到收到 STOP / SHUTDOWN
    while !STOP_REQ.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(300));
    }
    // STOP_REQ 已置位：bootstrap 的 graceful shutdown 会看到它并让 axum 退出。
    // 这里再等一小会让在途请求收尾，然后上报 STOPPED。
    std::thread::sleep(Duration::from_millis(1500));
    set_status(SERVICE_STOPPED, 0, 0);
}

/// 尝试以「服务」方式运行。
///
/// 返回 `true` = 确实作为服务运行且已结束（调用方应直接返回退出）；
/// 返回 `false` = 当前不是服务环境（普通命令行），调用方继续原流程。
///
/// 判定依据：非服务环境下 `StartServiceCtrlDispatcherW` 立即失败并置
/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`(1063)。
pub(crate) fn try_run_as_service() -> bool {
    STOP_REQ.store(false, Ordering::SeqCst);
    let name = wide(SVC_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr() as *mut u16,
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    ok != 0
}

/// 安装为自动启动服务，并配置崩溃重启策略。
///
/// 需管理员权限；非管理员会返回 `OpenSCManager 失败: 5（拒绝访问）`。
pub(crate) fn install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("取 exe 路径失败: {e}"))?;
    let exe_s = exe.to_string_lossy().to_string();
    let bin_cmd = format!("\"{exe_s}\" --service");

    unsafe {
        let scm = OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CREATE_SERVICE,
        );
        if scm == 0 {
            return Err(format!(
                "OpenSCManager 失败: {}（安装服务需要管理员权限）",
                GetLastError()
            ));
        }

        let wname = wide(SVC_NAME);
        let wdisp = wide(SVC_DISPLAY);
        let wcmd = wide(&bin_cmd);

        let svc = CreateServiceW(
            scm,
            wname.as_ptr(),
            wdisp.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            wcmd.as_ptr(),
            std::ptr::null(),            // lploadordergroup
            std::ptr::null_mut::<u32>(), // lpdwtagid（需 *mut u32）
            std::ptr::null(),            // lpdependencies
            std::ptr::null(),            // lpservicestartname（LocalSystem）
            std::ptr::null(),            // lppassword
        );
        if svc == 0 {
            let err = GetLastError();
            CloseServiceHandle(scm);
            if err == 1073 {
                return Err("服务已存在。先执行 --uninstall-service 再装".into());
            }
            return Err(format!("CreateService 失败: {err}（需管理员权限）"));
        }

        // 描述（失败不致命）
        let wdesc = wide(SVC_DESC);
        let mut d = SERVICE_DESCRIPTIONW {
            lpDescription: wdesc.as_ptr() as *mut u16,
        };
        ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_DESCRIPTION,
            &mut d as *mut _ as *mut core::ffi::c_void,
        );

        // 崩溃重启：第 1 次 5s 后重启，第 2 次 30s，之后 60s；一天后重置计数。
        // 这是「SCM 托管」相对托盘的核心价值之一。
        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 30_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 60_000,
            },
        ];
        let mut fa = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86_400,
            lpRebootMsg: std::ptr::null_mut(),
            lpCommand: std::ptr::null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &mut fa as *mut _ as *mut core::ffi::c_void,
        );

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }

    emit!("✓ 服务已安装: {SVC_NAME}");
    emit!("  exe     : {exe_s}");
    emit!("  启动方式: 自动（开机自启）");
    emit!("  崩溃重启: 5s / 30s / 60s（计数 24h 重置）");
    emit!("");
    emit!("下一步（均需管理员）:");
    emit!("  sc start {SVC_NAME}      # 启动");
    emit!("  sc query {SVC_NAME}      # 查看状态");
    emit!("  sc stop  {SVC_NAME}      # 停止");
    emit!("  {exe_s} --uninstall-service   # 卸载");
    Ok(())
}

/// 卸载服务。需管理员权限。
pub(crate) fn uninstall() -> Result<(), String> {
    unsafe {
        let scm = OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CONNECT,
        );
        if scm == 0 {
            return Err(format!(
                "OpenSCManager 失败: {}（卸载服务需要管理员权限）",
                GetLastError()
            ));
        }
        let wname = wide(SVC_NAME);
        let svc = OpenServiceW(scm, wname.as_ptr(), SERVICE_ALL_ACCESS);
        if svc == 0 {
            let err = GetLastError();
            CloseServiceHandle(scm);
            if err == ERROR_SERVICE_DOES_NOT_EXIST {
                return Err(format!("服务不存在: {SVC_NAME}"));
            }
            return Err(format!("OpenService 失败: {err}"));
        }
        let ok = DeleteService(svc);
        let err = GetLastError();
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok == 0 {
            return Err(format!("DeleteService 失败: {err}"));
        }
    }
    emit!("✓ 服务已标记删除: {SVC_NAME}（正在运行则停止后彻底移除）");
    Ok(())
}
