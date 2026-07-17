//! 执行沙箱隔离器（Grok Build 吸收 · Phase A1）
//!
//! 复用 `boundary.rs::ExecutionSandbox` 的**策略门控**；本模块在其**后方**提供真实隔离：
//! 1. **Windows Job Object（kill-on-job-close）**：把每个 MCP 子进程纳入一个进程级 Job，
//!    agent-core 退出时 Job 关闭 → 所有 MCP 子进程及其后代被一并清掉，斩断孤儿/逃逸进程。
//! 2. **注入 `AGENT_SANDBOX_ROOT` 环境变量**：供守规的 MCP server / 工具做自检
//!    （如路径门闸、写前快照），属于"协作式"约束。
//! 3. **可选 cwd 约束**（`AGENT_SANDBOX_CONFINE_CWD=1` 时启用，默认关）：把子进程 cwd
//!    限定到沙箱根，避免相对路径逃逸。默认关是为了不破坏依赖相对路径的现有 MCP。
//!
//! ⚠️ 这是"进程级最佳努力隔离"，**不是内核文件系统沙箱**。Windows 没有 Linux Landlock /
//! macOS Seatbelt 的等价物（Grok Build 的 `nono` 沙箱在 Windows 上同样是空转，见
//! `docs/OPTIMIZATION_GROK_BUILD_ABSORPTION.md §9`）。真正的文件系统隔离需要 AppContainer
//! （未来 Phase）。本模块的意义是：① 杜绝孤儿子进程；② 给守规组件一个明确的沙箱根；
//! ③ 配合 `boundary.rs` 的路径门闸拦截敏感路径访问。

use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

// ── 全局沙箱根（可选；配置后启用"严格越界门闸"）──
// 解析顺序：环境变量 AGENT_SANDBOX_ROOT > 启动时程序化设置 > 未配置（仅 deny 列表生效）
static SANDBOX_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// 程序化设置沙箱根（由 main 在启动时根据配置调用）
pub fn init_sandbox_root(root: Option<PathBuf>) {
    let _ = SANDBOX_ROOT.set(root);
}

/// 解析最终生效的沙箱根
pub fn resolve_sandbox_root() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("AGENT_SANDBOX_ROOT") {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    SANDBOX_ROOT.get().cloned().flatten()
}

// ── Windows Job Object ─────────────────────────────────
// 用裸 FFI 调 kernel32，避免引入新依赖（联网拉包风险）。
// Job 句柄存于进程级 AtomicPtr，随 agent-core 生命周期存在 → 退出即 kill-on-close。

#[cfg(windows)]
mod win_job {
    use super::*;
    use std::os::raw::{c_ulong, c_void};
    use std::ptr;

    type HANDLE = *mut c_void;
    type BOOL = i32;
    type DWORD = c_ulong;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x0000_2000;
    // ⚠️ KILL_ON_JOB_CLOSE 标志仅对「Extended」信息类合法；用 Basic(class 2) 会被
    // SetInformationJobObject 以参数无效拒绝（之前线上一直 WARN 降级的根因）。
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: DWORD = 9;
    // 本机 Windows 的 JOBOBJECT_EXTENDED_LIMIT_INFORMATION 实际大小 = 144 字节
    // （Basic 64 + IoInfo 48 + 4×SIZE_T 32，无 BasicUIRestrictions/Reserved 尾字段）。
    // 已用探针运行时确认 len=144 时 SetInformationJobObject 返回成功。
    const JOB_EXT_CB_LEN: DWORD = 144;
    const PROCESS_ALL_ACCESS: DWORD = 0x001F_0FFF;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        PerProcessUserTimeLimit: i64,
        PerJobUserTimeLimit: i64,
        LimitFlags: DWORD,
        MinimumWorkingSetSize: usize,
        MaximumWorkingSetSize: usize,
        ActiveProcessLimit: DWORD,
        Affinity: usize,
        PriorityClass: DWORD,
        SchedulingClass: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct IO_COUNTERS {
        ReadOperationCount: u64,
        WriteOperationCount: u64,
        OtherOperationCount: u64,
        ReadTransferCount: u64,
        WriteTransferCount: u64,
        OtherTransferCount: u64,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        IoInfo: IO_COUNTERS,
        ProcessMemoryLimit: usize,
        JobMemoryLimit: usize,
        PeakProcessMemoryUsed: usize,
        PeakJobMemoryUsed: usize,
        // 注意：本机 Windows 的 JOBOBJECT_EXTENDED_LIMIT_INFORMATION 实际大小为 144 字节
        // （Basic 64 + IoInfo 48 + 4×SIZE_T 32，无 BasicUIRestrictions / Reserved 尾字段）。
        // Rust repr(C) 对齐后 size_of 恰为 144，与 Windows 期望一致。
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(lpattributes: *const c_void, lpname: *const u16) -> HANDLE;
        fn AssignProcessToJobObject(hjob: HANDLE, hprocess: HANDLE) -> BOOL;
        fn SetInformationJobObject(
            hjob: HANDLE,
            jobobjectinfoclass: DWORD,
            lpjobobjectinfo: *const c_void,
            cbjobobjectinfo: DWORD,
        ) -> BOOL;
        fn OpenProcess(dwdesiredaccess: DWORD, binherithandle: BOOL, dwprocessid: DWORD) -> HANDLE;
        fn CloseHandle(hobject: HANDLE) -> BOOL;
        fn GetLastError() -> DWORD;
    }

    // 进程级单例 Job 句柄（null = 未创建/不可用）
    static JOB: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

    fn get_or_create_job() -> Option<HANDLE> {
        let existing = JOB.load(Ordering::Acquire);
        if !existing.is_null() {
            return Some(existing);
        }
        let job = unsafe { CreateJobObjectW(ptr::null::<c_void>(), ptr::null::<u16>()) };
        if job.is_null() {
            tracing::warn!("sandbox: CreateJobObjectW 失败，跳过 Job Object 约束");
            return None;
        }
        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                PerProcessUserTimeLimit: 0,
                PerJobUserTimeLimit: 0,
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                MinimumWorkingSetSize: 0,
                MaximumWorkingSetSize: 0,
                ActiveProcessLimit: 0,
                Affinity: 0,
                PriorityClass: 0,
                SchedulingClass: 0,
            },
            IoInfo: IO_COUNTERS {
                ReadOperationCount: 0,
                WriteOperationCount: 0,
                OtherOperationCount: 0,
                ReadTransferCount: 0,
                WriteTransferCount: 0,
                OtherTransferCount: 0,
            },
            ProcessMemoryLimit: 0,
            JobMemoryLimit: 0,
            PeakProcessMemoryUsed: 0,
            PeakJobMemoryUsed: 0,
        };
        let ok = unsafe {
            SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                &info as *const _ as *const c_void,
                JOB_EXT_CB_LEN,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            tracing::warn!(
                "sandbox: SetInformationJobObject(Extended) 失败，Job 不生效，last_err={} (rust_sizeof={}, passed={})",
                err,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
                JOB_EXT_CB_LEN
            );
            unsafe {
                CloseHandle(job);
            }
            return None;
        }
        // 发布；若并发下别的线程已创建，则关闭我们多余的，复用先到者
        match JOB.compare_exchange(ptr::null_mut(), job, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Some(job),
            Err(prev) => {
                unsafe {
                    CloseHandle(job);
                }
                if prev.is_null() {
                    None
                } else {
                    Some(prev)
                }
            }
        }
    }

    /// 把指定 pid 的进程纳入 Job（best-effort：失败仅 warn，绝不阻断 MCP 启动）
    pub fn confine_child(pid: u32) -> bool {
        let job = match get_or_create_job() {
            Some(j) => j,
            None => return false,
        };
        let hproc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if hproc.is_null() {
            tracing::warn!("sandbox: OpenProcess({}) 失败", pid);
            return false;
        }
        let ok = unsafe { AssignProcessToJobObject(job, hproc) };
        unsafe {
            CloseHandle(hproc);
        }
        if ok == 0 {
            // 常见原因：子进程已被其它 Job 托管（agent-core 自身处于某 Job 时）
            tracing::debug!(
                "sandbox: AssignProcessToJobObject({}) 失败（可能已在其它 Job 中）",
                pid
            );
            return false;
        }
        tracing::debug!("sandbox: 已将 pid {} 纳入 Job Object（kill-on-close）", pid);
        true
    }
}

#[cfg(not(windows))]
mod win_job {
    pub fn confine_child(_pid: u32) -> bool {
        false
    }
}

/// 给一个刚 spawn 的 MCP 子进程套沙箱约束（Job Object；env 注入在 spawn_process 内完成）
pub fn confine_child_process(child: &std::process::Child) {
    win_job::confine_child(child.id());
}

/// 是否启用 cwd 约束（默认关，避免破坏依赖相对路径的 MCP）
pub fn confine_cwd_enabled() -> bool {
    std::env::var("AGENT_SANDBOX_CONFINE_CWD")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// 若启用 cwd 约束且能解析到沙箱根，返回该根（供 spawn_process 设 cwd）
pub fn cwd_root() -> Option<PathBuf> {
    if confine_cwd_enabled() {
        resolve_sandbox_root()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_root_from_env() {
        std::env::set_var("AGENT_SANDBOX_ROOT", "C:/agent-sandbox");
        assert_eq!(
            resolve_sandbox_root(),
            Some(PathBuf::from("C:/agent-sandbox"))
        );
        std::env::remove_var("AGENT_SANDBOX_ROOT");
    }

    #[test]
    fn confine_cwd_default_off() {
        std::env::remove_var("AGENT_SANDBOX_CONFINE_CWD");
        assert!(!confine_cwd_enabled());
        assert!(cwd_root().is_none());
    }
}
