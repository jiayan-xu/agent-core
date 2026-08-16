//! officecli MCP 源连通性集成测试（P1 最小可验证闭环）
//!
//! 用真实 stdio 源（officecli_mcp_bridge.py）验证：
//!   1. tools/list 能列出 8 个 officecli_* 工具
//!   2. call_tool_routed 能跨源路由并实际调用 officecli_read
//!   3. 目录穿越路径被 bridge 拒绝
//!
//! 依赖 officecli-win-x64.exe + officecli_mcp_bridge.py 存在于 office-tools 目录。
//! 运行：cargo test --test eval_officecli -- --ignored --nocapture
//!
//! 说明：本文件是标记 #[ignore] 的真实子进程集成测试（需 officecli 二进制 + office-tools 目录），
//! 非默认单元测试。少量输入/产物校验使用同步 std::fs（file 小、量少），对 tokio 运行时影响可忽略；
//! 关键前置检查（require_fixture）已放在 async 段之前执行。
//!
//! bridge 错误契约（office-tools/officecli_mcp_bridge.py，仓库外，但为稳定对外承诺）：
//! - 目录穿越：含 `..` 的输入 file 一律拒绝，错误含「禁止目录穿越」（先验穿越、后验文件存在）。
//! - 写保护：officecli_query 的 selector 以 set/add/remove/move/swap 开头即拒绝，错误含「禁止写入」。
//! 测试据此断言稳定信号；若 bridge 措辞调整，需同步更新此处契约与对应断言。

use agent_core::agent::{AgentConfig, AgentCore, AgentIdentity};
use agent_core::boundary::PermissionLevel;
use agent_core::checkpoint::CheckpointStore;
use agent_core::harness::HarnessStore;
use agent_core::llm::LlmConfig;
use agent_core::meta_evolve::{MetaEvolutionConfig, SafetyConfig};
use agent_core::resources::LocalResourceSnapshot;
use std::sync::{Arc, Mutex};

// office-tools 目录通过环境变量 OFFICE_TOOLS 注入（避免在公开仓库提交本机绝对路径）。
// 缺省回退到仓库旁的 office-tools（相对路径），便于本地跑。
fn office_tools_dir() -> std::path::PathBuf {
    std::env::var("OFFICE_TOOLS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("office-tools")
        })
}

fn python_bin() -> String {
    std::env::var("PYTHON_BIN").unwrap_or_else(|_| {
        // Windows 通常装 python；Unix 系多只有 python3
        if cfg!(windows) { "python".to_string() } else { "python3".to_string() }
    })
}

/// 生成带进程唯一后缀的输出文件名，避免 repeated/concurrent 测试互相覆盖。
/// 输出仍由 bridge 锚定到 office-tools/_out/ 下（见 _out_path），不会污染仓库根。
fn unique_out_name(base: &str, ext: &str) -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("e2e_{base}_{pid}_{nanos}.{ext}")
}

/// 给真实子进程调用包一层超时，避免 python/officecli 卡死时测试无限挂起。
/// 超时返回 Err（含 "timeout" 字样），由调用方断言失败而非拖死整个测试进程。
/// 注意：外层预算须大于 stdio 客户端内部超时（mcp_client::StdioMcpClient，30s），
/// 否则外层先触发会 drop 掉内部的 kill-and-restart 路径，导致子进程残留并锁住 _out/ 产物。
async fn with_timeout<T>(fut: impl std::future::Future<Output = T>) -> Result<T, String> {
    tokio::time::timeout(std::time::Duration::from_secs(60), fut)
        .await
        .map_err(|_| "调用超时（60s）：officecli 子进程可能卡死".to_string())
}

/// 返回 read/query-guard/pdf 共用的输入 fixture（office-tools/_out.docx），并断言其存在，
/// 避免 fixture 缺失时错误深埋在子进程内难以诊断。
fn require_fixture() -> std::path::PathBuf {
    let fixture = office_tools_dir().join("_out.docx");
    assert!(
        fixture.is_file(),
        "fixture 缺失: {fixture:?}（office-tools 目录需预置 _out.docx）"
    );
    fixture
}

/// 统一的路径规范化：先把相对路径按 process cwd 拼成绝对路径，再 canonicalize 消解 symlink；
/// canonicalize 失败（文件未落盘/权限拒绝/Windows \\?\ verbatim 前缀）时回退词法规范化——
/// 逐组件去 `..`/`.`，保证两侧（out_dir 与 resolved）用同一套规范化后前缀比较一致。
fn normalize_path(p: &std::path::Path) -> std::path::PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(p)
    };
    abs.canonicalize().unwrap_or_else(|_| {
        let mut out = std::path::PathBuf::new();
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

/// 把 bridge 返回的 output 路径解析为绝对路径，并强制锚定在 office-tools/_out/ 内。
/// 防御：若 bridge 返回 `..` 或任意绝对路径逃逸 _out，直接断言失败——
/// 因为 OutputGuard::drop 会删除该路径，绝不允许误删 _out 之外的文件。
fn resolve_output(output: &str) -> std::path::PathBuf {
    let out_dir = normalize_path(&office_tools_dir().join("_out"));
    let p = std::path::Path::new(output);
    let resolved = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match p.strip_prefix("_out") {
            Ok(rel) => office_tools_dir().join("_out").join(rel),
            Err(_) => office_tools_dir().join("_out").join(p),
        }
    };
    // 两侧用同一套 normalize_path（先词法转绝对再 canonicalize，失败去 `..`/`.`），
    // 保证 OFFICE_TOOLS 为相对路径或 Windows \\?\ verbatim 前缀时前缀比较仍一致。
    let resolved = normalize_path(&resolved);
    // 拒绝逃逸 _out 的路径（.. 或任意绝对路径或 symlink 逃逸），避免删除守卫误删 _out 之外文件
    assert!(
        resolved.starts_with(&out_dir)
            && !resolved
                .strip_prefix(&out_dir)
                .unwrap_or(&out_dir)
                .components()
                .any(|c| c == std::path::Component::ParentDir),
        "bridge 输出路径逃逸 _out 目录: {output}"
    );
    resolved
}

/// 产物清理守卫：drop 时 best-effort 删除文件，即使中间断言 panic 也不泄漏 _out/ 产物。
/// 只在 resolve 时已确认存在的文件才删除；删除前对父目录+文件名重新 canonicalize 并再次锚定
/// 校验，规避 TOCTOU——避免 resolve 后、drop 前中间 symlink 变化导致误删 _out 之外的文件。
struct OutputGuard {
    path: std::path::PathBuf,
}
impl OutputGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}
impl Drop for OutputGuard {
    fn drop(&mut self) {
        // 文件不存在则无需清理（也可能是测试失败未产出），直接返回
        if !self.path.exists() {
            return;
        }
        // 删除前重新 canonicalize 父目录+文件名并锚定校验，防止 resolve 后 symlink 变化逃逸 _out
        let out_dir = std::fs::canonicalize(&office_tools_dir().join("_out"));
        let Ok(out_dir) = out_dir else { return };
        let rechecked = std::fs::canonicalize(&self.path);
        if let Ok(rechecked) = rechecked {
            if !rechecked.starts_with(&out_dir) {
                return; // 已逃逸 _out，拒绝删除（宁可泄漏也不误删外部文件）
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn agent_with_officecli() -> AgentCore {
    let tools_dir = office_tools_dir();
    let stdio = tools_dir.join("officecli_mcp_bridge.py");
    let config = AgentConfig {
        identity: AgentIdentity {
            agent_id: "eval-officecli".into(),
            namespace: "agent/eval-officecli".into(),
            badge_token: String::new(),
            ns_full_path: None,
            persona_id: None,
            owner_user_id: None,
            workspace_dir: None,
            tool_allowlist: Vec::new(),
            memory_namespace: None,
        },
        llm: LlmConfig::default(),
        memoria_url: String::new(),
        additional_mcp: vec![(
            "officecli".to_string(),
            String::new(), // stdio 源 url 置空
            String::new(),
            Some((
                python_bin(),
                vec![stdio.to_string_lossy().to_string()],
            )),
            None, // namespace 留空 = 全局可见
        )],
        skill_whitelist: None,
        max_tool_rounds: 3,
        parent_permission: PermissionLevel::Write,
        enable_compositional_routing: true,
        compositional_preview: true,
        strict_schema: false,
        system_prompt_template: None,
        approver_id: None,
        meta_evolution: MetaEvolutionConfig::default(),
        safety: SafetyConfig::default(),
        human_approval: false,
        features: agent_core::agent::FeatureFlags::default(),
        lats: agent_core::lats::LatsConfig::default(),
        multiagent: agent_core::multiagent::MultiAgentConfig::default(),
        ttc: agent_core::ttc::TtcConfig::default(),
        intake_filter: agent_core::intake_filter::IntakeFilterConfig::default(),
        orchestration: agent_core::orchestration::OrchestrationConfig::default(),
        tool_overrides: vec![],
    };
    let harness = HarnessStore::open_memory().unwrap();
    let cp = CheckpointStore::open_memory().unwrap();
    let local_resources = Arc::new(Mutex::new(LocalResourceSnapshot::default()));
    AgentCore::new(
        config,
        harness,
        cp,
        local_resources,
        Arc::new(agent_core::metrics::MetricsRegistry::default()),
    )
}

#[tokio::test]
#[ignore = "需要 officecli 二进制 + office-tools 目录"]
async fn officecli_tools_are_listed() {
    let agent = agent_with_officecli();
    let tools = with_timeout(agent.fetch_tools_filtered(&["agent/eval-officecli".to_string()]))
        .await
        .expect("fetch_tools_filtered 应在 60s 内返回");
    let names: Vec<&str> = tools.iter().map(|t| t.function.name.as_str()).collect();
    let expected = [
        "officecli_read",
        "officecli_validate",
        "officecli_issues",
        "officecli_merge",
        "officecli_render",
        "officecli_pdf",
        "officecli_create",
        "officecli_query",
    ];
    for exp in expected {
        assert!(names.contains(&exp), "应列出 {exp}，实际: {names:?}");
    }
    // 精确性：officecli 源应恰好暴露这 8 个工具，不允许多出/遗漏
    let officecli_names: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| n.starts_with("officecli_"))
        .collect();
    let mut sorted = officecli_names.clone();
    sorted.sort_unstable();
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort_unstable();
    assert_eq!(
        sorted, expected_sorted,
        "officecli 源工具集应精确匹配，实际: {officecli_names:?}"
    );
}

#[tokio::test]
#[ignore = "需要 officecli 二进制 + office-tools 目录 + 真实文档"]
async fn officecli_read_routes_and_calls() {
    let agent = agent_with_officecli();
    let fixture = require_fixture();
    let out = with_timeout(agent.call_tool_routed(
            "officecli_read",
            "default",
            &serde_json::json!({"file": fixture, "max_lines": 3}),
            &["agent/eval-officecli".to_string()],
            "officecli-e2e",
        ))
        .await
        .expect("officecli_read 应在 60s 内返回")
        .expect("officecli_read 应调用成功");
    // 解析 JSON 断言 success==true（而非 contains("success")，避免错误负载含 success 字样蒙混过关）
    let val: serde_json::Value =
        serde_json::from_str(&out).expect("read 返回应为合法 JSON");
    assert_eq!(
        val["success"].as_bool(),
        Some(true),
        "read 应 success==true，实际: {out}"
    );
    assert!(
        val["data"].is_object() || val["raw"].is_string(),
        "read 应含 data/raw 内容，实际: {out}"
    );
}

#[tokio::test]
#[ignore = "需要 officecli 二进制 + office-tools 目录"]
async fn officecli_rejects_traversal() {
    let agent = agent_with_officecli();
    // 用平台原生分隔符构造穿越路径（Windows `..\..\Windows\win.ini`，Unix `../../etc/passwd`），
    // 避免硬编码单平台反斜杠导致平台不健壮。
    // bridge 错误契约（见文件顶部注释）：对含 `..` 的输入，先验穿越、后验文件存在，
    // 因此必然触发「禁止目录穿越」拒绝，与目标文件是否存在无关。
    let sep = std::path::MAIN_SEPARATOR;
    let traversal = format!("..{sep}..{sep}Windows{sep}win.ini");
    let payload = serde_json::json!({"file": traversal});
    let res = with_timeout(agent.call_tool_routed(
            "officecli_read",
            "default",
            &payload,
            &["agent/eval-officecli".to_string()],
            "officecli-e2e-traversal",
        ))
        .await
        .expect("穿越调用应在 60s 内返回");
    assert!(res.is_err(), "目录穿越路径应被拒绝");
    let err = res.unwrap_err();
    // 只认 bridge 的显式穿越拒绝信号（「禁止目录穿越」），不匹配 `..` 回显——避免「文件不存在」导致的误通过
    assert!(err.contains("穿越"), "错误信息应说明穿越拒绝，实际: {err}");
}

#[tokio::test]
#[ignore = "需要 officecli 二进制 + office-tools 目录"]
async fn officecli_create_adds_and_query() {
    let agent = agent_with_officecli();
    let out_name = unique_out_name("create", "docx");
    // create：建 docx + 加一个段落
    let create_out = with_timeout(agent.call_tool_routed(
            "officecli_create",
            "default",
            &serde_json::json!({
                "output": out_name,
                "adds": [{"type": "paragraph", "parent": "/body", "props": {"text": "E2E 集成创建"}}],
            }),
            &["agent/eval-officecli".to_string()],
            "officecli-e2e-create",
        ))
        .await
        .expect("officecli_create 应在 60s 内返回")
        .expect("officecli_create 应成功");
    // 解析 JSON 断言 success==true，并取回输出路径
    let val: serde_json::Value =
        serde_json::from_str(&create_out).expect("create 返回应为 JSON");
    assert_eq!(
        val["success"].as_bool(),
        Some(true),
        "create 应 success==true，实际: {create_out}"
    );
    let output = val["output"].as_str().expect("应含 output 路径");
    assert!(output.ends_with(&out_name), "output 应指向 {out_name}: {output}");
    // bridge 锚定输出到 office-tools/_out/；resolve_output 统一解析（绝对路径直接用，裸名补 _out/）
    let abs_output = resolve_output(output);
    // RAII 清理：即使后续 query/断言 panic 也不泄漏 _out/ 产物
    let _guard = OutputGuard::new(abs_output.clone());
    assert!(abs_output.is_file(), "create 产物应已落盘: {abs_output:?}");

    // query：命中刚创建的段落。
    // file 用 bridge 返回的原始绝对路径（_out_path 返回 os.path.abspath 拼接，非 navigate verbatim）；
    // 若意外为相对路径，则与 resolve_output 用同一套 _out strip 前缀逻辑（避免 output 已带 _out/ 时
    // 产生 office-tools/_out/_out/<name> 双前缀），再转词法绝对路径（不经 canonicalize，
    // 避免 Windows \\?\ verbatim 前缀触发文件锁）
    let query_file = if std::path::Path::new(output).is_absolute() {
        output.to_string()
    } else {
        let rel = std::path::Path::new(output)
            .strip_prefix("_out")
            .unwrap_or(std::path::Path::new(output));
        office_tools_dir().join("_out").join(rel).to_string_lossy().to_string()
    };
    let q_out = with_timeout(agent.call_tool_routed(
            "officecli_query",
            "default",
            &serde_json::json!({"file": query_file, "selector": "paragraph"}),
            &["agent/eval-officecli".to_string()],
            "officecli-e2e-query",
        ))
        .await
        .expect("officecli_query 应在 60s 内返回")
        .expect("officecli_query 应成功");
    // query 返回 JSON 字符串；解析后对解码的字符串值做包含检查，
    // 避免 bridge 用 ensure_ascii 转义中文（\uXXXX）时字面子串匹配失败。
    let q_val: serde_json::Value =
        serde_json::from_str(&q_out).expect("query 返回应为合法 JSON");
    let q_text = serde_json::to_string(&q_val).unwrap_or_default();
    assert!(
        q_text.contains("E2E 集成创建"),
        "query 应命中新段落，实际: {q_out}"
    );
}

#[tokio::test]
#[ignore = "需要 officecli 二进制 + office-tools 目录"]
async fn officecli_query_rejects_write_selector() {
    let agent = agent_with_officecli();
    let fixture = require_fixture();
    // 写保护契约：bridge（officecli_mcp_bridge.py）对外承诺「写类 selector 一律拒绝」。
    // 断言稳定的信号（错误含 selector 关键词或中文写保护文案），避免与 bridge 内部措辞强耦合。
    let res = with_timeout(agent.call_tool_routed(
            "officecli_query",
            "default",
            &serde_json::json!({"file": fixture, "selector": "add /body paragraph"}),
            &["agent/eval-officecli".to_string()],
            "officecli-e2e-query-guard",
        ))
        .await
        .expect("query 调用应在 60s 内返回");
    assert!(res.is_err(), "query 应拒绝写类 selector");
    let err = res.unwrap_err();
    // 只认文件顶部契约文档声明的稳定标记「禁止写入」；若 bridge 的写保护回归（如误报 selector 格式错误），本断言会失败——这正是要检测的
    assert!(err.contains("禁止写入"), "错误信息应含写保护标记，实际: {err}");
}

#[tokio::test]
#[ignore = "需要 officecli 二进制 + office-tools 目录 + PDF exporter 插件"]
async fn officecli_pdf_exports_valid_pdf() {
    let agent = agent_with_officecli();
    let fixture = require_fixture();
    let out_name = unique_out_name("export", "pdf");
    let out = with_timeout(agent.call_tool_routed(
            "officecli_pdf",
            "default",
            &serde_json::json!({"file": fixture, "output": out_name}),
            &["agent/eval-officecli".to_string()],
            "officecli-e2e-pdf",
        ))
        .await
        .expect("officecli_pdf 应在 60s 内返回")
        .expect("officecli_pdf 应成功");
    // 解析 JSON 取回输出路径校验产物是合法 PDF。
    // 注意：pdf 插件的 `view pdf` 输出是纯文件路径文本（非 JSON），bridge 以 {"raw": path, "output": path} 返回，
    // 因此这里不要求 success==true——以 %PDF 魔数 + 非空作为成功判据。
    let val: serde_json::Value =
        serde_json::from_str(&out).expect("pdf 返回应为 JSON");
    let pdf_path = val["output"].as_str().expect("应含 output 路径");
    let pdf_path_abs = resolve_output(pdf_path);
    // RAII 清理：即使后续断言 panic 也不泄漏 _out/ 产物
    let _guard = OutputGuard::new(pdf_path_abs.clone());
    let bytes = std::fs::read(&pdf_path_abs).expect("PDF 文件应存在");
    assert!(bytes.len() > 100, "PDF 不应为空");
    assert!(
        bytes.starts_with(b"%PDF"),
        "应以 %PDF 魔数开头，实际: {:?}",
        &bytes[..5.min(bytes.len())]
    );
}
