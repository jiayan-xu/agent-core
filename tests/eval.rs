//! 场景回归评测集（W2 P1-3）
//!
//! 覆盖 OPTIMIZATION_PLAN 的 E01–E10。纯逻辑可测项直接 `cargo test --test eval` 跑；
//! 依赖运行时的项用 `#[ignore]` 标注，启动真实服务 + Memoria 后 `cargo test --test eval -- --ignored` 跑。
//! 新增红线/边界规则时，必须在此追加对应 case。

use agent_core::agent::{AgentConfig, AgentCore, AgentIdentity};
use agent_core::boundary::PermissionLevel;
use agent_core::checkpoint::{CheckpointState, CheckpointStore};
use agent_core::harness::HarnessStore;
use agent_core::llm::LlmConfig;

/// 构造最小 AgentCore（内存 harness + 内存 checkpoint，不连真实 MCP）
fn test_agent() -> AgentCore {
    let config = AgentConfig {
        identity: AgentIdentity {
            agent_id: "eval-agent".into(),
            namespace: "agent/eval-agent".into(),
            badge_token: String::new(),
            ns_full_path: None,
        },
        llm: LlmConfig::default(),
        memoria_url: String::new(),
        additional_mcp: Vec::new(),
        skill_whitelist: None,
        max_tool_rounds: 3,
        parent_permission: PermissionLevel::Write,
        enable_compositional_routing: true,
        compositional_preview: true,
        system_prompt_template: None,
        approver_id: None,
    };
    let harness = HarnessStore::open_memory().unwrap();
    let cp = CheckpointStore::open_memory().unwrap();
    AgentCore::new(config, harness, cp)
}

#[test]
fn eval_cases_json_valid() {
    let raw = include_str!("../eval/cases.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("cases.json 必须合法 JSON");
    let cases = v["cases"].as_array().expect("cases 应为数组");
    assert!(cases.len() >= 10, "应至少覆盖 E01–E10，实际 {}", cases.len());
    for c in cases {
        assert!(c["id"].is_string(), "每个 case 需有 id");
        assert!(c["scenario"].is_string(), "{} 缺 scenario", c["id"]);
        assert!(c["expected"].is_string(), "{} 缺 expected", c["id"]);
    }
}

// ── E06: 错误工具名不 panic，友好错误 ──
#[tokio::test]
async fn eval_e06_unknown_tool_no_panic() {
    let agent = test_agent();
    let res = agent
        .call_tool_routed(
            "this_tool_does_not_exist_xyz",
            &serde_json::json!({}),
            &["agent/eval-agent".to_string()],
        )
        .await;
    assert!(res.is_err(), "未知工具应被拒绝（Err），而非 panic");
}

// ── E10: checkpoint 续跑数据契约 ──
#[test]
fn eval_e10_checkpoint_resumable() {
    let store = CheckpointStore::open_memory().unwrap();
    let plan = serde_json::json!({
        "steps": [{"step_id":1,"description":"d","tool":"t","arguments":{},"depends_on":[]}]
    });
    let payload = serde_json::json!({"plan": plan, "step_results": {"1": "ok"}});
    store
        .save("s1", "a", CheckpointState::ExecutingPlan, &payload)
        .unwrap();
    let cp = store.load("s1").unwrap();
    assert_eq!(cp.state, CheckpointState::ExecutingPlan);
    assert_eq!(cp.payload["step_results"]["1"].as_str(), Some("ok"));
    assert_eq!(cp.payload["plan"]["steps"][0]["tool"].as_str(), Some("t"));
}

// ── E04: 外发类工具（export_ 前缀）无审批人时硬拒绝 ──
#[tokio::test]
async fn eval_e04_exfil_hard_deny() {
    let agent = test_agent();
    let b = agent.boundary.lock().await;
    let check = b.check_tool(
        "export_secret_data",
        &serde_json::json!({}),
        "eval-agent",
        "user",
        &PermissionLevel::Write,
        None,
    );
    assert!(!check.allow, "外发类工具（export_ 前缀）必须被硬拒绝");
}

// ── 以下为运行时依赖项，需真实服务 + Memoria 后跑 ──

#[tokio::test]
#[ignore = "needs running agent-core + Memoria"]
async fn eval_e01_no_auth_401() {
    // 启动服务后：curl -X POST localhost:9753/api/chat 不带身份头 → 期望 401
    unimplemented!("用 reqwest 起服务或针对已运行实例断言 401");
}

#[tokio::test]
#[ignore = "needs running agent-core + Memoria + 业务 MCP"]
async fn eval_e09_composer_preview_no_exec() {
    // 多步请求 → 返回计划预览 → 断言此间未调用任何 MCP 工具
    unimplemented!("断言预览态 MCP 调用次数为 0");
}
