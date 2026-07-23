//! HY3 #399 量化 harness：LATS 过程树深化（多步 beam + 价值网络）vs 浅层列候选 vs 无规划
//! 对「多步任务完成度」的影响。固定 flash 生成终答，pro 当 judge 评完成度(0-10)。
//!
//! 运行：cargo test --release --test eval_lats -- --ignored --nocapture （需 AGENT_API_KEY）

use agent_core::lats::{LatsConfig, LatsController, ValueEstimatorMode};
use agent_core::llm::{LlmClient, LlmConfig, LlmProvider, Message};

const FLASH_MODEL: &str = "deepseek-v4-flash";
const PRO_MODEL: &str = "deepseek-v4-pro";
const BASE: &str = "https://api.deepseek.com";
const CHAT_PATH: &str = "/v1/chat/completions";

struct Task {
    task: &'static str,
}

/// 需要多步规划/检索/分析才能充分完成的任务集合（judge 评完成度）
const TASKS: &[Task] = &[
    Task { task: "请帮我查一下研发部本月提交了多少个代码评审，并与上月对比，最后给出趋势结论。" },
    Task { task: "统计华东区本季度销售额，换算成人民币，并和去年同期对比给出百分比变化。" },
    Task { task: "从知识库检索『会员等级规则』，整理成表格，并指出与旧版的三处主要差异。" },
    Task { task: "分析上季度客服工单，按问题类型分组计数，找出 top3 高频问题并给改进建议。" },
    Task { task: "拉取过去30天系统告警日志，按严重程度分类，给出最需要优先处理的两类及其原因。" },
    Task { task: "查销售漏斗各阶段转化率，定位流失最严重的环节并给出提升方案。" },
    Task { task: "检索公司考勤制度，确认年假计算方式，并举例说明一名入职满1年的员工应有的年假天数。" },
    Task { task: "汇总本月新增客户来源渠道，按占比排序，并对比预算给出获客成本评价。" },
];

fn mk_provider(model: &str, key: &str) -> LlmProvider {
    LlmProvider {
        base_url: BASE.to_string(),
        model: model.to_string(),
        api_key: key.to_string(),
        chat_path: CHAT_PATH.to_string(),
    }
}

async fn generate(llm: &LlmClient, system: Option<&str>, task: &str) -> String {
    let mut msgs = Vec::new();
    if let Some(s) = system {
        msgs.push(Message {
            role: "system".to_string(),
            content: Some(s.to_string()),
            tool_calls: None,
            tool_call_id: None,
        });
    }
    msgs.push(Message {
        role: "user".to_string(),
        content: Some(task.to_string()),
        tool_calls: None,
        tool_call_id: None,
    });
    match llm.chat(&msgs, &[]).await {
        Ok(r) => r.text.trim().to_string(),
        Err(e) => {
            eprintln!("generate err: {}", e);
            String::new()
        }
    }
}

fn parse_score(s: &str) -> f64 {
    s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter_map(|t| t.parse::<f64>().ok())
        .next()
        .unwrap_or(0.0)
}

async fn judge(judge_llm: &LlmClient, task: &str, answer: &str) -> f64 {
    let prompt = format!(
        "你是严格的评审。给定原始任务与某助手给出的回答，请评估回答是否充分、结构化、\
         完成了任务要求的多步工作。仅输出 0 到 10 之间的小数（不要解释）。\n\n\
         原始任务：{}\n\n助手回答：{}\n\n完成度分数：",
        task, answer
    );
    match judge_llm
        .chat(
            &[Message {
                role: "user".to_string(),
                content: Some(prompt),
                tool_calls: None,
                tool_call_id: None,
            }],
            &[],
        )
        .await
    {
        Ok(r) => parse_score(&r.text),
        Err(e) => {
            eprintln!("judge err: {}", e);
            0.0
        }
    }
}

#[tokio::test]
#[ignore]
async fn eval_lats_planning() {
    let key = std::env::var("AGENT_API_KEY").expect("AGENT_API_KEY required");
    let flash = mk_provider(FLASH_MODEL, &key);
    let pro = mk_provider(PRO_MODEL, &key);
    let flash_llm = LlmClient::new(LlmConfig::from_provider(&flash));
    let judge_llm = LlmClient::new(LlmConfig::from_provider(&pro));

    let cfg = LatsConfig {
        enabled: true,
        max_depth: 2,
        max_branches: 3,
        beam_width: 2,
        value_estimator: ValueEstimatorMode::Heuristic,
        daily_token_budget: 10_000_000,
    };
    let ctrl = LatsController::new(cfg);

    let mut no_scores = Vec::new();
    let mut shallow_scores = Vec::new();
    let mut tree_scores = Vec::new();

    for (i, t) in TASKS.iter().enumerate() {
        // shallow：旧浅层行为（仅列候选下一步，不排序/不选优）
        let cands = ctrl.expand_once(&flash_llm, t.task).await;
        let shallow_hint = if cands.is_empty() {
            None
        } else {
            Some(format!(
                "## LATS 规划提示（候选下一步）\n{}",
                cands
                    .iter()
                    .enumerate()
                    .map(|(i, c)| format!("{}. {}", i + 1, c))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        };
        // tree：新多步过程树选优路径
        let tree_hint = ctrl.best_plan(&flash_llm, t.task, None).await;

        let ans_no = generate(&flash_llm, None, t.task).await;
        let ans_shallow = generate(&flash_llm, shallow_hint.as_deref(), t.task).await;
        let ans_tree = generate(&flash_llm, tree_hint.as_deref(), t.task).await;

        let s_no = judge(&judge_llm, t.task, &ans_no).await;
        let s_sh = judge(&judge_llm, t.task, &ans_shallow).await;
        let s_tr = judge(&judge_llm, t.task, &ans_tree).await;

        no_scores.push(s_no);
        shallow_scores.push(s_sh);
        tree_scores.push(s_tr);
        println!(
            "[{}] no={:.1} shallow={:.1} tree={:.1}\n    tree_plan:\n{}",
            i + 1,
            s_no,
            s_sh,
            s_tr,
            tree_hint.unwrap_or_default()
        );
    }

    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let m_no = mean(&no_scores);
    let m_sh = mean(&shallow_scores);
    let m_tr = mean(&tree_scores);
    println!(
        "\n=== LATS 规划量化（flash 生成 / pro judge，{}/任务，0-10）===",
        TASKS.len()
    );
    println!("mean_no      = {:.2}", m_no);
    println!("mean_shallow = {:.2}", m_sh);
    println!("mean_tree    = {:.2}", m_tr);
    println!("Δ(tree-shallow) = {:.2}", m_tr - m_sh);
    println!("Δ(tree-no)      = {:.2}", m_tr - m_no);
    println!("Δ(shallow-no)   = {:.2}", m_sh - m_no);
}
