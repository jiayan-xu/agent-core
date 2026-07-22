//! 1.3 Best-of-N 量化对比 eval harness（HY3 量化验收：BoN 相对单次调用 +10pp）
//!
//! 设计：对每个「可验证质量」prompt，分别用
//!   - 单次调用（best_of_n = None）
//!   - Best-of-N（best_of_n = 3，scorer = Judge）
//! 取得回答后，用 judge LLM 对两者各打 0-10 分，统计
//!   mean_single / mean_bon / Δpp / win-tie-loss。
//!
//! 任务域：代码 / 结构化可验证 prompt。战略结论「可验证任务收益大、开放生成有限」，
//! 故不用开放式创意文案，改用有参考答案/可核查的编程与查询任务，使 Δpp 更可信。
//!
//! 注意：本 harness 仅作「测量」用途。+10pp 是**暂定验收目标**，需 ≥N 条可验样本、
//! 且 judge 打分稳定后才构成验收证据；打分 bug 修复前 +10pp 线不可信（见 parse_score）。
//!
//! 运行（需 `AGENT_API_KEY` 环境变量 + 默认 [llm.difficulty] 配置可读）：
//!   cargo test --release --test eval_bon -- --ignored --nocapture
//!
//! 默认 `#[ignore]`，避免无 key / 无网络时 CI 失败；需要真实 LLM 调用才跑。

use agent_core::llm::{LlmClient, LlmConfig, LlmProvider, Message, RoutedLlm};

fn provider(model: &str, key: &str) -> LlmProvider {
    LlmProvider {
        base_url: "https://api.deepseek.com".to_string(),
        model: model.to_string(),
        api_key: key.to_string(),
        chat_path: "/v1/chat/completions".to_string(),
    }
}

fn msg(content: &str) -> Message {
    Message {
        role: "user".to_string(),
        content: Some(content.to_string()),
        tool_calls: None,
        tool_call_id: None,
    }
}

/// 解析 judge 返回的分数：取文本中**第一个完整数字 token**（整数或小数），clamp 到 [0,10]。
///
/// 修复原实现 `chars().find_map(|c| c.to_digit(10))` 只取首个字符导致
/// judge 回「10」被误判为 1、Δpp 严重失真的 bug。
fn parse_score(text: &str) -> f64 {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_digit() {
            let mut end = i + 1;
            while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
                end += 1;
            }
            if let Ok(v) = text[i..end].parse::<f64>() {
                return v.clamp(0.0, 10.0);
            }
            i = end; // 非法数字 token（如多小数点），跳过继续找
        } else {
            i += 1;
        }
    }
    0.0
}

async fn judge_score(client: &LlmClient, prompt: &str, answer: &str) -> f64 {
    let j = format!(
        "用户请求：\n{}\n\n候选回答：\n{}\n\n请只返回一个 0-10 的整数分数（越高越好），不要其他文字。",
        prompt, answer
    );
    match client.chat(&[msg(&j)], &[]).await {
        Ok(r) => parse_score(&r.text),
        Err(_) => 0.0,
    }
}

#[tokio::test]
#[ignore = "needs AGENT_API_KEY + live LLM; costs tokens"]
async fn eval_bon_vs_single_delta_pp() {
    let key = std::env::var("AGENT_API_KEY").expect("AGENT_API_KEY 必须设置");
    // flash 作易池，pro 作难池 + judge
    let flash = provider("deepseek-chat", &key);
    let pro = provider("deepseek-reasoner", &key);

    let mut single_cfg = LlmConfig::default();
    single_cfg.api_key = key.clone();
    single_cfg.difficulty.easy = Some(flash.clone());
    single_cfg.difficulty.hard = Some(pro.clone());
    single_cfg.difficulty.classify = agent_core::llm::ClassifyMode::Heuristic;
    single_cfg.difficulty.best_of_n = None; // 单次
    single_cfg.difficulty.scorer = agent_core::llm::ScorerMode::Judge;
    single_cfg.difficulty.judge_provider = Some(pro.clone());

    let mut bon_cfg = single_cfg.clone();
    bon_cfg.difficulty.best_of_n = Some(3); // Best-of-N

    let judge_client = LlmClient::new(LlmConfig::from_provider(&pro));

    // 代码 / 结构化可验证 prompt（有参考答案或可被核查，BoN 收益更可量化）
    let prompts: &[&str] = &[
        "用 Python 写一个函数：给定整数列表，返回去重后保持原顺序的结果，并附 3 个单元测试。",
        "用 SQL 写出查询：从 orders 表找出每个用户最近一笔订单的金额，按金额降序取前 10。",
        "用 TypeScript 实现 debounce(fn, ms)，要求合并高频调用，并给出调用示例。",
        "给定二叉树的中序与后序遍历数组，用 Python 重建二叉树并返回层序遍历结果。",
        "写一个命令统计当前目录下 .rs 文件的总行数，并解释其含义。",
    ];

    let mut n = 0;
    let mut sum_single = 0.0;
    let mut sum_bon = 0.0;
    let mut wins = 0;
    let mut ties = 0;
    let mut losses = 0;

    for p in prompts {
        let single = RoutedLlm::from_config(&single_cfg)
            .chat(&[msg(p)], &[])
            .await
            .expect("single chat");
        let bon = RoutedLlm::from_config(&bon_cfg)
            .chat(&[msg(p)], &[])
            .await
            .expect("bon chat");

        let s_single = judge_score(&judge_client, p, &single.text).await;
        let s_bon = judge_score(&judge_client, p, &bon.text).await;
        n += 1;
        sum_single += s_single;
        sum_bon += s_bon;
        if s_bon > s_single {
            wins += 1;
        } else if (s_bon - s_single).abs() < f64::EPSILON {
            ties += 1;
        } else {
            losses += 1;
        }
        println!(
            "[{}/{}] '{}'  single={:.0} bon={:.0}",
            n,
            prompts.len(),
            p.chars().take(20).collect::<String>(),
            s_single,
            s_bon
        );
    }

    let mean_single = sum_single / n as f64;
    let mean_bon = sum_bon / n as f64;
    let delta_pp = (mean_bon - mean_single) * 10.0; // 0-10 分制 → 百分点
    println!("===== BoN eval =====");
    println!("prompts={}", n);
    println!("mean_single = {:.2}", mean_single);
    println!("mean_bon    = {:.2}", mean_bon);
    println!("Δpp         = {:.1} (暂定验收线 +10pp；需 ≥N 条可验样本且 judge 稳定)", delta_pp);
    println!("win={} tie={} loss={}", wins, ties, losses);
}
