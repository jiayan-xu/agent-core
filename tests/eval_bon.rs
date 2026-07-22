//! 1.3 Best-of-N 量化对比 eval harness（HY3 量化验收：BoN 相对单次调用 +10pp）
//!
//! 设计：对每个「开放式质量」prompt，分别用
//!   - 单次调用（best_of_n = None）
//!   - Best-of-N（best_of_n = 3，scorer = Judge）
//! 取得回答后，用 judge LLM 对两者各打 0-10 分，统计
//!   mean_single / mean_bon / Δpp / win-tie-loss。
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

async fn judge_score(client: &LlmClient, prompt: &str, answer: &str) -> f64 {
    let j = format!(
        "用户请求：\n{}\n\n候选回答：\n{}\n\n请只返回一个 0-10 的整数分数（越高越好），不要其他文字。",
        prompt, answer
    );
    match client.chat(&[msg(&j)], &[]).await {
        Ok(r) => r
            .text
            .chars()
            .find_map(|c| c.to_digit(10).map(|d| d as f64))
            .unwrap_or(0.0),
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

    // 开放式质量 prompt（无标准答案，BoN 想象力/覆盖度收益最大）
    let prompts: &[&str] = &[
        "用一句话解释量子纠缠，让小学生也能听懂",
        "给「智能固废管理平台」想三个有差异的产品 slogan",
        "写一段关于「保持专注」的、有画面感的 100 字短文",
        "给拖延症患者三条可立刻执行的微习惯建议",
        "用比喻说明什么是「技术债」，给一个生活例子",
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
    println!("Δpp         = {:.1} (验收线 +10pp)", delta_pp);
    println!("win={} tie={} loss={}", wins, ties, losses);
}
