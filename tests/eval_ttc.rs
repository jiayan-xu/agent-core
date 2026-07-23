//! TTC 量化对比 eval harness（HY3 TTC 验收：单发 greedy vs 终答自一致性 Majority）
//!
//! 设计：对每个「有唯一可验证答案」的 prompt，分别用
//!   - 单发（temperature=0，greedy，1 次调用）
//!   - TTC 终答自一致性（best_of_n=3，ScorerMode=Majority，temp=0.7，N 路采样+多数票）
//! 取得回答后，复用 `llm::extract_answer` 抽取核心答案，与 gold 比对命中率，
//! 统计 acc_single / acc_ttc / Δpp（百分点）。
//!
//! 与 eval_bon 的区别：eval_bon 用 judge 打「质量分」（软指标）；本 harness 用 gold 答案测「准确率」（硬指标），
//! 直接对应自一致性论文（Wang et al. 2022）的设定，且无需 judge 模型、更客观、更省 token。
//!
//! 生成模型固定 deepseek-chat（非推理模型，制造可观测方差）。
//!
//! 运行（需 AGENT_API_KEY 环境变量）：
//!   cargo test --release --test eval_ttc -- --ignored --nocapture
//!
//! 默认 `#[ignore]`，避免无 key / 无网络时 CI 失败；需要真实 LLM 调用才跑。

use agent_core::llm::{extract_answer, LlmConfig, LlmProvider, LlmResponse, Message, RoutedLlm, ScorerMode};
use agent_core::ttc::TtcConfig;

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

/// 归一化：去首尾空白 + 去尾随中英文标点；用于与 gold 做宽松匹配。
fn norm(s: &str) -> String {
    let s = s.trim();
    let s = s.trim_end_matches(|c: char| "。.!！?？,，、；;:： \t".contains(c));
    s.trim().to_string()
}

/// 进一步去掉可能残留的「答案：/结论：」前缀，使抽取结果可直接与 gold 比对。
fn clean(s: &str) -> String {
    let s = norm(s);
    for p in ["答案：", "答案:", "结论：", "结论:", "Answer:", "answer:"] {
        if let Some(rest) = s.strip_prefix(p) {
            return norm(rest);
        }
    }
    s
}

/// gold 比对：字符串相等，或二者均可解析为浮点且相等（覆盖 "42" vs "42.0" 等）。
fn matches(ans: &str, gold: &str) -> bool {
    let a = clean(ans);
    let g = clean(gold);
    if a == g {
        return true;
    }
    if let (Ok(x), Ok(y)) = (a.parse::<f64>(), g.parse::<f64>()) {
        return (x - y).abs() < 1e-9;
    }
    false
}

struct Task {
    prompt: &'static str,
    gold: &'static str,
}

// 有唯一可验证答案的任务（多步数学/逻辑），刻意制造 greedy 可能偶发失误、采样+多数票可修复的空间。
// 第一版易任务集（单步算术/代码输出）测得 Δpp=0.0（天花板效应：deepseek-chat 在 temp=0 已确定性全对，TTC 无空间）。
// 本版升级为多步推理，使 greedy 偶发滑铁卢、temp=0.7 采样产生方差，自一致性才能显出信号。
const TASKS: &[Task] = &[
    Task {
        prompt: "书店里有 3 排书架，每排 12 本书。上午卖出 15 本，下午又进购 2 箱，每箱 20 本，傍晚又卖出 18 本。现在书店还剩多少本书？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "43",
    },
    Task {
        prompt: "一个农场有鸡和兔共 35 只，脚共 94 只。鸡有几只？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "23",
    },
    Task {
        prompt: "连续整数 1 到 50 中所有偶数的和是多少？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "650",
    },
    Task {
        prompt: "一个数除以 7 余 3，除以 11 余 5，这个数最小的正整数值是多少？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "38",
    },
    Task {
        prompt: "从 1 写到 100（含 100），一共写了多少个数字『9』（包括个位和十位分别计数）？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "20",
    },
    Task {
        prompt: "一个等差数列首项 5，公差 3，第 20 项是多少？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "62",
    },
    Task {
        prompt: "若 2^x = 32 且 3^y = 81，x + y 等于多少？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "9",
    },
    Task {
        prompt: "一个长方体的体积是 120 立方厘米，长 6 厘米，宽 4 厘米，高是多少厘米？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "5",
    },
    Task {
        prompt: "100 元按年利率 5% 单利存 3 年，到期本息合计多少元？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "115",
    },
    Task {
        prompt: "求 1² + 2² + 3² + ... + 10² 的和。请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "385",
    },
];

#[tokio::test]
#[ignore = "needs AGENT_API_KEY + live LLM; costs tokens"]
async fn eval_ttc_single_vs_selfconsistency_delta_pp() {
    let key = std::env::var("AGENT_API_KEY").expect("AGENT_API_KEY 必须设置");
    // 生成模型固定 deepseek-chat（非推理模型，制造可观测方差）
    let gen = provider("deepseek-chat", &key);

    // 单发：temperature=0（greedy），best_of_n=None → 1 次确定性调用
    // LlmConfig::from_provider 默认 temperature=0.0，difficulty 默认 best_of_n=None
    let single_cfg = LlmConfig::from_provider(&gen);
    let routed = RoutedLlm::from_config(&single_cfg);

    // TTC 终答自一致性：N=3 采样 + Majority 投票（与 agent-core 生产默认一致）
    let ttc = TtcConfig {
        enabled: true,
        best_of_n: 3,
        scorer: ScorerMode::Majority,
        sample_temperature: 0.7,
        token_budget: 8000,
        ..Default::default()
    };

    let mut n = 0usize;
    let mut correct_single = 0usize;
    let mut correct_ttc = 0usize;

    for t in TASKS {
        let single = match routed.chat(&[msg(t.prompt)], &[]).await {
            Ok(r) => r,
            Err(e) => {
                println!("[ERR] single chat failed: {}", e);
                continue;
            }
        };
        let baseline = LlmResponse {
            text: single.text.clone(),
            tool_calls: vec![],
        };
        let ttc_resp = routed.chat_ttc(&[msg(t.prompt)], &baseline, &ttc).await;

        let a_single = extract_answer(&single.text);
        let a_ttc = extract_answer(&ttc_resp.text);
        let cs = matches(&a_single, t.gold);
        let ct = matches(&a_ttc, t.gold);
        if cs {
            correct_single += 1;
        }
        if ct {
            correct_ttc += 1;
        }
        n += 1;
        println!(
            "[{}/{}] '{}' single_ok={} ttc_ok={} | single={:?} ttc={:?} gold={:?}",
            n,
            TASKS.len(),
            t.prompt.chars().take(16).collect::<String>(),
            cs,
            ct,
            a_single,
            a_ttc,
            t.gold
        );
    }

    let acc_single = if n > 0 {
        correct_single as f64 / n as f64 * 100.0
    } else {
        0.0
    };
    let acc_ttc = if n > 0 {
        correct_ttc as f64 / n as f64 * 100.0
    } else {
        0.0
    };
    let delta_pp = acc_ttc - acc_single;
    println!("===== TTC eval (self-consistency, Majority, N=3) =====");
    println!("prompts        = {}", n);
    println!("acc_single     = {:.1}%", acc_single);
    println!("acc_ttc        = {:.1}%", acc_ttc);
    println!(
        "Δpp            = {:.1} (生产开闸建议线：Δpp 稳定 > 0 且收益 > 成本×N 才翻 features.ttc)",
        delta_pp
    );
    println!("correct_single = {}/{}", correct_single, n);
    println!("correct_ttc    = {}/{}", correct_ttc, n);
}
