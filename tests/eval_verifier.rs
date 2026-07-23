//! TTC 量化对比 eval harness（HY3 TTC Phase 3 验收：单发 greedy vs verifier-guided 生成）
//!
//! 设计：对每个「有唯一可验证答案」的 prompt，分别用
//!   - 单发（temperature=0，greedy，1 次调用）
//!   - verifier-guided（生成后用 judge=deepseek-v4-pro 打分，<阈值则带反馈重生成，基线保底）
//! 取得回答后，复用 `llm::extract_answer` 抽取核心答案，与 gold 比对命中率，
//! 统计 acc_single / acc_verifier / Δpp（百分点）。
//!
//! 与 eval_ttc 的区别：eval_ttc 测「自一致性盲投票」（对强模型 Δpp=0，系统性错修不了）；
//! 本 harness 测「verifier-guided 带反馈重生成」——裁判能识别错误并给出可修正的批评，
//! 是 TTC 终答侧唯一可能真正产生质量增益的变体。
//!
//! 生成固定 deepseek-v4-flash；裁判固定 deepseek-v4-pro（judge_provider）。
//!
//! 运行（需 AGENT_API_KEY 环境变量）：
//!   cargo test --release --test eval_verifier -- --ignored --nocapture
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

/// 归一化：去首尾空白 + 去尾随中英文标点。
fn norm(s: &str) -> String {
    let s = s.trim();
    let s = s.trim_end_matches(|c: char| "。.!！?？,，、；;:： \t『』「」“”‘’（）()".contains(c));
    s.trim().to_string()
}

/// 去常见中文单位后缀（度/千克/个/元/%/天...），使「90度」与「90」可比对。
fn strip_units(s: &str) -> String {
    let mut s = s.to_string();
    let units = [
        "千克", "公斤", "公里", "千米", "厘米", "毫米", "米", "克", "度", "个", "名", "颗", "人",
        "天", "日", "年", "月", "元", "万元", "%", "平方", "立方", "分", "秒", "小时", "分钟",
    ];
    loop {
        let before = s.len();
        for u in &units {
            if let Some(rest) = s.strip_suffix(u) {
                s = rest.to_string();
            }
        }
        if s.len() == before {
            break;
        }
    }
    s.trim().to_string()
}

/// 进一步去掉「答案：/结论：」前缀。
fn clean(s: &str) -> String {
    let s = norm(s);
    for p in ["答案：", "答案:", "结论：", "结论:", "Answer:", "answer:"] {
        if let Some(rest) = s.strip_prefix(p) {
            return norm(rest);
        }
    }
    s
}

/// gold 比对：字符串相等，或二者均可解析为浮点且相等。
fn matches(ans: &str, gold: &str) -> bool {
    let a = strip_units(&clean(ans));
    let g = strip_units(&clean(gold));
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

// 多步推理 + 计算/逻辑陷阱，刻意制造 greedy（flash temp=0）可能偶发失误、verifier 可修复的空间。
// 陷阱类型：单位换算、闰年、分数链、复合百分比、集合容斥、几何、反转词、方程、复利。
const TASKS: &[Task] = &[
    Task {
        prompt: "一桶油连桶重 5.5 千克，用去一半油后，连桶重 3 千克。桶重多少千克？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "0.5",
    },
    Task {
        prompt: "2024 年 2 月有多少天？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "29",
    },
    Task {
        prompt: "小明有 12 颗糖，给了小红 1/3，又吃了剩下的 1/4，还剩几颗？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "6",
    },
    Task {
        prompt: "一件商品先涨价 20% 再降价 20%，现价是原价的百分之多少？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "96",
    },
    Task {
        prompt: "从 1 到 100 中，既不是 2 的倍数也不是 3 的倍数的数有几个？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "33",
    },
    Task {
        prompt: "一个班级 40 人，25 人会游泳，18 人会骑车，两种都会的 8 人。两种都不会的有几人？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "5",
    },
    Task {
        prompt: "时钟 3 点整，时针与分针夹角多少度？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "90",
    },
    Task {
        prompt: "把单词 'stressed' 倒过来拼写是什么？最后用『答案：X』给出结果。只输出答案行。",
        gold: "desserts",
    },
    Task {
        prompt: "一个数加上 8 等于这个数的 3 倍，这个数是多少？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "4",
    },
    Task {
        prompt: "1000 元按年利率 4% 复利存 2 年，到期本息约多少元（保留一位小数）？请逐步推理，最后用『答案：N』给出结果。只输出答案行。",
        gold: "1081.6",
    },
];

#[tokio::test]
#[ignore = "needs AGENT_API_KEY + live LLM; costs tokens"]
async fn eval_verifier_single_vs_guided_delta_pp() {
    let key = std::env::var("AGENT_API_KEY").expect("AGENT_API_KEY 必须设置");

    // 生成模型：deepseek-v4-flash（强模型，但仍可能偶发踩陷阱）
    let gen = provider("deepseek-v4-flash", &key);
    // 裁判：更强的 deepseek-v4-pro（judge_provider），用于识别错误并给可修正批评
    let verifier = provider("deepseek-v4-pro", &key);

    let mut cfg = LlmConfig::from_provider(&gen);
    cfg.difficulty.judge_provider = Some(verifier);
    let routed = RoutedLlm::from_config(&cfg);

    // verifier-guided 配置（与生产接线一致；chat_verifier_guided 只看 verifier_enabled）
    let ttc = TtcConfig {
        enabled: true,
        best_of_n: 3,
        scorer: ScorerMode::Majority,
        sample_temperature: 0.7,
        token_budget: 8000,
        verifier_enabled: true,
        max_refine_rounds: 2,
        verifier_threshold: 7.0,
    };

    let mut n = 0usize;
    let mut correct_single = 0usize;
    let mut correct_verifier = 0usize;

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
        let guided = routed.chat_verifier_guided(&[msg(t.prompt)], &baseline, &ttc).await;

        let a_single = extract_answer(&single.text);
        let a_guided = extract_answer(&guided.text);
        let cs = matches(&a_single, t.gold);
        let cv = matches(&a_guided, t.gold);
        if cs {
            correct_single += 1;
        }
        if cv {
            correct_verifier += 1;
        }
        n += 1;
        println!(
            "[{}/{}] '{}' single_ok={} guided_ok={} | single={:?} guided={:?} gold={:?}",
            n,
            TASKS.len(),
            t.prompt.chars().take(16).collect::<String>(),
            cs,
            cv,
            a_single,
            a_guided,
            t.gold
        );
    }

    let acc_single = if n > 0 {
        correct_single as f64 / n as f64 * 100.0
    } else {
        0.0
    };
    let acc_verifier = if n > 0 {
        correct_verifier as f64 / n as f64 * 100.0
    } else {
        0.0
    };
    let delta_pp = acc_verifier - acc_single;
    println!("===== TTC eval (verifier-guided, pro judge, flash gen) =====");
    println!("prompts           = {}", n);
    println!("acc_single        = {:.1}%", acc_single);
    println!("acc_verifier      = {:.1}%", acc_verifier);
    println!(
        "Δpp               = {:.1} (verifier 仅在修复偶发错时转正；基线保底不退化)",
        delta_pp
    );
    println!("correct_single    = {}/{}", correct_single, n);
    println!("correct_verifier  = {}/{}", correct_verifier, n);
}
