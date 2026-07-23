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
//! 生成模型默认 deepseek-chat（非推理模型，制造可观测方差），可经环境变量 EVAL_MODEL / EVAL_BASE_URL 切换（如换更弱模型以显信号）。
//!
//! 运行（需 AGENT_API_KEY 环境变量）：
//!   cargo test --release --test eval_ttc -- --ignored --nocapture
//!
//! 默认 `#[ignore]`，避免无 key / 无网络时 CI 失败；需要真实 LLM 调用才跑。

use agent_core::llm::{extract_answer, LlmConfig, LlmProvider, LlmResponse, Message, RoutedLlm, ScorerMode};
use agent_core::ttc::TtcConfig;

fn provider(model: &str, key: &str) -> LlmProvider {
    // 允许经 EVAL_BASE_URL 切换底座（默认 deepseek），便于将来切更弱模型显信号
    let base = std::env::var("EVAL_BASE_URL").unwrap_or_else(|_| "https://api.deepseek.com".to_string());
    LlmProvider {
        base_url: base,
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

// 对抗性 eval 集（第二版）：刻意诱导 greedy(temp=0) 走「最似然但错误」的启发式路径，
// 而 temp=0.7 采样能扩散错误、让正确推理在多数票中胜出。覆盖已知 LLM 失败模式：
// 小数位数比较(9.9 vs 9.11)、字母计数(strawberry)、拿走陷阱、栅栏立柱 off-by-one、
// 条件概率(男孩女孩悖论)、三段论诡辩、单位/分数换算翻车等。
// 第一版易任务集(单步算术)撞天花板 Δpp=0.0；本集目标压出 Δpp>0 以证明 TTC 自一致性在生产模型上确有收益。
const TASKS: &[Task] = &[
    // —— 小数位数比较陷阱（greedy 常按「数位/版本号」误判）——
    Task {
        prompt: "请比较 9.9 和 9.11，哪个数更大？请逐步推理，最后用『答案：X』一行给出结果，X 只写较大的那个数本身（不要任何解释或单位文字）。",
        gold: "9.9",
    },
    Task {
        prompt: "请比较 7.5 和 7.45，哪个数更大？请逐步推理，最后用『答案：X』一行给出结果，X 只写较大的那个数本身（不要任何解释或单位文字）。",
        gold: "7.5",
    },
    Task {
        prompt: "请比较 8.08 和 8.8，哪个数更大？请逐步推理，最后用『答案：X』一行给出结果，X 只写较大的那个数本身（不要任何解释或单位文字）。",
        gold: "8.8",
    },
    Task {
        prompt: "请比较 3.3 和 3.21，哪个数更大？请逐步推理，最后用『答案：X』一行给出结果，X 只写较大的那个数本身（不要任何解释或单位文字）。",
        gold: "3.3",
    },
    // —— 字母计数陷阱（greedy 常漏数/多数）——
    Task {
        prompt: "英文单词 'strawberry' 中一共有几个字母 'r'？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "3",
    },
    Task {
        prompt: "英文单词 'raspberry' 中一共有几个字母 'r'？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "3",
    },
    Task {
        prompt: "英文单词 'broccoli' 中一共有几个字母 'o'？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "2",
    },
    Task {
        prompt: "英文单词 'occurrence' 中一共有几个字母 'r'？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "2",
    },
    // —— 「拿走/拥有」语义陷阱（greedy 常做减法而非保留）——
    Task {
        prompt: "你有 3 个苹果，你从里面拿走了 2 个。请问你现在手里有几个苹果？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "2",
    },
    // —— 球棒与球（System 1 锚定陷阱）——
    Task {
        prompt: "一个球棒和一个球总共 1.10 美元，且球棒比球贵正好 1.00 美元。请问球多少钱？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身（单位美元）。",
        gold: "0.05",
    },
    Task {
        prompt: "一个球棒和一个球总共 3.30 美元，且球棒比球贵正好 3.00 美元。请问球多少钱？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身（单位美元）。",
        gold: "0.15",
    },
    // —— 栅栏立柱 off-by-one 陷阱 ——
    Task {
        prompt: "一条路长 100 米，从起点开始每隔 10 米种一棵树，并且两端（起点和终点）都种。一共种了多少棵树？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "11",
    },
    // —— 条件概率（男孩女孩悖论）——
    Task {
        prompt: "一个家庭有两个孩子，已知其中至少有一个是男孩。在只考虑这两个孩子的前提下，两个都是男孩的概率是多少？请用最简分数表示（如 1/3）。请逐步推理，最后用『答案：X』一行给出结果，X 只写分数本身。",
        gold: "1/3",
    },
    Task {
        prompt: "一个家庭有两个孩子，已知年龄较大的那个是男孩。在只考虑这两个孩子的前提下，两个都是男孩的概率是多少？请用最简分数表示（如 1/2）。请逐步推理，最后用『答案：X』一行给出结果，X 只写分数本身。",
        gold: "1/2",
    },
    // —— 三段论诡辩 ——
    Task {
        prompt: "已知：所有 A 都是 B；有些 B 是 C。据此能否推出『有些 A 是 C』？请逐步推理，最后用『答案：X』一行给出结果，X 只写『是』或『否』本身。",
        gold: "否",
    },
    // —— 日期 off-by-one / 星期推算 ——
    Task {
        prompt: "从 3 月 1 日到 3 月 31 日（含首尾两天）一共有多少天？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "31",
    },
    Task {
        prompt: "已知 2024 年 1 月 1 日是星期一。2024 年 1 月 31 日是星期几？请逐步推理，最后用『答案：X』一行给出结果，X 只写『星期X』三个字本身（如 星期三）。",
        gold: "星期三",
    },
    // —— 整除计数 off-by-one ——
    Task {
        prompt: "在 1 到 1000（含 1000）这些整数中，能被 7 整除的数一共有多少个？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "142",
    },
    // —— 容斥原理（greedy 常漏加回交集）——
    Task {
        prompt: "在 1 到 100（含）的整数中，既不是 2 的倍数也不是 3 的倍数的数一共有多少个？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "33",
    },
    // —— 连续整数求和求最大项 ——
    Task {
        prompt: "三个连续整数的和是 51，其中最大的那个整数是多少？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "18",
    },
    // —— 单位换算翻车（分钟→小时）——
    Task {
        prompt: "一辆汽车以 60 公里/小时的速度行驶了 90 分钟，一共行驶了多少公里？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "90",
    },
    // —— 合作工时 ——
    Task {
        prompt: "甲单独完成一项工作需要 6 小时，乙单独完成需要 3 小时。若两人合作，完成同一项工作需要多少小时？请逐步推理，最后用『答案：X』一行给出结果，X 只写数字本身。",
        gold: "2",
    },
];

#[tokio::test]
#[ignore = "needs AGENT_API_KEY + live LLM; costs tokens"]
async fn eval_ttc_single_vs_selfconsistency_delta_pp() {
    let key = std::env::var("AGENT_API_KEY").expect("AGENT_API_KEY 必须设置");
    // 评测模型可经 EVAL_MODEL 切换（默认 deepseek-chat，非推理模型，制造可观测方差）
    let model = std::env::var("EVAL_MODEL").unwrap_or_else(|_| "deepseek-chat".to_string());
    let gen = provider(&model, &key);

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
