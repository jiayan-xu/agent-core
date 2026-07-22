//! 1.3 Best-of-N 量化对比 eval harness（HY3 量化验收：BoN 相对单次调用 +10pp）
//!
//! 设计：对每个「可验证质量」prompt，分别用
//!   - 单次调用（best_of_n = None）
//!   - Best-of-N（best_of_n = 3，scorer = Judge）
//! 取得回答后，用 judge LLM 对两者各打 0-10 分，统计
//!   mean_single / mean_bon / Δpp / win-tie-loss。
//!
//! 任务域：代码 / 结构化可验证 prompt，且**刻意选有真实质量方差的硬任务**
//! （边界/并发/溢出/转义），使单次一枪常有瑕疵（6-8 分），BoN（3 选 1）更易命中满分。
//! judge 用**逐条 rubric 扣分（0.5 步长）**，避免天花板效应（旧版 5 条易题致 judge 饱和 10/10、
//! Δpp=0.0 的天花板假象）。
//!
//! 生成模型固定为较弱的 deepseek-chat（增大方差），judge 用 deepseek-reasoner（更强、更严）。
//!
//! 运行（需 `AGENT_API_KEY` 环境变量）：
//!   cargo test --release --test eval_bon -- --ignored --nocapture
//!
//! 默认 `#[ignore]`，避免无 key / 无网络时 CI 失败；需要真实 LLM 调用才跑。

use agent_core::llm::{LlmClient, LlmConfig, LlmProvider, Message, RoutedLlm, parse_judge_score};

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

/// 解析 judge 返回的分数：委托 `llm::parse_judge_score`（BoN-A 生产/eval 统一入口）。
fn parse_score(text: &str) -> f64 {
    parse_judge_score(text)
}

async fn judge_score(client: &LlmClient, prompt: &str, rubric: &str, answer: &str) -> f64 {
    let j = format!(
        "用户请求：\n{}\n\n评分标准(rubric)：\n{}\n\n候选回答：\n{}\n\n请严格按 rubric 逐条核查，每条未满足扣对应分（0.5 步长），只有全部满足才给满分 10。先简短说明扣分点，最后一行只输出：SCORE: <0-10 的数字，可含一位小数>",
        prompt, rubric, answer
    );
    match client.chat(&[msg(&j)], &[]).await {
        Ok(r) => parse_score(&r.text),
        Err(_) => 0.0,
    }
}

struct Task {
    prompt: &'static str,
    rubric: &'static str,
}

// 硬任务 + 逐条 rubric：刻意制造真实质量方差（边界/并发/溢出/转义），
// 使单次一枪常有瑕疵、BoN(3 选 1) 更易命中满分，Δpp 才能被验证（非天花板）。
const TASKS: &[Task] = &[
    Task {
        prompt: "用 Python 实现一个线程安全的 LRU 缓存，容量 N，get/put 均为 O(1) 均摊。要求：(1) 用锁保证并发安全；(2) get 命中时更新最近使用；(3) 超出容量时淘汰最久未使用；(4) 附 3 个单元测试（含一个并发测试）。",
        rubric: "核查：① 是否用锁(threading.Lock 或等价)保护临界区；② get 是否刷新 recency（移到最近）；③ put 超出容量是否淘汰 LRU；④ 是否有 ≥3 测试且含并发场景；⑤ 复杂度是否 O(1) 均摊（dict+双向链表或 OrderedDict）。每项缺失/错误扣 2 分。",
    },
    Task {
        prompt: "写一个 PCRE 正则精确校验 IPv4 地址：四段、每段 0-255、无前导零（'0' 本身允许，'01' 不允许）、恰好四段。必须拒绝：256.1.1.1、1.2.3、01.2.3.4、1.2.3.4.5、1.2.3.4.。并逐段解释正则。",
        rubric: "核查：① 是否拒绝 >255；② 是否拒绝前导零(01)；③ 是否恰好四段（拒绝 3 段/5 段）；④ 是否拒绝空段；⑤ 是否正确解释。每项缺陷扣 2 分。仅形式正确但漏边界仍扣分。",
    },
    Task {
        prompt: "修复这条 SQL 使其返回『按订单总金额降序的前 10 名用户』：\nSELECT user_id, SUM(amount) FROM orders GROUP BY user_id ORDER BY amount DESC LIMIT 10;\n额外要求：金额相同（并列）时按 user_id 升序确定性排序；amount 在 SELECT 中需正确命名。",
        rubric: "核查：① ORDER BY 是否用 SUM(amount)（原语义错，order by amount 歧义）；② 别名是否正确（如 total_amount）；③ 并列(tie)是否用 user_id 兜底确定性；④ 结果是否真为前 10。每项缺陷扣 2.5 分。",
    },
    Task {
        prompt: "按 RFC 6901 实现 JSON Pointer 解析：输入嵌套 dict/list 与指针 '/a/b/0/c'，返回引用值。须正确处理转义 ~1→'/'、~0→'~'，数组下标为整数，缺失路径抛 KeyError。给出 Python 实现 + 2 个测试（含转义与数组）。",
        rubric: "核查：① 是否拆分 '/' 且处理空串/根；② ~1→/ 与 ~0→~ 转义是否正确（顺序等效即可）；③ 数组下标是否按整数索引；④ 缺失是否抛 KeyError；⑤ 是否有 ≥2 测试覆盖转义+数组。每项缺陷扣 2 分。",
    },
    Task {
        prompt: "实现 Python bisect_left 语义：在升序整数数组中返回目标最左插入位置；必须避免整数溢出（用 mid = lo + (hi-lo)//2）；处理空数组；给出测试覆盖重复元素与空数组。",
        rubric: "核查：① 是否返回最左位置（重复元素不返回右端）；② 是否避免 (lo+hi)//2 溢出写法；③ 空数组是否返回 0；④ 是否有重复元素与空数组测试。每项缺陷扣 2.5 分。",
    },
];

#[tokio::test]
#[ignore = "needs AGENT_API_KEY + live LLM; costs tokens"]
async fn eval_bon_vs_single_delta_pp() {
    let key = std::env::var("AGENT_API_KEY").expect("AGENT_API_KEY 必须设置");
    // 生成模型固定为较弱的 deepseek-chat（增大方差）；judge 用更强的 deepseek-reasoner
    let gen = provider("deepseek-chat", &key);
    let judge_p = provider("deepseek-reasoner", &key);

    let mut single_cfg = LlmConfig::default();
    single_cfg.api_key = key.clone();
    single_cfg.difficulty.easy = Some(gen.clone());
    single_cfg.difficulty.hard = Some(gen.clone()); // 生成统一用弱模型，最大化方差
    single_cfg.difficulty.classify = agent_core::llm::ClassifyMode::Heuristic;
    single_cfg.difficulty.best_of_n = None; // 单次
    single_cfg.difficulty.scorer = agent_core::llm::ScorerMode::Judge;
    single_cfg.difficulty.judge_provider = Some(judge_p.clone());

    let mut bon_cfg = single_cfg.clone();
    bon_cfg.difficulty.best_of_n = Some(3); // Best-of-N

    let judge_client = LlmClient::new(LlmConfig::from_provider(&judge_p));

    let mut n = 0;
    let mut sum_single = 0.0;
    let mut sum_bon = 0.0;
    let mut wins = 0;
    let mut ties = 0;
    let mut losses = 0;

    for t in TASKS {
        let single = RoutedLlm::from_config(&single_cfg)
            .chat(&[msg(t.prompt)], &[])
            .await
            .expect("single chat");
        let bon = RoutedLlm::from_config(&bon_cfg)
            .chat(&[msg(t.prompt)], &[])
            .await
            .expect("bon chat");

        let s_single = judge_score(&judge_client, t.prompt, t.rubric, &single.text).await;
        let s_bon = judge_score(&judge_client, t.prompt, t.rubric, &bon.text).await;
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
            "[{}/{}] '{}'  single={:.1} bon={:.1}",
            n,
            TASKS.len(),
            t.prompt.chars().take(18).collect::<String>(),
            s_single,
            s_bon
        );
    }

    let mean_single = sum_single / n as f64;
    let mean_bon = sum_bon / n as f64;
    let delta_pp = (mean_bon - mean_single) * 10.0; // 0-10 分制 → 百分点
    println!("===== BoN eval (hard tasks + rubric judge) =====");
    println!("prompts={}", n);
    println!("mean_single = {:.2}", mean_single);
    println!("mean_bon    = {:.2}", mean_bon);
    println!("Δpp         = {:.1} (暂定验收线 +10pp；需 ≥N 条可验样本且 judge 稳定)", delta_pp);
    println!("win={} tie={} loss={}", wins, ties, losses);
}
