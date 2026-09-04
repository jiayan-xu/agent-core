//! P2-2：consolidate 固定评估集（《程序化汇合改造方案》§8 P2）。
//!
//! 给 dream/consolidate 循环挂「固定题集 + 单一北极星指标」，让后续 P3 的 prompt
//! 离线进化有可比基线（autoresearch 协议：固定题集、固定预算、单指标、保留或丢弃）。
//!
//! 判分全部程序化，无 LLM 参与判分：
//! - **正例**（应提炼的观察）：被 ≥1 条**过写库门槛**的 pattern 以【依据】引用 → hit；
//! - **负例**（prompt 禁区样本：流水账 / 无关话题 / 测试冒烟 / 工具回显）：被任何
//!   valid pattern 引用 → leak；
//! - 北极星指标 = `positive_hit_rate`（命中正例数 / 正例总数）；次级指标
//!   `keyword_hits`（pattern 文本含正例关键词）与 `negative_leaks`（禁区泄漏）。
//!
//! 评估会**真实调用提炼 LLM**：仅 admin 手动触发（/api/admin/consolidate_eval），
//! 不进任何自动循环；报告原子落盘 `data/consolidate_eval/<时间戳>.json` 供跨次比较。

use std::time::Instant;

use crate::agent::AgentCore;

/// 评估用例。`expect_pattern=false` 的观察是 prompt 禁区样本（理想行为：不引用）。
struct EvalCase {
    obs: &'static str,
    expect_pattern: bool,
    /// 命中关键词（次级指标：pattern 文本包含任一关键词也计 keyword hit）
    keywords: &'static [&'static str],
}

/// 固定题集（v1）。选题对齐 consolidate prompt 的正反两面：
/// 正例 = 可长期复用的工程/运维/业务规则观察；负例 = prompt 明令禁止的四类禁区。
/// 修改题集 = 更换基线，会使历史评估不可比——新增用例只能追加，不得改写已发布用例。
static EVAL_SET: &[EvalCase] = &[
    EvalCase {
        obs: "掺烧工业固废前必须先做热值反推校验，热值低于 8000 kJ/kg 的批次要下调掺烧比",
        expect_pattern: true,
        keywords: &["热值", "掺烧"],
    },
    EvalCase {
        obs: "agent-core 重启必须走看门狗 start_both_tray.ps1，直接 Stop-Process 会误杀看门狗导致 memoria 失去自动恢复",
        expect_pattern: true,
        keywords: &["看门狗", "重启"],
    },
    EvalCase {
        obs: "生产环境密钥统一放 ~/.svc-secrets 目录，项目目录内不允许有明文 .env 文件",
        expect_pattern: true,
        keywords: &["svc-secrets", "密钥"],
    },
    EvalCase {
        obs: "会议共识落地前要经 /api/approval 审批流确认，admin 与 jarvis 令牌不得配同值",
        expect_pattern: true,
        keywords: &["审批", "令牌"],
    },
    EvalCase {
        obs: "memoria 检索走 FTS5+HNSW 混合通道，纯向量召回不足时先检查 HyPE 索引是否完成启动重建",
        expect_pattern: true,
        keywords: &["检索", "HNSW"],
    },
    EvalCase {
        obs: "PFAiX 静默安装 /S 前必须先杀光 Jan 进程，否则安装器会因文件锁失败",
        expect_pattern: true,
        keywords: &["PFAiX", "安装"],
    },
    // ── 负例：prompt 禁区四类 ──
    EvalCase {
        obs: "2026-09-04 14:32 cron 巡检任务运行完成，输出已写入 logs/patrol.log",
        expect_pattern: false,
        keywords: &[],
    },
    EvalCase {
        obs: "世界杯决赛今晚开球，大家记得准时观看",
        expect_pattern: false,
        keywords: &[],
    },
    EvalCase {
        obs: "刚才把冒烟测试用例跑了一遍，全部通过了",
        expect_pattern: false,
        keywords: &[],
    },
    EvalCase {
        obs: "cd /c/Users/user/agent-core && cargo check --all-targets",
        expect_pattern: false,
        keywords: &[],
    },
];

/// 评估报告（JSON 序列化后落盘，供跨次比较）
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvalReport {
    pub ns: String,
    pub cases_positive: usize,
    pub cases_negative: usize,
    /// 过写库门槛（pattern_ok_for_consolidate）的 pattern 数
    pub patterns_valid: usize,
    /// 被有效 pattern 引用的正例数
    pub positive_hits: usize,
    /// **北极星指标**：positive_hits / cases_positive
    pub positive_hit_rate: f64,
    /// 次级指标：pattern 文本包含正例关键词的正例数
    pub keyword_hits: usize,
    /// 负例被引用次数（应趋近 0，>0 说明禁区约束退化）
    pub negative_leaks: usize,
    pub duration_ms: u64,
    pub patterns: Vec<String>,
    pub ts: String,
}

/// 跑一轮固定评估：真实调用提炼 LLM（与 consolidate 同款 prompt 结构），程序判分。
/// 消耗一次 LLM 调用——仅限 admin 手动触发。
pub async fn run_consolidate_eval(agent: &AgentCore, ns: &str) -> Result<EvalReport, String> {
    let started = Instant::now();
    let positives = EVAL_SET.iter().filter(|c| c.expect_pattern).count();
    let negatives = EVAL_SET.len() - positives;

    // 与 consolidate 相同的 prompt 结构（编号观察 + 依据标注要求），仅原料换成固定题集
    let obs_text = EVAL_SET
        .iter()
        .enumerate()
        .map(|(i, c)| format!("[{}] {}", i + 1, c.obs))
        .collect::<Vec<_>>()
        .join("\n- ");
    let prompt = format!(
        "你是知识巩固引擎。只从观察中提炼**可长期复用**的高层规则（架构取舍、运维约束、业务偏好、排障经验）。\n\
         硬性禁止写成 pattern：\n\
         - 一次性会话过程、工具回显、文件路径流水账、cron 任务日志\n\
         - 测试/冒烟/世界杯等无关话题\n\
         - 复述某条观察原文、或过短空话\n\
         每条模式一行、一句话、具体可执行，最多 5 条；行末必须标注支撑它的观察序号，格式如【依据: 1,3】。\n\
         若无可提炼内容，只输出「无模式」。\n\n\
         ## 待巩固观察（评估题集，命名空间 {}）\n- {}",
        ns,
        obs_text.chars().take(6000).collect::<String>()
    );
    let msg = crate::llm::Message {
        role: "system".to_string(),
        content: Some(prompt),
        tool_calls: None,
        tool_call_id: None,
    };
    let reply = agent
        .llm
        .chat(&[msg], &[])
        .await
        .map_err(|e| format!("评估 LLM 调用失败: {}", e))?;
    let reply = reply.text.trim().to_string();

    // 解析（与 consolidate 相同规则）：行末【依据: 序号】→ 过写库门槛的 pattern
    let mut patterns_valid: Vec<(String, Vec<usize>)> = Vec::new();
    for line in reply.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if l.contains("无模式") && l.chars().count() < 20 {
            break;
        }
        let (text, cite) = match l.find("【依据") {
            Some(pos) => (&l[..pos], &l[pos..]),
            None => (l, ""),
        };
        let nums: Vec<usize> = cite
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<usize>().ok())
            .filter(|n| *n >= 1 && *n <= EVAL_SET.len())
            .collect();
        let p = text
            .trim_start_matches(|c: char| {
                c.is_numeric() || c == '.' || c == '-' || c == '、' || c == ' ' || c == '*'
            })
            .trim()
            .to_string();
        if !p.is_empty() && AgentCore::pattern_ok_for_consolidate(&p) {
            patterns_valid.push((p, nums));
        }
    }

    // 程序判分：引用关系决定 hit / leak，零语义自由裁量
    let mut cited = vec![false; EVAL_SET.len()];
    let mut negative_leaks = 0usize;
    for (_, cites) in &patterns_valid {
        for n in cites {
            let idx = n.saturating_sub(1);
            if let Some(case) = EVAL_SET.get(idx) {
                if case.expect_pattern {
                    cited[idx] = true;
                } else {
                    negative_leaks += 1;
                }
            }
        }
    }
    let positive_hits = EVAL_SET
        .iter()
        .zip(&cited)
        .filter(|(c, h)| c.expect_pattern && **h)
        .count();
    let keyword_hits = EVAL_SET
        .iter()
        .enumerate()
        .filter(|(i, c)| {
            c.expect_pattern
                && patterns_valid.iter().any(|(p, _)| {
                    c.keywords.iter().any(|k| p.contains(k)) || cited[*i]
                })
        })
        .count();
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let report = EvalReport {
        ns: ns.to_string(),
        cases_positive: positives,
        cases_negative: negatives,
        patterns_valid: patterns_valid.len(),
        positive_hits,
        positive_hit_rate: if positives > 0 {
            positive_hits as f64 / positives as f64
        } else {
            0.0
        },
        keyword_hits,
        negative_leaks,
        duration_ms: started.elapsed().as_millis() as u64,
        patterns: patterns_valid.iter().map(|(p, _)| p.clone()).collect(),
        ts: ts.clone(),
    };

    // 落盘 data/consolidate_eval/<ts>.json（best-effort：失败不影响返回）
    let dir = std::path::Path::new("data/consolidate_eval");
    if std::fs::create_dir_all(dir).is_ok() {
        let file_ts = ts.replace([':', ' '], "-");
        if let Ok(json) = serde_json::to_string_pretty(&report) {
            let _ = std::fs::write(dir.join(format!("{}.json", file_ts)), json);
        }
    }
    tracing::info!(
        target: "consolidate_eval",
        ns = %report.ns,
        hit_rate = format!("{:.2}", report.positive_hit_rate),
        leaks = report.negative_leaks,
        valid = report.patterns_valid,
        "P2-2: 固定评估完成（报告已落盘 data/consolidate_eval/）"
    );
    Ok(report)
}

/// 读取历史评估报告的北极星指标序列（跨次比较用；按文件名时间戳升序）。
/// 供未来 P3 进化循环取「上一次基线」——现在先提供读取面。
pub fn list_past_hit_rates() -> Vec<(String, f64)> {
    let mut out: Vec<(String, f64)> = Vec::new();
    let dir = std::path::Path::new("data/consolidate_eval");
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    names.sort();
    for path in names {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                let rate = v["positive_hit_rate"].as_f64().unwrap_or(0.0);
                let ts = v["ts"]
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| path.display().to_string());
                out.push((ts, rate));
            }
        }
    }
    out
}
