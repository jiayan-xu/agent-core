//! P2-2：consolidate 固定评估集（《程序化汇合改造方案》§8 P2）。
//!
//! 给 dream/consolidate 循环挂「固定题集 + 单一北极星指标」，让后续 P3 的 prompt
//! 离线进化有可比基线（autoresearch 协议：固定题集、固定预算、单指标、保留或丢弃）。
//!
//! 判分全部程序化，无 LLM 参与判分：
//! - **正例**（应提炼的观察）：被 ≥1 条**过写库门槛**的 pattern 以【依据】引用 → hit；
//! - **负例**（prompt 禁区样本）：**在任何候选行**（含未过写库门槛的）中以引用或
//!   禁区关键词出现 → leak。泄漏检查刻意放在写库门槛**之前**——门槛本身会硬拒含
//!   「世界杯」等词的行，若只查过门槛的 pattern，最典型的违规形式反而永远计 0；
//! - 北极星指标 = `positive_hit_rate`（命中正例数 / 正例总数）；次级指标
//!   `keyword_hits` 与 `negative_leaks`（按负例用例去重计数，与正例计数同单位）。
//!
//! 口径与生产严格一致：prompt 字面量与【依据】解析共用 agent.rs 的
//! `pattern_extraction_prompt` / `parse_pattern_citation`；候选先 `take(8)`、过门槛后
//! `take(5)`，与生产 consolidate 相同——评估测的必须是正在运行的行为。
//!
//! 评估会**真实调用提炼 LLM**：仅 admin 手动触发（/api/admin/consolidate_eval），
//! 不进任何自动循环；报告 tmp+rename 原子落盘 `data/consolidate_eval/<毫秒时间戳>.json`
//! 供跨次比较。

use std::time::Instant;

use crate::agent::AgentCore;

/// 题集版本戳：**任何对 EVAL_SET 的修改（含追加）都必须递增本值**——追加用例同样
/// 更换基线（分母变化使历史 hit_rate 不可比）。报告落盘携带本值，
/// `list_past_hit_rates` 按版本过滤，P3 进化循环不会把跨版本数字当序列比较。
pub const EVAL_SET_VERSION: u32 = 1;

/// 评估用例。`expect_pattern=false` 的观察是 prompt 禁区样本（理想行为：不被引用）。
struct EvalCase {
    obs: &'static str,
    expect_pattern: bool,
    /// 正例：命中关键词（次级指标：过门槛 pattern 文本包含任一关键词也计 keyword hit）；
    /// 负例：禁区关键词（任何候选行包含 → 该负例计一次 leak）。
    keywords: &'static [&'static str],
}

/// 固定题集（v1）。正例 = 可长期复用的工程/运维/业务规则观察；负例 = prompt 明令
/// 禁止的四类禁区。修改题集（含追加）= 更换基线：递增 EVAL_SET_VERSION。
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
    // ── 负例：prompt 禁区四类（keywords = 禁区指纹，任何候选行命中即 leak）──
    EvalCase {
        obs: "2026-09-04 14:32 cron 巡检任务运行完成，输出已写入 logs/patrol.log",
        expect_pattern: false,
        keywords: &["cron", "patrol.log", "巡检任务运行完成"],
    },
    EvalCase {
        obs: "世界杯决赛今晚开球，大家记得准时观看",
        expect_pattern: false,
        keywords: &["世界杯", "world cup"],
    },
    EvalCase {
        obs: "刚才把冒烟测试用例跑了一遍，全部通过了",
        expect_pattern: false,
        keywords: &["冒烟"],
    },
    EvalCase {
        obs: "cd /c/Users/user/agent-core && cargo check --all-targets",
        expect_pattern: false,
        keywords: &["cargo check"],
    },
];

/// 单条候选 pattern 的可调试记录（报告落盘，跨次比较时能区分覆盖回归与格式回归）
#[derive(Debug, Clone, serde::Serialize)]
pub struct PatternFinding {
    pub text: String,
    pub cites: Vec<usize>,
    pub passed_gate: bool,
}

/// 每个用例的判定结果（报告落盘：哪个正例没命中、哪个负例泄漏一目了然）
#[derive(Debug, Clone, serde::Serialize)]
pub struct CaseResult {
    pub index: usize,
    pub expect_pattern: bool,
    pub cited: bool,
    pub keyword_hit: bool,
    pub leaked: bool,
}

/// 评估报告（JSON 序列化后原子落盘，供跨次比较）
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvalReport {
    pub ns: String,
    pub eval_set_version: u32,
    pub cases_positive: usize,
    pub cases_negative: usize,
    /// ok：有有效 pattern，hit_rate 可比；no_patterns / empty_reply：本轮无基线意义
    pub outcome: String,
    /// 过写库门槛（pattern_ok_for_consolidate）的 pattern 数（与生产一致：先 take(8) 后 take(5)）
    pub patterns_valid: usize,
    /// 被有效 pattern 引用的正例数
    pub positive_hits: usize,
    /// **北极星指标**：positive_hits / cases_positive（仅 outcome=ok 有意义）
    pub positive_hit_rate: f64,
    /// 次级指标：过门槛 pattern 文本包含正例关键词的正例数
    pub keyword_hits: usize,
    /// 负例被 implicated 的用例数（引用或禁区关键词，任一候选行；应趋近 0）
    pub negative_leaks: usize,
    /// 过门槛但未标注【依据】的 pattern 条数（>0 = 格式回归：hit_rate 低未必是覆盖回归）
    pub patterns_missing_citations: usize,
    pub duration_ms: u64,
    pub patterns: Vec<PatternFinding>,
    pub case_results: Vec<CaseResult>,
    pub ts: String,
}

/// 跑一轮固定评估：真实调用提炼 LLM（与生产 consolidate 同款 prompt），程序判分。
/// 消耗一次 LLM 调用——仅限 admin 手动触发。
pub async fn run_consolidate_eval(agent: &AgentCore, ns: &str) -> Result<EvalReport, String> {
    let started = Instant::now();
    let positives = EVAL_SET.iter().filter(|c| c.expect_pattern).count();
    let negatives = EVAL_SET.len() - positives;

    // 与生产相同的 prompt（共享字面量）+ 编号观察。scope 用**中性表述**（只报条数与
    // 命名空间）——「正例 6/负例 4」会向被测模型泄露评估结构，使其比生产更保守，
    // 压低 hit_rate 且对不同措辞敏感度不同（ocr PR#65 第三轮评审）。
    let obs_lines: Vec<String> = EVAL_SET.iter().map(|c| c.obs.to_string()).collect();
    let (prompt, included) = AgentCore::pattern_extraction_prompt(
        &format!("候选观察 {} 条，命名空间 {}", EVAL_SET.len(), ns),
        &obs_lines,
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
        .map_err(|e| format!("评估 LLM 调用失败: {}", e))?
        .text
        .trim()
        .to_string();

    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let empty_reply = reply.is_empty();
    let no_patterns =
        reply == "无模式" || (reply.contains("无模式") && reply.chars().count() < 20);

    // 解析：与生产同规则（take(8) 候选 → 过门槛 → take(5)），引用解析共享
    // parse_pattern_citation；序号上界 = `included`（6000 字窗口内实际可见数）
    let mut findings: Vec<PatternFinding> = Vec::new();
    for line in reply
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .take(8)
    {
        let (text, cites) = AgentCore::parse_pattern_citation(line, included);
        let text = text
            .trim_start_matches(|c: char| {
                c.is_numeric() || c == '.' || c == '-' || c == '、' || c == ' ' || c == '*'
            })
            .trim()
            .to_string();
        if text.is_empty() {
            continue;
        }
        findings.push(PatternFinding {
            passed_gate: AgentCore::pattern_ok_for_consolidate(&text),
            text,
            cites,
        });
    }
    // 有效 pattern = 过门槛且不超过生产上限 take(5)
    let valid: Vec<&PatternFinding> = findings
        .iter()
        .filter(|f| f.passed_gate)
        .take(5)
        .collect();
    // 但有效 pattern 之外的候选行仍参与**泄漏**检查（写库门槛本身会拦部分禁区词，
    // 只查过门槛行会让最典型的回归形式永远计 0——见模块头注释）
    let leak_scan_lines: Vec<&PatternFinding> = findings.iter().collect();

    // 程序判分（零语义自由裁量）。
    // 关键词匹配一律**大小写不敏感**（对齐生产门槛 pattern_ok 的 lower.contains）：
    // ASCII 指纹（cron/PATROL.LOG/World Cup/cargo check）正是 LLM 最爱改大小写的
    // 词，大小写敏感会把真实泄漏误判为干净（ocr PR#65 第二轮评审）。
    let contains_ci = |haystack: &str, needle: &str| -> bool {
        haystack.to_lowercase().contains(&needle.to_lowercase())
    };
    let mut cited = vec![false; EVAL_SET.len()];
    let mut leaked = vec![false; EVAL_SET.len()];
    for f in &valid {
        for n in &f.cites {
            cited[n.saturating_sub(1)] = true;
        }
    }
    for f in &leak_scan_lines {
        for (i, case) in EVAL_SET.iter().enumerate() {
            if !case.expect_pattern {
                let kw_hit = case.keywords.iter().any(|k| contains_ci(&f.text, k));
                let cited_hit = f.cites.contains(&(i + 1));
                if kw_hit || cited_hit {
                    leaked[i] = true;
                }
            }
        }
    }
    let case_results: Vec<CaseResult> = EVAL_SET
        .iter()
        .enumerate()
        .map(|(i, c)| CaseResult {
            index: i + 1,
            expect_pattern: c.expect_pattern,
            cited: c.expect_pattern && cited[i],
            // keyword_hit 与 cited 是**独立信号**：只看文本关键词命中，不含引用
            // （`|| cited[i]` 会让本指标退化成 positive_hits 的超集，失去独立诊断价值）
            keyword_hit: c.expect_pattern
                && valid.iter().any(|f| c.keywords.iter().any(|k| contains_ci(&f.text, k))),
            leaked: !c.expect_pattern && leaked[i],
        })
        .collect();
    let positive_hits = case_results.iter().filter(|r| r.cited).count();
    let keyword_hits = case_results.iter().filter(|r| r.keyword_hit).count();
    let negative_leaks = case_results.iter().filter(|r| r.leaked).count();
    let patterns_missing_citations = valid.iter().filter(|f| f.cites.is_empty()).count();
    let outcome = if empty_reply || no_patterns || valid.is_empty() {
        if empty_reply { "empty_reply" } else { "no_patterns" }.to_string()
    } else {
        "ok".to_string()
    };
    let report = EvalReport {
        ns: ns.to_string(),
        eval_set_version: EVAL_SET_VERSION,
        cases_positive: positives,
        cases_negative: negatives,
        outcome,
        patterns_valid: valid.len(),
        positive_hits,
        positive_hit_rate: if positives > 0 {
            positive_hits as f64 / positives as f64
        } else {
            0.0
        },
        keyword_hits,
        negative_leaks,
        patterns_missing_citations,
        duration_ms: started.elapsed().as_millis() as u64,
        patterns: findings,
        case_results,
        ts,
    };

    // 原子落盘 data/consolidate_eval/<毫秒时间戳>.json：tmp + rename（对齐仓库
    // write_meetings_file / experience_memo 约定），毫秒文件名防同秒覆盖；
    // 每一步失败都 warn 留痕，不再静默吞错。
    let dir = std::path::Path::new("data/consolidate_eval");
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!(target: "consolidate_eval", error = %e, "P2-2: 无法创建评估目录，报告未落盘");
    } else {
        let file_ts = chrono::Local::now().format("%Y%m%dT%H%M%S%3f");
        let final_path = dir.join(format!("{}.json", file_ts));
        let tmp_path = dir.join(format!("{}.json.tmp", file_ts));
        match serde_json::to_string_pretty(&report) {
            Ok(json) => match std::fs::write(&tmp_path, json).and_then(|_| std::fs::rename(&tmp_path, &final_path)) {
                Ok(()) => {}
                Err(e) => tracing::warn!(target: "consolidate_eval", error = %e, "P2-2: 评估报告落盘失败"),
            },
            Err(e) => tracing::warn!(target: "consolidate_eval", error = %e, "P2-2: 评估报告序列化失败"),
        }
    }
    tracing::info!(
        target: "consolidate_eval",
        ns = %report.ns,
        outcome = %report.outcome,
        hit_rate = format!("{:.2}", report.positive_hit_rate),
        leaks = report.negative_leaks,
        valid = report.patterns_valid,
        "P2-2: 固定评估完成（报告已落盘 data/consolidate_eval/）"
    );
    Ok(report)
}

/// 读取历史评估的基线序列（跨次比较用；按文件名时间戳升序）。
/// **只返回 `outcome=ok` 且版本等于当前题集的报告**——空回复/无模式轮没有基线意义，
/// 跨题集版本的数字不可比（见 EVAL_SET_VERSION）。
/// 三类跳过都留痕（ocr PR#65 第三轮评审）：读文件/解析失败与字段缺失 warn（可能
/// 是 serde 字段名漂移或报告损坏，值得人看一眼）；版本不匹配 debug + 汇总一行——
/// 否则「20 份报告全部损坏」与「从未跑过评估」返回同一个空 Vec，调用方无从区分。
pub fn list_past_hit_rates() -> Vec<(String, u32, f64)> {
    let mut out: Vec<(String, u32, f64)> = Vec::new();
    let mut skipped_version = 0u32;
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
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(target: "consolidate_eval", path = %path.display(), error = %e,
                    "P2-2: 基线报告读取失败，已跳过");
                continue;
            }
        };
        let v = match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "consolidate_eval", path = %path.display(), error = %e,
                    "P2-2: 基线报告 JSON 解析失败，已跳过");
                continue;
            }
        };
        if v["outcome"].as_str() != Some("ok") {
            continue;
        }
        let version = v["eval_set_version"].as_u64().unwrap_or(0) as u32;
        if version != EVAL_SET_VERSION {
            skipped_version += 1;
            continue;
        }
        // 字段缺失/不可解析 → **丢弃该记录并 warn**，不得默认 0.0——伪造的 0.0 与
        // 真实最差分不可区分，会毒化 P3 的 keep/discard 基线
        let Some(rate) = v["positive_hit_rate"].as_f64() else {
            tracing::warn!(target: "consolidate_eval", path = %path.display(),
                "P2-2: 基线报告缺 positive_hit_rate 字段（serde 字段名漂移？），已跳过");
            continue;
        };
        let ts = v["ts"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| path.display().to_string());
        out.push((ts, version, rate));
    }
    if skipped_version > 0 {
        tracing::debug!(target: "consolidate_eval", count = skipped_version,
            "P2-2: {} 份基线报告因题集版本不匹配被排除（预期行为：跨版本不可比）", skipped_version);
    }
    out
}
