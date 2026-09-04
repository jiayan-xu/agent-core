//! P2-2：consolidate 固定评估集（《程序化汇合改造方案》§8 P2）。
//!
//! 给 dream/consolidate 循环挂「固定题集 + 单一北极星指标」，让后续 P3 的 prompt
//! 离线进化有可比基线（autoresearch 协议：固定题集、固定预算、单指标、保留或丢弃）。
//!
//! 判分全部程序化，无 LLM 参与判分：
//! - **正例**（应提炼的观察）：被 ≥1 条**过写库门槛**的 pattern 以【依据】引用 → hit；
//! - **负例**（prompt 禁区样本）：**在任何候选行**（含未过写库门槛的）中以引用或
//!   禁区关键词（大小写不敏感）出现 → leak——泄漏检查刻意放在写库门槛之前；
//! - 北极星 = `positive_hit_rate = min(hits,5)/min(positives,5)`（按 pattern 预算
//!   归一）；次级 `keyword_hits` 与 `negative_leaks`（按负例用例去重）。
//!
//! 口径与生产严格一致：prompt 字面量与候选管线共用 agent.rs 的
//! `pattern_extraction_prompt` / `parse_pattern_reply`；**题集用例本身也必须通过
//! 生产原料门槛 `obs_ok_for_consolidate`（默认 ≥70 字）**——否则评估测的是运行
//! 系统从不产生的输入分布（ocr PR#68 high），由 `eval_set_passes_production_gate`
//! 单测锁死。评分逻辑是纯函数 [`score_reply`]，回归不花 LLM 调用（ocr PR#68）。
//!
//! 评估会**真实调用提炼 LLM**：仅 admin 手动触发（/api/admin/consolidate_eval），
//! 不进任何自动循环；报告 tmp+rename 原子落盘（spawn_blocking）
//! `data/consolidate_eval/<毫秒时间戳>.json` 供跨次比较。

use std::time::Instant;

use crate::agent::{AgentCore, PatternReplyKind, PATTERN_BUDGET};

/// 题集版本戳：**任何对 EVAL_SET 的修改（含追加）都必须递增本值**——追加用例同样
/// 更换基线（分母变化使历史 hit_rate 不可比）。报告落盘携带本值，
/// `list_past_hit_rates` 按版本过滤，P3 进化循环不会把跨版本数字当序列比较。
pub const EVAL_SET_VERSION: u32 = 2;

/// 生产原料门槛默认值（CONSOLIDATE_MIN_OBS_CHARS，agent.rs consolidate 读同一 env；
/// 此处只用于题集完整性单测的独立常量，评估不重复过滤——题集构造时即已达标）。
const PRODUCTION_MIN_OBS_CHARS: usize = 70;

/// 评估用例。`expect_pattern=false` 的观察是 prompt 禁区样本（理想行为：不被引用）。
struct EvalCase {
    obs: &'static str,
    expect_pattern: bool,
    /// 正例：命中关键词（次级指标）；负例：禁区指纹（任何候选行命中即 leak）。
    keywords: &'static [&'static str],
}

/// 固定题集（v2）。正例 = 可长期复用的工程/运维/业务规则观察（**均 ≥70 字，通过
/// 生产原料门槛**——v1 的短用例绕过了该门槛，评估分布与生产不符，ocr PR#68 high，
/// 已加长并递增版本戳）；负例 = prompt 禁区四类。修改题集（含追加）= 更换基线：
/// 递增 EVAL_SET_VERSION。
static EVAL_SET: &[EvalCase] = &[
    EvalCase {
        obs: "掺烧工业固废入炉前必须先做热值反推校验并留存计算底稿：热值低于 8000 kJ/kg 的批次要按比例下调掺烧比，同时在台账里登记下调依据与当班审核人，未经校验的批次禁止直接入炉。",
        expect_pattern: true,
        keywords: &["热值", "掺烧"],
    },
    EvalCase {
        obs: "agent-core 与 memoria 的重启必须走看门狗 start_both_tray.ps1 或托盘菜单：直接对进程执行 Stop-Process 会连看门狗一起误杀，memoria 失去自动恢复能力，需要人工到机房恢复服务。",
        expect_pattern: true,
        keywords: &["看门狗", "重启"],
    },
    EvalCase {
        obs: "生产环境的密钥与令牌统一存放在 ~/.svc-secrets 目录并仅授权 user/SYSTEM/Admins 读取：任何项目目录内不允许出现明文 .env 或硬编码密钥，发现即视为安全事故并在当周整改闭环。",
        expect_pattern: true,
        keywords: &["svc-secrets", "密钥"],
    },
    EvalCase {
        obs: "涉及线上数据变更的会议共识在落地前必须走 /api/approval 审批流由第二人确认：admin 与 jarvis 的令牌不得配置同值，审批记录需含操作哈希以防参数被偷换后通过回显校验。",
        expect_pattern: true,
        keywords: &["审批", "令牌"],
    },
    EvalCase {
        obs: "memoria 检索召回质量下降时先做分层排查：确认 FTS5 与 HNSW 混合通道都在命中、HyPE 假设问句索引是否完成启动重建（权威源是 memory_vectors 表、索引损坏会自动软降级）、再查 rerank 是否 fail-open 降级。",
        expect_pattern: true,
        keywords: &["检索", "HNSW"],
    },
    EvalCase {
        obs: "PFAiX 发新版时静默安装参数 /S 执行前必须先结束全部 Jan 相关进程：安装器覆盖文件时持有文件锁会直接失败，且更新清单 latest.json 必须与安装包 sha256/size 同批写入，避免发了版清单没跟上。",
        expect_pattern: true,
        keywords: &["PFAiX", "安装"],
    },
    // ── 负例：prompt 禁区四类（keywords = 禁区指纹，任何候选行命中即 leak）──
    EvalCase {
        obs: "2026-09-04 14:32 例行巡检任务运行完成，本轮共扫描 3 个目录、输出已追加写入 logs/patrol.log 文件末尾，进程退出码为 0，无异常堆栈产生。",
        expect_pattern: false,
        keywords: &["patrol.log", "巡检任务运行完成"],
    },
    EvalCase {
        obs: "这周五下午部门组织团建聚餐，地点定在园区南门外的家常菜馆，人均预算八十元左右，想参加的同事请在周三下班前找行政报名并备注忌口，方便统计人数提前订位。",
        expect_pattern: false,
        keywords: &["团建聚餐", "订位"],
    },
    EvalCase {
        obs: "刚才把新写的冒烟用例完整地跑了一遍，总共十二个断言全部顺利通过且没有任何报错信息，本地环境看起来没有什么明显的问题，下午可以继续安排前后端联调和接口自测的工作。",
        expect_pattern: false,
        keywords: &["冒烟"],
    },
    EvalCase {
        obs: "cd /c/Users/user/agent-core 这条目录下面的仓库可以用 cargo check --all-targets 命令做快速编译检查，跑完大概需要二十秒左右的时间，输出末尾出现 Finished 字样就说明当前代码没有编译错误可以提交。",
        expect_pattern: false,
        keywords: &["cargo check"],
    },
];

/// 单条候选 pattern 的可调试记录（报告落盘，跨次比较时能区分覆盖回归与格式回归）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PatternFinding {
    pub text: String,
    pub cites: Vec<usize>,
    pub passed_gate: bool,
}

/// 每个用例的判定结果（报告落盘：哪个正例没命中、哪个负例泄漏一目了然）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaseResult {
    pub index: usize,
    pub expect_pattern: bool,
    pub cited: bool,
    pub keyword_hit: bool,
    pub leaked: bool,
}

/// 评估报告（JSON 序列化后原子落盘，供跨次比较）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvalReport {
    pub ns: String,
    pub eval_set_version: u32,
    /// 6000 字窗口内实际可见的观察数（< 题集大小时尾部用例从未展示给模型——
    /// hit_rate 会被结构性压低，报告必须可辨别这一状态）
    pub observations_visible: usize,
    pub cases_positive: usize,
    pub cases_negative: usize,
    /// ok：有有效 pattern，hit_rate 可比；no_patterns：模型明说无模式；
    /// gate_rejected：有候选但全部未过写库门槛；empty_reply：模型空响应
    pub outcome: String,
    /// 过写库门槛（pattern_ok_for_consolidate）的 pattern 数（与生产一致：先 take(8) 后 take(5)）
    pub patterns_valid: usize,
    /// 被有效 pattern 引用的正例数
    pub positive_hits: usize,
    /// **北极星指标**：`min(hits, 5) / min(positives, 5)`——生产 prompt 与写库都
    /// 限额 5 条 pattern，按正例总数归一时 6 正例的可达上限是 5/6≈0.83，顶部
    /// 变化会把「覆盖质量」与「多例合并行为」混在一起（ocr PR#65 第五轮）。
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

/// 纯评分函数（ocr PR#68：评分与 LLM 调用解耦，回归测试不花真实调用）。
/// `included` = pattern_extraction_prompt 返回的可见观察数（引用上界）。
fn score_reply(reply: &str, included: usize, ns: &str, duration_ms: u64, ts: String) -> EvalReport {
    let positives = EVAL_SET.iter().filter(|c| c.expect_pattern).count();
    let negatives = EVAL_SET.len() - positives;
    let parsed = AgentCore::parse_pattern_reply(reply, included);
    let findings: Vec<PatternFinding> = parsed
        .lines
        .iter()
        .map(|c| PatternFinding {
            text: c.text.clone(),
            cites: c.cites.clone(),
            passed_gate: c.passed_gate,
        })
        .collect();
    let valid: Vec<&PatternFinding> = findings.iter().filter(|f| f.passed_gate).take(5).collect();
    // 泄漏扫描覆盖**全部候选行**（门槛前）——写库门槛本身会拦部分禁区词，
    // 只查过门槛行会让最典型的回归形式永远计 0
    let leak_scan_lines: Vec<&PatternFinding> = findings.iter().collect();

    // 程序判分（零语义自由裁量）；关键词匹配大小写不敏感（对齐生产门槛 lower.contains）
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
            keyword_hit: c.expect_pattern
                && valid.iter().any(|f| c.keywords.iter().any(|k| contains_ci(&f.text, k))),
            leaked: !c.expect_pattern && leaked[i],
        })
        .collect();
    let positive_hits = case_results.iter().filter(|r| r.cited).count();
    let keyword_hits = case_results.iter().filter(|r| r.keyword_hit).count();
    let negative_leaks = case_results.iter().filter(|r| r.leaked).count();
    let patterns_missing_citations = valid.iter().filter(|f| f.cites.is_empty()).count();
    let outcome = match parsed.kind {
        PatternReplyKind::Empty => "empty_reply",
        PatternReplyKind::NoPatterns => "no_patterns",
        PatternReplyKind::Valid if valid.is_empty() => "gate_rejected",
        PatternReplyKind::Valid => "ok",
    }
    .to_string();
    let denom = positives.min(PATTERN_BUDGET);
    EvalReport {
        ns: ns.to_string(),
        eval_set_version: EVAL_SET_VERSION,
        observations_visible: included,
        cases_positive: positives,
        cases_negative: negatives,
        outcome,
        patterns_valid: valid.len(),
        positive_hits,
        positive_hit_rate: if denom > 0 {
            positive_hits.min(PATTERN_BUDGET) as f64 / denom as f64
        } else {
            0.0
        },
        keyword_hits,
        negative_leaks,
        patterns_missing_citations,
        duration_ms,
        patterns: findings,
        case_results,
        ts,
    }
}

/// 跑一轮固定评估：真实调用提炼 LLM（与生产 consolidate 同款 prompt），程序判分。
/// 消耗一次 LLM 调用——仅限 admin 手动触发。
pub async fn run_consolidate_eval(agent: &AgentCore, ns: &str) -> Result<EvalReport, String> {
    let started = Instant::now();
    let positives = EVAL_SET.iter().filter(|c| c.expect_pattern).count();
    let negatives = EVAL_SET.len() - positives;

    // 与生产相同的 prompt（共享字面量）+ 编号观察。scope 用**中性表述**（只报条数与
    // 命名空间）——「正例 6/负例 4」会向被测模型泄露评估结构，使其比生产更保守
    // （ocr PR#65 第四轮）。
    let obs_lines: Vec<String> = EVAL_SET.iter().map(|c| c.obs.to_string()).collect();
    let (prompt, included) = AgentCore::pattern_extraction_prompt(
        &format!("候选观察 {} 条，命名空间 {}", EVAL_SET.len(), ns),
        &obs_lines,
    );
    if included < EVAL_SET.len() {
        tracing::warn!(target: "consolidate_eval",
            visible = included, total = EVAL_SET.len(),
            "P2-2: 评估题集超出 6000 字窗口，尾部用例从未展示给模型——hit_rate 被结构性压低，需精简用例或拆批");
    }
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
    let report = score_reply(&reply, included, ns, started.elapsed().as_millis() as u64, ts);

    // 原子落盘 data/consolidate_eval/<毫秒时间戳>.json：tmp + rename（对齐仓库
    // write_meetings_file / experience_memo 约定）。整块 fs I/O 在 spawn_blocking
    // （ocr PR#65 第四轮）：本函数在 axum handler 响应路径上被 await，同步 fs 在被
    // AV 扫描的 Windows 目录上会阻塞 tokio worker。
    // 序列化失败也 warn（ocr PR#68 第二轮：f64 NaN/Infinity 会被 serde_json 拒绝，
    // 静默跳过会让「评估完成」日志与磁盘上无报告并存）；成功日志**以实际落盘
    // 结果为准**，不再无条件宣称已落盘。
    let mut persisted = false;
    match serde_json::to_string_pretty(&report) {
        Ok(report_json) => {
            let dir = std::path::PathBuf::from("data/consolidate_eval");
            let file_ts = chrono::Local::now().format("%Y%m%dT%H%M%S%3f").to_string();
            let res = tokio::task::spawn_blocking(move || {
                std::fs::create_dir_all(&dir)?;
                let final_path = dir.join(format!("{}.json", file_ts));
                let tmp_path = dir.join(format!("{}.json.tmp", file_ts));
                std::fs::write(&tmp_path, &report_json)
                    .and_then(|_| std::fs::rename(&tmp_path, &final_path))
            })
            .await;
            match res {
                Ok(Ok(())) => persisted = true,
                Ok(Err(e)) => tracing::warn!(target: "consolidate_eval", error = %e, "P2-2: 评估报告落盘失败"),
                Err(e) => tracing::warn!(target: "consolidate_eval", error = %e, "P2-2: 评估报告落盘任务失败"),
            }
        }
        Err(e) => tracing::warn!(target: "consolidate_eval", error = %e, "P2-2: 评估报告序列化失败（NaN/Infinity？），未落盘"),
    }
    tracing::info!(
        target: "consolidate_eval",
        ns = %report.ns,
        outcome = %report.outcome,
        hit_rate = format!("{:.2}", report.positive_hit_rate),
        leaks = report.negative_leaks,
        valid = report.patterns_valid,
        persisted,
        "P2-2: 固定评估完成"
    );
    let _ = (positives, negatives); // 仅日志用途的统计在报告里已有
    Ok(report)
}

/// 读取历史评估的基线序列（跨次比较用；按时间升序）。
/// **只返回 `outcome=ok` 且版本等于当前题集的报告**；元组携带 `ns`（P3 消费方按
/// ns 分组后再比较，防 agent_id 变更/多实例混序列）。
/// 异步封装（ocr PR#68）：内部 fs 全在 spawn_blocking，async 调用方直用即可。
pub async fn list_past_hit_rates() -> Vec<(String, u32, String, f64)> {
    let dir = std::path::PathBuf::from("data/consolidate_eval");
    match tokio::task::spawn_blocking(move || list_past_hit_rates_blocking(&dir)).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target: "consolidate_eval", error = %e, "P2-2: 基线读取任务失败");
            Vec::new()
        }
    }
}

/// [`list_past_hit_rates`] 的同步实现（测试可直接调用临时目录）。
/// 读文件/解析失败与字段缺失 warn；版本/结果不匹配计数后 debug 汇总——
/// 否则「20 份报告全部损坏」与「从未跑过评估」返回同一个空 Vec，调用方无从区分。
/// **read_dir 失败区分 ErrorKind**：NotFound = 合法空（从未评估）；其他错误
/// （权限/句柄耗尽/CWD 漂移）warn 留痕而非静默当空（ocr PR#68）。
fn list_past_hit_rates_blocking(dir: &std::path::Path) -> Vec<(String, u32, String, f64)> {
    /// 只收最近 N 份**有效**基线（倒序早停）；全部被跳过时会扫完全部历史——
    /// 这是刻意的：连续 gate_rejected 正是要暴露的回归形态，不能提前停
    const READ_LIMIT: usize = 50;
    let mut out: Vec<(String, u32, String, f64)> = Vec::new();
    let mut skipped_version = 0u32;
    let mut skipped_outcome = 0u32;
    let mut skipped_window = 0u32;
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out, // 从未评估：合法空
        Err(e) => {
            tracing::warn!(target: "consolidate_eval", dir = %dir.display(), error = %e,
                "P2-2: 基线目录读取失败（权限/句柄/CWD 漂移？），按空基线处理");
            return out;
        }
    };
    let mut names: Vec<_> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    names.sort();
    for path in names.into_iter().rev() {
        if out.len() >= READ_LIMIT {
            break;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(target: "consolidate_eval", path = %path.display(), error = %e,
                    "P2-2: 基线报告读取失败，已跳过");
                continue;
            }
        };
        // typed 解析（ocr PR#68 第二轮）：读写共用 EvalReport schema——字符串键
        // 索引复制一份字段名，serde 改名时读侧静默错位；typed 缺字段即解析失败，
        // 漂移可观测
        let rep = match serde_json::from_str::<EvalReport>(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "consolidate_eval", path = %path.display(), error = %e,
                    "P2-2: 基线报告解析失败（schema 漂移或损坏），已跳过");
                continue;
            }
        };
        if rep.outcome != "ok" {
            skipped_outcome += 1;
            continue;
        }
        if rep.eval_set_version != EVAL_SET_VERSION {
            skipped_version += 1;
            continue;
        }
        // 窗口截断轮剔除（ocr PR#68 第二轮）：题集超窗时尾部用例从未展示，
        // 该轮 hit_rate 被结构性压低，与完整轮不可比
        if rep.observations_visible < EVAL_SET.len() {
            skipped_window += 1;
            continue;
        }
        let rate = rep.positive_hit_rate;
        let ts = rep.ts;
        out.push((ts, rep.eval_set_version, rep.ns, rate));
    }
    if skipped_version > 0 || skipped_outcome > 0 || skipped_window > 0 {
        tracing::debug!(target: "consolidate_eval",
            version_skipped = skipped_version, outcome_skipped = skipped_outcome,
            window_skipped = skipped_window,
            "P2-2: 基线读取跳过统计；outcome_skipped 持续增长需排查 prompt 回归");
    }
    out.reverse(); // 升序返回
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 题集完整性（ocr PR#68 high）：每个用例必须通过生产原料门槛（默认 ≥70 字，
    /// 且不被 obs_ok 的测试/助理前缀规则拦截）——否则评估测的是生产从不产生的
    /// 输入分布，历史基线对 P3 不可迁移。
    #[test]
    fn eval_set_passes_production_gate() {
        for (i, c) in EVAL_SET.iter().enumerate() {
            assert!(
                AgentCore::obs_ok_for_consolidate(c.obs, PRODUCTION_MIN_OBS_CHARS),
                "用例 {} 未过生产原料门槛（≥{} 字）：{}",
                i + 1,
                PRODUCTION_MIN_OBS_CHARS,
                &c.obs[..30.min(c.obs.len())]
            );
        }
    }

    /// 题集必须完整落进 6000 字窗口（尾部用例不可见会结构性压低指标）
    #[test]
    fn eval_set_fits_prompt_window() {
        let obs: Vec<String> = EVAL_SET.iter().map(|c| c.obs.to_string()).collect();
        let (_, included) = AgentCore::pattern_extraction_prompt("test", &obs);
        assert_eq!(included, EVAL_SET.len());
    }

    fn score(reply: &str) -> EvalReport {
        score_reply(reply, EVAL_SET.len(), "agent/test", 0, "t".into())
    }

    /// 引用→命中映射：正例被引用计 hit；窗口外序号被管线丢弃不计伪命中
    #[test]
    fn citation_to_hit_mapping() {
        let r = score("规则甲条文内容足够长可以过门槛的【依据: 1,3】\n规则乙条文内容同样足够长过门槛【依据: 99】");
        assert_eq!(r.outcome, "ok");
        assert!(r.case_results[0].cited, "正例 1 应命中");
        assert!(r.case_results[2].cited, "正例 3 应命中");
        assert!(!r.case_results.iter().any(|c| c.index == 99), "窗口外序号不产生用例");
    }

    /// 泄漏：引用负例或禁区关键词（含改大小写）都计 leak，且按用例去重
    #[test]
    fn leak_detection_ci_and_citation() {
        let r = score("团建聚餐相关的规则不该出现在这里【依据: 8】\nPATROL.LOG 巡检流水也不该在【依据: 1】");
        // 第二行引用正例 1 但文本命中禁区指纹 → 正例命中 + 负例泄漏并存
        assert!(r.case_results[0].cited);
        assert_eq!(r.negative_leaks, 2, "负例 8（引用）与负例 7（关键词，大小写不敏感）都泄漏");
    }

    /// outcome 三态：无模式 / 门槛拒绝 / 空
    #[test]
    fn outcome_classification() {
        assert_eq!(score("").outcome, "empty_reply");
        assert_eq!(score("无模式").outcome, "no_patterns");
        assert_eq!(score("太短").outcome, "gate_rejected");
    }

    /// 北极星按预算归一：6 正例、5 条各覆盖一个不同正例 → 1.0（不含并水分）
    #[test]
    fn hit_rate_budget_normalized() {
        let lines: Vec<String> = (1..=5)
            .map(|n| format!("第{n}条规则的内容写得足够具体足够长可以稳定通过写库门槛【依据: {n}】"))
            .collect();
        let r = score(&lines.join("\n"));
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.positive_hits, 5);
        assert!((r.positive_hit_rate - 1.0).abs() < 1e-9);
    }

    /// 基线读取：NotFound=空、版本过滤、损坏告警跳过、ns 透传（临时目录）
    #[test]
    fn baseline_reader_filters() {
        let tmp = std::env::temp_dir().join(format!("consolidate_eval_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // 不存在 → 合法空
        assert!(list_past_hit_rates_blocking(&tmp).is_empty());
        std::fs::create_dir_all(&tmp).unwrap();
        let ok = serde_json::json!({
            "ns":"agent/a","eval_set_version":EVAL_SET_VERSION,"observations_visible":EVAL_SET.len(),
            "cases_positive":6,"cases_negative":4,"outcome":"ok","patterns_valid":5,
            "positive_hits":4,"positive_hit_rate":0.8,"keyword_hits":5,"negative_leaks":0,
            "patterns_missing_citations":0,"duration_ms":1,"patterns":[],"case_results":[],"ts":"t1"});
        let old_ver = serde_json::json!({
            "ns":"agent/a","eval_set_version":1,"observations_visible":EVAL_SET.len(),
            "cases_positive":6,"cases_negative":4,"outcome":"ok","patterns_valid":5,
            "positive_hits":5,"positive_hit_rate":0.9,"keyword_hits":6,"negative_leaks":0,
            "patterns_missing_citations":0,"duration_ms":1,"patterns":[],"case_results":[],"ts":"t0"});
        std::fs::write(tmp.join("a.json"), ok.to_string()).unwrap();
        std::fs::write(tmp.join("b.json"), old_ver.to_string()).unwrap();
        std::fs::write(tmp.join("c.json"), "{broken").unwrap();
        let v = list_past_hit_rates_blocking(&tmp);
        assert_eq!(v.len(), 1, "只收当前版本且损坏跳过");
        assert_eq!(v[0].2, "agent/a");
        assert!((v[0].3 - 0.8).abs() < 1e-9);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
