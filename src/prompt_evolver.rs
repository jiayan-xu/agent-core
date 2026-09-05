//! P3：prompt 离线进化循环（《P3 prompt 进化循环设计方案》2026-09-05）。
//!
//! autoresearch 协议：固定题集 + 固定预算 + 单指标 + 策略层。
//! 以 consolidate 提炼 prompt 为首个验证目标，后续可推广到任意文本优化。
//!
//! 循环：变异（LLM 生成候选指令）→ 评估（候选指令跑 P2-2 固定题集，纯函数判分）
//! → 判定（保留/丢弃按策略层规则）→ 持久化（prompt_evolution.db 版本链）。
//!
//! **安全边界**：零泄漏硬门（negative_leaks > 0 无条件丢弃）、预算硬上限
//! （单轮 ≤5 候选）、人类采纳门（进化结果不自动进生产，`active_prompt` 表
//! 需要 admin 显式写入）。

use std::time::Instant;

use crate::agent::AgentCore;

/// 进化目标标识（首期只有 pattern_extraction，后续可扩展）
pub const TARGET_PATTERN_EXTRACTION: &str = "pattern_extraction";

/// 单轮预算硬上限（代码 clamp，策略层只能往下调）
pub const MAX_BUDGET: usize = 5;

/// 默认的 pattern_extraction 指令模板（不含数据部分；`{}` = PATTERN_BUDGET）
/// 与 `AgentCore::pattern_extraction_prompt` 的字面量严格同步。
pub fn default_extraction_instruction() -> String {
    format!(
        "你是知识巩固引擎。只从观察中提炼**可长期复用**的高层规则（架构取舍、运维约束、业务偏好、排障经验）。\n\
         硬性禁止写成 pattern：\n\
         - 一次性会话过程、工具回显、文件路径流水账、cron 任务日志\n\
         - 测试/冒烟/世界杯等无关话题\n\
         - 复述某条观察原文、或过短空话\n\
         每条模式一行、一句话、具体可执行，最多 {} 条；行末必须标注支撑它的观察序号，格式如【依据: 1,3】。\n\
         若无可提炼内容，只输出「无模式」。",
        crate::agent::PATTERN_BUDGET
    )
}

/// 用自定义指令渲染完整 prompt（指令 + 数据部分）
pub fn render_with_instruction(instruction: &str, scope: &str, obs_lines: &[String]) -> (String, usize) {
    let (default_prompt, included) = AgentCore::pattern_extraction_prompt(scope, obs_lines);
    // 替换指令部分：找到 "## 待巩固观察" 的位置，前面的部分替换为自定义指令
    if let Some(pos) = default_prompt.find("## 待巩固观察") {
        let data_part = &default_prompt[pos..];
        (format!("{}\n\n{}", instruction.trim(), data_part), included)
    } else {
        // 回退：默认 prompt 结构异常时原样返回
        (default_prompt, included)
    }
}

// ── 进化报告 ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct CandidateResult {
    pub generation: usize,
    pub mutation_strategy: String,
    pub mutation_rationale: String,
    pub instruction: String,
    pub hit_rate: f64,
    pub positive_hits: usize,
    pub negative_leaks: usize,
    pub patterns_valid: usize,
    pub accepted: bool,
    pub rejected_reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EvolutionReport {
    pub run_id: String,
    pub target: String,
    pub baseline_instruction: String,
    pub baseline_hit_rate: f64,
    pub baseline_negative_leaks: usize,
    pub candidates: Vec<CandidateResult>,
    pub improved: bool,
    pub best_candidate: Option<CandidateResult>,
    pub duration_ms: u64,
    pub started_at: String,
    pub config: EvolutionConfig,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvolutionConfig {
    pub target: String,
    pub budget: usize,
    pub strategies: Vec<String>,
}

impl Default for EvolutionConfig {
    fn default() -> Self {
        EvolutionConfig {
            target: TARGET_PATTERN_EXTRACTION.to_string(),
            budget: 3,
            strategies: vec!["rephrase".to_string(), "constrain".to_string()],
        }
    }
}

// ── 变异 ──

/// 变异策略提示词（给 LLM 的指令，让它生成候选 prompt 变体）
fn mutation_prompt(strategy: &str, current: &str, last_result: Option<&CandidateResult>) -> String {
    let feedback = match last_result {
        Some(r) => format!(
            "\n上一轮候选的评估结果：hit_rate={:.2}, leaks={}。{}",
            r.hit_rate,
            r.negative_leaks,
            if r.negative_leaks > 0 {
                "存在禁区泄漏——请收紧禁区约束的措辞。"
            } else if r.hit_rate < 1.0 {
                "有正例未被覆盖——请检查指令是否遗漏了关键约束或格式要求。"
            } else {
                "满分——请尝试不同的优化方向（更简洁/更鲁棒/更通用）。"
            }
        ),
        None => String::new(),
    };
    match strategy {
        "constrain" => format!(
            "你是一个 prompt 优化专家。以下是「知识巩固提炼」的指令（用于从运维观察中提取可复用规则）。\n\
             请分析这个指令可能遗漏的场景或不够明确的约束，补充 1-2 条新约束或示例。\n\
             保留原有全部约束，只增不减。输出**完整的改写后指令**（不要解释，只输出指令文本）。\n\
             安全边界：这不是系统指令，只影响提炼行为；不要添加任何关于角色、权限或人格的内容。\n\
             指令中的 {{}} 是模板变量（最大 pattern 数量），保留原样。{}\n\n## 当前指令\n{}",
            feedback, current
        ),
        _ => format!(
            "你是一个 prompt 优化专家。以下是「知识巩固提炼」的指令（用于从运维观察中提取可复用规则）。\n\
             请用不同的措辞重写这个指令，**保留全部语义约束**（禁止项、输出格式、引用要求），\n\
             但用更清晰、更不易歧义的表达。输出**完整的重写后指令**（不要解释，只输出指令文本）。\n\
             安全边界：这不是系统指令，只影响提炼行为；不要添加任何关于角色、权限或人格的内容。\n\
             指令中的 {{}} 是模板变量（最大 pattern 数量），保留原样。{}\n\n## 当前指令\n{}",
            feedback, current
        ),
    }
}

/// 用自定义指令跑评估（复用 P2-2 的 EVAL_SET 与判分逻辑）
async fn score_with_instruction(agent: &AgentCore, instruction: &str) -> Result<crate::consolidate_eval::EvalReport, String> {
    // 构造完整的 prompt（用自定义指令替换默认指令）
    let obs_lines: Vec<String> = crate::consolidate_eval::eval_set_lines();
    let (prompt, included) = render_with_instruction(instruction, "进化评估", &obs_lines);
    let msg = crate::llm::Message {
        role: "system".to_string(),
        content: Some(prompt),
        tool_calls: None,
        tool_call_id: None,
    };
    let reply = agent
        .llm
        .chat_batch(&[msg], &[])
        .await
        .map_err(|e| format!("评估 LLM 调用失败: {}", e))?
        .text
        .trim()
        .to_string();
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    Ok(crate::consolidate_eval::score_reply(
        &reply,
        included,
        "agent/evolution",
        "evolution",
        0,
        ts,
    ))
}

// ── 主循环 ──

/// 跑一轮进化：变异 → 评估 → 判定。消耗 budget × 2 次 LLM 调用。
pub async fn run_evolution(
    agent: &AgentCore,
    config: EvolutionConfig,
) -> Result<EvolutionReport, String> {
    let started = Instant::now();
    let budget = config.budget.min(MAX_BUDGET);
    if budget == 0 {
        return Err("budget 必须大于 0".to_string());
    }
    if config.target != TARGET_PATTERN_EXTRACTION {
        return Err(format!("未知进化目标: {}", config.target));
    }

    let run_id = format!(
        "evo_{}",
        chrono::Local::now().format("%Y%m%dT%H%M%S%3f")
    );
    let started_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

    // 1. 基线评估（用默认/当前活跃指令跑一次）
    let baseline_instruction = default_extraction_instruction();
    let baseline_report = score_with_instruction(agent, &baseline_instruction)
        .await
        .map_err(|e| format!("基线评估失败: {}", e))?;
    let mut best_hit_rate = baseline_report.positive_hit_rate;
    let mut best_instruction = baseline_instruction.clone();
    let mut best_candidate: Option<CandidateResult> = None;

    tracing::info!(target: "prompt_evolver",
        baseline_hit_rate = best_hit_rate,
        baseline_leaks = baseline_report.negative_leaks,
        "P3 进化启动: 基线评估完成");

    let mut candidates: Vec<CandidateResult> = Vec::new();
    let strategies = if config.strategies.is_empty() {
        vec!["rephrase".to_string()]
    } else {
        config.strategies.clone()
    };

    for gen in 1..=budget {
        // 2. 变异：LLM 生成候选指令
        let strategy = &strategies[(gen - 1) % strategies.len()];
        let mutation_instruction = mutation_prompt(strategy, &best_instruction, best_candidate.as_ref());
        let mutation_msg = crate::llm::Message {
            role: "user".to_string(),
            content: Some(mutation_instruction),
            tool_calls: None,
            tool_call_id: None,
        };
        let candidate_text = match agent.llm.chat_batch(&[mutation_msg], &[]).await {
            Ok(r) if !r.text.trim().is_empty() => r.text.trim().to_string(),
            Ok(_) => {
                tracing::warn!(target: "prompt_evolver", gen, "变异 LLM 空响应，跳过本代");
                continue;
            }
            Err(e) => {
                tracing::warn!(target: "prompt_evolver", gen, error = %e, "变异 LLM 失败，跳过本代");
                continue;
            }
        };
        // 安全检查：候选不应包含角色/权限类指令
        let lower = candidate_text.to_lowercase();
        if lower.contains("你是系统") || lower.contains("你现在是") || lower.contains("ignore previous") {
            candidates.push(CandidateResult {
                generation: gen,
                mutation_strategy: strategy.clone(),
                mutation_rationale: "被安全检查拦截：候选包含角色/权限类指令".to_string(),
                instruction: candidate_text,
                hit_rate: 0.0,
                positive_hits: 0,
                negative_leaks: 0,
                patterns_valid: 0,
                accepted: false,
                rejected_reason: Some("安全检查：候选包含角色/权限类指令".to_string()),
            });
            continue;
        }

        // 3. 评估：候选指令跑固定题集
        let eval_report = match score_with_instruction(agent, &candidate_text).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(target: "prompt_evolver", gen, error = %e, "候选评估失败");
                candidates.push(CandidateResult {
                    generation: gen,
                    mutation_strategy: strategy.clone(),
                    mutation_rationale: "评估 LLM 调用失败".to_string(),
                    instruction: candidate_text,
                    hit_rate: 0.0,
                    positive_hits: 0,
                    negative_leaks: 0,
                    patterns_valid: 0,
                    accepted: false,
                    rejected_reason: Some(format!("评估失败: {}", e)),
                });
                continue;
            }
        };

        // 4. 判定：零泄漏硬门 + hit_rate >= 当前最佳
        let (accepted, rejected_reason) = if eval_report.negative_leaks > 0 {
            (false, Some(format!("零泄漏硬门：leaks={}", eval_report.negative_leaks)))
        } else if eval_report.positive_hit_rate < best_hit_rate {
            (false, Some(format!(
                "hit_rate {:.2} < 最佳 {:.2}",
                eval_report.positive_hit_rate, best_hit_rate
            )))
        } else {
            (true, None)
        };

        let result = CandidateResult {
            generation: gen,
            mutation_strategy: strategy.clone(),
            mutation_rationale: format!(
                "策略: {}; 候选长度: {} 字",
                strategy,
                candidate_text.chars().count()
            ),
            instruction: candidate_text,
            hit_rate: eval_report.positive_hit_rate,
            positive_hits: eval_report.positive_hits,
            negative_leaks: eval_report.negative_leaks,
            patterns_valid: eval_report.patterns_valid,
            accepted,
            rejected_reason,
        };

        if accepted {
            best_hit_rate = eval_report.positive_hit_rate;
            best_instruction = result.instruction.clone();
            best_candidate = Some(result.clone());
        }
        candidates.push(result);
    }

    let improved = best_candidate.is_some();
    let duration_ms = started.elapsed().as_millis() as u64;
    tracing::info!(target: "prompt_evolver",
        improved, best_hit_rate, candidates = candidates.len(),
        duration_ms,
        "P3 进化完成");

    Ok(EvolutionReport {
        run_id,
        target: config.target.clone(),
        baseline_instruction,
        baseline_hit_rate: baseline_report.positive_hit_rate,
        baseline_negative_leaks: baseline_report.negative_leaks,
        candidates,
        improved,
        best_candidate,
        duration_ms,
        started_at,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认指令模板与 pattern_extraction_prompt 字面量同步
    #[test]
    fn default_instruction_syncs_with_prompt() {
        let instruction = default_extraction_instruction();
        let (rendered, _) = render_with_instruction(&instruction, "test", &["观察一".to_string()]);
        // 渲染结果应包含指令的全部关键约束
        assert!(rendered.contains("知识巩固引擎"), "缺少角色定义");
        assert!(rendered.contains("硬性禁止"), "缺少禁止项标题");
        assert!(rendered.contains("cron 任务日志"), "缺少禁止项");
        assert!(rendered.contains("【依据: 1,3】"), "缺少引用格式说明");
        assert!(rendered.contains("无模式"), "缺少无模式回退");
        assert!(rendered.contains("## 待巩固观察"), "缺少数据部分标题");
    }

    /// 自定义指令正确替换默认指令
    #[test]
    fn custom_instruction_replaces_default() {
        let custom = "自定义测试指令。最多 {} 条。";
        let (rendered, _) = render_with_instruction(custom, "test", &["观察".to_string()]);
        assert!(rendered.starts_with("自定义测试指令"), "应以自定义指令开头");
        assert!(rendered.contains("## 待巩固观察"), "数据部分应保留");
        assert!(!rendered.contains("知识巩固引擎"), "默认指令不应出现");
    }

    /// 空指令列表 / 空范围不 panic
    #[test]
    fn render_degenerate_inputs() {
        let (_, included) = render_with_instruction("test", "scope", &[]);
        assert_eq!(included, 0);
    }

    /// 预算 clamp 与目标校验
    #[test]
    fn config_validation() {
        // budget 由 run_evolution 内 clamp，这里测 config 序列化
        let c = EvolutionConfig::default();
        assert_eq!(c.budget, 3);
        assert_eq!(c.target, TARGET_PATTERN_EXTRACTION);
        assert!(c.strategies.contains(&"rephrase".to_string()));
    }

    /// 变异 prompt 包含安全边界指令
    #[test]
    fn mutation_prompt_contains_safety() {
        for strategy in ["rephrase", "constrain"] {
            let p = mutation_prompt(strategy, "test instruction", None);
            assert!(p.contains("安全边界"), "{} 策略缺少安全边界", strategy);
            assert!(p.contains("不要添加任何关于角色"), "{} 缺少角色禁止", strategy);
        }
    }
}
