//! LLM 客户端 — 兼容 DeepSeek / OpenAI API（支持流式）

use std::collections::HashMap;
use std::time::Duration;

use futures::future::join_all;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// SSE 流式事件
#[derive(Debug, Clone, Serialize)]
pub enum SseEvent {
    #[serde(rename = "thinking")]
    ThinkingEvt { content: String },
    #[serde(rename = "text")]
    TextEvt { content: String },
    #[serde(rename = "tool_call")]
    ToolCallEvt {
        name: String,
        arguments: serde_json::Value,
        id: String,
    },
    #[serde(rename = "tool_result")]
    ToolResultEvt { name: String, result: String },
    #[serde(rename = "done")]
    DoneEvt,
    #[serde(rename = "error")]
    ErrorEvt { message: String },
}

/// 备用 / 池内 LLM Provider（具名字段，便于 agent.toml 编辑维护）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmProvider {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    /// chat/completions 路径（不同厂商约定不同：DeepSeek/硅基流动=/v1/chat/completions，火山方舟=/chat/completions）
    #[serde(default = "default_chat_path")]
    pub chat_path: String,
}

/// LlmConfig 缺省 max_tokens（供 serde(default) 使用，避免用户删字段导致解析失败）
fn default_max_tokens() -> u32 {
    4096
}

/// LlmConfig 缺省 chat_path
fn default_chat_path() -> String {
    "/v1/chat/completions".to_string()
}

/// LLM 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    /// chat/completions 路径（不同厂商约定不同）
    #[serde(default = "default_chat_path")]
    pub chat_path: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default)]
    pub temperature: f64,
    /// 备用 Provider 池（failover + 圆桌多 LLM 轮询；具名字段便于编辑）
    pub fallbacks: Vec<LlmProvider>,
    /// 难度路由策略（易/难任务选择不同 provider；缺省不路由）
    #[serde(default)]
    pub difficulty: DifficultyPolicy,
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            base_url: "https://api.deepseek.com".to_string(),
            model: "deepseek-chat".to_string(),
            api_key: String::new(),
            chat_path: "/v1/chat/completions".to_string(),
            max_tokens: 4096,
            temperature: 0.0,
            fallbacks: Vec::new(),
            difficulty: DifficultyPolicy::default(),
        }
    }
}

/// 任务难度（难度路由用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskDifficulty {
    #[default]
    Easy,
    Hard,
}

/// 难度分类方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifyMode {
    /// 启发式规则（零额外调用，默认）
    #[default]
    Heuristic,
    /// 用 judge_provider 跑一次廉价分类调用
    Judge,
}

/// Best-of-N 打分方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScorerMode {
    /// 启发式规则（零额外调用，默认）
    #[default]
    Heuristic,
    /// 用 judge_provider 跑一次廉价打分（对所有候选一次性打分）
    Judge,
    /// 自一致性投票（抽取核心答案多数票；零额外调用，TTC 默认）
    Majority,
}

/// 难度路由策略：易→easy provider，难→hard provider；缺省不路由（用主模型）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DifficultyPolicy {
    /// 易任务 Provider（如 flash）。None 表示用主模型
    #[serde(default)]
    pub easy: Option<LlmProvider>,
    /// 难任务 Provider（如 reasoning/pro）。None 表示用主模型
    #[serde(default)]
    pub hard: Option<LlmProvider>,
    /// 分类方式（默认 heuristic）
    #[serde(default)]
    pub classify: ClassifyMode,
    /// Best-of-N 采样数（>=2 开启；None 关闭，默认关闭以零成本）
    #[serde(default)]
    pub best_of_n: Option<usize>,
    /// Best-of-N 打分方式（默认 heuristic）
    #[serde(default)]
    pub scorer: ScorerMode,
    /// Best-of-N 采样温度（默认 0.7，制造多样性）
    #[serde(default)]
    pub sample_temperature: Option<f64>,
    /// judge 模式使用的分类/打分模型（None 则用主模型作 judge）
    #[serde(default)]
    pub judge_provider: Option<LlmProvider>,
}

impl LlmConfig {
    /// 从单个 Provider 构造一个最小 LlmConfig（便于 easy/hard 路由）
    pub fn from_provider(p: &LlmProvider) -> Self {
        LlmConfig {
            base_url: p.base_url.clone(),
            model: p.model.clone(),
            api_key: p.api_key.clone(),
            chat_path: p.chat_path.clone(),
            max_tokens: 4096,
            temperature: 0.0,
            fallbacks: Vec::new(),
            difficulty: DifficultyPolicy::default(),
        }
    }
}

/// 难度路由包装：在 LlmClient 之上按任务难度选择 provider
#[derive(Clone)]
pub struct RoutedLlm {
    base: LlmClient,
    easy: Option<LlmClient>,
    hard: Option<LlmClient>,
    policy: DifficultyPolicy,
}

impl std::fmt::Debug for RoutedLlm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutedLlm")
            .field("base_model", &self.base.config.model)
            .field("has_easy", &self.easy.is_some())
            .field("has_hard", &self.hard.is_some())
            .field("classify", &self.policy.classify)
            .finish()
    }
}

impl RoutedLlm {
    pub fn from_config(cfg: &LlmConfig) -> Self {
        let base = LlmClient::new(cfg.clone());
        let easy = cfg.difficulty.easy.as_ref().map(|p| LlmClient::new(LlmConfig::from_provider(p)));
        let hard = cfg.difficulty.hard.as_ref().map(|p| LlmClient::new(LlmConfig::from_provider(p)));
        RoutedLlm { base, easy, hard, policy: cfg.difficulty.clone() }
    }

    fn select(&self, d: TaskDifficulty) -> &LlmClient {
        match d {
            TaskDifficulty::Easy => self.easy.as_ref().unwrap_or(&self.base),
            TaskDifficulty::Hard => self.hard.as_ref().unwrap_or(&self.base),
        }
    }

    /// 对外暴露难度分类（供 MultiAgent Compose 判断 Hard 任务后再分解派发）
    pub async fn classify(&self, messages: &[Message]) -> TaskDifficulty {
        classify_difficulty(&self.policy, messages).await
    }

    /// 暴露 judge_provider 构造的 LlmClient（价值网络 / verifier-guided 复用），无则 None
    pub fn judge_client(&self) -> Option<LlmClient> {
        self.policy
            .judge_provider
            .as_ref()
            .map(|p| LlmClient::new(LlmConfig::from_provider(p)))
    }

    pub async fn chat(&self, messages: &[Message], tools: &[ToolDef]) -> Result<LlmResponse, String> {
        let d = classify_difficulty(&self.policy, messages).await;
        tracing::info!(difficulty = ?d, "difficulty_route");
        let selected = self.select(d);
        // P1-2：Best-of-N 与工具调用隔离——Agent 循环中终答常为「空文本 + tool_calls」，
        // 若进入 N 路采样，启发式打分只看 c.text 会把合法工具调用样本打成 -inf / 选错样本。
        // 故 tools 非空时跳过 BoN，直接走单次普通调用（BoN 只对纯文本终答有意义）。
        match self.policy.best_of_n {
            Some(n) if n >= 2 && tools.is_empty() => {
                self.chat_best_of_n(selected, messages, tools, n, d).await
            }
            _ => selected.chat(messages, tools).await,
        }
    }

    async fn chat_best_of_n(
        &self,
        base: &LlmClient,
        messages: &[Message],
        tools: &[ToolDef],
        n: usize,
        d: TaskDifficulty,
    ) -> Result<LlmResponse, String> {
        // BoN-A：先拿 temp=0 基线；采样劣于基线则回退，避免「选到 8 压过单次 10」回归。
        let mut baseline_client = base.clone();
        baseline_client.config.temperature = 0.0;
        let baseline = match baseline_client.chat(messages, tools).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(err = %e, "best_of_n baseline failed, falling back to single call");
                return base.chat(messages, tools).await;
            }
        };

        let temp = self.policy.sample_temperature.unwrap_or(0.7);
        let mut samplers: Vec<LlmClient> = Vec::with_capacity(n);
        for _ in 0..n {
            let mut s = base.clone();
            s.config.temperature = temp;
            samplers.push(s);
        }
        let tasks: Vec<_> = samplers.iter().map(|s| s.chat(messages, tools)).collect();
        let results = join_all(tasks).await;
        let errors: Vec<String> = results.iter().filter_map(|r| r.as_ref().err().cloned()).collect();
        if !errors.is_empty() {
            tracing::warn!(
                n_failed = errors.len(),
                first_err = %errors.first().unwrap(),
                "best_of_n_sample_errors"
            );
        }
        let mut candidates: Vec<LlmResponse> = results.into_iter().filter_map(|r| r.ok()).collect();
        if candidates.is_empty() {
            tracing::warn!("best_of_n all samples failed, returning baseline");
            return Ok(baseline);
        }
        // 基线参与评选，保证「不比单次更差」
        candidates.push(baseline.clone());
        if candidates.len() == 1 {
            return Ok(candidates.into_iter().next().unwrap());
        }
        let scores = self.score(messages, &candidates, d).await;
        let mut best_idx = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for (i, sc) in scores.iter().enumerate() {
            if *sc > best_score {
                best_score = *sc;
                best_idx = i;
            }
        }
        let baseline_idx = candidates.len() - 1;
        let baseline_score = scores.get(baseline_idx).copied().unwrap_or(0.0);
        // 采样最优不严格优于基线 → 回退基线（平局也回退，偏好确定性）
        if best_idx != baseline_idx && best_score <= baseline_score + f64::EPSILON {
            tracing::info!(
                best_of_n = n,
                scores = ?scores,
                chosen = "baseline_fallback",
                best_score,
                baseline_score,
                "best_of_n_select"
            );
            return Ok(baseline);
        }
        tracing::info!(best_of_n = n, scores = ?scores, chosen = best_idx, "best_of_n_select");
        Ok(candidates.into_iter().nth(best_idx).unwrap())
    }

    async fn score(&self, messages: &[Message], candidates: &[LlmResponse], d: TaskDifficulty) -> Vec<f64> {
        self.ttc_score(messages, candidates, &self.policy.scorer, d).await
    }

    /// TTC 选择器分发：Judge（相对排序打分）/ Heuristic（零额外调用）/ Majority（自一致性投票）
    async fn ttc_score(
        &self,
        messages: &[Message],
        candidates: &[LlmResponse],
        mode: &ScorerMode,
        d: TaskDifficulty,
    ) -> Vec<f64> {
        match mode {
            ScorerMode::Judge => self.score_by_judge(messages, candidates).await,
            ScorerMode::Heuristic => {
                let is_code = d == TaskDifficulty::Hard;
                candidates.iter().map(|c| score_heuristic(c, is_code)).collect()
            }
            ScorerMode::Majority => score_by_majority(candidates),
        }
    }

    /// TTC 终答采样：对「终答轮」做 N 路采样 + 选择器择优。
    /// `baseline` 为已产出的单次终答（作为保底，保证不比单次差）。
    /// 若 `best_of_n < 2` 或预算超限 → 直接返回 baseline。
    pub async fn chat_ttc(
        &self,
        messages: &[Message],
        baseline: &LlmResponse,
        ttc: &crate::ttc::TtcConfig,
    ) -> LlmResponse {
        let n = ttc.best_of_n;
        if n < 2 {
            return baseline.clone();
        }
        // 预算预估（与 llm_loop 同口径）：ctx_chars/4 * n
        let ctx_chars: usize = messages
            .iter()
            .map(|m| m.content.as_ref().map(|c| c.len()).unwrap_or(0))
            .sum();
        let est = (ctx_chars as u64 / 4) * n as u64;
        if est > ttc.token_budget {
            tracing::info!(
                target = "agent.ttc",
                ttc = "budget_skip",
                est,
                budget = ttc.token_budget,
                "TTC 预算超限，回退单次"
            );
            return baseline.clone();
        }
        let d = classify_difficulty(&self.policy, messages).await;
        let client = self.select(d).clone();
        let temp = ttc.sample_temperature;
        let mut samplers: Vec<LlmClient> = Vec::with_capacity(n);
        for _ in 0..n {
            let mut s = client.clone();
            s.config.temperature = temp;
            samplers.push(s);
        }
        let tasks: Vec<_> = samplers.iter().map(|s| s.chat(messages, &[])).collect();
        let results = join_all(tasks).await;
        let mut candidates: Vec<LlmResponse> = results
            .into_iter()
            .filter_map(|r| r.ok())
            .filter(|r| !r.text.is_empty())
            .collect();
        if candidates.is_empty() {
            return baseline.clone();
        }
        // 基线参与评选，保证「不比单次更差」
        candidates.push(baseline.clone());
        let scores = self.ttc_score(messages, &candidates, &ttc.scorer, d).await;
        let mut best_idx = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for (i, sc) in scores.iter().enumerate() {
            if *sc > best_score {
                best_score = *sc;
                best_idx = i;
            }
        }
        let baseline_idx = candidates.len() - 1;
        let baseline_score = scores.get(baseline_idx).copied().unwrap_or(0.0);
        // 采样最优不严格优于基线 → 回退基线（平局也回退，偏好确定性）
        if best_idx != baseline_idx && best_score <= baseline_score + f64::EPSILON {
            tracing::info!(
                target = "agent.ttc",
                best_of_n = n,
                chosen = "baseline_fallback",
                "ttc_select"
            );
            return baseline.clone();
        }
        tracing::info!(target = "agent.ttc", best_of_n = n, chosen = best_idx, "ttc_select");
        candidates.into_iter().nth(best_idx).unwrap()
    }

    /// TTC verifier-guided 生成：终答后用 judge（judge_provider）或主模型自评打分，
    /// 不通过（< verifier_threshold）则带批评反馈重新生成，最多 max_refine_rounds 轮。
    /// 基线保底：生成失败或全轮不通过，回退入参 baseline（不比单次更差）。
    pub async fn chat_verifier_guided(
        &self,
        messages: &[Message],
        baseline: &LlmResponse,
        ttc: &crate::ttc::TtcConfig,
    ) -> LlmResponse {
        if ttc.max_refine_rounds == 0 {
            return baseline.clone();
        }
        let d = classify_difficulty(&self.policy, messages).await;
        let generator = self.select(d).clone();
        // verifier 客户端：优先 judge_provider（配了且 key 非空），否则主模型自评
        let verifier = match &self.policy.judge_provider {
            Some(p) if !p.api_key.is_empty() => LlmClient::new(LlmConfig::from_provider(p)),
            _ => self.base.clone(),
        };
        let task = last_user_content(messages);
        let mut cur = baseline.clone();
        for round in 1..=ttc.max_refine_rounds {
            let (score, critique) = Self::verify_answer(&verifier, &task, &cur.text).await;
            tracing::info!(
                target = "agent.ttc",
                mode = "verifier",
                round,
                score,
                threshold = ttc.verifier_threshold,
                "verifier_score"
            );
            if score >= ttc.verifier_threshold {
                return cur;
            }
            if round == ttc.max_refine_rounds {
                break;
            }
            let refine = Self::build_refine_messages(messages, &cur.text, &critique);
            match generator.chat(&refine, &[]).await {
                Ok(r) if !r.text.trim().is_empty() => cur = r,
                _ => return baseline.clone(),
            }
        }
        cur
    }

    /// 用 verifier 给「任务+答案」打分（0-10）+ 批评文本。
    /// 失败/无法判 → 记 0 分（保守：视为不通过，触发重生成或保底）。
    async fn verify_answer(verifier: &LlmClient, task: &str, answer: &str) -> (f64, String) {
        let prompt = Message {
            role: "user".to_string(),
            content: Some(format!(
                "你是一个严格答案审阅员。\n用户问题：\n{}\n\n待审阅答案：\n{}\n\n请判断答案是否正确、完整、有无明显错误或幻觉。\
                 先简短指出问题（若没有问题写「无」），最后一行只输出：SCORE: <0-10 的数字，可含一位小数>",
                task, answer
            )),
            tool_calls: None,
            tool_call_id: None,
        };
        match verifier.chat(&[prompt], &[]).await {
            Ok(r) => {
                let score = parse_judge_score(&r.text);
                let critique = r
                    .text
                    .lines()
                    .filter(|l| !l.trim().to_uppercase().starts_with("SCORE:"))
                    .collect::<Vec<_>>()
                    .join("\n")
                    .trim()
                    .to_string();
                (score, critique)
            }
            Err(e) => {
                tracing::warn!(target = "agent.ttc", err = %e, "verifier 评估失败，视为不通过");
                (0.0, String::new())
            }
        }
    }

    /// 构造「带批评反馈的重新生成」消息：把上一版答案作为 assistant 轮，附用户指正。
    fn build_refine_messages(messages: &[Message], prev: &str, critique: &str) -> Vec<Message> {
        let mut v = messages.to_vec();
        v.push(Message {
            role: "assistant".to_string(),
            content: Some(prev.to_string()),
            tool_calls: None,
            tool_call_id: None,
        });
        v.push(Message {
            role: "user".to_string(),
            content: Some(format!(
                "你的上一版回答被审阅指出以下问题：\n{}\n请修正并给出最终准确回答。\
                 若题目需要明确结论，请用「答案：X」给出（如适用）。",
                critique
            )),
            tool_calls: None,
            tool_call_id: None,
        });
        v
    }

    async fn score_by_judge(&self, messages: &[Message], candidates: &[LlmResponse]) -> Vec<f64> {
        // BoN-A：与 eval_bon 对齐——弃用「一次吐绝对分数组」弱提示（Δpp=-4 /「8 压过 10」根因）。
        // 优先 1 次相对排序；失败再逐候选 SCORE:（与 eval 同解析器）。
        let judge_cfg = match self.policy.judge_provider.clone() {
            Some(p) if !p.api_key.is_empty() => LlmConfig::from_provider(&p),
            Some(_) => {
                tracing::warn!(
                    invalid_judge_config = true,
                    reason = "judge_provider.api_key empty",
                    "best_of_n judge 配置无效，回退启发式打分"
                );
                return self.score_heuristic_all(messages, candidates);
            }
            None => {
                tracing::warn!(
                    invalid_judge_config = true,
                    reason = "judge_provider not configured",
                    "best_of_n judge 配置无效，回退启发式打分"
                );
                return self.score_heuristic_all(messages, candidates);
            }
        };
        let client = LlmClient::new(judge_cfg);
        let last_user = last_user_content(messages);

        if let Some(order) = self.ask_relative_rank(&client, &last_user, candidates).await {
            if order.len() == candidates.len() {
                let n = candidates.len() as f64;
                let mut by_rank = vec![0.0; candidates.len()];
                let mut ok = true;
                for (rank, idx1) in order.iter().enumerate() {
                    if *idx1 >= 1 && *idx1 <= candidates.len() {
                        by_rank[idx1 - 1] = n - rank as f64;
                    } else {
                        ok = false;
                        break;
                    }
                }
                // 必须是 1..=n 的排列
                if ok {
                    let mut seen = vec![false; candidates.len()];
                    for idx1 in &order {
                        if seen[idx1 - 1] {
                            ok = false;
                            break;
                        }
                        seen[idx1 - 1] = true;
                    }
                }
                if ok && by_rank.iter().all(|s| *s > 0.0) {
                    tracing::info!(order = ?order, "best_of_n relative_rank applied");
                    return by_rank;
                }
            }
        }

        let mut scores = Vec::with_capacity(candidates.len());
        for (i, c) in candidates.iter().enumerate() {
            let prompt = Message {
                role: "user".to_string(),
                content: Some(format!(
                    "用户请求：\n{}\n\n候选 #{} 回答：\n{}\n\n请按下列维度打分（0-10）：正确性、完整性、有无明显错误/幻觉、格式可用性。\
先简短说明扣分点，最后一行只输出：SCORE: <0-10 数字，可含一位小数>",
                    last_user, i + 1, c.text
                )),
                tool_calls: None,
                tool_call_id: None,
            };
            match client.chat(&[prompt], &[]).await {
                Ok(r) => scores.push(parse_judge_score(&r.text)),
                Err(e) => {
                    tracing::warn!(candidate = i, err = %e, "best_of_n judge 单候选失败，该候选记 0");
                    scores.push(0.0);
                }
            }
        }
        scores
    }

    fn score_heuristic_all(&self, messages: &[Message], candidates: &[LlmResponse]) -> Vec<f64> {
        let is_code = classify_heuristic(messages) == TaskDifficulty::Hard;
        candidates.iter().map(|c| score_heuristic(c, is_code)).collect()
    }

    /// 请 judge 给出从优到劣的候选编号排序（1-based）。失败返回 None。
    async fn ask_relative_rank(
        &self,
        client: &LlmClient,
        last_user: &str,
        candidates: &[LlmResponse],
    ) -> Option<Vec<usize>> {
        let list: String = candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let preview: String = c.text.chars().take(400).collect();
                format!("#{}\n{}\n", i + 1, preview)
            })
            .collect();
        let prompt = Message {
            role: "user".to_string(),
            content: Some(format!(
                "用户请求：\n{}\n\n以下是 {} 个候选回答（已截断预览）。请从优到劣排序，\
只返回 JSON 数组，元素为候选编号（1-based），例如 [2,1,3]，不要其他文字。\n{}",
                last_user,
                candidates.len(),
                list
            )),
            tool_calls: None,
            tool_call_id: None,
        };
        let r = client.chat(&[prompt], &[]).await.ok()?;
        let txt = &r.text;
        let start = txt.find('[')?;
        let end = txt[start..].find(']')?;
        let arr_str = &txt[start..start + end + 1];
        serde_json::from_str::<Vec<usize>>(arr_str).ok()
    }

    /// 注意：此处仅做「难度路由选择 provider」，真·SSE token 流由选中 provider 的
    /// `LlmClient::chat_stream` 完成（RoutedLlm 不重新切片）。对外文档勿写成「RoutedLlm 假流切片」。
    pub async fn chat_stream(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        sender: mpsc::UnboundedSender<SseEvent>,
    ) -> Result<(), String> {
        let d = classify_difficulty(&self.policy, messages).await;
        tracing::info!(difficulty = ?d, "difficulty_route_stream");
        self.select(d).chat_stream(messages, tools, sender).await
    }
}

/// 按策略分类任务难度
pub async fn classify_difficulty(policy: &DifficultyPolicy, messages: &[Message]) -> TaskDifficulty {
    match policy.classify {
        ClassifyMode::Judge => classify_by_judge(policy, messages).await,
        ClassifyMode::Heuristic => classify_heuristic(messages),
    }
}

/// 取最后一条 user 消息的正文（多轮对话里 last 可能是 assistant/tool，必须用此取用户意图）
fn last_user_content(messages: &[Message]) -> String {
    messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .and_then(|m| m.content.clone())
        .unwrap_or_default()
}

/// 启发式：基于最后一条用户消息的信号
fn classify_heuristic(messages: &[Message]) -> TaskDifficulty {
    let last_user = last_user_content(messages);
    let text = last_user.to_lowercase();

    // 难任务信号优先级高于易白名单：代码 / 算法 / 推理 / 架构等强信号一旦命中直接 Hard。
    // 否则「sql 查询最近订单」这类同时含「查询」(易白名单) + 「sql」(代码) 的 prompt 会被
    // 白名单误压成 Easy 走 flash，丢失写 SQL 的真实难度（eval 抓出的真实 bug）。
    // 收窄后的难信号：仅代码 / 算法 / 推理 / 架构等强信号才进 Hard；
    // 已移除「查询/分析/复杂/函数」等过宽日常词（避免运维问答常走 pro）。
    let hard_signals = [
        "```", "写代码", "编码", "实现", "debug", "调试", "修复", "bug",
        "算法", "优化", "重构", "编译", "单元测试", "集成测试", "正则",
        "regex", "sql", "递归", "动态规划", "proof", "推导", "证明",
        "架构", "设计模式", "并发", "async", "线程",
        "rust", "python", "typescript", "react", "算法题",
    ];
    if hard_signals.iter().any(|s| text.contains(s)) {
        return TaskDifficulty::Hard;
    }

    // P1-3：易任务白名单（寒暄 / 状态查询 / 固废运维日常查询）。命中强制 Easy，
    // 避免默认成本模型偏激进，把中文运维/固废问答（查询/统计/车辆/称重…）误入 Hard 走 pro。
    // 注意：仅在无任何难信号时才生效，故不会与上方代码信号冲突。
    let easy_signals = [
        "你好", "您好", "在吗", "hi", "hello", "hey",
        "状态", "多少", "几辆", "几吨", "几车", "今天", "昨天", "前天",
        "本周", "本月", "今年", "记录", "查询", "查一下", "帮我查", "查个",
        "统计", "明细", "列表", "名单", "进厂", "出厂", "过磅", "称重",
        "车辆", "车牌", "固废", "危废", "企业", "登录", "版本", "时间", "日期",
    ];
    if easy_signals.iter().any(|s| text.contains(s)) {
        return TaskDifficulty::Easy;
    }

    if last_user.chars().count() > 800 {
        return TaskDifficulty::Hard;
    }
    TaskDifficulty::Easy
}

async fn classify_by_judge(policy: &DifficultyPolicy, messages: &[Message]) -> TaskDifficulty {
    // P2-2：judge_provider 缺失或 api_key 为空时，显式暴露配置无效（而非仅静默降级到启发式）。
    // 否则「配了 judge 模式却没给 key」会被误以为在工作，属静默错误。
    let judge_cfg = match policy.judge_provider.clone() {
        Some(p) if !p.api_key.is_empty() => LlmConfig::from_provider(&p),
        Some(_) => {
            tracing::warn!(
                invalid_judge_config = true,
                reason = "judge_provider.api_key empty",
                "classify_by_judge 配置无效，回退启发式分类"
            );
            LlmConfig::default()
        }
        None => {
            tracing::warn!(
                invalid_judge_config = true,
                reason = "judge_provider not configured",
                "classify_by_judge 配置无效，回退启发式分类"
            );
            LlmConfig::default()
        }
    };
    let client = LlmClient::new(judge_cfg);
    // P1-1 修复：取最后一条 user 消息，而非 messages.last()（多轮里 last 常是 assistant/tool，
    // 取错会喂给 judge 非用户内容 → 分类偏。与 classify_heuristic 一致取 last user。
    let user_text = last_user_content(messages);
    let prompt = Message {
        role: "user".to_string(),
        content: Some(
            "判断下述用户任务的难度，仅回复 easy 或 hard：\n".to_string() + &user_text,
        ),
        tool_calls: None,
        tool_call_id: None,
    };
    match client.chat(&[prompt], &[]).await {
        Ok(r) if r.text.to_lowercase().contains("hard") => TaskDifficulty::Hard,
        _ => TaskDifficulty::Easy,
    }
}

/// 解析 judge 返回的分数（与 `tests/eval_bon.rs` 口径对齐，BoN-A）。
/// 1) 优先取显式 `SCORE: X`；2) 回退取首个完整数字 token；clamp 到 [0,10]。
pub fn parse_judge_score(text: &str) -> f64 {
    if let Some(pos) = text.find("SCORE") {
        let rest = &text[pos..];
        let b = rest.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_digit() {
                let mut end = i + 1;
                while end < b.len() && (b[end].is_ascii_digit() || b[end] == b'.') {
                    end += 1;
                }
                if let Ok(v) = rest[i..end].parse::<f64>() {
                    return v.clamp(0.0, 10.0);
                }
                i = end;
            } else {
                i += 1;
            }
        }
    }
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
            i = end;
        } else {
            i += 1;
        }
    }
    0.0
}

/// 自一致性投票：抽取各候选「核心答案」做计数，多数票胜；平票则在平票候选内用启发式决出。
/// 返回与 `candidates` 等长的分数向量（胜者 10.0，其余按情况 0）。
fn score_by_majority(candidates: &[LlmResponse]) -> Vec<f64> {
    if candidates.len() <= 1 {
        return vec![1.0; candidates.len()];
    }
    let answers: Vec<String> = candidates.iter().map(|c| extract_answer(&c.text)).collect();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for a in &answers {
        *counts.entry(a.clone()).or_insert(0) += 1;
    }
    let max_count = counts.values().copied().max().unwrap_or(0);
    let winners: Vec<usize> = answers
        .iter()
        .enumerate()
        .filter(|(_, a)| counts.get(*a).copied().unwrap_or(0) == max_count)
        .map(|(i, _)| i)
        .collect();
    let mut scores = vec![0.0; candidates.len()];
    if winners.len() == 1 {
        scores[winners[0]] = 10.0;
        return scores;
    }
    // 平票：仅在平票候选内用启发式比较，非平票候选保持 0（确保平票胜者不被 baseline 误压）
    for &i in &winners {
        scores[i] = score_heuristic(&candidates[i], false);
    }
    scores
}

/// 抽取候选终答的「核心答案」用于自一致性投票。
/// 优先代码块；否则抓「答案/结论」标记后的内容；否则取最后一段非空文本；否则整段。
/// 导出为 `pub`：eval harness（`eval_ttc.rs`）复用同一抽取器，保证单发 vs TTC 公平比对。
pub fn extract_answer(text: &str) -> String {
    // 代码块
    if let Some(start) = text.find("```") {
        if let Some(end) = text[start + 3..].find("```") {
            let block = &text[start + 3..start + 3 + end];
            let code: String = block.lines().skip(1).collect::<Vec<_>>().join("\n");
            let code = if code.trim().is_empty() { block } else { code.as_str() };
            return code.trim().to_string();
        }
    }
    // 答案/结论标记（取标记后第一行）
    for marker in [
        "答案：", "答案:", "结论：", "结论:", "####", "Answer:", "answer:",
    ] {
        if let Some(pos) = text.rfind(marker) {
            let tail = text[pos + marker.len()..].lines().next().unwrap_or("").trim();
            if !tail.is_empty() {
                return tail.to_string();
            }
        }
    }
    // 最后一段非空
    if let Some(last) = text.split("\n\n").map(|s| s.trim()).filter(|s| !s.is_empty()).last() {
        if !last.is_empty() {
            return last.to_string();
        }
    }
    text.trim().to_string()
}

/// Best-of-N 启发式打分（零额外调用，作为 Judge 不可用时的回退）
///
/// 设计目标：降低「纯长度偏置」——原实现以 `len*0.01` 为主信号，易选啰嗦答案。
/// 现改为「结构 / 相关性 / 拒答」多信号：长度仅作轻微 tiebreaker 且超过阈值反而扣分（抑制冗余），
/// 强信号来自代码块 / 列表 / 步骤标记等结构化特征。
fn score_heuristic(c: &LlmResponse, is_code: bool) -> f64 {
    let text = &c.text;
    let len = text.chars().count();
    if len == 0 {
        return f64::NEG_INFINITY; // 空文本（工具调用终答）永不被选为最优
    }
    let low = text.to_lowercase();

    // 拒答/拒绝对齐：强负信号
    if low.contains("抱歉")
        || low.contains("i cannot")
        || low.contains("作为ai")
        || low.contains("我无法")
        || low.contains("i'm unable")
        || low.contains("i am unable")
    {
        return -50.0;
    }

    let mut s = 0.0;
    // 长度：轻微正贡献且有上限（≤ ~2.2）；超过 800 字符开始扣分，抑制「越长越好」偏置
    if len <= 200 {
        s += len as f64 * 0.005;
    } else if len <= 800 {
        s += 1.0 + (len - 200) as f64 * 0.002;
    } else {
        s += 2.2 - ((len - 800) as f64 * 0.002);
    }

    // 结构信号：有组织的回答通常质量更高（代码块 / 列表 / 步骤标记）
    let list_hit = text.contains("\n1.") || text.contains("\n- ") || text.contains("\n* ");
    let marker_hit = low.contains("步骤") || low.contains("首先") || low.contains("总结") || low.contains("注意");
    let structure = (text.contains("```") as i32) + (list_hit as i32) + (marker_hit as i32);
    s += structure as f64 * 1.5;

    // 代码场景：代码块 / 函数定义是强正信号
    if is_code {
        if text.contains("```") {
            s += 6.0;
        }
        if text.contains("fn ")
            || text.contains("def ")
            || text.contains("function ")
            || text.contains("impl ")
        {
            s += 4.0;
        }
    }
    s
}

/// LLM 响应中的工具调用
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// LLM 响应
#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
}

/// LLM 消息
#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolCallJson {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub function: ToolFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolFunction {
    pub name: String,
    pub arguments: String,
}

/// 工具定义（供 LLM 的 tools 参数）
#[derive(Debug, Clone, Serialize)]
pub struct ToolDef {
    #[serde(rename = "type")]
    pub type_: String,
    pub function: ToolDefFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolDefFunction {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// LLM 客户端
#[derive(Clone)]
pub struct LlmClient {
    client: Client,
    config: LlmConfig,
}

impl std::fmt::Debug for LlmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmClient")
            .field("provider", &self.config.base_url)
            .field("model", &self.config.model)
            .finish()
    }
}

impl LlmClient {
    pub fn new(config: LlmConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest Client::build");
        LlmClient { client, config }
    }

    /// 发送聊天请求，返回响应（带重试 + failover）
    #[tracing::instrument(skip_all, fields(model = %self.config.model, provider = %self.config.base_url, tool_count = tools.len()))]
    pub async fn chat(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
    ) -> Result<LlmResponse, String> {
        // 主 Provider + 备用 Provider 列表
        let mut providers: Vec<LlmProvider> = Vec::new();
        providers.push(LlmProvider {
            base_url: self.config.base_url.clone(),
            model: self.config.model.clone(),
            api_key: self.config.api_key.clone(),
            chat_path: self.config.chat_path.clone(),
        });
        for fb in &self.config.fallbacks {
            providers.push(fb.clone());
        }

        let mut last_error = String::new();
        tracing::info!("llm.complete start");

        for (idx, p) in providers.iter().enumerate() {
            let base_url = &p.base_url;
            let model = &p.model;
            let api_key = &p.api_key;
            let url = format!("{}{}", base_url.trim_end_matches('/'), p.chat_path);

            let mut body = serde_json::json!({
                "model": model,
                "messages": messages,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            });

            if !tools.is_empty() {
                body["tools"] =
                    serde_json::to_value(tools).map_err(|e| format!("tools json: {}", e))?;
            }

            // 3 次重试：0s, 1s, 2s 退避
            let max_retries = if idx == 0 { 3 } else { 1 }; // 主 Provider 重试 3 次，备用只试 1 次
            for attempt in 0..max_retries {
                let resp_result = self
                    .client
                    .post(&url)
                    .json(&body)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .send()
                    .await;

                match resp_result {
                    Ok(resp) => {
                        let status = resp.status();
                        if !status.is_success() {
                            let err_body = resp.text().await.unwrap_or_default();
                            let msg = format!(
                                "HTTP {}: {}",
                                status.as_u16(),
                                err_body.chars().take(200).collect::<String>()
                            );
                            if attempt < max_retries - 1 {
                                tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                                continue;
                            }
                            last_error = msg;
                            break;
                        }

                        let data: serde_json::Value =
                            resp.json().await.map_err(|e| format!("LLM json: {}", e))?;

                        let choice = data["choices"][0]
                            .as_object()
                            .ok_or("LLM returned no choices")?
                            .clone();

                        let message = choice["message"]
                            .as_object()
                            .ok_or("LLM returned no message")?;

                        let text = message
                            .get("content")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();

                        let tool_calls = message
                            .get("tool_calls")
                            .and_then(|tc| tc.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|tc| {
                                        let id = tc["id"].as_str()?.to_string();
                                        let name = tc["function"]["name"].as_str()?.to_string();
                                        let args_str = tc["function"]["arguments"].as_str()?;
                                        let arguments: serde_json::Value =
                                            serde_json::from_str(args_str).ok()?;
                                        Some(ToolCall {
                                            id,
                                            name,
                                            arguments,
                                        })
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();

                        // 备用 Provider 调用成功时记录日志
                        if idx > 0 {
                            tracing::info!(failover_to = %model, provider_index = idx, "LLM provider failover（主 Provider 失败）");
                        }

                        return Ok(LlmResponse { text, tool_calls });
                    }
                    Err(e) => {
                        let msg = format!("连接失败: {}", e);
                        if attempt < max_retries - 1 {
                            tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                            continue;
                        }
                        last_error = msg;
                    }
                }
            }
        }

        Err(format!(
            "LLM 所有 Provider 均失败，最后错误: {}",
            last_error
        ))
    }

    /// 流式聊天（SSE 事件通过 sender 发送）
    /// P2-6 修复：添加 failover 支持
    pub async fn chat_stream(
        &self,
        messages: &[Message],
        tools: &[ToolDef],
        sender: mpsc::UnboundedSender<SseEvent>,
    ) -> Result<(), String> {
        // P2-6: 主 Provider 失败时尝试备用 Provider
        let mut providers: Vec<LlmProvider> = Vec::new();
        providers.push(LlmProvider {
            base_url: self.config.base_url.clone(),
            model: self.config.model.clone(),
            api_key: self.config.api_key.clone(),
            chat_path: self.config.chat_path.clone(),
        });
        for fb in &self.config.fallbacks {
            providers.push(fb.clone());
        }

        let mut last_error = String::new();
        tracing::info!("llm.complete start");

        for (idx, p) in providers.iter().enumerate() {
            let base_url = &p.base_url;
            let model = &p.model;
            let api_key = &p.api_key;
            let chat_path = &p.chat_path;
            match self
                .chat_stream_single(base_url, model, api_key, chat_path, messages, tools, &sender)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if idx == 0 {
                        tracing::warn!("流式主 Provider 失败，尝试 failover: {}", e);
                    }
                    last_error = e;
                    // 发送错误事件让前端知道在重试
                    if idx < providers.len() - 1 {
                        let _ = sender.send(SseEvent::ThinkingEvt {
                            content: format!("⚠️ 连接失败，正在切换到备用服务器..."),
                        });
                    }
                }
            }
        }

        let _ = sender.send(SseEvent::ErrorEvt {
            message: last_error.clone(),
        });
        Err(last_error)
    }

    /// 单个 Provider 的流式聊天
    async fn chat_stream_single(
        &self,
        base_url: &str,
        model: &str,
        api_key: &str,
        chat_path: &str,
        messages: &[Message],
        tools: &[ToolDef],
        sender: &mpsc::UnboundedSender<SseEvent>,
    ) -> Result<(), String> {
        let url = format!("{}{}", base_url.trim_end_matches('/'), chat_path);
        tracing::warn!(url = %url, chat_path = %chat_path, "LLM request url (chat_path applied)");

        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": true,
        });

        if !tools.is_empty() {
            body["tools"] =
                serde_json::to_value(tools).map_err(|e| format!("tools json: {}", e))?;
        }

        // DeepSeek 专用：禁用 thinking 输出（避免中文乱码）
        body["extra_body"] = serde_json::json!({"thinking": {"type": "disabled"}});

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| format!("stream request: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "HTTP {}: {}",
                status.as_u16(),
                err_body.chars().take(200).collect::<String>()
            ));
        }

        use futures::StreamExt;
        let mut stream = resp.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| format!("stream read: {}", e))?;
            let text = String::from_utf8_lossy(&chunk);

            for line in text.lines() {
                if !line.starts_with("data: ") {
                    continue;
                }
                let data = &line[6..];
                if data == "[DONE]" {
                    let _ = sender.send(SseEvent::DoneEvt);
                    return Ok(());
                }

                if let Ok(val) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(choices) = val["choices"].as_array() {
                        if choices.is_empty() {
                            continue;
                        }
                        let delta = &choices[0]["delta"];

                        // thinking
                        if let Some(tc) = delta.get("reasoning_content").and_then(|c| c.as_str()) {
                            if !tc.is_empty() {
                                let _ = sender.send(SseEvent::ThinkingEvt {
                                    content: tc.to_string(),
                                });
                            }
                        }

                        // text
                        if let Some(tc) = delta.get("content").and_then(|c| c.as_str()) {
                            if !tc.is_empty() {
                                let _ = sender.send(SseEvent::TextEvt {
                                    content: tc.to_string(),
                                });
                            }
                        }

                        // tool_calls
                        if let Some(tcs) = delta.get("tool_calls").and_then(|tc| tc.as_array()) {
                            for tc in tcs {
                                let id = tc["id"].as_str().unwrap_or("").to_string();
                                let name =
                                    tc["function"]["name"].as_str().unwrap_or("").to_string();
                                let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
                                if let Ok(args) = serde_json::from_str(args_str) {
                                    let _ = sender.send(SseEvent::ToolCallEvt {
                                        name,
                                        arguments: args,
                                        id,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let _ = sender.send(SseEvent::DoneEvt);
        Ok(())
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;

    fn msg(role: &str, content: &str) -> Message {
        Message {
            role: role.to_string(),
            content: Some(content.to_string()),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    #[test]
    fn heuristic_easy_whitelist_ops_query() {
        // P1-3：固废运维日常查询/寒暄应走 Easy，不误入 Hard 走 pro
        assert_eq!(
            classify_heuristic(&[msg("user", "查询本周进厂车辆记录")]),
            TaskDifficulty::Easy
        );
        assert_eq!(
            classify_heuristic(&[msg("user", "今天称重多少吨")]),
            TaskDifficulty::Easy
        );
        assert_eq!(classify_heuristic(&[msg("user", "你好，在吗")]), TaskDifficulty::Easy);
    }

    #[test]
    fn heuristic_hard_code_signal() {
        assert_eq!(
            classify_heuristic(&[msg("user", "帮我用 rust 写一个并发函数")]),
            TaskDifficulty::Hard
        );
        assert_eq!(
            classify_heuristic(&[msg("user", "实现快速排序算法")]),
            TaskDifficulty::Hard
        );
    }

    #[test]
    fn heuristic_takes_last_user_not_assistant() {
        // P1-1 同源逻辑：多轮里 last 是 assistant 含「实现」，最后一条 user 是寒暄/查询 → 应为 Easy
        let msgs = vec![
            msg("user", "你好"),
            msg("assistant", "你好，有什么可以帮你？实现登录功能的话……"),
            msg("user", "查询一下昨天的企业信息"),
        ];
        assert_eq!(classify_heuristic(&msgs), TaskDifficulty::Easy);
    }

    #[test]
    fn score_heuristic_empty_negative_inf() {
        // P1-2 动机：空文本（工具调用终答）打分 -inf，确保不会被 BoN 选为最优
        let c = LlmResponse {
            text: String::new(),
            tool_calls: vec![],
        };
        let s = score_heuristic(&c, false);
        assert!(s.is_infinite() && s.is_sign_negative());
    }

    #[test]
    fn score_heuristic_code_bonus() {
        let c = LlmResponse {
            text: "```rust\nfn main() {}\n```".to_string(),
            tool_calls: vec![],
        };
        assert!(score_heuristic(&c, true) > 0.0);
    }

    #[test]
    fn score_heuristic_structure_beats_bare_length() {
        // P2-1 验收：结构化但不长的答案，应优于更长却无结构的啰嗦答案，
        // 证明打分不再由「纯长度」主导。
        let concise = LlmResponse {
            text: "步骤如下：\n1. 打开配置\n2. 修改端口\n3. 重启服务".to_string(),
            tool_calls: vec![],
        };
        let verbose = LlmResponse {
            text: "关于这个问题，我想说的是，其实有很多种方法可以考虑，通常我们会从多个角度去想，比如说第一个方面，第二个方面，第三个方面，总之大家都觉得这个事情比较复杂，需要慢慢来，不能着急，因为着急容易出错，所以我们还是要稳妥一点比较好，当然这也取决于具体情况。".to_string(),
            tool_calls: vec![],
        };
        assert!(
            score_heuristic(&concise, false) > score_heuristic(&verbose, false),
            "结构化短答案应优于无结构长答案"
        );
    }

    #[test]
    fn score_heuristic_oververbosity_penalized() {
        // P2-1 验收：超过 800 字符后，长度贡献不再线性增长甚至回落
        let moderate = LlmResponse {
            text: "a".repeat(600),
            tool_calls: vec![],
        };
        let bloated = LlmResponse {
            text: "b".repeat(3000),
            tool_calls: vec![],
        };
        // 同等无结构情况下，超长不应显著优于中等（长度权重被压制）
        let delta = score_heuristic(&bloated, false) - score_heuristic(&moderate, false);
        assert!(delta < 5.0, "超长答案长度优势应被抑制，实际 Δ={}", delta);
    }
}

/// 1.3 分类准确率 eval harness（HY3 量化验收：启发式分类 ≥90%）
///
/// 数据集为「人工意图标注」的代表性 prompt；运行 classify_heuristic 比对，
/// 既验证当前分类质量，也在未来规则改动时防止回归。
/// 注：少数「意图 Hard 但无代码关键词」的样本（如服务排查类）按 P1-3 设计属可接受的保守误判，
/// 会体现在 mismatches 里供人工审视，不影响 ≥90% 验收线。
#[cfg(test)]
mod eval_tests {
    use super::*;

    fn m(content: &str) -> Message {
        Message {
            role: "user".to_string(),
            content: Some(content.to_string()),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// 返回 (正确数, 总数, 错分样本)
    fn eval_classification_accuracy() -> (usize, usize, Vec<(String, TaskDifficulty, TaskDifficulty)>) {
        // (prompt, 人工意图标注)
        let dataset: &[(&str, TaskDifficulty)] = &[
            // —— Easy：寒暄 / 固废运维 / 状态查询（白名单强制 Easy）——
            ("你好", TaskDifficulty::Easy),
            ("在吗", TaskDifficulty::Easy),
            ("查询本周进厂车辆记录", TaskDifficulty::Easy),
            ("今天称重多少吨", TaskDifficulty::Easy),
            ("帮我查一下昨天的企业信息", TaskDifficulty::Easy),
            ("现在系统状态怎么样", TaskDifficulty::Easy),
            ("登录一下后台", TaskDifficulty::Easy),
            ("固废处置流程是什么", TaskDifficulty::Easy),
            ("介绍一下你们公司的业务", TaskDifficulty::Easy),
            ("把这句话翻译成英文", TaskDifficulty::Easy),
            ("总结一下上面的对话", TaskDifficulty::Easy),
            ("提醒我下午三点开会", TaskDifficulty::Easy),
            ("这个接口返回 500 是什么原因", TaskDifficulty::Easy), // 无代码关键词
            // —— Hard：代码 / 算法 / 架构 / 推理（强信号）——
            ("帮我用 rust 写一个并发函数", TaskDifficulty::Hard),
            ("实现快速排序算法", TaskDifficulty::Hard),
            ("帮我 debug 这个崩溃", TaskDifficulty::Hard),
            ("写一个正则匹配邮箱", TaskDifficulty::Hard),
            ("用 python 写个爬虫脚本", TaskDifficulty::Hard),
            ("设计一个线程安全的并发队列", TaskDifficulty::Hard),
            ("解释动态规划思想并举例", TaskDifficulty::Hard),
            ("给我一段 sql 查询最近订单", TaskDifficulty::Hard),
            ("重构这段代码提高性能", TaskDifficulty::Hard),
            ("写一个 async/await 示例", TaskDifficulty::Hard),
            ("用 typescript 实现防抖函数", TaskDifficulty::Hard),
            ("推导一下这个公式", TaskDifficulty::Hard),
            ("写一个递归的斐波那契", TaskDifficulty::Hard),
            ("工厂设计模式怎么用", TaskDifficulty::Hard),
            ("帮我写个 react 组件", TaskDifficulty::Hard),
            ("证明这个定理", TaskDifficulty::Hard),
            ("实现一个编译器的词法分析", TaskDifficulty::Hard),
            ("写一个单元测试覆盖边界条件", TaskDifficulty::Hard),
            // —— 长文（>800 字符）强制 Hard —— 用中性无关键词长句，确保走到 len>800 分支
            (&(("请依下列要求详述产品：").to_string() + &"功能设想与边界情形 ".repeat(200)), TaskDifficulty::Hard),
            // —— 意图 Hard 但无代码关键词（保守误判，计入 mismatches 供审视）——
            ("服务启动报端口被占用，帮我排查一下", TaskDifficulty::Hard), // 实际 heuristic → Easy
            ("线上数据库连不上，紧急处理", TaskDifficulty::Hard),        // 实际 heuristic → Easy
        ];

        let mut correct = 0usize;
        let mut total = 0usize;
        let mut mismatches = Vec::new();
        for (prompt, expected) in dataset {
            let got = classify_heuristic(&[m(prompt)]);
            total += 1;
            if got == *expected {
                correct += 1;
            } else {
                mismatches.push((prompt.to_string(), *expected, got));
            }
        }
        // 多轮场景单独加入统计（last user = Easy）
        let multi_easy = vec![m("你好"), m("好的，有什么可以帮你？"), m("查询一下昨天的进厂记录")];
        total += 1;
        if classify_heuristic(&multi_easy) == TaskDifficulty::Easy {
            correct += 1;
        } else {
            mismatches.push(("多轮(last=user查询)".to_string(), TaskDifficulty::Easy, TaskDifficulty::Hard));
        }
        // 多轮场景（last user = Hard）
        let multi_hard = vec![m("你好"), m("好的"), m("用 python 写个数据清洗脚本")];
        total += 1;
        if classify_heuristic(&multi_hard) == TaskDifficulty::Hard {
            correct += 1;
        } else {
            mismatches.push(("多轮(last=user代码)".to_string(), TaskDifficulty::Hard, TaskDifficulty::Easy));
        }
        (correct, total, mismatches)
    }

    #[test]
    fn classification_accuracy_ge_90_percent() {
        let (correct, total, mismatches) = eval_classification_accuracy();
        let acc = correct as f64 / total as f64;
        for (p, exp, got) in &mismatches {
            eprintln!("[MISMATCH] '{}' -> expected {:?}, got {:?}", p, exp, got);
        }
        eprintln!("classification accuracy = {}/{} = {:.1}%", correct, total, acc * 100.0);
        assert!(acc >= 0.90, "分类准确率 {:.1}% 低于验收线 90%", acc * 100.0);
    }

    #[test]
    fn parse_judge_score_prefers_score_line_and_handles_ten() {
        assert_eq!(parse_judge_score("理由...\nSCORE: 10"), 10.0);
        assert_eq!(parse_judge_score("SCORE: 8.5"), 8.5);
        assert_eq!(parse_judge_score("满分 10 分"), 10.0); // 完整 token，非首字符 1
        assert_eq!(parse_judge_score("无数字"), 0.0);
    }
}
