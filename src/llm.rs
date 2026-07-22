//! LLM 客户端 — 兼容 DeepSeek / OpenAI API（支持流式）

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

    pub async fn chat(&self, messages: &[Message], tools: &[ToolDef]) -> Result<LlmResponse, String> {
        let d = classify_difficulty(&self.policy, messages).await;
        tracing::info!(difficulty = ?d, "difficulty_route");
        let selected = self.select(d);
        match self.policy.best_of_n {
            Some(n) if n >= 2 => self.chat_best_of_n(selected, messages, tools, n, d).await,
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
        let candidates: Vec<LlmResponse> = results.into_iter().filter_map(|r| r.ok()).collect();
        if candidates.is_empty() {
            // 兜底：所有采样失败则退化为单次普通调用，保证请求不整体失败
            tracing::warn!("best_of_n all samples failed, falling back to single call");
            return base.chat(messages, tools).await;
        }
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
        tracing::info!(best_of_n = n, scores = ?scores, chosen = best_idx, "best_of_n_select");
        Ok(candidates.into_iter().nth(best_idx).unwrap())
    }

    async fn score(&self, messages: &[Message], candidates: &[LlmResponse], d: TaskDifficulty) -> Vec<f64> {
        match self.policy.scorer {
            ScorerMode::Judge => self.score_by_judge(messages, candidates).await,
            ScorerMode::Heuristic => {
                let is_code = d == TaskDifficulty::Hard;
                candidates.iter().map(|c| score_heuristic(c, is_code)).collect()
            }
        }
    }

    async fn score_by_judge(&self, messages: &[Message], candidates: &[LlmResponse]) -> Vec<f64> {
        let judge_cfg = self
            .policy
            .judge_provider
            .clone()
            .map(|p| LlmConfig::from_provider(&p))
            .unwrap_or_else(LlmConfig::default);
        let client = LlmClient::new(judge_cfg);
        let last_user = messages
            .iter()
            .rev()
            .find(|m| m.role == "user")
            .and_then(|m| m.content.clone())
            .unwrap_or_default();
        let candidates_text: String = candidates
            .iter()
            .enumerate()
            .map(|(i, c)| format!("#{}: {}\n", i + 1, c.text))
            .collect();
        let prompt = Message {
            role: "user".to_string(),
            content: Some(format!(
                "用户请求：\n{}\n\n下面是 {} 个候选回答，请对质量逐个打分（0-10，越高质量越好），仅返回 JSON 数组如 [7,9,6]，不要其他文字。\n{}",
                last_user,
                candidates.len(),
                candidates_text
            )),
            tool_calls: None,
            tool_call_id: None,
        };
        match client.chat(&[prompt], &[]).await {
            Ok(r) => {
                let txt = &r.text;
                if let Some(start) = txt.find('[') {
                    if let Some(end) = txt[start..].find(']') {
                        let arr_str = &txt[start..start + end + 1];
                        if let Ok(arr) = serde_json::from_str::<Vec<f64>>(arr_str) {
                            if arr.len() == candidates.len() {
                                return arr;
                            }
                        }
                    }
                }
                tracing::warn!("best_of_n judge 解析失败，回退启发式打分");
                let is_code = classify_heuristic(messages) == TaskDifficulty::Hard;
                candidates.iter().map(|c| score_heuristic(c, is_code)).collect()
            }
            Err(e) => {
                tracing::warn!("best_of_n judge 调用失败，回退启发式打分: {}", e);
                let is_code = classify_heuristic(messages) == TaskDifficulty::Hard;
                candidates.iter().map(|c| score_heuristic(c, is_code)).collect()
            }
        }
    }

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

/// 启发式：基于最后一条用户消息的信号
fn classify_heuristic(messages: &[Message]) -> TaskDifficulty {
    let last_user = messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .and_then(|m| m.content.clone())
        .unwrap_or_default();
    let text = last_user.to_lowercase();
    let hard_signals = [
        "```", "实现", "写代码", "编码", "debug", "调试", "修复", "bug",
        "算法", "优化", "重构", "编译", "单元测试", "集成测试", "正则",
        "regex", "sql", "查询", "递归", "动态规划", "proof", "推导",
        "复杂", "分析", "架构", "设计模式", "并发", "async", "线程",
        "rust", "python", "typescript", "react", "算法题", "函数",
    ];
    if hard_signals.iter().any(|s| text.contains(s)) {
        return TaskDifficulty::Hard;
    }
    if last_user.chars().count() > 800 {
        return TaskDifficulty::Hard;
    }
    TaskDifficulty::Easy
}

async fn classify_by_judge(policy: &DifficultyPolicy, messages: &[Message]) -> TaskDifficulty {
    let judge_cfg = policy
        .judge_provider
        .clone()
        .map(|p| LlmConfig::from_provider(&p))
        .unwrap_or_else(LlmConfig::default);
    let client = LlmClient::new(judge_cfg);
    let prompt = Message {
        role: "user".to_string(),
        content: Some(
            "判断下述用户任务的难度，仅回复 easy 或 hard：\n".to_string()
                + &messages.last().and_then(|m| m.content.clone()).unwrap_or_default(),
        ),
        tool_calls: None,
        tool_call_id: None,
    };
    match client.chat(&[prompt], &[]).await {
        Ok(r) if r.text.to_lowercase().contains("hard") => TaskDifficulty::Hard,
        _ => TaskDifficulty::Easy,
    }
}

/// Best-of-N 启发式打分（零额外调用，作为 Judge 不可用时的回退）
fn score_heuristic(c: &LlmResponse, is_code: bool) -> f64 {
    let text = &c.text;
    let len = text.chars().count();
    if len == 0 {
        return f64::NEG_INFINITY;
    }
    let mut s = (len.min(1500) as f64) * 0.01;
    let low = text.to_lowercase();
    if low.contains("抱歉")
        || low.contains("i cannot")
        || low.contains("作为ai")
        || low.contains("我无法")
        || low.contains("i'm unable")
        || low.contains("i am unable")
    {
        s -= 50.0;
    }
    if is_code {
        if text.contains("```") {
            s += 20.0;
        }
        if text.contains("fn ")
            || text.contains("def ")
            || text.contains("function ")
            || text.contains("impl ")
        {
            s += 10.0;
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
