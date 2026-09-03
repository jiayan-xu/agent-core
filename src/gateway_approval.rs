//! 分级审批（2026-09-03 用户方针）：重大操作（不可逆删除/大范围修改）人工；
//! 其余可逆写操作由廉价 LLM judge 判定自动批准；fail-safe 落人工；全程审计 + 可撤销。
//!
//! ADR-016 修订：网关**执行路径**仍无 LLM；仅审批分级允许一次可配置的 judge 调用
//! （[gateway_approval]），judge 失败/超时/解析失败一律按人工处理（fail-safe），
//! 判定与执行全部落审计（audit_events.db）与审批权威表（approvals，status=AutoApproved）。

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

/// [gateway_approval] 配置（agent.toml）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayApprovalConfig {
    /// human_all = 现状（全部人工，零行为变化，默认）；llm_auto = 启用分级自动审批
    #[serde(default = "default_mode")]
    pub mode: String,
    /// LLM 自动判定区工具名单（硬人工名单永远优先，名单内工具不可进自动区）
    #[serde(default = "default_auto_tools")]
    pub auto_tools: Vec<String>,
    /// 每人每日自动批准上限（超限自动落人工，防 LLM 被诱导刷写）
    #[serde(default = "default_daily_quota")]
    pub daily_quota: u32,
    /// judge 调用超时（毫秒）
    #[serde(default = "default_judge_timeout_ms")]
    pub judge_timeout_ms: u64,
    /// 独立 judge provider（base_url/model/api_key/chat_path）。缺省 = 主 [llm]
    /// 的第一个 fallback（通常更快），再退主 provider。judge 需要快而稳的分类模型。
    #[serde(default)]
    pub judge: Option<crate::llm::LlmProvider>,
}

fn default_mode() -> String {
    "human_all".to_string()
}
fn default_daily_quota() -> u32 {
    50
}
fn default_judge_timeout_ms() -> u64 {
    8000
}
fn default_auto_tools() -> Vec<String> {
    vec![
        "manage_whitelist",   // 单牌增删改（软删可逆；sync_whitelist_plates 大范围在硬人工区）
        "fill_excel_log",     // 台账填写（可重写）
        "generate_month_log", // 月报生成（可再生）
        "manage_holiday",
        "organize_folders",
        "archive_operate",
        "manage_samples",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

impl Default for GatewayApprovalConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            auto_tools: default_auto_tools(),
            daily_quota: default_daily_quota(),
            judge_timeout_ms: default_judge_timeout_ms(),
            judge: None,
        }
    }
}

impl GatewayApprovalConfig {
    pub fn llm_auto_enabled(&self) -> bool {
        self.mode.trim().eq_ignore_ascii_case("llm_auto")
    }
}

/// 硬人工区：LLM 无权放行。与 boundary 的 is_dangerous_floor 前缀同源 +
/// 显式名单（不可逆删除 / 大范围同步 / 关停 / 外泄 / 身份变更）。
pub const HUMAN_ALWAYS_TOOLS: &[&str] = &[
    "delete_entrance_record",
    "batch_update_whitelist",
    "sync_whitelist_plates", // 大范围同步（全量白名单）
    "batch_delete_memories",
    "memory_import",
    "memory_export", // 导出 = 外泄红线
    "local_fs_write",
    "write_text",
    "append_text",
    "move_file",
    "delete_path",
    "scenario_commit",
    "evolution_rollback",
    "agent_revoke",
    "register_agent",
    "shutdown_agent",
    "shutdown_server",
    "sync_exception_correction", // 批量纠正，范围大
];

const HUMAN_ALWAYS_PREFIXES: &[&str] = &[
    "delete_", "batch_delete", "shutdown_", "drop_", "truncate_", "purge_", "destroy_",
    "wipe_", "format_", "reset_", "revoke_", "ban_", "kill_", "rm_",
];

#[derive(Debug, Clone)]
pub struct AutoPolicy {
    auto_tools: HashSet<String>,
}

impl AutoPolicy {
    pub fn from_config(cfg: &GatewayApprovalConfig) -> Self {
        let mut set: HashSet<String> = cfg
            .auto_tools
            .iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        // 硬人工名单永远赢：即便误配进 auto_tools 也剔除
        for t in HUMAN_ALWAYS_TOOLS {
            set.remove(*t);
        }
        Self { auto_tools: set }
    }

    /// 工具是否落在硬人工区（名单或前缀命中）
    pub fn human_always(&self, tool: &str) -> bool {
        let t = tool.to_lowercase();
        HUMAN_ALWAYS_TOOLS.iter().any(|x| *x == t)
            || HUMAN_ALWAYS_PREFIXES.iter().any(|p| t.starts_with(p))
    }

    /// 工具是否在自动判定区（且不在硬人工区）
    pub fn in_auto_zone(&self, tool: &str) -> bool {
        !self.human_always(tool) && self.auto_tools.contains(&tool.to_lowercase())
    }
}

/// judge 判定结果
#[derive(Debug, Clone, Serialize)]
pub struct RiskVerdict {
    pub auto: bool,
    pub reason: String,
    /// judge 使用的模型（审计用）
    pub model: String,
    pub elapsed_ms: u64,
}

const JUDGE_SYSTEM_PROMPT: &str = r#"你是写操作风险判定器。给定工具与参数，判断该操作能否**无人值守自动执行**。
自动执行的条件（全部满足）：单记录/小范围、可逆或可重做、不影响他人数据、不删除不可恢复内容。
需要人工的条件（任一）：删除/不可逆、批量/大范围影响、修改他人或共享关键数据、权限/身份变更、导出数据。
只输出 JSON：{"auto": true|false, "reason": "≤40字中文理由"}"#;

/// 廉价风险判定。任何失败（超时/HTTP/解析）→ auto=false + reason（fail-safe 落人工）。
pub async fn judge_risk(
    client: &crate::llm::LlmClient,
    tool: &str,
    args: &serde_json::Value,
    timeout_ms: u64,
) -> RiskVerdict {
    judge_risk_with(client, None, tool, args, timeout_ms).await
}

/// cfg.judge 提供时优先用之（快模型），否则用传入的主 client。
pub async fn judge_risk_with(
    client: &crate::llm::LlmClient,
    judge_cfg: Option<&crate::llm::LlmProvider>,
    tool: &str,
    args: &serde_json::Value,
    timeout_ms: u64,
) -> RiskVerdict {
    if let Some(p) = judge_cfg {
        let dedicated = crate::llm::LlmClient::new(crate::llm::LlmConfig {
            base_url: p.base_url.clone(),
            model: p.model.clone(),
            api_key: p.api_key.clone(),
            chat_path: p.chat_path.clone(),
            max_tokens: 256,
            temperature: 0.1,
            fallbacks: vec![],
            difficulty: Default::default(),
        });
        return judge_risk_impl(&dedicated, tool, args, timeout_ms).await;
    }
    judge_risk_impl(client, tool, args, timeout_ms).await
}

async fn judge_risk_impl(
    client: &crate::llm::LlmClient,
    tool: &str,
    args: &serde_json::Value,
    timeout_ms: u64,
) -> RiskVerdict {
    let t0 = std::time::Instant::now();
    let args_str = serde_json::to_string(args).unwrap_or_default();
    let summary: String = if args_str.chars().count() > 1200 {
        let cut: String = args_str.chars().take(1200).collect();
        format!("{}…(截断)", cut)
    } else {
        args_str
    };
    let user_msg = format!("工具: {}\n参数: {}", tool, summary);
    let messages = vec![
        crate::llm::Message {
            role: "system".into(),
            content: Some(JUDGE_SYSTEM_PROMPT.to_string()),
            tool_calls: None,
            tool_call_id: None,
        },
        crate::llm::Message {
            role: "user".into(),
            content: Some(user_msg),
            tool_calls: None,
            tool_call_id: None,
        },
    ];
    let fut = client.chat(&messages, &[]);
    let model = client.model_desc().to_string();
    match tokio::time::timeout(Duration::from_millis(timeout_ms.max(1000)), fut).await {
        Err(_) => RiskVerdict {
            auto: false,
            reason: format!("judge 超时({}ms)，fail-safe 转人工", timeout_ms),
            model,
            elapsed_ms: t0.elapsed().as_millis() as u64,
        },
        Ok(Err(e)) => RiskVerdict {
            auto: false,
            reason: format!("judge 失败({})，fail-safe 转人工", truncate(&e, 60)),
            model,
            elapsed_ms: t0.elapsed().as_millis() as u64,
        },
        Ok(Ok(resp)) => {
            let elapsed = t0.elapsed().as_millis() as u64;
            match parse_verdict(&resp.text) {
                Some((auto, reason)) => RiskVerdict {
                    auto,
                    reason,
                    model,
                    elapsed_ms: elapsed,
                },
                None => RiskVerdict {
                    auto: false,
                    reason: format!("judge 输出不可解析({})", truncate(&resp.text, 60)),
                    model,
                    elapsed_ms: elapsed,
                },
            }
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// 从 LLM 文本稳健提取 {"auto":bool,"reason":str}（容忍围栏/闲话）
pub fn parse_verdict(text: &str) -> Option<(bool, String)> {
    let s = text.trim();
    let s = s
        .strip_prefix("```json")
        .or_else(|| s.strip_prefix("```"))
        .unwrap_or(s);
    let s = s.strip_suffix("```").unwrap_or(s).trim();
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end < start {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&s[start..=end]).ok()?;
    let auto = v.get("auto").and_then(|a| a.as_bool())?;
    let reason = v
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .chars()
        .take(80)
        .collect::<String>();
    Some((auto, reason))
}

/// 改前状态抓取：返回 (before_state, undo_args)。
/// 首批仅 manage_whitelist（行级可逆）；其余自动区工具返回 None（不可撤销但可审计）。
pub fn build_undo_for(tool: &str, executed_args: &serde_json::Value, before: Option<&serde_json::Value>) -> Option<serde_json::Value> {
    if tool != "manage_whitelist" {
        return None;
    }
    let action = executed_args.get("action").and_then(|a| a.as_str())?.to_lowercase();
    let plate = executed_args.get("plate").and_then(|p| p.as_str())?.to_string();
    match action.as_str() {
        // add 的逆 = remove（软删可逆，remove 的逆在 before 行里有）
        "add" => Some(serde_json::json!({"action": "remove", "plate": plate, "confirmed": true})),
        // remove/update 的逆 = 用改前行恢复（add 回原值或 update 回原值）
        "remove" | "update_company" | "update_waste_type" => {
            let b = before?;
            if b.get("found").and_then(|f| f.as_bool()).unwrap_or(false) == false {
                // 改前就不在白名单：逆 = remove
                return Some(serde_json::json!({"action": "remove", "plate": plate, "confirmed": true}));
            }
            let company = b.get("company").and_then(|c| c.as_str()).unwrap_or("");
            let waste = b.get("waste_type").and_then(|c| c.as_str()).unwrap_or("");
            let undo_action = if action == "remove" { "add" } else { "update_company" };
            let mut undo = serde_json::json!({
                "action": undo_action, "plate": plate,
                "company_name": company, "waste_type": waste, "confirmed": true,
            });
            if action == "update_waste_type" {
                undo["action"] = serde_json::json!("update_waste_type");
            }
            Some(undo)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_always_by_name_and_prefix() {
        let p = AutoPolicy::from_config(&GatewayApprovalConfig::default());
        assert!(p.human_always("sync_whitelist_plates"));
        assert!(p.human_always("delete_entrance_record"));
        assert!(p.human_always("DELETE_WHATEVER")); // 前缀 + 大小写
        assert!(p.human_always("rm_rf_home"));
        assert!(!p.human_always("manage_whitelist"));
    }

    #[test]
    fn auto_zone_excludes_human_tools_even_if_misconfigured() {
        let cfg = GatewayApprovalConfig {
            auto_tools: vec!["manage_whitelist".into(), "sync_whitelist_plates".into()],
            ..Default::default()
        };
        let p = AutoPolicy::from_config(&cfg);
        assert!(p.in_auto_zone("manage_whitelist"));
        assert!(!p.in_auto_zone("sync_whitelist_plates")); // 硬名单赢
        assert!(!p.in_auto_zone("unknown_tool"));
    }

    #[test]
    fn parse_verdict_variants() {
        assert_eq!(parse_verdict(r#"{"auto": true, "reason": "单牌可逆"}"#).unwrap().0, true);
        assert_eq!(
            parse_verdict("```json\n{\"auto\": false, \"reason\": \"批量操作\"}\n```")
                .unwrap()
                .0,
            false
        );
        assert!(parse_verdict("模型抽风").is_none());
        assert!(parse_verdict(r#"{"reason": "缺 auto"}"#).is_none());
    }

    #[test]
    fn undo_add_is_remove() {
        let u = build_undo_for(
            "manage_whitelist",
            &serde_json::json!({"action":"add","plate":"鲁A11111"}),
            None,
        )
        .unwrap();
        assert_eq!(u["action"], "remove");
        assert_eq!(u["confirmed"], true);
    }

    #[test]
    fn undo_remove_restores_before_row() {
        let before = serde_json::json!({"found": true, "company": "某公司", "waste_type": "农林垃圾"});
        let u = build_undo_for(
            "manage_whitelist",
            &serde_json::json!({"action":"remove","plate":"鲁B22222"}),
            Some(&before),
        )
        .unwrap();
        assert_eq!(u["action"], "add");
        assert_eq!(u["company_name"], "某公司");
    }

    #[test]
    fn undo_update_uses_before_value() {
        let before = serde_json::json!({"found": true, "company": "旧公司", "waste_type": "旧种类"});
        let u = build_undo_for(
            "manage_whitelist",
            &serde_json::json!({"action":"update_waste_type","plate":"鲁C33333","waste_type":"新种类"}),
            Some(&before),
        )
        .unwrap();
        assert_eq!(u["action"], "update_waste_type");
        assert_eq!(u["waste_type"], "旧种类");
    }
}
