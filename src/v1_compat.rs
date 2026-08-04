//! OpenAI `/v1/chat/completions` 入参折叠（契约层）。
//!
//! 历史坑：只取最后一条 user、丢弃 system —— Jan 把附件/指令放进 system 时分析必失败。
//! 本模块把 system 折叠进当前用户消息（后缀），并抽出 user/assistant 历史供会话。

/// 折叠结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1FoldedInput {
    /// 发给 agent 的当前用户文本（可能已附加 system 上下文）
    pub user_message: String,
    /// 除当前 user 外的 user/assistant 历史（时间正序）
    pub history: Vec<(String, String)>,
    /// 原始 system 拼接（便于测试/观测）；已截断
    pub system_ctx: String,
}

const SYSTEM_SUFFIX_CAP: usize = 16_000;
const USER_CAP: usize = 32_768;

/// 从 OpenAI 风格 messages 折叠出 agent-core 入参。
///
/// - 当前消息 = 最后一条 `user`（避免把 assistant 自我介绍拼进 user 导致空转）
/// - 所有 `system` 拼成上下文，缀在 user 后（保留客户端指令/附件元数据）
/// - history = 其余 user/assistant（跳过当前这条 user）
pub fn fold_v1_messages(messages: &[(String, String)]) -> V1FoldedInput {
    let system_raw: String = messages
        .iter()
        .filter(|(role, _)| role.eq_ignore_ascii_case("system"))
        .map(|(_, c)| c.as_str())
        .filter(|t| !t.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    let system_ctx: String = system_raw.chars().take(SYSTEM_SUFFIX_CAP).collect();

    let raw_last = messages
        .iter()
        .rev()
        .find(|(role, _)| role.eq_ignore_ascii_case("user"))
        .map(|(_, c)| c.as_str())
        .unwrap_or("");
    // 附件消息（File:/Sheet: 块）容量大：两份 xlsx 全文可达 7 万字符，32768 会截掉第二份
    let cap = if raw_last.contains("File: ") && (raw_last.contains("# Sheet:") || raw_last.contains("附件正文")) {
        100_000
    } else {
        USER_CAP
    };
    let last_user: String = raw_last.chars().take(cap).collect();

    // 历史：过滤后跳过「最后一条 user」的那一次出现
    let mut history: Vec<(String, String)> = Vec::new();
    let mut skipped_last_user = false;
    for (role, content) in messages.iter().rev() {
        if role.eq_ignore_ascii_case("system") {
            continue;
        }
        if !role.eq_ignore_ascii_case("user") && !role.eq_ignore_ascii_case("assistant") {
            continue;
        }
        if !skipped_last_user && role.eq_ignore_ascii_case("user") {
            skipped_last_user = true;
            continue;
        }
        history.push((role.clone(), content.clone()));
    }
    history.reverse();

    let user_message = compose_user_with_system(&last_user, &system_ctx);
    V1FoldedInput {
        user_message,
        history,
        system_ctx,
    }
}

/// 把 system 上下文缀到 user 文本后（空 system 则原样返回）。
pub fn compose_user_with_system(user: &str, system_ctx: &str) -> String {
    let user = user.trim_end();
    let sys = system_ctx.trim();
    if sys.is_empty() {
        return user.to_string();
    }
    format!("{}\n\n【客户端 system 上下文】\n{}", user, sys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_last_user_and_folds_system() {
        let msgs = vec![
            ("system".into(), "附件: report.pdf 正文略".into()),
            ("user".into(), "上一轮".into()),
            ("assistant".into(), "好的".into()),
            ("user".into(), "请分析附件".into()),
        ];
        let f = fold_v1_messages(&msgs);
        assert!(f.user_message.starts_with("请分析附件"));
        assert!(f.user_message.contains("【客户端 system 上下文】"));
        assert!(f.user_message.contains("report.pdf"));
        assert_eq!(f.history.len(), 2);
        assert_eq!(f.history[0].0, "user");
        assert_eq!(f.history[1].0, "assistant");
    }

    #[test]
    fn empty_system_passthrough() {
        let msgs = vec![("user".into(), "你好".into())];
        let f = fold_v1_messages(&msgs);
        assert_eq!(f.user_message, "你好");
        assert!(f.system_ctx.is_empty());
        assert!(f.history.is_empty());
    }

    #[test]
    fn ignores_non_ua_roles_in_history() {
        let msgs = vec![
            ("tool".into(), "should skip".into()),
            ("user".into(), "q".into()),
        ];
        let f = fold_v1_messages(&msgs);
        assert_eq!(f.user_message, "q");
        assert!(f.history.is_empty());
    }
}
