//! 外发消息凭证脱敏（传输层，对齐 GenOffice loop.ts `sanitizeAgentPayload`）。
//!
//! 背景：用户可能把 API key / URL 密码 / 密钥赋值误粘贴进对话，若原样发给远端
//! LLM provider 即泄露。本模块在 LLM 载荷构建前对 `role=user` 消息做脱敏替换，
//! 纯字符扫描实现（无 regex 依赖），规则：
//!   1. `sk-` / `AIza` / `ghp_` / `secret_` 前缀 + ≥16 位字母数字下划线横杠 → `[REDACTED_API_KEY]`
//!   2. `scheme://user:pass@host`（URL userinfo）→ `scheme://user:[REDACTED_CREDENTIALS]@host`
//!   3. `password|passwd|secret_key|private_key` 赋值（`=`/`:` 后引号包裹值）→ `[REDACTED_SECURE_TOKEN]`

/// 对一段文本做脱敏。普通对话（含 "a:b@c" 这类无 scheme 的写法）不会被改写。
pub fn sanitize_agent_payload(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len());
    let chars: Vec<char> = payload.chars().collect();
    let n = chars.len();
    let mut i = 0usize;

    // 检查从 i 起是否匹配指定的字符序列（全 ASCII，char 级比较即可）
    let starts_with = |i: usize, pat: &str| -> bool {
        let pc: Vec<char> = pat.chars().collect();
        if i + pc.len() > n {
            return false;
        }
        (0..pc.len()).all(|k| chars[i + k] == pc[k])
    };

    // 消费 [A-Za-z0-9_-]，返回消费掉的字符数
    let consume_token_chars = |mut j: usize| -> usize {
        let start = j;
        while j < n && (chars[j].is_ascii_alphanumeric() || chars[j] == '_' || chars[j] == '-') {
            j += 1;
        }
        j - start
    };

    while i < n {
        let c = chars[i];
        // 规则 1：API key 前缀
        let prefix_matched = ["sk-", "AIza", "ghp_", "secret_"]
            .iter()
            .find(|p| starts_with(i, p));
        if let Some(p) = prefix_matched {
            let token_len = consume_token_chars(i + p.len());
            if token_len >= 16 {
                out.push_str("[REDACTED_API_KEY]");
                i += p.len() + token_len;
                continue;
            }
        }
        // 规则 2：URL userinfo（scheme://user:pass@，且 @ 在首个 / 或空白之前）
        // 触发点 = ':' 位置；scheme 字符（如 https 的 h..s）已在此前按原样输出，
        // 因此只需补 "://" + user: + 遮蔽密码。
        if c == ':' && starts_with(i, "://") {
            // 回找 scheme 起点（连续小写字母，如 http 的 'h'）
            let mut scheme_start = i;
            while scheme_start > 0 && chars[scheme_start - 1].is_ascii_lowercase() {
                scheme_start -= 1;
            }
            let scheme_len = i - scheme_start;
            if (1..=32).contains(&scheme_len) {
                if let Some(at) = find_userinfo_at(&chars, i) {
                    if let Some(colon_rel) = find_userinfo_colon(&chars, i, at) {
                        // 保留 "://" 与 "user:"，仅遮蔽密码
                        out.push_str("://");
                        out.push_str(&chars[i + 3..colon_rel + 1].iter().collect::<String>());
                        out.push_str("[REDACTED_CREDENTIALS]@");
                        i = at + 1; // 跳到 @ 之后
                        continue;
                    }
                }
            }
        }
        // 规则 3：密钥赋值 key = "value" / key: "value"
        if (starts_with(i, "password") || starts_with(i, "passwd")
            || starts_with(i, "secret_key") || starts_with(i, "private_key"))
        {
            let key_end = i + if starts_with(i, "secret_key") { 10 } else if starts_with(i, "private_key") { 11 } else if starts_with(i, "password") { 8 } else { 6 };
            // 允许 key 后空格
            let mut j = key_end;
            while j < n && (chars[j] == ' ' || chars[j] == '\t') {
                j += 1;
            }
            if j < n && (chars[j] == '=' || chars[j] == ':') {
                let mut k = j + 1;
                while k < n && (chars[k] == ' ' || chars[k] == '\t') {
                    k += 1;
                }
                if k < n && (chars[k] == '"' || chars[k] == '\'') {
                    let quote = chars[k];
                    // 找到收尾引号（不跨行）
                    if let Some(close_rel) = chars[k + 1..]
                        .iter()
                        .position(|&q| q == quote && q != '\n')
                    {
                        out.push_str(&chars[i..k + 1].iter().collect::<String>());
                        out.push_str("[REDACTED_SECURE_TOKEN]");
                        out.push(quote);
                        i = k + 1 + close_rel + 1;
                        continue;
                    }
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// 在 `://` 之后寻找 URL userinfo 的 `@`：必须出现在首个 `/`、`?`、`#` 或空白之前。
/// `colon_pos` 为 ':' 的位置（"://" 起点）。
fn find_userinfo_at(chars: &[char], colon_pos: usize) -> Option<usize> {
    let mut j = colon_pos + 3; // 跳过 "://"
    while j < chars.len() {
        match chars[j] {
            '@' => return Some(j),
            '/' | '?' | '#' | ' ' | '\t' | '\n' | '\r' => return None,
            _ => j += 1,
        }
    }
    None
}

/// 在 `://` 与 `@` 之间找 `:`（userinfo 的 user:pass 分隔）。无冒号则不算凭据（如 "user@host"）。
fn find_userinfo_colon(chars: &[char], colon_pos: usize, at: usize) -> Option<usize> {
    let mut j = colon_pos + 3;
    while j < at {
        if chars[j] == ':' {
            return Some(j);
        }
        j += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_api_key_prefixes() {
        assert_eq!(
            sanitize_agent_payload("use sk-abc1234567890abcdefgh"),
            "use [REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("AIzaSyA1234567890abcdefghijklmnopqrstuv"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("ghp_1234567890abcdefghijkl"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("secret_abcdefghijklmnopqrstuvwxyz1"),
            "[REDACTED_API_KEY]"
        );
    }

    #[test]
    fn short_tokens_untouched() {
        // 不足 16 位不脱敏（避免误伤普通词，如 "secret_ok"）
        assert_eq!(sanitize_agent_payload("secret_ok"), "secret_ok");
        assert_eq!(sanitize_agent_payload("sk-x"), "sk-x");
    }

    #[test]
    fn redacts_url_userinfo() {
        assert_eq!(
            sanitize_agent_payload("connect https://admin:hunter2@example.com:5432/db"),
            "connect https://admin:[REDACTED_CREDENTIALS]@example.com:5432/db"
        );
    }

    #[test]
    fn plain_userhost_untouched() {
        // 无 scheme 或无人:pass 分隔，不脱敏
        assert_eq!(sanitize_agent_payload("a:b@c"), "a:b@c");
        assert_eq!(sanitize_agent_payload("user@host.com"), "user@host.com");
    }

    #[test]
    fn redacts_secret_assignments() {
        assert_eq!(
            sanitize_agent_payload("password = \"hunter2\""),
            "password = \"[REDACTED_SECURE_TOKEN]\""
        );
        assert_eq!(
            sanitize_agent_payload("secret_key: 'abc'"),
            "secret_key: '[REDACTED_SECURE_TOKEN]'"
        );
        assert_eq!(
            sanitize_agent_payload("private_key='xyz'"),
            "private_key='[REDACTED_SECURE_TOKEN]'"
        );
    }

    #[test]
    fn plain_text_untouched() {
        let s = "帮我查一下今天的固废进厂车辆，密码是进厂凭证";
        assert_eq!(sanitize_agent_payload(s), s);
    }

    #[test]
    fn mixed_content() {
        let out = sanitize_agent_payload(
            "db url=https://user:pass@host/x key=sk-1234567890abcdefghijklmnop",
        );
        assert!(out.contains("[REDACTED_CREDENTIALS]"), "got: {out}");
        assert!(out.contains("[REDACTED_API_KEY]"), "got: {out}");
    }
}
