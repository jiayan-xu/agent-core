//! 外发消息凭证脱敏（传输层，对齐 GenOffice loop.ts `sanitizeAgentPayload`）。
//!
//! 背景：用户可能把 API key / URL 密码 / 密钥赋值误粘贴进对话，若原样发给远端
//! LLM provider 即泄露。本模块在 LLM 载荷构建前对 `role=user` 消息做脱敏替换，
//! 纯字符扫描实现（无 regex 依赖），规则：
//!   1. `sk-` / `AIza` / `ghp_` / `secret_` 前缀 + ≥16 位字母数字下划线横杠 → `[REDACTED_API_KEY]`
//!      （前缀匹配不区分大小写；匹配前要求词边界，避免误伤 `task-...` / `secret_config_...` 等普通词）
//!   2. `scheme://user:pass@host`（URL userinfo）→ `scheme://user:[REDACTED_CREDENTIALS]@host`
//!      （scheme 识别不区分大小写；userinfo 分隔符取最后一个 `@`，RFC 3986 语义）
//!   3. `password|passwd|secret_key|private_key` 赋值（`=`/`:` 后引号包裹值）→ `[REDACTED_SECURE_TOKEN]`
//!      （收尾引号扫描跳过 `\` 转义序列、遇换行即止，防跨行/转义引号导致漏脱敏或过度脱敏）

/// 快速判定文本是否**需要**脱敏（非分配实现，供调用方在常见无敏感路径上零成本短路；
/// ocr 2026-08-12 第二轮 perf·medium：sanitize_messages 的检测 pass 不得再整段分配）。
/// 检测：规则 1/2/3 任一触发模式存在即返回 true。逻辑与 `sanitize_agent_payload`
/// 保持同源（触发条件一致，只做存在性判断，不重建输出）。
pub fn needs_redaction(payload: &str) -> bool {
    let chars: Vec<char> = payload.chars().collect();
    let n = chars.len();
    let starts_with_ci = |i: usize, pat: &str| -> bool {
        let pb = pat.as_bytes();
        if i + pb.len() > n {
            return false;
        }
        pb.iter()
            .enumerate()
            .all(|(k, &b)| chars[i + k].to_ascii_lowercase() as u8 == b)
    };
    let at_word_boundary = |i: usize| -> bool {
        i == 0
            || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_' || chars[i - 1] == '-')
    };
    let consume_token_chars = |mut j: usize| -> (usize, bool) {
        let start = j;
        let mut has_underscore = false;
        while j < n && (chars[j].is_ascii_alphanumeric() || chars[j] == '_' || chars[j] == '-') {
            if chars[j] == '_' {
                has_underscore = true;
            }
            j += 1;
        }
        (j - start, has_underscore)
    };
    let mut i = 0usize;
    while i < n {
        // 规则 1：API key 前缀
        let prefix_matched = ["sk-", "aiza", "ghp_", "secret_"]
            .iter()
            .find(|p| at_word_boundary(i) && starts_with_ci(i, p));
        if let Some(p) = prefix_matched {
            let (token_len, has_underscore) = consume_token_chars(i + p.len());
            if token_len >= 16 && !has_underscore {
                return true;
            }
        }
        // 规则 2：URL userinfo（scheme://...:...@...）
        if chars[i] == ':' && starts_with_ci(i, "://") {
            let mut scheme_start = i;
            while scheme_start > 0 && chars[scheme_start - 1].is_ascii_alphabetic() {
                scheme_start -= 1;
            }
            let scheme_len = i - scheme_start;
            if (1..=32).contains(&scheme_len) {
                if let Some(at) = find_userinfo_at(&chars, i) {
                    if find_userinfo_colon(&chars, i, at).is_some() {
                        return true;
                    }
                }
            }
        }
        // 规则 3：密钥赋值
        let key_len = if starts_with_ci(i, "secret_key") {
            10
        } else if starts_with_ci(i, "private_key") {
            11
        } else if starts_with_ci(i, "password") {
            8
        } else if starts_with_ci(i, "passwd") {
            6
        } else {
            0
        };
        if key_len > 0 {
            let mut j = i + key_len;
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
                    if find_closing_quote(&chars, k + 1, quote).is_some() {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

/// 对一段文本做脱敏。普通对话（含 "a:b@c" 这类无 scheme 的写法）不会被改写。
pub fn sanitize_agent_payload(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len());
    let chars: Vec<char> = payload.chars().collect();
    let n = chars.len();
    let mut i = 0usize;

    // 检查从 i 起是否匹配指定的 ASCII 序列（大小写不敏感；pattern 全小写，比较时 char 转小写）
    let starts_with_ci = |i: usize, pat: &str| -> bool {
        let pb = pat.as_bytes();
        if i + pb.len() > n {
            return false;
        }
        pb.iter().enumerate().all(|(k, &b)| {
            chars[i + k].to_ascii_lowercase() as u8 == b
        })
    };

    // 词边界：i 之前必须是「非 token 字符」（防 task-123... 里的 sk- 误命中）
    let at_word_boundary = |i: usize| -> bool {
        i == 0
            || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_' || chars[i - 1] == '-')
    };

    // 消费 [A-Za-z0-9_-]，返回消费掉的字符数；同时检测 token 内是否含下划线
    // （真实 API key 不含 `_`；snake_case 标识符如 secret_config_management_v2_2024 含
    //  `_` → 不视为 key，防误伤，ocr 2026-08-12）
    let consume_token_chars = |mut j: usize| -> (usize, bool) {
        let start = j;
        let mut has_underscore = false;
        while j < n && (chars[j].is_ascii_alphanumeric() || chars[j] == '_' || chars[j] == '-') {
            if chars[j] == '_' {
                has_underscore = true;
            }
            j += 1;
        }
        (j - start, has_underscore)
    };

    while i < n {
        let c = chars[i];
        // 规则 1：API key 前缀（大小写不敏感 + 词边界 + token 无下划线）
        let prefix_matched = ["sk-", "aiza", "ghp_", "secret_"]
            .iter()
            .find(|p| at_word_boundary(i) && starts_with_ci(i, p));
        if let Some(p) = prefix_matched {
            let (token_len, has_underscore) = consume_token_chars(i + p.len());
            if token_len >= 16 && !has_underscore {
                out.push_str("[REDACTED_API_KEY]");
                i += p.len() + token_len;
                continue;
            }
        }
        // 规则 2：URL userinfo（scheme://user:pass@，且 @ 在首个 / 或空白之前）
        // 触发点 = ':' 位置；scheme 字符（如 https 的 h..s）已在此前按原样输出，
        // 因此只需补 "://" + user: + 遮蔽密码。
        if c == ':' && starts_with_ci(i, "://") {
            // 回找 scheme 起点（连续 ASCII 字母，大小写均可；RFC 3986 scheme 大小写不敏感）
            let mut scheme_start = i;
            while scheme_start > 0 && chars[scheme_start - 1].is_ascii_alphabetic() {
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
        // 规则 3：密钥赋值 key = "value" / key: "value"（key 大小写不敏感）
        let key_len = if starts_with_ci(i, "secret_key") {
            10
        } else if starts_with_ci(i, "private_key") {
            11
        } else if starts_with_ci(i, "password") {
            8
        } else if starts_with_ci(i, "passwd") {
            6
        } else {
            0
        };
        if key_len > 0 {
            // 允许 key 后空格
            let mut j = i + key_len;
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
                    // 找收尾引号：跳过 `\` 转义序列、遇换行/回车即止（不跨行），
                    // 避免转义引号提前截断（漏脱敏）或末尾无关引号跨行过度脱敏。
                    if let Some(close_rel) = find_closing_quote(&chars, k + 1, quote) {
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

/// 从 `start` 起寻找与 `quote` 匹配的收尾引号：
/// - 遇 `\` 跳过下一字符（转义引号不算收尾）
/// - 遇 `\n`/`\r` 返回 None（不跨行）
fn find_closing_quote(chars: &[char], start: usize, quote: char) -> Option<usize> {
    let mut j = start;
    while j < chars.len() {
        match chars[j] {
            '\\' => j += 2, // 跳过转义序列（含 \" 本身）
            '\n' | '\r' => return None,
            q if q == quote => return Some(j - start),
            _ => j += 1,
        }
    }
    None
}

/// 在 `://` 之后寻找 URL userinfo 的 `@`：必须出现在首个 `/`、`?`、`#` 或空白之前。
/// 多个 `@` 时取**最后一个**（RFC 3986：userinfo 内嵌 @ 须百分号编码，最后一个才是分隔符）。
/// `colon_pos` 为 ':' 的位置（"://" 起点）。
fn find_userinfo_at(chars: &[char], colon_pos: usize) -> Option<usize> {
    let mut j = colon_pos + 3; // 跳过 "://"
    let mut last_at: Option<usize> = None;
    while j < chars.len() {
        match chars[j] {
            '@' => {
                last_at = Some(j);
                j += 1;
            }
            '/' | '?' | '#' | ' ' | '\t' | '\n' | '\r' => return last_at,
            _ => j += 1,
        }
    }
    last_at
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
    fn uppercase_prefixes_redacted() {
        // ocr 2026-08-12: 大写变体（SK- / GHP_ / SECRET_）此前漏脱敏
        assert_eq!(
            sanitize_agent_payload("SK-ABCDEFGHIJKLMNOPQRSTUVWX"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("GHP_ABCDEFGHIJKLMNOPQRSTUVWX"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("SECRET_ABCDEFGHIJKLMNOPQRSTUVWX"),
            "[REDACTED_API_KEY]"
        );
    }

    #[test]
    fn word_boundary_prevents_false_positive() {
        // ocr 2026-08-12: 普通词内含 sk- 前缀（task-123...）此前被误脱敏
        assert_eq!(
            sanitize_agent_payload("task-1234567890abcdefgh"),
            "task-1234567890abcdefgh"
        );
        assert_eq!(
            sanitize_agent_payload("secret_config_management_v2_2024"),
            "secret_config_management_v2_2024"
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
    fn uppercase_scheme_redacted() {
        // ocr 2026-08-12: 大写 scheme（HTTPS://）此前 scheme_len=0 完全不触发
        assert_eq!(
            sanitize_agent_payload("connect HTTPS://admin:hunter2@example.com/db"),
            "connect HTTPS://admin:[REDACTED_CREDENTIALS]@example.com/db"
        );
    }

    #[test]
    fn multi_at_uses_last_delimiter() {
        // ocr 2026-08-12: 密码内含 @ 时取最后一个 @ 为分隔符，避免明文泄漏后半段
        assert_eq!(
            sanitize_agent_payload("https://user:p@ss@host.com/x"),
            "https://user:[REDACTED_CREDENTIALS]@host.com/x"
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
    fn uppercase_keyword_redacted() {
        assert_eq!(
            sanitize_agent_payload("Password = \"hunter2\""),
            "Password = \"[REDACTED_SECURE_TOKEN]\""
        );
    }

    #[test]
    fn escaped_quote_handled() {
        // ocr 2026-08-12: 转义引号（password = "a\"b"）此前只遮蔽 a\" 剩余 b" 明文泄漏
        assert_eq!(
            sanitize_agent_payload("password = \"a\\\"b\""),
            "password = \"[REDACTED_SECURE_TOKEN]\""
        );
    }

    #[test]
    fn unterminated_quote_not_crossing_line() {
        // ocr 2026-08-12: 未闭合引号 + 后续行无关引号，此前会跨行过度脱敏
        assert_eq!(
            sanitize_agent_payload("password = \"abc\n后面还有内容\"继续"),
            "password = \"abc\n后面还有内容\"继续"
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
