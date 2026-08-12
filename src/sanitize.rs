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
//!
//! 覆盖边界（安全·low 文档化，ocr 2026-08-12 第三轮）：
//!   - 规则 3 仅覆盖**引号包裹**的值；无引号赋值（`key=abc`）与无 scheme 的
//!     `user:pass@host` 形式不在传输层脱敏范围（避免误伤正常对话文本），
//!     调用方须知悉该边界。

/// 快速判定文本是否**需要**脱敏（**零分配**实现：直接字节扫描，不物化 Vec；
/// ocr 2026-08-12 第二/三轮 perf·medium：sanitize_messages 的检测 pass 不得整段分配）。
/// 检测：规则 1/2/3 任一触发模式存在即返回 true。逻辑与 `sanitize_agent_payload`
/// 保持同源（触发条件一致，只做存在性判断，不重建输出）。
pub fn needs_redaction(payload: &str) -> bool {
    let bytes = payload.as_bytes();
    let n = bytes.len();
    // 字节级大小写不敏感前缀匹配（pattern 全 ASCII 小写；只对 ASCII 字节转小写，
    // ≥0x80 的多字节字符首字节与 ASCII pattern 永不相交，天然避免 Unicode 误匹配）
    let starts_with_ci = |i: usize, pat: &str| -> bool {
        let pb = pat.as_bytes();
        if i + pb.len() > n {
            return false;
        }
        pb.iter()
            .enumerate()
            .all(|(k, &b)| bytes[i + k].to_ascii_lowercase() == b)
    };
    // 词边界（规则 1 用）：i 之前必须是「非 token 字节」（防 task-123... 里的 sk- 误命中）
    let at_word_boundary = |i: usize| -> bool {
        i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric()
                || bytes[i - 1] == b'_'
                || bytes[i - 1] == b'-')
    };
    // 弱边界（规则 3 用）：i 之前仅要求「非字母数字」——允许 `_`/`-` 前缀，
    // 覆盖 DB_PASSWORD= / api_secret_key= 等常见 env/JSON 键名（ocr 2026-08-12
    // 第五轮 security·medium），同时仍挡 mypassword/resetpassword（前邻字母）。
    let at_weak_boundary = |i: usize| -> bool {
        i == 0 || !bytes[i - 1].is_ascii_alphanumeric()
    };
    // 消费 [A-Za-z0-9_-]，返回消费掉的字节数；同时检测 token 内是否含下划线
    let consume_token_bytes = |mut j: usize| -> (usize, bool) {
        let start = j;
        let mut has_underscore = false;
        while j < n
            && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'-')
        {
            if bytes[j] == b'_' {
                has_underscore = true;
            }
            j += 1;
        }
        (j - start, has_underscore)
    };
    // snake_case 标识符判定（第九/十轮 security·high 修正）：仅当 token 的 `_` 分隔段
    // **全部**为「纯小写字母单词段」或「版本段（纯数字 / v+数字）」**且至少含一个
    // 版本段**时，才判为 snake_case 标识符（误伤源，拒绝脱敏）。
    // 版本段是标识符的强特征（真实 API key 几乎不带 `_v2_`/`_2024` 版本号）：
    // - `secret_configuration_management_v2_2024`：单词段 + v2/2024 版本段 → 豁免 ✓
    // - `sk-proj_abcdefghijklmnop_qrstuvwxyz`（全小写随机段、无版本段）→ 脱敏 ✓
    // - 任何段含大写 / 字母数字混合（hex 随机段，如 9f8e7d6c）→ 脱敏 ✓
    let is_snake_case = |seg: &[u8]| -> bool {
        let segs: Vec<&[u8]> = seg
            .split(|&b| b == b'_')
            .filter(|s| !s.is_empty())
            .collect();
        if segs.is_empty() {
            return false;
        }
        let mut has_version = false;
        for s in &segs {
            if s.iter().all(|&b| b.is_ascii_lowercase()) {
                // 纯小写字母单词段（长度不限：configuration=13 也是单词）
            } else if s.len() >= 2
                && (s.iter().all(|&b| b.is_ascii_digit())
                    || (s[0] == b'v' && s[1..].iter().all(|&b| b.is_ascii_digit())))
            {
                has_version = true; // 版本段：纯数字（如 2024）或 v+数字（如 v2）
            } else {
                return false; // 含大写 / 字母数字混合（hex 随机段）→ 非标识符
            }
        }
        has_version
    };
    let mut i = 0usize;
    while i < n {
        // 规则 1：API key 前缀。覆盖常见真实格式（ocr 2026-08-12 第七轮 security·medium）：
        //   sk- / AIza / ghp_ / secret_ / sk_live_ / sk_test_ / hf_ / github_pat_ / AKIA…
        // 下划线处理（第八轮 security·high 修正）：不再「含 _ 即拒」——sk-proj_xxx_yyy
        // 等 OpenAI 新格式真实 key 含 _，直接拒绝会漏脱敏。改为 snake_case 形态判定：
        // token 的 _ 分隔段全部为「小写字母/数字且 ≤12 字符」才判为 snake_case 标识符
        // （secret_config_management_v2_2024）拒绝；任何含大写/长随机段的 token 放行。
        let prefix_matched = [
            "sk-", "aiza", "ghp_", "secret_", "sk_live_", "sk_test_", "hf_", "github_pat_", "akia",
        ]
        .iter()
        .find(|p| at_word_boundary(i) && starts_with_ci(i, p));
        if let Some(p) = prefix_matched {
            let (token_len, has_underscore) = consume_token_bytes(i + p.len());
            let snake_case = has_underscore
                && is_snake_case(&bytes[i + p.len()..i + p.len() + token_len]);
            if token_len >= 16 && !snake_case {
                return true;
            }
        }
        // 规则 2：URL userinfo（scheme://...:...@...）
        if bytes[i] == b':' && starts_with_ci(i, "://") {
            // RFC 3986 scheme = 字母开头 + [A-Za-z0-9+.-]*：s3://、git+ssh:// 等
            // 含数字/符号的 scheme 也要识别（ocr 2026-08-12 第五轮 security·medium；
            // 原实现仅回扫字母，s3:// 的 scheme_len 会算成 0 而漏脱敏）
            let mut scheme_start = i;
            while scheme_start > 0
                && (bytes[scheme_start - 1].is_ascii_alphanumeric()
                    || bytes[scheme_start - 1] == b'+'
                    || bytes[scheme_start - 1] == b'-'
                    || bytes[scheme_start - 1] == b'.')
            {
                scheme_start -= 1;
            }
            let scheme_len = i - scheme_start;
            // 首字符必须是字母（RFC 3986 scheme 约束），防「数字:」被误认。
            // （词边界由回扫循环本身保证：循环仅在 scheme 字符集 [A-Za-z0-9+.-]
            // 上回退，退出时 scheme 起点前一字符必非 scheme 字符——无需额外检查，
            // ocr 2026-08-12 第七轮指出此前 boundary_ok 为恒真死代码）
            let first_alpha = bytes[scheme_start].is_ascii_alphabetic();
            if first_alpha && (1..=32).contains(&scheme_len) {
                if let Some(at) = find_userinfo_at_bytes(bytes, i) {
                    if find_userinfo_colon_bytes(bytes, i, at).is_some() {
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
        // 规则 3：密钥赋值 key = "value" / key: "value"（key 大小写不敏感 + 弱边界）
        if key_len > 0 && at_weak_boundary(i) {
            let mut j = i + key_len;
            // JSON 风格键名（"password": "value"）：键名收尾引号后接 :，
            // 当前逻辑漏脱敏（ocr 2026-08-12 第四轮 security·high），此处跳过一个收尾引号
            if j < n && (bytes[j] == b'"' || bytes[j] == b'\'') {
                j += 1;
            }
            while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < n && (bytes[j] == b'=' || bytes[j] == b':') {
                let mut k = j + 1;
                while k < n && (bytes[k] == b' ' || bytes[k] == b'\t') {
                    k += 1;
                }
                if k < n && (bytes[k] == b'"' || bytes[k] == b'\'') {
                    let quote = bytes[k] as char;
                    if find_closing_quote_bytes(bytes, k + 1, quote).is_some() {
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

    // 检查从 i 起是否匹配指定的 ASCII 序列（大小写不敏感；pattern 全小写）
    let starts_with_ci = |i: usize, pat: &str| -> bool {
        let pb = pat.as_bytes();
        if i + pb.len() > n {
            return false;
        }
        pb.iter().enumerate().all(|(k, &b)| {
            // eq_ignore_ascii_case 而非 `as u8` 截断（同 needs_redaction，ocr 第三轮 bug·medium）
            chars[i + k].eq_ignore_ascii_case(&(b as char))
        })
    };

    // 词边界（规则 1 用）：i 之前必须是「非 token 字符」（防 task-123... 里的 sk- 误命中）
    let at_word_boundary = |i: usize| -> bool {
        i == 0
            || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_' || chars[i - 1] == '-')
    };

    // 弱边界（规则 3 用）：仅要求前邻非字母数字，允许 `_`/`-` 前缀（DB_PASSWORD= 等，
    // ocr 2026-08-12 第五轮 security·medium）
    let at_weak_boundary = |i: usize| -> bool {
        i == 0 || !chars[i - 1].is_ascii_alphanumeric()
    };

    // 消费 [A-Za-z0-9_-]，返回消费掉的字符数；同时检测 token 内是否含下划线
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

    // snake_case 标识符判定（与字节版 is_snake_case 同构，第九轮 bug·medium 防分歧）：
    // 段全部为「纯小写字母单词段」或「版本段（纯数字/v+数字）」且至少一个版本段
    //（第十轮 security·high：全小写随机段无版本号不得豁免，与字节版同构防分歧）。
    let is_snake_case_chars = |seg: &[char]| -> bool {
        let segs: Vec<&[char]> = seg
            .split(|&c| c == '_')
            .filter(|s| !s.is_empty())
            .collect();
        if segs.is_empty() {
            return false;
        }
        let mut has_version = false;
        for s in &segs {
            if s.iter().all(|&c| c.is_ascii_lowercase()) {
                // 纯小写字母单词段（长度不限）
            } else if s.len() >= 2
                && (s.iter().all(|&c| c.is_ascii_digit())
                    || (s[0] == 'v' && s[1..].iter().all(|&c| c.is_ascii_digit())))
            {
                has_version = true; // 版本段
            } else {
                return false; // 含大写 / 字母数字混合 → 非标识符
            }
        }
        has_version
    };

    while i < n {
        let c = chars[i];
        // 规则 1：API key 前缀（大小写不敏感 + 词边界）。覆盖 sk_live_/hf_/github_pat_/
        // AKIA 等真实格式（第七轮 security·medium）；下划线处理：仅 snake_case 段形态
        // （全小写/数字、段长 ≤12）拒绝——sk-proj_xxx_yyy 等真实含 _ 的 key 放行
        // （第八轮 security·high 修正，OpenAI 新格式 sk-proj_ 前有真实泄露案例）。
        let prefix_matched = [
            "sk-", "aiza", "ghp_", "secret_", "sk_live_", "sk_test_", "hf_", "github_pat_", "akia",
        ]
        .iter()
        .find(|p| at_word_boundary(i) && starts_with_ci(i, p));
        if let Some(p) = prefix_matched {
            let (token_len, has_underscore) = consume_token_chars(i + p.len());
            let snake_case = has_underscore
                && is_snake_case_chars(&chars[i + p.len()..i + p.len() + token_len]);
            if token_len >= 16 && !snake_case {
                out.push_str("[REDACTED_API_KEY]");
                i += p.len() + token_len;
                continue;
            }
        }
        // 规则 2：URL userinfo（scheme://user:pass@，且 @ 在首个 / 或空白之前）
        // 触发点 = ':' 位置；scheme 字符（如 https 的 h..s）已在此前按原样输出，
        // 因此只需补 "://" + user: + 遮蔽密码。
        if c == ':' && starts_with_ci(i, "://") {
            // RFC 3986 scheme = 字母开头 + [A-Za-z0-9+.-]*：s3://、git+ssh:// 等
            // 含数字/符号的 scheme 也要识别（ocr 2026-08-12 第五轮 security·medium）
            let mut scheme_start = i;
            while scheme_start > 0
                && (chars[scheme_start - 1].is_ascii_alphanumeric()
                    || chars[scheme_start - 1] == '+'
                    || chars[scheme_start - 1] == '-'
                    || chars[scheme_start - 1] == '.')
            {
                scheme_start -= 1;
            }
            let scheme_len = i - scheme_start;
            // 首字符必须是字母（RFC 3986 scheme 约束），防「数字:」被误认。
            // （词边界由回扫循环本身保证：循环仅在 scheme 字符集 [A-Za-z0-9+.-]
            // 上回退，退出时 scheme 起点前一字符必非 scheme 字符——无需额外检查，
            // ocr 2026-08-12 第七轮指出此前 boundary_ok 为恒真死代码）
            let first_alpha = chars[scheme_start].is_ascii_alphabetic();
            if first_alpha && (1..=32).contains(&scheme_len) {
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
        // 规则 3：密钥赋值 key = "value" / key: "value"（key 大小写不敏感 + 弱边界）
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
        if key_len > 0 && at_weak_boundary(i) {
            // 允许 key 后空格
            let mut j = i + key_len;
            // JSON 风格键名（"password": "value"）：跳过一个收尾引号再找分隔符
            // （ocr 2026-08-12 第四轮 security·high：{...} 配置粘贴时 password 值漏脱敏）
            if j < n && (chars[j] == '"' || chars[j] == '\'') {
                j += 1;
            }
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
/// - 遇 `\` 跳过下一字符（转义引号不算收尾）；若下一字符是换行则返回 None（行尾
///   反斜杠不得跨行匹配，ocr 2026-08-12 第五轮 bug·low）
/// - 遇 `\n`/`\r` 返回 None（不跨行）
fn find_closing_quote(chars: &[char], start: usize, quote: char) -> Option<usize> {
    let mut j = start;
    while j < chars.len() {
        match chars[j] {
            '\\' => {
                if j + 1 < chars.len() && (chars[j + 1] == '\n' || chars[j + 1] == '\r') {
                    return None;
                }
                j += 2; // 跳过转义序列（含 \" 本身）
            }
            '\n' | '\r' => return None,
            q if q == quote => return Some(j - start),
            _ => j += 1,
        }
    }
    None
}

/// 字节版收尾引号查找（供零分配 `needs_redaction` 使用，语义同 `find_closing_quote`）。
fn find_closing_quote_bytes(bytes: &[u8], start: usize, quote: char) -> Option<usize> {
    let mut j = start;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => {
                if j + 1 < bytes.len() && (bytes[j + 1] == b'\n' || bytes[j + 1] == b'\r') {
                    return None;
                }
                j += 2; // 跳过转义序列（含 \" 本身）
            }
            b'\n' | b'\r' => return None,
            q if q as char == quote => return Some(j - start),
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

/// 字节版 userinfo `@` 查找（供零分配 `needs_redaction` 使用，语义同 `find_userinfo_at`）。
fn find_userinfo_at_bytes(bytes: &[u8], colon_pos: usize) -> Option<usize> {
    let mut j = colon_pos + 3; // 跳过 "://"
    let mut last_at: Option<usize> = None;
    while j < bytes.len() {
        match bytes[j] {
            b'@' => {
                last_at = Some(j);
                j += 1;
            }
            b'/' | b'?' | b'#' | b' ' | b'\t' | b'\n' | b'\r' => return last_at,
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

/// 字节版 userinfo `:` 查找（供零分配 `needs_redaction` 使用，语义同 `find_userinfo_colon`）。
fn find_userinfo_colon_bytes(bytes: &[u8], colon_pos: usize, at: usize) -> Option<usize> {
    let mut j = colon_pos + 3;
    while j < at {
        if bytes[j] == b':' {
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
    fn real_world_key_formats_redacted() {
        // ocr 2026-08-12 第七轮 security·medium：Stripe/HF/GitHub/AWS 等真实格式此前漏脱敏。
        // 注意：mock 串在 base62 段中间插 `-`（sanitize token 消费含 `-`，脱敏逻辑不受影响），
        // 目的是打断连续 base62 段，避免 GitHub Push Protection / gitleaks 把测试假 key
        // 误判为真实泄露而拒绝推送（2026-08-12 推送被 GH013 拦截后调整）。
        assert_eq!(
            sanitize_agent_payload("sk_live_51H-abcdefghijklmnopqrstuvwx"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("sk_test_51H-abcdefghijklmnopqrstuvwx"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("hf_-abcdefghijklmnopqrstuvwx"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("github_pat_-abcdefghijklmnopqrstuvwx"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("AKIA-ABCDEFGHIJKLMNOPQRSTUVWX"),
            "[REDACTED_API_KEY]"
        );
        // 字节版检测器一致
        assert!(needs_redaction("sk_live_51H-abcdefghijklmnopqrstuvwx"));
        assert!(needs_redaction("github_pat_-abcdefghijklmnopqrstuvwx"));
        assert!(needs_redaction("AKIA-ABCDEFGHIJKLMNOPQRSTUVWX"));
    }

    #[test]
    fn sk_proj_underscore_key_redacted() {
        // ocr 2026-08-12 第八/九轮 security·high：sk-proj_ 新格式含 `_`，此前被
        // 「含 _ 即拒」误拒漏脱敏；第九轮起 snake_case 判定收窄——hex 分段
        // （sk-proj_9f8e7d6c_...）字母数字混合段视为真实 key 放行脱敏。
        assert_eq!(
            sanitize_agent_payload("sk-proj_AbCdEfGhIjKlMnOpQrStUvWxYz"),
            "[REDACTED_API_KEY]"
        );
        assert_eq!(
            sanitize_agent_payload("sk-proj_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"),
            "[REDACTED_API_KEY]"
        );
        // 第九轮泄漏回归：hex 分段（全小写/数字段）不得被误判为 snake_case 豁免
        assert_eq!(
            sanitize_agent_payload("sk-proj_9f8e7d6c_5b4a3f2e_1d0c9b8a_7f6e5d4c"),
            "[REDACTED_API_KEY]"
        );
        // 第十轮泄漏回归：全小写随机段（无版本段）不得豁免——sk-proj_ 后跟
        // 纯小写长段（abcdefghijklmnop 16 字符）无版本号，判为真实 key
        assert_eq!(
            sanitize_agent_payload("sk-proj_abcdefghijklmnop_qrstuvwxyz"),
            "[REDACTED_API_KEY]"
        );
        assert!(needs_redaction("sk-proj_AbCdEfGhIjKlMnOpQrStUvWxYz"));
        assert!(needs_redaction("sk-proj_9f8e7d6c_5b4a3f2e_1d0c9b8a_7f6e5d4c"));
        assert!(needs_redaction("sk-proj_abcdefghijklmnop_qrstuvwxyz"));
        // snake_case 标识符仍不误伤（单词段+版本段）
        assert_eq!(
            sanitize_agent_payload("secret_config_management_v2_2024"),
            "secret_config_management_v2_2024"
        );
        // 第九轮误伤回归：13 字符单词段（configuration）仍是标识符，不得脱敏
        assert_eq!(
            sanitize_agent_payload("secret_configuration_management_v2_2024"),
            "secret_configuration_management_v2_2024"
        );
        assert!(!needs_redaction("secret_configuration_management_v2_2024"));
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
    fn json_style_keys_redacted() {
        // ocr 2026-08-12 第四轮 security·high：JSON 风格键名收尾引号后接 : 此前漏脱敏
        assert_eq!(
            sanitize_agent_payload("{\"password\": \"hunter2\"}"),
            "{\"password\": \"[REDACTED_SECURE_TOKEN]\"}"
        );
        assert_eq!(
            sanitize_agent_payload("{\"secret_key\":\"abc\"}"),
            "{\"secret_key\":\"[REDACTED_SECURE_TOKEN]\"}"
        );
        assert_eq!(
            sanitize_agent_payload("{\"api_key\": \"sk-abc1234567890abcdefgh\"}"),
            "{\"api_key\": \"[REDACTED_API_KEY]\"}"
        );
        // 字节版检测器保持一致（不变量测试兜底）
        assert!(needs_redaction("{\"password\": \"hunter2\"}"));
        assert!(needs_redaction("{\"secret_key\":\"abc\"}"));
    }

    #[test]
    fn keyword_suffix_not_redacted() {
        // ocr 2026-08-12 第四轮 bug·medium：规则 3 此前无词边界，mypassword/resetpassword 误脱敏
        assert_eq!(
            sanitize_agent_payload("mypassword = \"abc\""),
            "mypassword = \"abc\""
        );
        assert_eq!(
            sanitize_agent_payload("resetpassword = \"x\""),
            "resetpassword = \"x\""
        );
        assert!(!needs_redaction("mypassword = \"abc\""));
    }

    #[test]
    fn env_style_keys_redacted() {
        // ocr 2026-08-12 第五轮 security·medium：弱边界允许 `_`/`-` 前缀，
        // DB_PASSWORD= / api_secret_key= 等 env/JSON 键名必须脱敏
        assert_eq!(
            sanitize_agent_payload("DB_PASSWORD=\"postgres\""),
            "DB_PASSWORD=\"[REDACTED_SECURE_TOKEN]\""
        );
        assert_eq!(
            sanitize_agent_payload("RDS_PASSWORD=\"hunter2\""),
            "RDS_PASSWORD=\"[REDACTED_SECURE_TOKEN]\""
        );
        assert_eq!(
            sanitize_agent_payload("api_secret_key=\"abc\""),
            "api_secret_key=\"[REDACTED_SECURE_TOKEN]\""
        );
        assert_eq!(
            sanitize_agent_payload("{\"db_password\": \"x\"}"),
            "{\"db_password\": \"[REDACTED_SECURE_TOKEN]\"}"
        );
        // 字节版检测器保持一致
        assert!(needs_redaction("DB_PASSWORD=\"postgres\""));
        assert!(needs_redaction("api_secret_key=\"abc\""));
    }

    #[test]
    fn compound_scheme_redacted() {
        // ocr 2026-08-12 第五轮 security·medium：RFC 3986 scheme 含数字/符号
        // （s3://、git+ssh:// 等），原实现仅回扫字母会漏脱敏
        assert_eq!(
            sanitize_agent_payload("s3://admin:hunter2@bucket.example/x"),
            "s3://admin:[REDACTED_CREDENTIALS]@bucket.example/x"
        );
        assert_eq!(
            sanitize_agent_payload("git+ssh://user:pass@host/repo"),
            "git+ssh://user:[REDACTED_CREDENTIALS]@host/repo"
        );
        assert!(needs_redaction("s3://admin:hunter2@bucket.example/x"));
    }

    #[test]
    fn trailing_backslash_does_not_cross_line() {
        // ocr 2026-08-12 第五轮 bug·low：行尾反斜杠跳过换行继续匹配引号 → 跨行过度脱敏
        assert_eq!(
            sanitize_agent_payload("password = \"abc\\\n\"def\""),
            "password = \"abc\\\n\"def\""
        );
        assert!(!needs_redaction("password = \"abc\\\n\"def\""));
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

    #[test]
    fn needs_redaction_matches_payload_change_property() {
        // 关键不变量：needs_redaction(s) == (sanitize_agent_payload(s) != s)。
        // 两者实现同源但独立（字节扫描 vs 字符重建），防漂移导致「检测说无需脱敏、
        // 实际却会改写」→ 明文凭证漏发 LLM（ocr 2026-08-12 第三轮 test·medium）。
        let cases: Vec<&str> = vec![
            // 需脱敏
            "sk-abc1234567890abcdefgh",
            "SK-ABCDEFGHIJKLMNOPQRSTUVWX",
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
            "ghp_1234567890abcdefghijkl",
            "secret_abcdefghijklmnopqrstuvwxyz1",
            "connect https://admin:hunter2@example.com:5432/db",
            "connect HTTPS://admin:hunter2@example.com/db",
            "https://user:p@ss@host.com/x",
            "password = \"hunter2\"",
            "Password = \"hunter2\"",
            "secret_key: 'abc'",
            "private_key='xyz'",
            "db url=https://user:pass@host/x key=sk-1234567890abcdefghijklmnop",
            // 无需脱敏
            "",
            "你好世界",
            "task-1234567890abcdefgh",
            "secret_config_management_v2_2024",
            "secret_ok",
            "sk-x",
            "a:b@c",
            "user@host.com",
            "帮我查一下今天的固废进厂车辆，密码是进厂凭证",
            "password = \"abc\n后面还有内容\"继续",
            "šřž非ASCII文本",
        ];
        for s in cases {
            let redacted = sanitize_agent_payload(s);
            let changed = redacted != s;
            assert_eq!(
                needs_redaction(s),
                changed,
                "不变量被破坏: needs_redaction({s:?})={} 但 sanitize 改写={} (输出 {redacted:?})",
                needs_redaction(s),
                changed
            );
        }
    }
}
