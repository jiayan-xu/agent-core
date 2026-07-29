//! 受控写「写后回读」协议（通用骨架）。
//!
//! 目标：任意受控写在声明成功后，必须能用只读回读证明关键字段已落地。
//! 白名单、改码 verify 等都复用同一套判定文案，避免各业务各写一套「假成功」话术。

/// 回读校验结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    Pass { detail: String },
    Fail { detail: String },
    Skip { reason: String },
}

impl VerifyOutcome {
    pub fn as_reply_suffix(&self) -> String {
        match self {
            VerifyOutcome::Pass { detail } => format!("\n\n✅ 回读校验通过：{}", detail),
            VerifyOutcome::Fail { detail } => format!("\n\n⚠️ 回读校验未通过：{}", detail),
            VerifyOutcome::Skip { reason } => format!("\n\nℹ️ 回读校验跳过：{}", reason),
        }
    }

    pub fn is_pass(&self) -> bool {
        matches!(self, VerifyOutcome::Pass { .. })
    }
}

/// 若 `expected` 非空且出现在 `readback` 中 → Pass；否则 Fail。
pub fn match_expected_in_readback(label: &str, expected: &str, readback: &str) -> VerifyOutcome {
    let expected = expected.trim();
    if expected.is_empty() {
        return VerifyOutcome::Skip {
            reason: format!("{}：无期望值可核对", label),
        };
    }
    if readback.contains(expected) {
        VerifyOutcome::Pass {
            detail: format!("{} 已出现期望值「{}」", label, expected),
        }
    } else {
        let snip: String = readback.chars().take(240).collect();
        VerifyOutcome::Fail {
            detail: format!("{} 未找到「{}」。回读摘录：{}", label, expected, snip),
        }
    }
}

/// 车牌字符白名单（防回读 SQL/参数注入）：汉字省简称 + 字母数字。
pub fn sanitize_plate(plate: &str) -> Option<String> {
    let s: String = plate
        .chars()
        .filter(|c| {
            ('\u{4e00}'..='\u{9fff}').contains(c) || c.is_ascii_alphanumeric()
        })
        .take(16)
        .collect();
    if s.chars().count() >= 5 {
        Some(s)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_pass_and_fail() {
        assert!(match_expected_in_readback("白名单", "佳士能", "公司=佳士能环境").is_pass());
        assert!(!match_expected_in_readback("白名单", "佳士能", "公司=其他").is_pass());
    }

    #[test]
    fn sanitize_plate_ok() {
        assert_eq!(sanitize_plate("苏EZQ117").as_deref(), Some("苏EZQ117"));
        assert!(sanitize_plate("'; DROP").is_none());
    }
}
