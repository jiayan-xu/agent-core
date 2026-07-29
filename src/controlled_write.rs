//! 受控写「写后回读」协议 + 工具注册表。
//!
//! ## 权限生存线
//! - 注册表内的写工具：**必须**经审批/`confirmed`，禁止静默落盘。
//! - 回读 SQL **只允许**注册表内硬编码模板 + 消毒后的绑定值，禁止把 LLM 拼的 SQL 当回读。
//! - 未注册工具：不做自动回读（避免误开通用写通道）；需要时显式加注册项。
//!
//! 目标：声明成功后必须能证明关键字段已落地，消灭「假成功」话术。

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

    pub fn detail_text(&self) -> String {
        match self {
            VerifyOutcome::Pass { detail } | VerifyOutcome::Fail { detail } => detail.clone(),
            VerifyOutcome::Skip { reason } => reason.clone(),
        }
    }
}

/// 回读策略（只描述「怎么验」，真正发工具由 agent 执行）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStrategy {
    /// sync_whitelist_plates：按 action 选公司名/车牌存在性回读
    WhitelistSync,
    /// manage_whitelist update_waste_type：回读 waste_type 列
    WhitelistWasteType,
    /// 本地沙箱写
    LocalFsWrite,
    /// edit_code：结果须含自动 verify_code 成功标记
    EditCodeVerified,
    /// 仅信任写回执中的字段
    WriteJsonField {
        result_field: &'static str,
        arg_field: &'static str,
    },
}

/// 受控写规格
#[derive(Debug, Clone, Copy)]
pub struct ControlledWriteSpec {
    pub tool: &'static str,
    pub label: &'static str,
    pub strategy: VerifyStrategy,
}

/// 显式注册表：未列出的写工具不做自动回读，也不因此获得写权限。
pub static CONTROLLED_WRITES: &[ControlledWriteSpec] = &[
    ControlledWriteSpec {
        tool: "sync_whitelist_plates",
        label: "白名单受控写",
        strategy: VerifyStrategy::WhitelistSync,
    },
    ControlledWriteSpec {
        tool: "manage_whitelist",
        label: "白名单管理写",
        strategy: VerifyStrategy::WhitelistWasteType,
    },
    ControlledWriteSpec {
        tool: "local_fs_write",
        label: "沙箱文件写",
        strategy: VerifyStrategy::LocalFsWrite,
    },
    ControlledWriteSpec {
        tool: "edit_code",
        label: "部门改码",
        strategy: VerifyStrategy::EditCodeVerified,
    },
];

pub fn lookup(tool: &str) -> Option<&'static ControlledWriteSpec> {
    CONTROLLED_WRITES.iter().find(|s| s.tool == tool)
}

pub fn is_controlled_write_tool(tool: &str) -> bool {
    lookup(tool).is_some()
}

/// 回读计划：agent 按此调用只读工具或本地比对。
#[derive(Debug, Clone)]
pub enum PostVerifyPlan {
    /// 直接用写回执字段判定（可同步完成）
    FromWriteJson {
        result_field: String,
        expected: String,
        label: String,
    },
    /// 写回执全文须包含成功标记、且不含失败标记
    ContainsInWriteResult {
        needle: String,
        anti_needle: String,
        label: String,
    },
    /// 执行只读 SQL（模板已固定，params 已消毒）
    ReadSql {
        sql: String,
        expected: String,
        label: String,
    },
    /// 读文件内容比对
    ReadFile {
        path: String,
        expected: String,
        label: String,
    },
    Skip(String),
}

/// 根据注册策略生成回读计划（纯函数，无 I/O）。
pub fn plan_post_verify(
    tool: &str,
    args: &serde_json::Value,
    write_result: &str,
) -> PostVerifyPlan {
    let Some(spec) = lookup(tool) else {
        return PostVerifyPlan::Skip(format!("工具 {} 未在受控写注册表", tool));
    };
    match spec.strategy {
        VerifyStrategy::WhitelistSync => plan_whitelist_sync(spec, args, write_result),
        VerifyStrategy::WhitelistWasteType => plan_whitelist_waste(spec, args),
        VerifyStrategy::LocalFsWrite => plan_local_fs(spec, args, write_result),
        VerifyStrategy::EditCodeVerified => PostVerifyPlan::ContainsInWriteResult {
            needle: "【自动 verify_code】".into(),
            anti_needle: "【自动 verify_code 失败】".into(),
            label: spec.label.to_string(),
        },
        VerifyStrategy::WriteJsonField {
            result_field,
            arg_field,
        } => {
            let expected = args
                .get(arg_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            PostVerifyPlan::FromWriteJson {
                result_field: result_field.to_string(),
                expected,
                label: spec.label.to_string(),
            }
        }
    }
}

fn plan_whitelist_sync(
    spec: &ControlledWriteSpec,
    args: &serde_json::Value,
    write_result: &str,
) -> PostVerifyPlan {
    let _ = write_result;
    let plate = match args
        .get("plate")
        .and_then(|p| p.as_str())
        .and_then(sanitize_plate)
    {
        Some(p) => p,
        None => return PostVerifyPlan::Skip("缺少合法车牌".into()),
    };
    let action = args
        .get("action")
        .and_then(|a| a.as_str())
        .unwrap_or("update_company");

    match action {
        "remove" => {
            // 软删后：记录仍可能在，但 status/enabled 应反映失效
            let sql = format!(
                "SELECT license_plate, status, enabled FROM vehicle_whitelist WHERE license_plate = '{}'",
                plate
            );
            PostVerifyPlan::ReadSql {
                sql,
                // 接受 removed / enabled=0；若行消失也由 match 失败再靠写回执
                expected: "removed".into(),
                label: format!("{} 软删 {}", spec.label, plate),
            }
        }
        "add" => {
            let sql = format!(
                "SELECT license_plate, company_name, status FROM vehicle_whitelist WHERE license_plate = '{}'",
                plate
            );
            PostVerifyPlan::ReadSql {
                sql,
                expected: plate.clone(),
                label: format!("{} 新增 {}", spec.label, plate),
            }
        }
        _ => {
            // update_company 等
            let expected = args
                .get("company_name")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            let sql = format!(
                "SELECT license_plate, company_name FROM vehicle_whitelist WHERE license_plate = '{}'",
                plate
            );
            let label = if expected.is_empty() {
                format!("{} 车牌 {}", spec.label, plate)
            } else {
                format!("{} {} 公司名", spec.label, plate)
            };
            let needle = if expected.is_empty() {
                plate
            } else {
                expected
            };
            PostVerifyPlan::ReadSql {
                sql,
                expected: needle,
                label,
            }
        }
    }
}

fn plan_whitelist_waste(spec: &ControlledWriteSpec, args: &serde_json::Value) -> PostVerifyPlan {
    let plate = match args
        .get("plate")
        .and_then(|p| p.as_str())
        .and_then(sanitize_plate)
    {
        Some(p) => p,
        None => return PostVerifyPlan::Skip("缺少合法车牌".into()),
    };
    let waste = sanitize_waste_type(
        args.get("waste_type")
            .and_then(|w| w.as_str())
            .unwrap_or(""),
    );
    if waste.is_empty() {
        return PostVerifyPlan::Skip("缺少固废种类".into());
    }
    let sql = format!(
        "SELECT license_plate, waste_type FROM vehicle_whitelist WHERE license_plate = '{}'",
        plate
    );
    PostVerifyPlan::ReadSql {
        sql,
        expected: waste,
        label: format!("{} {} 固废种类", spec.label, plate),
    }
}

/// 固废种类消毒：仅保留中文/字母数字与常见连接符，最长 32。
pub fn sanitize_waste_type(raw: &str) -> String {
    let s: String = raw
        .chars()
        .filter(|c| {
            ('\u{4e00}'..='\u{9fff}').contains(c)
                || c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '/' | '（' | '）' | '(' | ')')
        })
        .take(32)
        .collect();
    s.trim().to_string()
}

fn plan_local_fs(
    spec: &ControlledWriteSpec,
    args: &serde_json::Value,
    write_result: &str,
) -> PostVerifyPlan {
    // 写工具自身已做回读时，写回执 verify_pass=true 即可
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(write_result) {
        if v.get("verify_pass").and_then(|x| x.as_bool()) == Some(true) {
            return PostVerifyPlan::FromWriteJson {
                result_field: "path".into(),
                expected: args
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
                label: spec.label.to_string(),
            };
        }
    }
    let path = args
        .get("path")
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .to_string();
    let expected = args
        .get("content")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    if path.is_empty() || expected.is_empty() {
        return PostVerifyPlan::Skip("local_fs_write 缺 path/content".into());
    }
    PostVerifyPlan::ReadFile {
        path,
        expected,
        label: spec.label.to_string(),
    }
}

/// 文件写后回读：全文或等长前缀一致即通过。
pub fn verify_file_writeback(path: &str, expected: &str, readback: &str) -> VerifyOutcome {
    if expected == readback {
        return VerifyOutcome::Pass {
            detail: format!("{} 全文一致（{} bytes）", path, expected.len()),
        };
    }
    let prefix_len = expected.len().min(256);
    if !expected.is_empty()
        && readback.len() >= prefix_len
        && readback.as_bytes()[..prefix_len] == expected.as_bytes()[..prefix_len]
        && readback.len() == expected.len()
    {
        return VerifyOutcome::Pass {
            detail: format!("{} 长度与前缀一致", path),
        };
    }
    VerifyOutcome::Fail {
        detail: format!(
            "{} 回读与写入不一致（期望 {} bytes，实际 {} bytes）",
            path,
            expected.len(),
            readback.len()
        ),
    }
}

/// 通用：从写工具 JSON 回执中取字段与期望比对。
pub fn verify_json_field(write_result: &str, field: &str, expected: &str) -> Option<VerifyOutcome> {
    let v: serde_json::Value = serde_json::from_str(write_result).ok()?;
    if v.get("success").and_then(|x| x.as_bool()) != Some(true) {
        return None;
    }
    let got = v.get(field)?.as_str()?;
    if expected.is_empty() {
        return Some(VerifyOutcome::Pass {
            detail: format!("写回执 {}={}", field, got),
        });
    }
    if got == expected || got.contains(expected) || expected.contains(got) {
        Some(VerifyOutcome::Pass {
            detail: format!("写回执 {}「{}」", field, got),
        })
    } else {
        Some(VerifyOutcome::Fail {
            detail: format!("写回执 {}「{}」≠ 期望「{}」", field, got, expected),
        })
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

    #[test]
    fn file_writeback_and_json_field() {
        assert!(verify_file_writeback("a.txt", "abc", "abc").is_pass());
        assert!(!verify_file_writeback("a.txt", "abc", "ab").is_pass());
        let ok = verify_json_field(
            r#"{"success":true,"new_company":"佳士能"}"#,
            "new_company",
            "佳士能",
        );
        assert!(ok.unwrap().is_pass());
    }

    #[test]
    fn registry_whitelist_plans_safe_sql() {
        let args = serde_json::json!({
            "action": "update_company",
            "plate": "苏EZQ117",
            "company_name": "佳士能环境工程有限公司"
        });
        let plan = plan_post_verify("sync_whitelist_plates", &args, r#"{"success":true}"#);
        match plan {
            PostVerifyPlan::ReadSql { sql, expected, .. } => {
                assert!(sql.contains("license_plate"));
                assert!(sql.contains("苏EZQ117"));
                assert!(!sql.to_lowercase().contains("drop"));
                assert_eq!(expected, "佳士能环境工程有限公司");
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn unregistered_tool_skips() {
        let plan = plan_post_verify("random_write", &serde_json::json!({}), "{}");
        assert!(matches!(plan, PostVerifyPlan::Skip(_)));
    }

    #[test]
    fn registry_waste_and_edit_code_plans() {
        let waste = plan_post_verify(
            "manage_whitelist",
            &serde_json::json!({
                "action": "update_waste_type",
                "plate": "苏EZQ117",
                "waste_type": "农林垃圾"
            }),
            "{}",
        );
        match waste {
            PostVerifyPlan::ReadSql { sql, expected, .. } => {
                assert!(sql.contains("waste_type"));
                assert_eq!(expected, "农林垃圾");
            }
            other => panic!("{:?}", other),
        }
        let edit = plan_post_verify("edit_code", &serde_json::json!({}), "ok\n【自动 verify_code】\nok");
        assert!(matches!(edit, PostVerifyPlan::ContainsInWriteResult { .. }));
    }
}
