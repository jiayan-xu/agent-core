//! 双轨·轨一：受控改库扳手（cw_select / cw_write）。
//!
//! **权限生存线（P0）**：
//! - 默认关闭：须显式 `AGENT_DB_WRITE=1` 才暴露/可调用
//! - `cw_write` 为危险写：走 L2 审批黄线；且须 `confirmed=true` + 落库侧再确认
//! - 仅作用于白名单表 `vehicle_whitelist` 与白名单列；杜绝 SQL 拼接
//! - 实际 SELECT 经 dashboard `execute_sql`（SELECT-only）；实际 WRITE 经 dashboard
//!   `controlled_db_write`（参数化 `?` 绑定，纵深防御）
//!
//! 设计裁决（与用户确认）：落库走「新增 dashboard 受控写工具」而非直接打开 `execute_sql`
//! 写能力，保持「固废数据仅经 dashboard MCP 暴露」的单一写入口。本模块只做：
//! 表/列白名单约束 + 值消毒 + 参数化 SQL 构造 + 回读计划输入。

use crate::llm::{ToolDef, ToolDefFunction};

pub const TOOL_SELECT: &str = "cw_select";
pub const TOOL_WRITE: &str = "cw_write";

pub fn is_db_write_tool(name: &str) -> bool {
    matches!(name, TOOL_SELECT | TOOL_WRITE)
}

/// 功能总闸：默认关闭。只有显式开启才允许暴露工具与执行。
pub fn is_enabled() -> bool {
    matches!(
        std::env::var("AGENT_DB_WRITE").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

/// 默认允许操作的表（最小白名单）。
pub fn allowed_tables() -> Vec<&'static str> {
    vec!["vehicle_whitelist"]
}

/// 允许读写/写的列白名单（与固废业务强绑定，防止越权改库）。
pub fn allowed_columns() -> Vec<&'static str> {
    vec![
        "license_plate",
        "company_name",
        "waste_type",
        "status",
        "enabled",
        "remark",
    ]
}

pub fn is_allowed_table(t: &str) -> bool {
    allowed_tables().iter().any(|x| x.eq_ignore_ascii_case(t))
}

pub fn is_allowed_column(c: &str) -> bool {
    allowed_columns().iter().any(|x| x.eq_ignore_ascii_case(c))
}

/// 值消毒：仅保留安全字符，截断长度（防注入与回读污染）。
pub fn sanitize_value(raw: &str) -> String {
    let s: String = raw
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || ('\u{4e00}'..='\u{9fff}').contains(c)
                || matches!(c, '-' | '_' | '/' | ' ' | '（' | '）' | '(' | ')' | '.' | '@')
        })
        .take(128)
        .collect();
    s.trim().to_string()
}

/// 构造安全参数化 SELECT：返回 `(sql, params)`。
/// args: `{ table, columns?, where_column?, where_value? }`
/// - 列若非 `*`，必须全部落在白名单列
/// - 条件值经 `sanitize_value` 后作为绑定参数（绝不内联进 SQL 文本）
pub fn build_select(args: &serde_json::Value) -> Result<(String, Vec<String>), String> {
    let table = args.get("table").and_then(|v| v.as_str()).ok_or("缺少 table")?;
    if !is_allowed_table(table) {
        return Err(format!("表 {} 不在允许白名单（受控读）", table));
    }
    let columns = args
        .get("columns")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "*".to_string());
    if columns != "*" {
        for col in columns.split(',') {
            let col = col.trim();
            if !col.is_empty() && !is_allowed_column(col) {
                return Err(format!("列 {} 不在允许白名单（受控读）", col));
            }
        }
    }
    let where_column = args.get("where_column").and_then(|v| v.as_str());
    let where_value = args.get("where_value").and_then(|v| v.as_str());
    if let (Some(wc), Some(wv)) = (where_column, where_value) {
        if !is_allowed_column(wc) {
            return Err(format!("条件列 {} 不在允许白名单（受控读）", wc));
        }
        let wv = sanitize_value(wv);
        Ok((
            format!("SELECT {} FROM {} WHERE {} = ?", columns, table, wc),
            vec![wv],
        ))
    } else {
        Ok((format!("SELECT {} FROM {}", columns, table), vec![]))
    }
}

/// 校验 `cw_write` 写参数，返回交给 dashboard `controlled_db_write` 的干净参数。
/// 透传 `confirmed` / `soft_delete` 等受控标志（由 controlled_db_write 解释）。
pub fn validate_write_args(args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let table = args.get("table").and_then(|v| v.as_str()).ok_or("缺少 table")?;
    if !is_allowed_table(table) {
        return Err(format!("表 {} 不在允许白名单（受控写）", table));
    }
    let column = args.get("column").and_then(|v| v.as_str()).ok_or("缺少 column")?;
    if !is_allowed_column(column) {
        return Err(format!("列 {} 不在允许白名单（受控写）", column));
    }
    let value = args.get("value").and_then(|v| v.as_str()).ok_or("缺少 value")?;
    let value = sanitize_value(value);
    let where_column = args.get("where_column").and_then(|v| v.as_str());
    let where_value = args.get("where_value").and_then(|v| v.as_str());

    let mut out = serde_json::json!({
        "table": table,
        "column": column,
        "value": value,
        "where_column": where_column.unwrap_or(""),
        "where_value": where_value.map(|w| sanitize_value(w)).unwrap_or_default(),
    });
    if let Some(c) = args.get("confirmed").and_then(|v| v.as_bool()) {
        out["confirmed"] = serde_json::json!(c);
    }
    if let Some(sd) = args.get("soft_delete").and_then(|v| v.as_bool()) {
        out["soft_delete"] = serde_json::json!(sd);
    }
    Ok(out)
}

pub fn tool_defs() -> Vec<ToolDef> {
    let table_prop = serde_json::json!({
        "type": "string",
        "description": "要操作的表，仅允许白名单表（默认 vehicle_whitelist）"
    });
    let col_prop = serde_json::json!({
        "type": "string",
        "description": "列名，仅允许白名单列"
    });
    vec![
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_SELECT.into(),
                description: "（受控只读）按白名单表/列参数化查询固废业务库，返回查询结果。仅 AGENT_DB_WRITE=1 时可用；SELECT-only，参数化绑定，杜绝拼接。"
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "table": table_prop,
                        "columns": { "type": "string", "description": "逗号分隔列名，或 *（默认）。仅白名单列" },
                        "where_column": col_prop,
                        "where_value": { "type": "string", "description": "条件值（参数化绑定，消毒）" }
                    },
                    "required": ["table"]
                }),
            },
        },
        ToolDef {
            type_: "function".into(),
            function: ToolDefFunction {
                name: TOOL_WRITE.into(),
                description: "（受控写）参数化更新/写入固废业务库白名单表。危险写：须 AGENT_DB_WRITE=1 + 人工审批 + confirmed=true；写后经 controlled_db_write 落库并回读校验。"
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "table": table_prop,
                        "column": col_prop,
                        "value": { "type": "string", "description": "要写入的值（消毒）" },
                        "where_column": col_prop,
                        "where_value": { "type": "string", "description": "定位行的条件列值" },
                        "soft_delete": { "type": "boolean", "description": "true 仅软删（status/enabled 标记），不物理删" },
                        "confirmed": { "type": "boolean", "description": "二次确认，true 才落库" }
                    },
                    "required": ["table", "column", "value"]
                }),
            },
        },
    ]
}

pub fn system_hint() -> &'static str {
    "\n\n## 受控改库扳手（轨一，默认关闭）\n\
     - 仅当运维设置 `AGENT_DB_WRITE=1` 时可用：`cw_select`（只读参数化查询）/ `cw_write`（受控写）\n\
     - 仅作用于白名单表 `vehicle_whitelist` 与白名单列；写必须经人工审批且 confirmed=true\n\
     - 实际落库与回读经 dashboard `controlled_db_write`（参数化绑定，杜绝 SQL 拼接）\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_whitelist_enforced() {
        assert!(is_allowed_table("vehicle_whitelist"));
        assert!(!is_allowed_table("vehicle_entrance"));
        assert!(is_allowed_column("company_name"));
        assert!(!is_allowed_column("net_weight"));
    }

    #[test]
    fn build_select_safe_and_parameterized() {
        let args = serde_json::json!({
            "table": "vehicle_whitelist",
            "columns": "license_plate,company_name",
            "where_column": "license_plate",
            "where_value": "苏EZQ117"
        });
        let (sql, params) = build_select(&args).unwrap();
        assert!(sql.contains("SELECT license_plate,company_name FROM vehicle_whitelist"));
        assert!(sql.contains("WHERE license_plate = ?"));
        assert!(!sql.contains("苏EZQ117")); // 值不在 SQL 文本中
        assert_eq!(params, vec!["苏EZQ117".to_string()]);
    }

    #[test]
    fn build_select_rejects_bad_table_or_column() {
        assert!(build_select(&serde_json::json!({"table": "vehicle_entrance"})).is_err());
        assert!(build_select(&serde_json::json!({
            "table": "vehicle_whitelist",
            "columns": "net_weight"
        }))
        .is_err());
    }

    #[test]
    fn sanitize_value_strips_injection() {
        // 真正的防注入靠参数化绑定；sanitize 负责剥掉可破坏字符串/语句的转义字符
        let s = sanitize_value("'; DROP TABLE x --");
        assert!(!s.contains('\''));
        assert!(!s.contains(';'));
        assert!(!s.contains('\\'));
        assert_eq!(sanitize_value("佳士能环境"), "佳士能环境");
    }

    #[test]
    fn validate_write_args_clean() {
        let args = serde_json::json!({
            "table": "vehicle_whitelist",
            "column": "company_name",
            "value": "佳士能环境",
            "where_column": "license_plate",
            "where_value": "苏EZQ117",
            "confirmed": true
        });
        let out = validate_write_args(&args).unwrap();
        assert_eq!(out["table"], "vehicle_whitelist");
        assert_eq!(out["column"], "company_name");
        assert_eq!(out["value"], "佳士能环境");
        assert_eq!(out["where_value"], "苏EZQ117");
        assert_eq!(out["confirmed"], true);
    }

    #[test]
    fn validate_write_args_rejects_bad_target() {
        assert!(validate_write_args(&serde_json::json!({
            "table": "vehicle_entrance",
            "column": "company_name",
            "value": "x"
        }))
        .is_err());
        assert!(validate_write_args(&serde_json::json!({
            "table": "vehicle_whitelist",
            "column": "net_weight",
            "value": "x"
        }))
        .is_err());
    }
}
