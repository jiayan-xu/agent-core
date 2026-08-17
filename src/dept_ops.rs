//! 固废本部门运维能力（P0）：工具包可见性 + 证据门禁 + 作业剧本 + 失败不许空嘴。
//!
//! 目标：在 `org/cs-pufa-2nd-thermal/dept/gufei` 权限内，PFAiX 先取证再下结论，
//! 而不是用 auto_route / 空嘴分析冒充运维。

use crate::composer::ExecutionPlan;
use std::sync::OnceLock;

/// 领域模式：控制「固废本部门运维纪律 / 证据门禁」是否启用。
/// 默认 `SolidWaste`（保持既有行为不变）；`Office` / `General` 下整套运维门禁与注入提示关闭，
/// 使 agent-core 可作为通用办公 / 通用 agent 运行。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainMode {
    SolidWaste,
    Office,
    General,
}

impl DomainMode {
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "office" => DomainMode::Office,
            "general" => DomainMode::General,
            _ => DomainMode::SolidWaste, // 默认保持固废行为
        }
    }
    pub fn is_solid_waste(&self) -> bool {
        *self == DomainMode::SolidWaste
    }
}

static DOMAIN_MODE: OnceLock<DomainMode> = OnceLock::new();

/// main 启动时调用一次，从 agent.toml `domain_mode` 字段加载。
pub fn init_domain_mode(mode: DomainMode) {
    let _ = DOMAIN_MODE.set(mode);
}

/// 当前领域模式（未初始化时默认 SolidWaste，行为与旧版一致）。
pub fn domain_mode() -> DomainMode {
    *DOMAIN_MODE.get().unwrap_or(&DomainMode::SolidWaste)
}

/// 公司根 ns（dashboard 技能树挂在此下）。
/// 重构 2026-08-04：由 main 启动时经 `init_org_ns` 注入（agent.toml `org_company`），
/// 与 main.rs 的 `org_company()` 保持一致；未注入时回退默认，行为与旧版相同。
static ORG_NS_CELL: OnceLock<String> = OnceLock::new();

pub fn init_org_ns(org_company: &str) {
    let _ = ORG_NS_CELL.set(format!("org/{}", org_company));
}

pub fn org_ns() -> String {
    ORG_NS_CELL
        .get()
        .cloned()
        .unwrap_or_else(|| "org/cs-pufa-2nd-thermal".to_string())
}

/// 固废部门工具包 ns（与 agent.toml [[mcp_source]] dashboard.namespace 对齐），
/// 随 org_ns 派生。部门=engineering(工程部)，项目=gufei(固废)。
pub fn dept_toolkit_ns() -> String {
    format!("{}/dept/engineering/proj/gufei", org_ns())
}

/// 是否关闭部门工具包自动 enrichment（默认开启；`DEPT_TOOLKIT_ENRICH=0` 关闭）
pub fn dept_toolkit_enrich_enabled() -> bool {
    std::env::var("DEPT_TOOLKIT_ENRICH")
        .map(|v| {
            let t = v.trim();
            !(t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off"))
        })
        .unwrap_or(true)
}

/// 为调用者补齐本部门工具包 ns，使 dashboard 固废技能必可见。
/// 已有 `*` 超管不改；可用 `DEPT_TOOLKIT_ENRICH=0` 关闭。
pub fn enrich_allowed_ns(allowed: &mut Vec<String>) {
    if !domain_mode().is_solid_waste() {
        return; // 非固废模式不自动注入部门工具包 ns
    }
    if !dept_toolkit_enrich_enabled() {
        return;
    }
    if allowed.iter().any(|n| n == "*") {
        return;
    }
    let org_ns = org_ns();
    let dept_ns = dept_toolkit_ns();
    if !allowed.iter().any(|n| n == &org_ns || n.starts_with(&format!("{org_ns}/"))) {
        allowed.push(org_ns);
    }
    if !allowed
        .iter()
        .any(|n| n == &dept_ns || n.starts_with(&format!("{dept_ns}/")))
    {
        allowed.push(dept_ns);
    }
}

/// 是否为「必须先取证」的固废现场/整理类意图
pub fn is_ops_investigate_intent(message: &str) -> bool {
    if !domain_mode().is_solid_waste() {
        return false;
    }
    const KEYS: &[&str] = &[
        "联单",
        "整理",
        "文件夹",
        "归档",
        "放入",
        "放错",
        "归类",
        "目录",
        "理文",
        "organize",
        "manifest",
        "archive",
        "未识别",
        "自动整理",
    ];
    KEYS.iter().any(|k| message.contains(k))
}

/// 是否为「本部门工程师改码」意图
pub fn is_engineer_intent(message: &str) -> bool {
    if !domain_mode().is_solid_waste() {
        return false;
    }
    const KEYS: &[&str] = &[
        "改代码",
        "改码",
        "修bug",
        "修 Bug",
        "修BUG",
        "报错",
        "traceback",
        "Traceback",
        "修复",
        "改 skill",
        "改skill",
        "edit_code",
        "verify_code",
        "代码里",
        "源码",
        "refactor",
        "编译失败",
        "语法错误",
    ];
    KEYS.iter().any(|k| message.contains(k))
}

/// 运维或工程师意图（证据门禁 / 拒演戏计划）
pub fn is_dept_grounded_intent(message: &str) -> bool {
    if !domain_mode().is_solid_waste() {
        return false;
    }
    is_ops_investigate_intent(message) || is_engineer_intent(message)
}

/// 纯编排/跨 agent「演戏」工具——不能当作固废现场取证
pub fn is_theater_tool(tool: &str) -> bool {
    matches!(
        tool,
        "auto_route"
            | "cross_agent_query"
            | "a2a_send"
            | "a2a_recv"
            | "continue_task"
            | "reasonix_dispatch"
            | "system_status"
            | "agent_list"
    )
}

/// 计划是否整单都是演戏工具（对运维意图应拒绝）
pub fn is_theater_plan(plan: &ExecutionPlan) -> bool {
    !plan.steps.is_empty() && plan.steps.iter().all(|s| is_theater_tool(&s.tool))
}

/// 注入 system prompt 的本部门运维纪律
pub fn ops_playbook_prompt() -> &'static str {
    if !domain_mode().is_solid_waste() {
        return "";
    }
    r#"

## 固废本部门运维纪律（P0，强制）
你在本部门（固废）权限内是**现场运维 Agent**，不是只会查库写报告的玩具。

### 证据门禁
涉及联单 / 文件夹整理 / 归档 /「放错、没放入」时：
1. **必须先取证**：调用目录/整理/进厂/媒体类工具（如 `organize_folders`、`check_media_files`、`query_entrance`、`query_today`、`archive_ops` 等清单内真实工具）
2. **禁止**在未拿到工具返回前输出「根因分析 / 修复方案 / 车牌OCR猜测」
3. **禁止**用 `auto_route` / `cross_agent_query` / A2A 代替本部门 dashboard 技能
4. 工具失败时：只报告失败原因与下一步可调工具，**禁止编造**业务故事

### 标准作业剧本
1. `query_today` / `query_entrance` 查进厂/联单记录（数据侧）
2. `check_media_files` / `organize_folders(dry_run=true)` 查目录现状（文件侧）
3. 对比差异（有文件无记录 / 有记录无文件 / 车牌不一致）
4. 必要时 `code_reader` 读整理相关 skill 源码定位逻辑
5. 真实整理（`organize_folders` 无 dry_run）须经用户确认 / HumanInLoop 审批后再执行

### NVR 录像下载
- 用户要求「下载录像 / 某日录像 / 补下录像 / NVR 历史录像」时：必须调用 `download_nvr_videos`（date / company / only_plate）
- **禁止**用 `system_ops`（只查进程/端口，不会下载）或 `check_media_files`（只对账磁盘与库）代替下载

### 失败纪律
- 调不通工具 ≠ 可以空嘴交差
- 没有 tool 结果就说「可能 OCR 错了」属于违规

## 固废本部门工程师纪律（P0，强制）
你在本部门权限内也是**可控闭环工程师 Agent**（不是只会查库的玩具）。

### 改码闭环（必须按序）
1. `code_reader` 读相关源码/搜关键词，先搞清现状
2. `edit_code(dry_run=true)` 出预览，把拟改摘要给用户
3. 用户确认后：`edit_code(dry_run=false)`（会触发 HumanInLoop 审批台）
4. 写入后立刻 `verify_code`（.py→py_compile；agent-core .rs→cargo check）
5. 据实验证结果汇报；失败则读错误再改，禁止空嘴说「应该好了」

### 工程师红线
- **禁止**用 `auto_route` / A2A 代替本部门 `edit_code`/`verify_code`
- **禁止**通用 shell；只能用白名单校验工具
- **禁止**改 `.env` / 密钥 / `*.db`
- 允许仓仅：dashboard / agent-core / agent-base

### 通用办公地基复用（P1，与 officecli 引擎协作）
- Excel / Word / PPT / PDF / 网页等**通用文档操作优先调用 officecli 引擎**（全局可见）：
  `officecli_read` / `officecli_query` / `officecli_create` / `officecli_merge` / `officecli_pdf` / `officecli_validate` / `officecli_issues` / `officecli_render`
- 文件系统/URL/分析底座走 fsutil 源：`list_dir` / `find_files` / `file_info` / `summarize_url` / `data_analysis`（只读）；`move_file` / `delete_path` 为**破坏性写操作**，须先经用户确认或 HumanInLoop 审批，禁止静默执行
- **禁止**在本部门 skill 内重复实现 openpyxl / docx / fpdf 样板；新需求一律走 officecli 引擎
"#
}

/// Composer 规划器附加规则（运维意图）
pub fn composer_ops_rules() -> &'static str {
    if !domain_mode().is_solid_waste() {
        return "";
    }
    r#"
- 【固废运维强制】用户提到联单/整理/文件夹/归档/放入/理文时：
  - 禁止整单只用 auto_route / cross_agent_query / a2a_*
  - 必须优先使用 dashboard 固废技能：organize_folders、check_media_files、query_entrance、query_today、archive_ops、ocr_manifest、download_nvr_videos 等（以可用工具列表为准）
  - 第一步必须是取证（查目录或查进厂），不能先「路由到某个 Agent」
  - 若列表里没有整理类工具，返回单步说明「当前身份看不到部门整理技能」，不要编造计划
- 【NVR 录像下载】用户要求下载/补下历史录像时：步骤必须用 `download_nvr_videos`，禁止用 `system_ops` / `check_media_files` 代替
- 【固废工程师强制】用户提到改代码/修bug/报错/源码时：
  - 步骤必须含 code_reader → edit_code(dry_run=true) →（确认后）edit_code → verify_code
  - 禁止整单只用 auto_route / cross_agent_query
  - 禁止 invent 不存在的 exec_shell / run_command
"#
}

/// 未取证却试图下结论时的拒答
pub fn refuse_ungrounded_ops_reply(message: &str) -> String {    if is_engineer_intent(message) {
        return format!(
            "⚠️ 未走改码闭环，拒绝空嘴交差。\n\
             涉及改代码/修 bug 时，必须先 code_reader 取证，再 edit_code(dry_run) 预览，\
             经确认与审批后写入，并用 verify_code 校验。\n\
             \n原始需求：{}",
            message.chars().take(200).collect::<String>()
        );
    }
    format!(
        "⚠️ 未取证，拒绝空嘴分析。\n\
         涉及联单/文件夹整理时，必须先调用本部门工具查当日目录与进厂记录，再给结论。\n\
         请直接再说一次需求，或回复「继续」让我执行取证；可用工具包括 organize_folders / query_entrance / check_media_files 等。\n\
         \n原始需求：{}",
        message.chars().take(200).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composer::{ExecutionPlan, StepPlan};

    #[test]
    fn enrich_adds_org_and_dept() {
        let mut ns = vec!["agent/user".to_string()];
        enrich_allowed_ns(&mut ns);
        assert!(ns.iter().any(|n| n == &org_ns()));
        assert!(ns.iter().any(|n| n == &dept_toolkit_ns()));
    }

    #[test]
    fn enrich_skips_star() {
        let mut ns = vec!["*".to_string()];
        enrich_allowed_ns(&mut ns);
        assert_eq!(ns, vec!["*"]);
    }

    #[test]
    fn ops_intent_and_theater() {
        assert!(is_ops_investigate_intent("7月26日理文联单整理放错文件夹"));
        assert!(!is_ops_investigate_intent("今天进厂多少车"));
        let plan = ExecutionPlan {
            steps: vec![
                StepPlan {
                    step_id: 1,
                    description: "route".into(),
                    tool: "auto_route".into(),
                    arguments: serde_json::json!({}),
                    depends_on: vec![],
                },
                StepPlan {
                    step_id: 2,
                    description: "ask".into(),
                    tool: "cross_agent_query".into(),
                    arguments: serde_json::json!({}),
                    depends_on: vec![1],
                },
            ],
        };
        assert!(is_theater_plan(&plan));
        assert!(is_engineer_intent("请改代码修这个 skill 的报错"));
        assert!(is_dept_grounded_intent("traceback 修bug"));
    }
}

/// P0-3 收尾：数据字典业务口径（并入部门 playbook，dept 身份常驻生效）
///
/// 口径与 dashboard /api/db/data-dictionary 一致（22 字段/4 派生规则），
/// 让 agent 答题口径不再靠 prompt 硬编码/猜单位。仅口径说明，无真实行数据。
pub fn data_dict_prompt() -> &'static str {
    r#"
## 固废数据字典（口径参考，P0-3）
查询/回答固废业务数据时，字段口径以本字典为准（与 dashboard /api/db/data-dictionary 一致）：
- vehicle_entrance（入厂记录）：license_plate=车牌；weight=毛重(吨)；net_weight=净重合计(吨)；entrance_date=YYYY-MM-DD；waste_type=固废种类(如一般工业固废SW59)
- vehicle_whitelist（白名单）：license_plate=授权车牌(唯一)；company_name=企业全称；short_name=企业简称；enabled=1启用/0停用
- manifest_records（联单）：manifest_no=联单编号；plate=验证后车牌；sender_company=移出单位；receiver_company=接收单位
- indicator_history（指标）：indicator_name 形如 当日重量_YYYY-MM-DD / 月总量_YYYY-MM；indicator_value 单位见 indicator_unit
- sample_records（取样）：supplier=供应商；license_plate=取样车牌
⚠️ 高敏字段（车牌/供应商）对只读试用身份默认打码展示，如 ***569；内部身份可看全量。
⚠️ 白名单≠入厂记录：某车可能只有白名单无入厂记录，反之亦然；两表勿混淆。
"#
}
