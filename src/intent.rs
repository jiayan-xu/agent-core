//! 统一意图分类（重构阶段 1：IntentClassifier）
//!
//! 背景：execute_chat 曾散落 7+ 个 `is_xxx` / `extract_xxx` 判断，每个守卫各自
//! 处理「附件/末轮/did_work 豁免」，正走向守卫链屎山。本模块定义**一次分类**
//! 的产物 `Intent`——下游守卫、预路由、循环内豁免、输出守卫统一读取，
//! 消除重复判断与豁免条件复制。
//!
//! 阶段 1 约定：`Intent` 是纯数据结构（零依赖），分类逻辑
//! `AgentCore::classify_intent` 在 agent.rs 内实现（复用既有确定性判断函数），
//! 行为与散落判断完全一致；阶段 2 起 execute_chat 逐步切换到本结构。

/// 意图大类（优先级从高到低：GuardBlocked > ApprovalConfirm > WhitelistWrite
/// > Attachment > DataQuery > Chat）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentKind {
    /// 输入守卫拦截（绕过审批 / 危险操作），直接拒绝
    GuardBlocked,
    /// 确认类消息（消费就绪审批）
    ApprovalConfirm,
    /// 白名单/台账受控写（走审批闸）
    WhitelistWrite,
    /// 附件消息（数据在消息内，豁免强制取数/证据门禁）
    Attachment,
    /// 业务数据查询（强制工具循环）
    DataQuery,
    /// 普通对话
    Chat,
}

impl IntentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            IntentKind::GuardBlocked => "guard_blocked",
            IntentKind::ApprovalConfirm => "approval_confirm",
            IntentKind::WhitelistWrite => "whitelist_write",
            IntentKind::Attachment => "attachment",
            IntentKind::DataQuery => "data_query",
            IntentKind::Chat => "chat",
        }
    }
}

/// 一次分类的完整产物：大类 + 细分字段（供下游守卫/预路由直接读取）。
#[derive(Debug, Clone)]
pub struct Intent {
    pub kind: IntentKind,
    /// 附件正文块（File:/Sheet:/【附件正文:】）——统一豁免出口
    pub attachment: bool,
    /// 业务数据查询意图（强制工具循环触发条件）
    pub data_query: bool,
    /// 确认类消息（消费就绪审批）
    pub approval_confirm: bool,
    /// 输入守卫拦截文案（Some = 已拦截，直接返回该文案）
    pub guard_block: Option<String>,
    // ── 白名单受控写（L3 预路由表输入）──
    pub whitelist_add: Option<(String, String)>,
    pub whitelist_update: Option<(String, String)>,
    pub whitelist_waste: Option<(String, String)>,
    pub whitelist_remove: Option<String>,
    pub exception_sync: bool,
    pub sample_sync: bool,
}

impl Intent {
    /// 是否有任何受控写意图（走 L3 预路由/审批闸）
    pub fn has_whitelist_write(&self) -> bool {
        self.whitelist_add.is_some()
            || self.whitelist_update.is_some()
            || self.whitelist_waste.is_some()
            || self.whitelist_remove.is_some()
            || self.exception_sync
            || self.sample_sync
    }
}
