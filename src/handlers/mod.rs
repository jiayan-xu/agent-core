//! HTTP handler 分组（从 src/main.rs 拆分）。
//!
//! 各子模块承载对应领域的 axum handler；共享类型（AppState/AuthContext 等）来自
//! crate::state / crate::auth / crate::config。四预算自治封套（AutonomyBudget）落点 = evolve.rs。

pub mod admin;
pub mod approval;
pub mod assistants;
pub mod chat;
pub mod collab;
pub mod discovery; // /.well-known 平台发现端点（智能体自助接入）
pub mod evolve;
pub mod gateway;
pub mod identity;
pub mod meetings;
pub mod meetings_group;
pub mod platform;
pub mod services; // P2：服务编排端点（启停/保活/状态）
pub mod system;
