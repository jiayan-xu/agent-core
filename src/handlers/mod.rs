//! HTTP handler 分组（从 src/main.rs 拆分）。
//!
//! 各子模块承载对应领域的 axum handler；共享类型（AppState/AuthContext 等）来自
//! crate::state / crate::auth / crate::config。四预算自治封套（AutonomyBudget）落点 = evolve.rs。

pub mod admin;
pub mod approval;
pub mod chat;
pub mod collab;
pub mod evolve;
pub mod identity;
pub mod meetings;
pub mod system;
