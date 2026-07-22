pub mod agent;
pub mod approval;
pub mod resources;
pub mod audit;
pub mod boundary;
pub mod boot_lifecycle;
pub mod checkpoint;
pub mod composer;
pub mod degrade;
pub mod harness;
pub mod llm;
pub mod mcp_client;
pub mod namespace;
pub mod file_checkpoint;
pub mod quota;
pub mod sandbox;
pub mod session;
pub mod runtime;
pub mod scheduler;
pub mod self_evolution;
pub mod text_signals;
pub mod memory_extract;
pub mod memory_evolve;
pub mod meta_evolve;
pub mod code_evolve;
pub mod skill_library; // HY3 1.3+：技能库注册表
pub mod features; // HY3 1.3：三大项热路径接线辅助（flag 默认 OFF）
pub mod lats; // HY3 1.3：LATS 过程树搜索（execute_chat 层，flag 默认 OFF）
pub mod multiagent; // HY3 1.3：MultiAgent Compose 子 agent 派发（flag 默认 OFF）
