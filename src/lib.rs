pub mod agent;
pub mod approval;
pub mod clarify; // P2-3：澄清工具（Request clarification 对标）
pub mod reply_polish; // PFAiX 回复净化：检测 JSON/代码块泄漏
pub mod approval_store; // TASK-652：审批权威表（checkpoints.db 同库异表）
pub mod resources;
pub mod audit;
pub mod boundary;
pub mod boot_lifecycle;
pub mod checkpoint;
pub mod checkpoint_recovery; // 战略罗盘「持久执行深化」：checkpoint 恢复核心（可纯内存 e2e 测试）
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
pub mod ttc; // HY3 TTC：推理时计算（终答自一致性 + 预算感知采样，flag 默认 OFF）
pub mod metrics; // 战略罗盘「可观测」：运行指标层（原子计数 + /api/metrics 快照，默认开启）
pub mod evolution_audit; // HY3 1.3 收口：记忆自进化生产证据审计（本地 JSONL 落盘，可复验）
pub mod intake_filter; // 摄入侧治本过滤：测试命名空间隔离 / A2A 回执丢弃 / 对话实质筛选
pub mod pref_write; // 偏好/决策落盘约定 + 用户强触发启发式
pub mod dept_ops; // 固废本部门运维：工具包可见 + 证据门禁 + 作业剧本
pub mod v1_compat; // OpenAI /v1/chat 入参折叠（保留 system）
pub mod controlled_write; // 受控写「写后回读」协议骨架
pub mod local_fs; // 本仓沙箱读写文件铁轨（不依赖 dashboard MCP）
pub mod db_write; // 双轨·轨一：受控改库扳手（cw_select / cw_write）
pub mod repo_ws; // 双轨·轨二：本机白名单仓库编辑（repo_ws_*）
