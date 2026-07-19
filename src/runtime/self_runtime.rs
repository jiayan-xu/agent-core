//! SelfRuntime —— 分身运行时（Phase 1 骨架）
//!
//! 仅依赖 std + crate 内部路径，不引入新第三方依赖。

/// 分身身份与配置
#[derive(Debug, Clone)]
pub struct Persona {
    pub persona_id: String,
    pub display_name: String,
    pub owner_user_id: String,
    pub workspace_dir: Option<std::path::PathBuf>,
    pub tool_allowlist: Vec<String>,
    pub memory_namespace: String,
    pub badge_token: String,
    pub ns_full_path: Option<String>,
}

/// 分身运行时的 tick 状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickState {
    Idle,
    Running,
    Sleeping,
}

/// 分身运行时实例
#[derive(Debug, Clone)]
pub struct SelfRuntime {
    pub ns: String,
    pub persona: Persona,
    pub goal_stack: Vec<String>,
    pub tick_state: TickState,
}

impl SelfRuntime {
    /// 创建分身运行时；ns 取 persona.memory_namespace（非空）否则 `agent/{persona_id}`
    pub fn new(persona: Persona) -> Self {
        let ns = if persona.memory_namespace.is_empty() {
            format!("agent/{}", persona.persona_id)
        } else {
            persona.memory_namespace.clone()
        };
        Self {
            ns,
            persona,
            goal_stack: Vec::new(),
            tick_state: TickState::Idle,
        }
    }

    /// 骨架 tick：依 tick_state 与 goal_stack 返回计划文本，不真正调用工具
    pub fn execute_tick(&self) -> String {
        match self.tick_state {
            TickState::Sleeping => format!("[{}] sleeping, skip tick", self.persona.persona_id),
            TickState::Idle => {
                if self.goal_stack.is_empty() {
                    format!("[{}] idle, no goals", self.persona.persona_id)
                } else {
                    format!(
                        "[{}] idle → running, next goal: {}",
                        self.persona.persona_id,
                        self.goal_stack.last().unwrap()
                    )
                }
            }
            TickState::Running => {
                if let Some(goal) = self.goal_stack.last() {
                    format!("[{}] running, executing goal: {}", self.persona.persona_id, goal)
                } else {
                    format!("[{}] running but no goal, → idle", self.persona.persona_id)
                }
            }
        }
    }
}
