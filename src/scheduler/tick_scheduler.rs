//! TickScheduler —— 多分身 tick 调度器（Phase 1 骨架）
//!
//! 仅依赖 std + crate 内部路径，不引入新第三方依赖。

use std::collections::HashMap;
use std::sync::Mutex;

use crate::runtime::self_runtime::SelfRuntime;

#[derive(Default)]
pub struct TickScheduler {
    runtimes: Mutex<HashMap<String, SelfRuntime>>,
}

impl TickScheduler {
    pub fn new() -> Self {
        Self {
            runtimes: Mutex::new(HashMap::new()),
        }
    }

    /// 注册一个分身运行时（以 persona_id 为 key）
    pub fn register(&self, rt: SelfRuntime) {
        let id = rt.persona.persona_id.clone();
        let mut map = self.runtimes.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(id, rt);
    }

    /// 注销分身运行时
    pub fn unregister(&self, id: &str) {
        let mut map = self.runtimes.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(id);
    }

    /// 当前注册的分身数量
    pub fn count(&self) -> usize {
        let map = self.runtimes.lock().unwrap_or_else(|p| p.into_inner());
        map.len()
    }

    /// 返回所有非 Sleeping 的分身运行时（克隆，供 AgentCore 驱动真实 tick）
    pub fn non_sleeping_runtimes(&self) -> Vec<SelfRuntime> {
        let map = self.runtimes.lock().unwrap_or_else(|p| p.into_inner());
        map.values()
            .filter(|rt| rt.tick_state != crate::runtime::self_runtime::TickState::Sleeping)
            .cloned()
            .collect()
    }
}
