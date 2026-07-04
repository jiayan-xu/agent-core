# ADR-002: Compositional Skill Routing (多 Skill 组合路由)

## Status
Proposed

## Date
2026-07-09

## Context
复杂用户请求往往需要多个 skill 组合才能完成（例如"查询上个月数据→生成图表→发送飞书"需要 query_sql + chart_gen + feishu_send）。当前系统有两种处理方式：

1. **LLM tool calling 自动多轮** — LLM 在 chat loop 中一步步决定调什么工具，每步依赖上一步结果
2. **Harness 模板匹配** — 预定义的固定步骤模板

问题在于：
- 方式 1 缺乏全局可见性：用户不知道 LLM 打算做几步、用什么工具，直到执行完
- 方式 2 需要先有执行日志才能蒸馏，对新场景不适用
- 两种方式都无法展示"执行计划"给用户确认

阿里 SkillWeaver 的思路提供了参考：先 decompose（拆分子任务）→ retrieve（匹配 skill）→ compose（编排依赖），让执行计划在确认阶段就可见。

## Decision
在现有 `execute_chat` 中增加一条**组合路由路径**，在 LLM loop 之前先做一步规划，输出执行计划后按序执行。

## Design

### 流程

```
用户确认理解 → Composer 介入
                    │
                    ▼
          LLM 规划（无工具）
          生成 JSON 执行计划
          [{"step": "查询上月数据", "tool": "query_sql", "args": {...}},
           {"step": "生成趋势图",   "tool": "chart_gen", "args": {...}},
           {"step": "发送飞书",     "tool": "feishu_send", "args": {...}}]
                    │
                    ▼
          用户可见计划（可选展示）
                    │
                    ▼
          按序/并行执行每个 step
          上一步输出作为上下文传入下一步
                    │
                    ▼
          汇总结果交付
```

### 新增模块

**`composer.rs`** — 组合路由引擎

```
CompositionalPlanner
  ├── decompose(query, tools) → Vec<SubTask>   // LLM 拆解
  ├── route(sub_tasks, tools) → Vec<StepPlan>   // 匹配工具
  └── execute(plan) → String                    // 按序执行
```

### 状态机扩展

在 `SessionState` 中新增或复用：
- `Confirmed` 状态下，检测是否需要组合路由
- 判断标准：`rephrase_and_confirm` 阶段 LLM 输出的复述中包含多步计划

### 与现有系统的关系

- **不替换**现有的 LLM loop — 组合路由是 LLM loop 的前置路径
- **互补**Harness — Harness 是事后蒸馏，Composer 是事前规划
- **复用**现有的 `find_mcp_for_tool` / `call_tool_routed` / boundary checks

### 执行计划格式

```json
{
  "plan": [
    {
      "step_id": 1,
      "description": "查询上个月车辆入厂数据",
      "tool": "query_sql",
      "arguments": {"query": "SELECT * FROM vehicle_entrance WHERE month='2026-06'"},
      "depends_on": []
    },
    {
      "step_id": 2,
      "description": "生成每日趋势图表",
      "tool": "chart_gen",
      "arguments": {"data_source": "step_1_result", "chart_type": "line"},
      "depends_on": [1]
    }
  ]
}
```

### 执行引擎

```rust
async fn execute_plan(&self, plan: &ExecutionPlan, session_id: &str) -> Result<String, String> {
    let mut step_results: HashMap<u32, String> = HashMap::new();
    
    // 按拓扑序执行（depends_on 决定顺序）
    for step in plan.plan.iter() {
        // 检查依赖是否就绪
        for dep_id in &step.depends_on {
            if !step_results.contains_key(dep_id) {
                return Err(format!("Step {} 的依赖 Step {} 未就绪", step.step_id, dep_id));
            }
        }
        
        // 注入上一步结果到参数中
        let mut args = step.arguments.clone();
        if let Some(obj) = args.as_object_mut() {
            for (key, val) in obj.clone().iter() {
                if let Some(s) = val.as_str() {
                    if s.starts_with("step_") {
                        if let Some(prev) = step_results.get(&step.step_id.saturating_sub(1)) {
                            obj[key.as_str()] = serde_json::Value::String(prev.clone());
                        }
                    }
                }
            }
        }
        
        // 执行工具
        let result = self.call_tool_routed(&step.tool, &args).await?;
        step_results.insert(step.step_id, result);
    }
    
    // 汇总
    Ok(format!("已完成 {} 步", plan.plan.len()))
}
```

### 配置开关

在 `AgentConfig` 中新增字段，默认关闭：
```rust
pub enable_compositional_routing: bool,  // 默认 false
```

## Alternatives Considered

### A. 仅依赖 LLM tool calling（现状）

优点：零改动、LLM 自动处理多步
缺点：无全局计划可见性、中间步骤不可控、token 浪费（LLM 每步都要重新决策）

### B. 完整的三段式架构（阿里 SkillWeaver 方式）

优点：学术完整、有 benchmark 支撑
缺点：太重（需要 FAISS 索引、bi-encoder 检索），不适合当前规模

### C. 选中的轻量方案

在现有 `execute_chat` 前置一个 LLM 规划调用。实现成本低（~200 行），收益明确（计划可见 + 结构化执行），且可逐步演进。

## Consequences

- **正面**：复杂任务有了全局执行计划，用户可在确认阶段看到计划
- **正面**：步骤间数据依赖清晰，减少 LLM 中途"偏航"
- **正面**：为将来并行执行独立步骤打下基础
- **代价**：增加一次 LLM 调用（规划阶段），延迟增加 ~1-2s
- **代价**：plan JSON 的解析和校验需要处理错误情况
- **风险**：LLM 生成的 JSON 计划可能不合法 → 需要降级到普通 LLM loop

## Future Work

- 并行执行无依赖步骤
- 执行计划的中间进度反馈（类似 task-workflow 的进度标识）
- 计划执行失败时的局部重试
- 从执行日志自动蒸馏成 Harness 模板（闭环）
