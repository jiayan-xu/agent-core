# memoria 驱动的 Agent 集群与个人助手方案

> 版本：草案 v0.1 · 2026-10-22
> 状态：待评审 → 按阶段实施
> 关联：`EVOLUTION.md` 2026-10-22（P2 服务治理）、memoria 沉淀 `c3b0dd8f` / `b91ca65d` / `86c27639` / `e9c2d6c9`

---

## 1. 背景

### 1.1 现状资产（全部已运行）

| 层 | 资产 | 状态 |
|---|---|---|
| 记忆层 | memoria :9003（MCP + 命名空间 + 图/向量 + 固化/梦境/衰减 + audit_query） | ~110k 条目，召回基线 @10=72.4% / @5=92.5% |
| 编排层 | A2A Bridge :9000（v1.3.0，REST + MCP 双面，badge 准入，审计写 memoria） | 生产运行，TASK_STORE 内存态 |
| 节点层 | OpenClaw :9011 / Hermes :9012 / WorkBuddy :9013 / Reasonix :52001+Worker :9004 | 各自独立运行，未接 memoria |
| 基础设施 | agent-core :9753（SCM 托管 + 编排 + persona 意识流 + LLM 池）、PFAiX dashboard :8000（badge 体系） | 2026-10-22 全量纳入编排 |

### 1.2 缺口（三个胶水）

1. **任务无记忆**：`TASK_STORE` 是纯内存字典——Bridge 重启即丢，任务不可追溯；agent 之间委托任务不共享任何上下文
2. **清单未平台化**：`platform_registry.py` 适配器已挂，但 `apps.json` 中 `type=agent` 条目为 **0 个**——分身清单仍硬编码在 `server.py` 的 `SYSTEMS`
3. **召回基线未稳**：@10=72.4%。集群化后写入量与记忆异质性都会上升，此指标会先恶化

### 1.3 机会

memoria 是现成的「公共记忆总线」：命名空间体系、固化/梦境、图+向量双存储全部就绪，且 A2A 的准入审计已经在往里写——**集群化不需要新建基础设施，只需要把三块接起来**。

---

## 2. 目标

### 2.1 集群目标

分身 agent 之间**共享记忆**：任一分身处理过的任务、踩过的坑、得出的结论，经 memoria 固化后全体可用；任务可交接、经验可沉淀、准入可审计。

### 2.2 个人助手目标

每个员工拥有一个**统一入口**的个人助手（memoria 个人 NS 驱动），后台编排其 2-3 个分身。**替换的是入口和体验，不是能力本身**——WorkBuddy 继续当 IDE、Reasonix 继续当编码器，收编的是「谁在指挥它们」。

### 2.3 非目标（明确不做）

- 不做跨机器集群（单机多分身已满足当前规模；跨机是远期演进）
- 不做 memoria 高可用主从（用降级模式替代，见 §6）
- 不做实时流式协同（A2A 异步任务模型足够）

---

## 3. 架构与关键设计

### 3.1 总体分层

```
┌─────────────────────────────────────────────────────┐
│  memoria :9003 — 公共记忆总线                        │
│  agent/<员工> 私域 · org/<company> 共享域   │
│  任务上下文(episodic) · 审计 · 固化/梦境 · 图+向量     │
└──────────────┬──────────────────────────────────────┘
               │ MCP（写：memory_remember/observe；读：recall/context）
┌──────────────┴──────────────────────────────────────┐
│  A2A Bridge :9000 — 编排层                           │
│  任务派发 · 结果回路 · badge 准入 · 按画像路由(阶段2)  │
└──────────────┬──────────────────────────────────────┘
               │ webhook /api/a2a/task
┌──────────────┴──────────────────────────────────────┐
│  分身执行层：固废监管分身 / 工程分析分身 / 编码分身 ... │
└─────────────────────────────────────────────────────┘
```

### 3.2 命名空间规范（已拍板 2026-10-22，memoria `e9c2d6c9`）

**助手记忆直接写入所属员工的 NS（`agent/<员工>`），不给助手单独开 NS。**

| 规则 | 内容 |
|---|---|
| NS 归属 | 员工离职 = 清一个 NS，全部助手记忆一并处置 |
| 助手身份 | 用 `memory_observe`/`memory_remember` 的 `source` + `agent_id` 字段标记，约定 `agent_id = "<员工>-<助手>"`（如 `xujiayan-ovc`） |
| 授权 | NsPolicy 给每个助手实例发独立 agent 身份，**授权写主人的 NS**（新姿势，需验证一次） |
| 共享域 | `org/<company>` 存放组织级结论/经验（固化产物） |
| 容量 | 单 NS 增长 = 该员工全部助手之和；按写入纪律（§3.3）100 员工规模日均 ~2.5k 条 |

### 3.3 写入纪律（核心约束）

**写入策略 > 扩容。** 记忆分三档：

- **必记**：决策、结论、偏好、用户纠偏（方案 A 现行纪律）
- **选记**：任务上下文（阶段 1 引入，随 A2A 任务生命周期自动写）
- **不记**：工具调用中间过程、原始对话、可从别处重建的数据（固废日志等有自己落库的地方）

### 3.4 已实测的容量数据（2026-10-22）

| 指标 | 实测值 | 说明 |
|---|---|---|
| `memory_observe` 写入延迟 | **~1ms/条** | 110k 条目现状 |
| `memory_search_v2` 读延迟 | ~1ms | 同上 |
| 全记场景（100 员工 × 2.5 助手 × 100 条/天） | 25k 条/天 = 25 秒写入/天 | 吞吐毫无压力 |
| 精选场景（×10 条/天） | 2.5k 条/天 = 2.5 秒写入/天 | 推荐态 |
| 存储 | ~1KB/条（含 FTS 索引） | 全记一年 ~9GB，精选 ~1GB |

**唯一未消化的未知项**：embed 异步链路深度——「写入 1ms」可能是入队即返，向量化异步补。若队列堆积，新记忆的向量检索存在延迟窗口。→ 阶段 0 用探针实测消除（写入后间隔 5min/30min/2h 各查一次召回与向量就绪）。

---

## 4. 分阶段实施计划

### 阶段 0：编排层地基（1~2 天，改动小、独立、立即可验）

**0.1 TASK_STORE 落 memoria**

A2A Bridge 改造点（`server.py`）：任务创建、状态变更、完成三个时机写 memoria。

```python
# server.py 新增（骨架）
async def _persist_task_event(task: TaskModel, event: str):
    """任务事件落 memoria（episodic，agent/a2a-bridge 命名空间）。
    失败仅记日志——审计管道故障不阻塞任务本身（与 _audit_admission 同策略）。"""
    payload = {
        "dialog": f"a2a_task {event} id={task.id} target={task.target} "
                  f"status={task.status.value} result={task.result or ''}",
        "role": "system",
        "session_id": task.id,
        "source": "a2a-bridge",
        "agent_id": "a2a-bridge",
        "params": {"target": task.target, "event": event},
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "memory_observe", "arguments": payload}}
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            await client.post(MEMORIA_MCP_URL, json=body, headers=_memoria_headers())
    except Exception as exc:
        logger.warning("task persist failed: %s", exc)
```

接入点：`task_send`（created）、`_delegate_task`（working/completed/failed）、`task_cancel`（canceled）。

**0.2 注册表迁移收尾**

`apps.json` 补 4 个 `type=agent` 条目（openclaw/hermes/workbuddy/reasonix），字段对齐 nvr 条目格式（id/name/url/authz.badge/scopes/lifecycle/health）。`server.py` 的内置 SYSTEMS 降级为兜底默认。

**0.3 write_guard 巡检**（对标 recall_guard）

巡检项：写入 P95 延迟、日增条数（按 namespace 分组）、embed 队列深度。输出与 recall_guard 同风格的 ⚠️+结构化表格。**只跑不改，run-and-report only。**

**验收**：重启 Bridge 后任务历史可查（memoria recall）；write_guard 首份报告产出。

### 阶段 1：记忆互联互通（1~2 周，集群的核心价值）

**1.1 分身接入 memoria MCP**——逐个分身验证（每接入一个跑一轮召回相关性检查，防止污染基线）。

**1.2 任务交接带记忆**——派发前写上下文（任务目标+前情摘要），接手方开工前 `memory_recall` 前任记录。第一个感知价值的点：分身之间真的开始共享记忆。

**1.3 授权验证**——NsPolicy 的「助手写主人 NS」路径实测（新姿势）。

**1.4 embed 异步链路查证**（阶段 0 遗留）。

### 阶段 2：职责分化（集群不是复制）

- **按记忆画像自动路由**：`cross_agent_query` 的 target 从手动指定改为可选自动——路由器查各分身 namespace 的「履历密度」决定派给谁
- **panel_discuss 升级**：圆桌时各分身携带自己 namespace 的相关记忆入场
- **经验固化闭环**：分身反复踩的坑 → consolidate 沉成 org 级 procedural → 全体受益

### 阶段 3：个人助手统一入口

- agent-core persona + memoria 个人 NS = 助手骨架（已就绪度最高）
- 收编编排：用户对统一助手说话 → 后台决定自己干/派分身
- 多员工推广：每员工一套 `agent/<员工>` NS + N 个助手身份（NsPolicy 批量发放）

---

## 5. 风险与对策（全部有今日实证）

| # | 风险 | 实证来源 | 对策 |
|---|---|---|---|
| R1 | memoria 单点：挂则集群失忆 | emb 挂 → memoria /health 慢至 2s（2026-10-22） | 降级模式：记忆不可用时 agent 退化为无记忆直答（不报错）；write_guard 监控 |
| R2 | 召回污染：集群记忆量翻倍 | @10=72.4% 基线 | 每接入一个分身跑一轮召回相关性检查；写入纪律（§3.3）先于一切 |
| R3 | 环境差异 | LocalSystem 缺 PYTHONPATH（2026-10-22） | 每个分身服务化过环境 checklist（PYTHONPATH/%APPDATA%/凭据/桌面交互） |
| R4 | 密钥面扩大 | EVOLVE_KEY 进公开历史（2026-10-22） | 统一 env 注入；禁止派生文件（备份还原占位符）；分身身份密钥全部走 NsPolicy 发放 |
| R5 | 写入膨胀 | 本方案 §3.3 | 写入纪律写入每个分身的系统提示；write_guard 日增告警 |
| R6 | 任务堆积 | TASK_STORE 无界字典 | 阶段 0 落 memoria 后加 TTL 清理；超时任务标 failed |

---

## 6. 验收标准

| 阶段 | 验收 |
|---|---|
| 0 | Bridge 重启后任务历史可查；write_guard 首份报告；embed 链路结论产出 |
| 1 | 演示：OpenClaw 处理固废日志 → Hermes 接手分析时 recall 到前情（录屏存档）；NsPolicy 新授权路径通过 |
| 2 | 自动路由命中正确分身 ≥ 演示场景 3/3 |
| 3 | 个人助手统一入口上线，第一员工（你自己）日常使用 ≥ 2 周 |

---

## 7. 待定事项

- [ ] P3 平台注册表的 mcp 字段格式（nvr-mcp 的 apps.json 挂载路径未定，不影响本方案）
- [ ] embed 异步队列深度监控接口（阶段 0 查证）
- [ ] 多员工规模的 NsPolicy 批量发放工具（阶段 3 前置）
- [ ] memoria 降级模式的具体实现点（agent-core 侧 catch-and-degrade）
