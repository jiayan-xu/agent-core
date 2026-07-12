# ADR-009: 边界策略收紧（Boundary Policy Tightening）

## Status
Accepted

## Date
2026-07-11

## Context
P0-4 之前：外发工具名靠精确匹配易漏；供应链白名单为空时过宽；未知工具默认当 WRITE 自动放行；SQL 只读未做参数级多语句扫描。这些都会让 P0-2 硬闸门出现缝隙。

## Decision
1. **外发检测前缀化 + 显式名表**：`boundary.rs` `DataExfiltrationGuard` 用前缀 `export_` / `send_` / `upload_` / `push_` / `webhook_` / `exfil` / `share_` + 显式危险名表（如 `export_data` / `send_email` / `api_push` / `webhook_send`）判定外发，避免漏判新命名。
2. **供应链白名单默认收紧**：`SupplyChainGuard { whitelist }`（`boundary.rs:421`）。生产默认要求白名单；`new(None)` 即空名单 → 不可信 MCP 工具默认拒接。`source=local` 仅 debug 配置可放行。
3. **未知工具默认 deny / YELLOW**：`register_from_tools`（`boundary.rs:666`）对未知工具不再默认当 WRITE 自动放行，改为 `unknown` 分类（YELLOW / 默认收紧，策略可配）。
4. **SQL 只读硬化**：保持正向 SELECT-only；参数级再扫多语句（`;` 后写操作）拦截。

## Design
- `ToolClassifier::classify` 返回 `unknown` 而非 `write`（默认收紧）。
- `DataExfiltrationGuard::check_export(name)` 前缀 + 名表；`SupplyChainGuard::new(whitelist)` 空名单即严格。

## Alternatives Considered
- **未知工具默认放行（老行为）**：运维便利但扩大攻击面 → 否决，改为默认收紧。
- **仅精确名表做外发检测**：易漏 → 否决，前缀 + 名表双保险。

## Consequences
- **正面**：外发 / 未知 / 供应链三类缝隙被堵，与 P0-2 硬闸门互补。
- **代价**：新增 MCP 源需显式加入白名单（运维步骤）。
- **风险**：白名单过严误伤可信源 → 保留 `source=local` debug 放行通道，且白名单可配。

## Future Work
- 白名单支持通配 / 命名空间级继承。
- 外发检测接入 DLP 规则（正则可配）。
