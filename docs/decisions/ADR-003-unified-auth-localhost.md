# ADR-003: 统一鉴权与本机默认（Unified Auth + Localhost Default）

## Status
Accepted

## Date
2026-07-11

## Context
W1（P0）之前，agent-core 的鉴权分散在各 handler，且默认监听可能暴露到非本机网络；桌面壳（Jan/PFAiX）与直接 API 调用方对身份的获取方式不一致，容易出现「旧客户端全 401」或「误暴露端口」两类问题。

需要一套统一、可文档化、向后兼容的鉴权与暴露面策略。

## Decision
1. **统一鉴权中间件** `auth_middleware` 覆盖所有 API（除 onboarding / 静态壳），从请求头解析身份：
   - `x-user-tag` 模式：安装实例自动注册短期身份，agent_key 回退到 `MEMORIA_ADMIN_KEY`（**兼容旧壳与本地联调**）。
   - `x-agent-id` + `x-agent-key` 模式：已向 Memoria 预注册身份的 Agent，用 key 反查 `allowed_ns`。
2. **本机默认**：`host` 默认 `127.0.0.1`；CORS 默认仅放行 `127.0.0.1` / `localhost`：`<port>`；非本机 host 才额外放行对应 origin。
3. **身份反查**：解析出的 `agent_id` 向 Memoria 反查命名空间授权（`get_allowed_ns`），结果短 TTL 缓存（60s）平衡性能与权限即时生效。
4. **密钥不留存内存明文**：鉴权缓存只存 `(badge_token, expires_at)`，不在内存留存用户 key。

## Design
- 中间件在 `main.rs` 以 `from_fn_with_state` 挂到受保护路由；`AuthContext { agent_id, allowed_ns }` 注入 `extensions`，下游 handler 直接取。
- `AppState.ns_cache` / `auth_cache` 为 `tokio::sync::Mutex<HashMap<...>>`，带 TTL 过期。
- 401 统一结构：`{"error":"unauthorized","message":...}`。

## Alternatives Considered
- **每 handler 各自鉴权**：已有痛点，重复且易遗漏 → 否决。
- **仅 x-agent-id 模式**：旧壳无预注册 key 会全 401 → 保留 `x-user-tag` legacy 兼容。

## Consequences
- **正面**：一处鉴权、全 API 覆盖；本机默认杜绝误暴露；旧壳平滑兼容。
- **代价**：新增 Memoria 反查调用（用短 TTL 缓存缓解）。
- **风险**：Memoria 不可用时鉴权链断裂 → 由 P1-5 降级状态机兜底（鉴权失败计入 unhealthy，最终收缩到 MemoriaReadonlyChat）。

## Future Work
- 可选 mTLS / OIDC 接入企业 IdP。
- 审计事件 `AuthFail` 统一上报（见 P2-2）。
