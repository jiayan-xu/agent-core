//! /.well-known/assistant-platform —— 助手平台发现端点（Phase 1.5，2026-10-26）。
//!
//! 目标：同事的智能体拿到「门牌（本服务地址）+ 令牌」即可自助接入，无需读源码
//! 或手册：GET 本端点返回机器可读的完整 API 契约（认证方式、scope 语义、端点
//! 清单、令牌刷新流程、NS 派生规则）。设计对齐 RFC 8414/9728 的发现思想：
//! - 无认证：只含契约，不含任何用户数据（类比 openid-configuration）；
//! - issuer 从请求 Host 头派生——经隧道/反代访问时自动反映客户端实际可达
//!   地址；端点一律相对路径，客户端按 issuer 拼接；
//! - scopes 清单引用 assistant_platform::ALLOWED_SCOPES 单一真值；端点表
//!   与 routes.rs 人工同步（改路由记得改这里）。

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::assistant_platform::ALLOWED_SCOPES;

/// scope → 人读语义（发现文档展示用；新增 scope 在此补一行）。
fn scope_doc(scope: &str) -> &'static str {
    match scope {
        "assistant:heartbeat" => "在线心跳（任意有效令牌的最低要求）",
        "memory:read:self" => "检索本人记忆（语义搜索）",
        "memory:write:self" => "写入本人记忆",
        "a2a:send" => "向其他助手发消息/建任务/传 artifact",
        "a2a:receive" => "收件箱、任务查询与回执、artifact 读取",
        "tools:call:read" => "调用平台只读工具白名单（日限 500 次）",
        "tools:call:write" => "发起写工具审批并轮询执行结果",
        _ => "",
    }
}

pub(crate) async fn handle_assistant_discovery(headers: HeaderMap) -> Response {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:9753");
    let base = format!("http://{host}");

    // [{scope, description}]，键序与 ALLOWED_SCOPES 一致
    let scopes: Vec<serde_json::Value> = ALLOWED_SCOPES
        .iter()
        .map(|s| {
            serde_json::json!({
                "scope": s,
                "description": scope_doc(s),
            })
        })
        .collect();

    Json(serde_json::json!({
        "platform": "PFAiX 个人智能体平台",
        "spec_version": "1.0",
        "issuer": base,
        "quickstart": [
            "1. 绑定：平台「我的智能体」页绑定助手 → 获得访问令牌（pat_tok_ 前缀，24 小时有效）与刷新令牌（prt_tok_ 前缀）",
            "2. 调用：以下端点均带 Authorization: Bearer <访问令牌>（或 X-Assistant-Token 头）",
            "3. 轮换：访问令牌过期前 POST token/refresh 用刷新令牌换新令牌对（轮换式，旧对立即作废）",
        ],
        "authentication": {
            "scheme": "bearer",
            "headers": [
                "Authorization: Bearer <access_token>",
                "X-Assistant-Token: <access_token>",
            ],
            "access_token_prefix": "pat_tok_",
            "refresh_token_prefix": "prt_tok_",
            "access_token_ttl_hours": 24,
            "refresh": {
                "endpoint": "/api/assistants/token/refresh",
                "method": "POST",
                "auth": "无需 Bearer，刷新令牌本身即凭证",
                "request": {"refresh_token": "<粘贴 prt_tok_ 前缀的刷新令牌原文>"},
                "response": {"token": {"access_token": "<新访问令牌>", "refresh_token": "<新刷新令牌>"}},
                "rotation": true,
                "note": "轮换式：刷新成功后旧令牌对立即失效；无效/重放返回 401 并留审计",
            },
        },
        "identity": {
            "binding_scoped": true,
            "memory_namespace": "agent/<user_id>",
            "namespace_rule": "ns 由服务端按令牌绑定的 user_id 派生；请求体中没有 ns 字段，无法跨 ns 读写。每条写入自动附加 assistant:<type> 与 binding:<id> 标签并记审计",
        },
        "scopes": scopes,
        "endpoints": [
            {"method": "GET", "path": "/api/assistants/me", "scope": "assistant:heartbeat",
             "description": "当前绑定身份与生效 scopes"},
            {"method": "POST", "path": "/api/assistants/heartbeat", "scope": "assistant:heartbeat",
             "request": {}, "description": "在线心跳（更新 last_seen_at）"},
            {"method": "POST", "path": "/api/assistants/token/revoke", "scope": "assistant:heartbeat",
             "description": "吊销本人当前令牌（之后请求立即 401）"},
            {"method": "POST", "path": "/api/agent/memory", "scope": "memory:write:self",
             "request": {"content": "必填", "memory_type": "可选，默认 declarative",
                          "category": "可选，默认 assistant_observation", "importance": "可选 1-5，默认 3",
                          "tags": "可选字符串数组（最多取 8 个）"},
             "response": {"status": "ok", "namespace": "实际写入的 ns", "memoria": "写入结果"},
             "description": "写入个人记忆"},
            {"method": "GET", "path": "/api/agent/context", "scope": "memory:read:self",
             "query": {"q": "必填，检索词", "limit": "可选 1-20，默认 5"},
             "description": "检索本人记忆（语义搜索）"},
            {"method": "GET", "path": "/api/agent/tools", "scope": "tools:call:read",
             "description": "只读工具白名单、可写工具与日配额"},
            {"method": "POST", "path": "/api/agent/tools/call",
             "scope": "tools:call:read（读白名单）或 tools:call:write（写白名单）",
             "request": {"tool": "工具名", "arguments": "工具参数对象"},
             "description": "调用平台工具：读白名单直接执行（日限 500）；写白名单转审批，202 返回 approval_id，用 approvals/{id} 轮询"},
            {"method": "GET", "path": "/api/agent/tools/approvals/{id}", "scope": "tools:call:write",
             "description": "写工具审批轮询：202 pending / 403 denied / 200 执行结果；防重放，同一 approval_id 执行成功后再请求返回 409"},
            {"method": "POST", "path": "/api/a2a/messages", "scope": "a2a:send",
             "request": {"target_binding": "对方 binding_id", "body": "消息正文",
                          "message_type": "可选，默认 text", "meeting_id": "可选（双方须为该会议成员）",
                          "task_id": "可选关联任务"},
             "description": "给其他助手发消息"},
            {"method": "GET", "path": "/api/a2a/inbox", "scope": "a2a:receive",
             "description": "拉取收件箱"},
            {"method": "GET", "path": "/api/a2a/inbox/stream", "scope": "a2a:receive",
             "query": {"since_id": "可选，缺省只推新消息"},
             "description": "SSE 实时收件流；令牌被撤销即时断流"},
            {"method": "POST", "path": "/api/a2a/tasks", "scope": "a2a:send",
             "request": {"target_binding": "对方 binding_id", "subject": "任务标题", "body": "任务正文",
                          "task_type": "可选，默认 generic", "meeting_id": "可选"},
             "description": "创建跨助手任务（对方按 queued→working→completed 推进）"},
            {"method": "GET", "path": "/api/a2a/tasks/{id}", "scope": "a2a:receive",
             "description": "查询任务详情"},
            {"method": "POST", "path": "/api/a2a/tasks/{id}/status", "scope": "a2a:receive",
             "request": {"status": "working / completed / …", "result": "可选结果文本"},
             "description": "更新任务状态/回执结果"},
            {"method": "POST", "path": "/api/a2a/artifacts/", "scope": "a2a:send",
             "description": "上传 artifact（≤50MB；本体存本地受控目录，消息里只传引用）"},
            {"method": "GET", "path": "/api/a2a/artifacts/", "scope": "a2a:receive",
             "description": "列出 artifact"},
            {"method": "GET", "path": "/api/a2a/artifacts/{id}", "scope": "a2a:receive",
             "description": "artifact 元数据"},
            {"method": "GET", "path": "/api/a2a/artifacts/{id}/content", "scope": "a2a:receive",
             "description": "下载 artifact 本体"},
        ],
        "notes": [
            "响应均为 JSON；错误统一 {error, message}：401=令牌无效/过期/缺 scope，403=审批拒绝，429=超日配额",
            "artifact 列表/上传挂在 /api/a2a/artifacts/ 下（注意尾部斜杠）",
        ],
    }))
    .into_response()
}
