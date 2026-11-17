# 架构与信任边界（中文摘要）

> 英文全文：[docs/modules.md](../modules.md)——包含完整 crate 列表、依赖图与 **Trust boundaries** 小节。
> 本文只做中文摘要与导航，细节以英文原文为准。

## 组件分层

```
浏览器 / 外部 MCP 客户端 / AI 助手
        │ HTTPS（Bearer JWT / API key）
        ▼
控制面 pingwaf-server（:9080 控制台+API，:9090 gRPC）──► PostgreSQL（状态与密钥）
        │ gRPC over TLS（下发规则包 / 上报日志·事件·指标）
        ▼
数据面 agent（:80/:443 代理流量）──► 源站
        │
        └─► 第三方：AI provider / Webhook / SMTP / Elasticsearch / ACME·DNS / GeoIP
```

## 信任边界摘要

| 边界 | 持有 / 可见 | 信任前提 |
| --- | --- | --- |
| 控制面 | 全部租户配置与日志、管理员凭据、JWT 密钥、`WAFRED_SECRET_KEY` | 仅管理员（控制台/API）与持 per-agent key 的 agent 可达；默认只监听环回 |
| 数据面 agent | 仅本站点规则包（含其 TLS 私钥/OIDC secret）、agent token、0600 本地缓存 | 无数据库、无控制面读面；enroll key 只带 `agent` 权限；断连时 fail-open/fail-closed 显式可选 |
| PostgreSQL | 站点私钥、basic-auth 明文口令、OIDC cookie secret、密封后的渠道/AI/备份凭据 | 视作密钥库：限制访问、加密备份 |
| 浏览器 | 同源控制台 + Bearer JWT / Passkey | 依赖 CSP/安全响应头；Passkey 需 HTTPS 或 localhost |
| 第三方 | AI provider 收到工具结果；Webhook/SMTP/ES/ACME/GeoIP 为运维配置的出网点 | 逐项审阅数据外发与保留策略；部分出网有 SSRF 校验 |

## 延伸阅读

- 信任边界与数据流：[modules.md](../modules.md)
- 请求处理流水线（各插件在哪个阶段生效）：[http-lifecycle.md](./http-lifecycle.md)
- 加固清单（逐项环境变量与步骤）：[SECURITY.md](../../SECURITY.md#hardening-checklist)
- 部署形态、端口与防火墙：[deployment.md](./deployment.md)
- 控制面 API 与 MCP 权限边界：[api.md](./api.md)
