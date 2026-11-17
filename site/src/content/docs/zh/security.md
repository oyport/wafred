---
title: 安全
description: 如何私密报告漏洞、哪些版本会收到安全修复，以及在把 PingWAF 暴露到互联网之前必须完成的加固步骤。
minutes: 8
---

## 漏洞报告

PingWAF 位于其所保护应用的请求路径上，因此它自身的安全漏洞与被保护站点的漏洞同等重要。请**私密**报告——切勿在公开 Issue、讨论或 Pull Request 中披露。

- **GitHub 私密漏洞报告（首选）：** [报告漏洞](https://github.com/shuaiZend/PingWAF/security/advisories/new)——私密、可跟踪，修复路径最快。
- **邮箱：** `security@pingwaf.com`，由至少两名维护者值守。PGP 公钥正在发布中；在指纹公布于此之前，请先发送纯文本摘要，我们会回复加密公钥。

请在报告中包含：受影响版本、运行模式（`all-in-one` / `server` / `agent`）、TLS 后端、复现步骤与攻击前提，并对 token、口令等敏感信息脱敏。我们会在 3 个工作日内确认收到，修复期间至少每周同步进展，并在修复发布后（或 90 天，以先到者为准）协调公开披露。完整政策见 [SECURITY.md](https://github.com/shuaiZend/PingWAF/blob/main/SECURITY.md)。

## 支持版本

| 版本 | 状态 | 安全修复 |
| --- | --- | --- |
| `0.32.x`（当前发布线） | 支持 | 是 |
| `0.31.x` | 仅关键修复 | 按需、尽力而为 |
| `0.30.x` 及更早 | 已停止支持（EOL） | 否 |

只有当前发布线保证收到安全补丁；安全修复随补丁版本发布，并在[更新日志](https://github.com/shuaiZend/PingWAF/blob/main/CHANGELOG.md)的 `### Security` 下列出。

## 暴露前的加固

控制台出厂带有便于评估的默认值。在把实例暴露到不可控网络之前：

1. **凭据**——修改默认管理员口令；把 `PINGWAF_JWT_SECRET` 与 `PINGWAF_SECRET_KEY` 都设为 32 字节随机值；关闭自助注册（`PINGWAF_ALLOW_REGISTRATION=false`）；修改 PostgreSQL 默认口令。
2. **网络**——控制台（`9080`）绑定环回或私网，经 VPN/反向代理访问；gRPC（`9090`）只对 agent 主机开放；PostgreSQL（`5432`）绝不暴露公网。
3. **TLS**——为控制台上传正式证书或在其前面终止 TLS；为每个站点启用 HTTPS 与 HSTS；保持 gRPC TLS 开启。
4. **静态密钥**——`PINGWAF_SECRET_KEY` 用于加密通知渠道口令、AI Provider Key 与备份目标凭据；不设置时这些字段以明文存储。请单独备份该密钥——目前没有在线轮换。
5. **日志**——访问日志原样保存请求/响应头（含 `Authorization`、`Cookie`、`Set-Cookie`）与最多 8 KiB 的 body，默认保留 180 天。请把 PostgreSQL/Elasticsearch 视作凭据存储，并尽量缩短保留期。
6. **MCP 与 AI**——MCP 的 `write` key 等同于 fleet-wide 管理员凭据；`read` key 只能看到其属主拥有的站点。内置 AI 助手会把工具结果（站点、日志、WAF 事件、审计条目）发送给所配置的第三方 provider，仅在该数据允许离开部署时启用。

完整清单（含具体环境变量、备份步骤与轮换注意事项）见 [SECURITY.md](https://github.com/shuaiZend/PingWAF/blob/main/SECURITY.md#hardening-checklist) 与 [docs/deployment.md](https://github.com/shuaiZend/PingWAF/blob/main/docs/deployment.md)。