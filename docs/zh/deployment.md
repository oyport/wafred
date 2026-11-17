# WAFred 部署指南（中文摘要）

> 本文是英文 [`docs/deployment.md`](../deployment.md) 的**中文摘要**，覆盖部署形态、端口、关键环境变量、TLS、备份与升级回滚。完整参数、逐项说明与故障排查以英文原文为准（[deployment.md](../deployment.md)）。

## 1. 部署形态

| 形态 | 说明 |
| --- | --- |
| `all-in-one`（默认） | 单进程同时跑控制面 + 数据面 + 内嵌 agent，配合 PostgreSQL。适合单机/演示。 |
| `server` + `agent`（分布式） | 控制面集中管理，多个边缘 agent 各自承载站点流量；agent 只持有本站点配置与 agent token。 |

## 2. 端口与防火墙

| 端口 | 协议 | 用途 | 是否必需 |
| --- | --- | --- | --- |
| 80 | TCP | HTTP 业务 / ACME HTTP-01 | 代理站点需要 |
| 443 | TCP | HTTPS 业务 | 代理站点需要 |
| 9080 | TCP | 控制台 + REST API（HTTPS，自签证书） | 是 |
| 9090 | TCP | gRPC 控制面（agent 连接） | 分布式模式需要 |
| 5432 | TCP | PostgreSQL | 仅内网 |

- **9080 是管理面，不要直接暴露公网**：绑定 `127.0.0.1` 或私网，经 VPN/SSH 隧道或反代访问；
- **9090 只允许 agent 主机访问**；
- 5432 保持内网/Compose 内部网络。

## 3. Docker Compose

```bash
# 在存放 docker-compose.yml 的目录执行
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
WAFRED_JWT_SECRET=$(openssl rand -hex 32)
WAFRED_SECRET_KEY=$(openssl rand -hex 32)
WAFRED_ADMIN_PASSWORD=$(openssl rand -hex 16)
WAFRED_ALLOW_REGISTRATION=false
EOF
chmod 600 .env          # .env 含密钥，权限 600 且不要提交到版本库
docker compose up -d
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9080/healthz   # 期望 200
```

## 4. 安装器加固（install.sh / compose installer）

两个官方安装器都已按安全默认值加固：

- **管理面网络范围**：二进制安装器默认把控制台 `127.0.0.1:9080`、gRPC `127.0.0.1:9090` 绑定；使用 `--listen-public` 才会监听所有网卡。Compose 默认将 80/443/9080/9090 发布到所有网卡，部署后请用主机防火墙限制 9080/9090，并先修改管理员口令。
- **校验 release 校验和**：每个发布资产都有 `.sha256`；缺失、格式错误或不匹配时安装器直接退出，不会安装被篡改/截断的包。
- **管理员口令**：二进制安装器未提供 `--admin-password`/`WAFRED_ADMIN_PASSWORD` 时生成随机口令并**只打印一次**；Compose 默认使用 `wafred123`，首次登录会要求修改。
- **生成 `WAFRED_SECRET_KEY`**：二进制安装器写入 `/etc/wafred/wafred.env`（`0600`，属主 `wafred`，systemd 通过 `EnvironmentFile=-/etc/wafred/wafred.env` 读取）；Compose 安装器写入 `.env`（`0600`），并在升级时保留。静默轮换会使已加密的渠道/AI/备份凭据无法解密。
- **不删数据卷**：Compose 安装器保留 `wafred-postgres-data`/`wafred-data`/`wafred-certs`；清理主机磁盘只能显式运行 `scripts/sweep-host-storage.sh --prune-volumes`。
- **旧版本文件提示**：从旧 release tag 下载的 Compose 文件可能没有 `WAFRED_SECRET_KEY` 透传。请升级到包含该设置的版本，避免密钥未加载时保存敏感凭据。

## 5. 关键环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `WAFRED_ADMIN_PORT` / `WAFRED_GRPC_PORT` | `9080` / `9090` | Compose 发布的控制台/API 与 gRPC 主机端口；默认绑定所有网卡 |
| `WAFRED_ADMIN_PASSWORD` | `wafred123` | 初始管理员口令，首次登录强制修改；生产部署请显式设置随机值 |
| `POSTGRES_PASSWORD` | `wafred`（开发回退） | PostgreSQL 口令；正式部署务必在 `.env` 设置随机值 |
| `WAFRED_SECRET_KEY` | 安装器生成 | 静态加密主密钥：加密通知渠道口令、AI Provider Key、备份目标凭据。请保存在权限 `600` 的文件中并单独备份；无在线轮换，详见 [SECURITY.md](../../SECURITY.md#credentials-and-secrets) |
| `WAFRED_JWT_SECRET` | 含占位符，首启生成并持久化随机值 | JWT 签名密钥，显式设置时至少 16 字符（建议 `openssl rand -hex 32`） |
| `WAFRED_ALLOW_REGISTRATION` | 代码默认 `true`（Compose 设为 `false`） | 是否允许自助注册；生产务必设为 `false` |
| `WAFRED_CORS_ORIGINS` | 空 | 允许的跨域来源，逗号分隔 |
| `WAFRED_TLS_ENABLED` | `true` | 控制台/API 使用 HTTPS（自签证书，可上传正式证书）；反代终止 TLS 时可设 `false` |
| `WAFRED_PASSKEY_ENABLED` | `true` | 启用 Passkey 登录。Passkey 需要安全上下文：HTTPS 主机名或 `localhost`；反代后需设 `WAFRED_PASSKEY_ORIGIN` |

其余变量（连接池、心跳、日志级别、Elasticsearch、限流等）见英文 [deployment.md → Configuration Reference](../deployment.md#configuration-reference)。

## 6. TLS

- **控制面 9080**：首启自动生成自签名证书；生产建议在 **Settings → Control plane HTTPS** 上传正式证书，并用 `WAFRED_TLS_SANS` 指定主机名。
- **业务站点**：使用 ACME（Let's Encrypt）或上传证书，启用 HSTS 并强制 HTTPS。
- **gRPC 9090**：默认 TLS（首启生成自签 CA）；仅在完全受控的环回 all-in-one 场景才考虑 `grpc_tls_mode = "off"`。

## 7. 安全加固清单

逐项清单见 [SECURITY.md 加固清单](../../SECURITY.md#hardening-checklist)，要点：

1. 修改默认管理员口令（首登强制改密）；
2. 设置 `WAFRED_JWT_SECRET` 与 `WAFRED_SECRET_KEY`，备份主密钥；
3. 关闭自助注册，修改 PostgreSQL 默认口令；
4. 9080/9090 不暴露公网，启用主机防火墙；
5. 站点启用 TLS + HSTS；
6. **日志即凭据存储**：访问日志原样保存 `Authorization`/`Cookie`/`Set-Cookie` 与最多 8 KiB body，默认保留 180 天；限制数据库/Elasticsearch 访问并加密其备份；
7. MCP `write` key 等同管理员凭据；AI 助手会把站点/日志/WAF 事件发送给第三方 provider，按需启用。

## 8. 备份与恢复

> 数据库是密钥库：`site_certificates` 含私钥、`site_basic_auth` 含明文口令、`site_oidc` 含 cookie secret。备份必须加密并限制读取。

```bash
# 备份
pg_dump -U wafred -d wafred -F c -f wafred_backup_$(date +%Y%m%d).dump
# 恢复
pg_restore -U wafred -d wafred --clean wafred_backup_20260101.dump
```

配置侧还应备份 `/etc/wafred/`、证书目录与 `.env`（权限 600）。注意：`WAFRED_SECRET_KEY` 丢失时已加密的渠道/AI/备份凭据无法解密，需重新录入。

## 9. 升级与回滚

```bash
cd /path/to/compose
# 1) 升级前快照：数据库 + .env + compose
docker compose exec -T postgres pg_dump -U wafred -d wafred -Fc > pre-upgrade.dump
cp .env pre-upgrade.env && chmod 600 pre-upgrade.env
# 2) 固定新版本（修改 .env 中的 WAFRED_TAG），只重建应用容器
docker compose pull wafred && docker compose up -d wafred
# 3) 验证
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9080/healthz
```

**回滚**：把 `WAFRED_TAG` 改回旧版本并 `docker compose up -d wafred`。数据库迁移**只向前**——若旧版本拒绝启动，需用 `pre-upgrade.dump` 恢复数据库后再启动旧版本。生产环境请固定版本 tag，不要使用 `:latest`。

> 普通重跑 Compose 安装器会保留现有 `.env`；使用 `--force` 会按本次选项重写配置，同时沿用现有 `WAFRED_SECRET_KEY`。二进制安装器保留
> `/etc/wafred/wafred.env`。两种安装器都不会删除 `wafred-postgres-data`/`wafred-data`/`wafred-certs`。需要清理主机磁盘时只能显式运行
> `scripts/sweep-host-storage.sh --prune-volumes`。
> 从**旧 release tag** 下载的 Compose 文件可能没有 `WAFRED_SECRET_KEY` 透传，
> 安装器会告警——请升级到包含这些改动的版本。

## 10. 管理员自救（break-glass）

维护 CLI 直连数据库执行，运行中的控制面会在数秒内感知：

```bash
wafred user reset-password --email admin@wafred.local     # 重置口令并撤销全部会话
wafred security allowlist off                             # 关闭控制面 IP 白名单（应急）
wafred mode observe|enforce|status                        # 观察模式开关
wafred config rollback --scope global                     # 回滚配置版本
```

详见英文 [deployment.md → Maintenance CLI](../deployment.md#maintenance-cli-break-glass)。
