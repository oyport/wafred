# PingWAF 部署指南（中文摘要）

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
JWT_SECRET=$(openssl rand -hex 32)
PINGWAF_SECRET_KEY=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -hex 16)
ALLOW_REGISTRATION=false
EOF
chmod 600 .env          # .env 含密钥，权限 600 且不要提交到版本库
docker compose up -d
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9080/healthz   # 期望 200
```

## 4. 安装器加固（install.sh / compose installer）

两个官方安装器都已按安全默认值加固：

- **默认只监听环回**：二进制安装器默认把控制台 `127.0.0.1:9080`、gRPC `127.0.0.1:9090` 绑定；compose 通过
  `PINGWAF_ADMIN_BIND`/`PINGWAF_GRPC_BIND` 也默认发布在 `127.0.0.1`。只有需要反向代理或远程 agent 时才显式改为
  `0.0.0.0`（或私网地址），并且**先修改管理员口令**；更推荐用 TLS 反向代理暴露，而不是直接公网。
- **校验 release 校验和**：每个发布资产都有 `.sha256`；缺失、格式错误或不匹配时安装器直接退出，不会安装被篡改/截断的包。
- **随机管理员口令**：未提供 `--admin-password`/`PINGWAF_ADMIN_PASSWORD` 时生成随机口令并**只打印一次**（结束前保存好）；不再有内置默认口令。
- **生成 `PINGWAF_SECRET_KEY`**：二进制安装器写入 `/etc/pingwaf/pingwaf.env`（`0600`，属主 `pingwaf`，systemd 通过
  `EnvironmentFile=-/etc/pingwaf/pingwaf.env` 读取）；compose 安装器写入 `.env`（`0600`）。升级时保留已有主密钥——静默轮换会使已密封的渠道/AI/备份凭据无法解密。
- **不删数据卷**：compose 安装器 `--force` 只重写 `.env`，保留 `postgres-data`/`pingwaf-data`/`pingwaf-certs`；
  清理主机磁盘只能显式运行 `scripts/sweep-host-storage.sh --prune-volumes`，且它**永不删除 `waf_*`** 数据卷。
- **旧 tag 提示**：安装器从 release tag 下载 compose 文件；若该 tag 的 compose 还没有上述加固（没有 `PINGWAF_SECRET_KEY` 透传、9080/9090 公网绑定、默认管理员口令），安装器会告警——请升级到包含这些改动的版本，而不要假定加固已生效。

## 5. 关键环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PINGWAF_ADMIN_BIND` / `PINGWAF_GRPC_BIND` | `127.0.0.1` | 控制台（9080）/gRPC（9090）发布地址；默认仅环回。需要反代或远程 agent 时才改 `0.0.0.0`，并先改管理员口令 |
| `ADMIN_PASSWORD` | **无默认值（新库必填）** | 初始管理员口令；为空会让首次启动失败，而不是播种已知口令。安装器会生成随机口令并只打印一次；首次登录强制改密 |
| `POSTGRES_PASSWORD` | `pingwaf`（开发回退） | PostgreSQL 口令；正式部署务必在 `.env` 设置随机值（compose 仍会回退到 `pingwaf`，安装器不生成该项） |
| `PINGWAF_SECRET_KEY` | 未设置（密封功能必需） | 静态加密主密钥：加密通知渠道口令、AI Provider Key、备份目标凭据。**必须设为 32 字节随机值**；不设置则这些字段明文入库。安装器会生成（compose → `.env`；二进制 → `/etc/pingwaf/pingwaf.env` 0600）。无在线轮换，备份与轮换步骤见 [SECURITY.md](../../SECURITY.md#credentials-and-secrets) |
| `PINGWAF_JWT_SECRET` | `change-me-in-production` | JWT 签名密钥，至少 16 字符（建议 `openssl rand -hex 32`）；占位符会在首启时替换为随机持久化值 |
| `PINGWAF_ALLOW_REGISTRATION` | 代码默认 `true`（Compose 设为 `false`） | 是否允许自助注册；生产务必设为 `false` |
| `PINGWAF_CORS_ORIGINS` | 空（仅同源） | 允许的跨域来源；为空时**不下发 CORS 头**，只有同源调用可用 |
| `PINGWAF_TLS_ENABLED` | `true` | 控制台/API 使用 HTTPS（自签证书，可上传正式证书）；反代终止 TLS 时可设 `false` |
| `PINGWAF_PASSKEY_ENABLED` | `true` | 启用 Passkey 登录。Passkey 需要安全上下文：HTTPS 主机名或 `localhost`；反代后需设 `PINGWAF_PASSKEY_ORIGIN` |

其余变量（连接池、心跳、日志级别、Elasticsearch、限流等）见英文 [deployment.md → Configuration Reference](../deployment.md#configuration-reference)。

## 6. TLS

- **控制面 9080**：首启自动生成自签名证书；生产建议在 **Settings → Control plane HTTPS** 上传正式证书，并用 `PINGWAF_TLS_SANS` 指定主机名。
- **业务站点**：使用 ACME（Let's Encrypt）或上传证书，启用 HSTS 并强制 HTTPS。
- **gRPC 9090**：默认 TLS（首启生成自签 CA）；仅在完全受控的环回 all-in-one 场景才考虑 `grpc_tls_mode = "off"`。

## 7. 安全加固清单

逐项清单见 [SECURITY.md 加固清单](../../SECURITY.md#hardening-checklist)，要点：

1. 修改默认管理员口令（首登强制改密）；
2. 设置 `PINGWAF_JWT_SECRET` 与 `PINGWAF_SECRET_KEY`，备份主密钥；
3. 关闭自助注册，修改 PostgreSQL 默认口令；
4. 9080/9090 不暴露公网，启用主机防火墙；
5. 站点启用 TLS + HSTS；
6. **日志即凭据存储**：访问日志原样保存 `Authorization`/`Cookie`/`Set-Cookie` 与最多 8 KiB body，默认保留 180 天；限制数据库/Elasticsearch 访问并加密其备份；
7. MCP `write` key 等同管理员凭据；AI 助手会把站点/日志/WAF 事件发送给第三方 provider，按需启用。

## 8. 备份与恢复

> 数据库是密钥库：`site_certificates` 含私钥、`site_basic_auth` 含明文口令、`site_oidc` 含 cookie secret。备份必须加密并限制读取。

```bash
# 备份
pg_dump -U pingwaf -d pingwaf -F c -f pingwaf_backup_$(date +%Y%m%d).dump
# 恢复
pg_restore -U pingwaf -d pingwaf --clean pingwaf_backup_20260101.dump
```

配置侧还应备份 `/etc/pingwaf/`、证书目录与 `.env`（权限 600）。注意：`PINGWAF_SECRET_KEY` 丢失时已密封的渠道/AI/备份凭据无法解密，需重新录入。

## 9. 升级与回滚

```bash
cd /path/to/compose
# 1) 升级前快照：数据库 + .env + compose
docker compose exec -T postgres pg_dump -U pingwaf -d pingwaf -Fc > pre-upgrade.dump
cp .env pre-upgrade.env && chmod 600 pre-upgrade.env
# 2) 固定新版本（修改 .env 中的 PINGWAF_TAG），只重建应用容器
docker compose pull pingwaf && docker compose up -d pingwaf
# 3) 验证
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9080/healthz
```

**回滚**：把 `PINGWAF_TAG` 改回旧版本并 `docker compose up -d pingwaf`。数据库迁移**只向前**——若旧版本拒绝启动，需用 `pre-upgrade.dump` 恢复数据库后再启动旧版本。生产环境请固定版本 tag，不要使用 `:latest`。

> 安装器升级会保留密钥与数据卷：compose 安装器 `--force` 复用已有管理员口令与 `PINGWAF_SECRET_KEY`，二进制安装器保留
> `/etc/pingwaf/pingwaf.env`；两者都不会删除 `postgres-data`/`pingwaf-data`/`pingwaf-certs`。需要清理主机磁盘时只能显式运行
> `scripts/sweep-host-storage.sh --prune-volumes`（只清理未使用的**非 PingWAF** 卷，`waf_*` 永不删除）。
> 从**旧 release tag** 下载的 compose 文件不含本轮加固（环回绑定、`PINGWAF_SECRET_KEY` 透传、无默认管理员口令），
> 安装器会告警——请升级到包含这些改动的版本。

## 10. 管理员自救（break-glass）

维护 CLI 直连数据库执行，运行中的控制面会在数秒内感知：

```bash
pingwaf user reset-password --email admin@pingwaf.local   # 重置口令并撤销全部会话
pingwaf security allowlist off                            # 关闭控制面 IP 白名单（应急）
pingwaf mode observe|enforce|status                       # 观察模式开关
pingwaf config rollback --scope global                    # 回滚配置版本
```

详见英文 [deployment.md → Maintenance CLI](../deployment.md#maintenance-cli-break-glass)。