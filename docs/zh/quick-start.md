# PingWAF 快速开始（中文摘要）

> 本文是英文 [`docs/quick-start.md`](../quick-start.md) 的**中文摘要**，覆盖安装与首次运行的关键步骤与安全默认值；完整参数、故障排查与逐项说明以英文原文为准（[quick-start.md](../quick-start.md)）。

## 1. 选择部署方式

| 方式 | 适用 | 命令 |
| --- | --- | --- |
| Docker Compose（推荐） | 一条命令起 all-in-one（控制面 + 数据面 + PostgreSQL） | `curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/deploy/compose/install.sh \| bash` |
| 二进制 + systemd | 生产环境、需要精细控制 | 见 [deployment.md](./deployment.md) 与英文 [quick-start.md](../quick-start.md) |
| 源码构建 | 开发/自建 | `cargo build --release --bin pingwaf --features full` |

预编译二进制仅提供 **Linux amd64 / arm64**（[Releases](https://github.com/shuaiZend/PingWAF/releases)）。

## 2. 首次启动前的安全默认值

源码/二进制方式直接运行时，代码默认**允许自助注册**，且未设置静态加密主密钥。首次启动请至少：

```bash
export PINGWAF_ALLOW_REGISTRATION=false          # 关闭注册
export PINGWAF_JWT_SECRET="$(openssl rand -hex 32)"     # JWT 签名密钥
export PINGWAF_SECRET_KEY="$(openssl rand -hex 32)"     # 静态加密主密钥（渠道/AI/备份凭据）
./pingwaf all-in-one --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

- `PINGWAF_SECRET_KEY` **不设置时，通知渠道口令、AI Provider Key、备份目标凭据会以明文入库**（仅打一条 WARN）。它没有在线轮换：轮换前请记录明文，轮换后逐个重新录入；详见 [SECURITY.md 加固清单](../../SECURITY.md#credentials-and-secrets)。
- 主密钥/JWT 密钥/数据库口令等应放在权限 `600` 的 `.env` 或 secret manager 中，不要提交到版本库。
- 默认管理员 `admin@pingwaf.local`，口令为部署时设置/安装器生成的随机口令（仅裸二进制未设 `PINGWAF_ADMIN_PASSWORD` 时回退到 `pingwaf123`）；首次登录会被强制改密。
- 安装器默认把控制台 `127.0.0.1:9080` 与 gRPC `127.0.0.1:9090` 绑定；只有需要反向代理或远程 agent 时才用 `--listen-public`（或 `PINGWAF_LISTEN_PUBLIC=1`）显式开放，并且先修改管理员口令。

## 3. 打开控制台

浏览 **https://localhost:9080**（首次启动自动生成自签名证书，浏览器会告警；可在 **Settings → Control plane HTTPS** 上传正式证书）。控制台支持中文/英文/日文。

## 4. 第一个站点

1. **Sites → 新建站点**：填写主域名、上游地址（`host:port`）；
2. **SSL**：启用 HTTPS，选择 ACME 或上传证书；
3. 用 `curl -H 'Host: <你的域名>' http://<边缘 IP>/` 验证代理链路；
4. 需要 WAF 拦截时确认站点 WAF 模式为 `block`（默认 `monitor`）。

## 5. 常见下一步

- 加固清单（防火墙、TLS、密钥、日志保留、MCP/AI 数据边界）：[SECURITY.md](../../SECURITY.md#hardening-checklist)
- 部署拓扑、环境变量、备份与升级：[deployment.md](./deployment.md)
- REST API 与鉴权：[api.md](./api.md)
- 控制台使用：[user-guide.md](./user-guide.md)

## 故障排查

完整清单见英文 [quick-start.md → Troubleshooting](../quick-start.md#troubleshooting)：

- `healthz` 不是 200：先看 `docker compose ps` / `podman logs pingwaf`；
- 8080/9080 打不开：确认端口未被占用、TLS 自签证书已信任或使用 `-k`；
- 数据库连接失败：检查 `PINGWAF_DB_URL` 与 PostgreSQL 容器健康状态。