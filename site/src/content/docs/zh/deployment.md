---
title: 部署
description: Docker Compose 与源码构建、端口、配置优先级、systemd 单元以及分布式 Agent 部署。
minutes: 10
---

## 部署形态

**All-in-one** 在单个进程内同时运行控制面与一个数据面，适合单机、评估以及只需一个边缘的中小型部署。

**分布式** 运行一个 `wafred server` 与任意数量的 `wafred agent`。状态由控制面持有，Agent 除规则缓存外无状态，因此新增边缘节点无需触碰数据库。

## 端口

| 端口 | 用途 | 说明 |
| --- | --- | --- |
| `9080` | REST API + 控制台 | 使用自签证书提供 HTTPS，直到你替换它；请保持私有 |
| `9090` | gRPC 控制面 | Agent 在此连接；默认 TLS，`grpc_tls_mode = "off"` 会降级为明文 |
| `80` | 代理流量 | 创建首个站点后开始绑定 |
| `443` | 代理流量 | 创建首个站点后开始绑定；新站点会自动签发自签名证书 |

`GET /healthz` 在 HTTP 与 HTTPS 下都会响应，适合作为 compose 健康检查与负载均衡探针；其余路径一律跳转 HTTPS。

## Docker Compose

```bash
git clone https://github.com/oyport/wafred.git
cd wafred
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

compose 文件以 all-in-one 模式启动 `ghcr.io/oyport/wafred:latest`，并与 `postgres:16-alpine` 一起运行，发布 `80`、`443`、`9080` 与 `9090`。数据库端口默认只绑定 `127.0.0.1`。

使用 Compose 安装脚本时，Debian/Ubuntu 若缺少 Docker Engine 或 Compose v2，脚本会从当前系统的软件源安装并启动 Docker。此时需要 root 或免密码 sudo；`--no-install-docker` 可禁止自动安装。其他发行版需先自行安装 Docker 与 Compose v2。

### GitHub / GHCR 下载加速

安装脚本支持 `--mirror`（GitHub 文件前缀）和 `--image-mirror`（OCI 镜像前缀）。默认的 `--mirror-mode host-path` 适用于把 `raw.githubusercontent.com/...` 接在加速站后面的服务；若服务要求保留完整原始 URL，则使用 `--mirror-mode full-url`。例如 [GH-Proxy 的文件规则](https://gh-proxy.com/docs/github-accelerator)和[镜像规则](https://gh-proxy.com/docs/docker-mirror)分别使用完整 URL 和 `/docker/` 路径：

```bash
curl -fsSL https://gh-proxy.org/https://raw.githubusercontent.com/oyport/wafred/main/deploy/compose/install.sh \
  | bash -s -- --mirror https://gh-proxy.org --mirror-mode full-url \
      --image-mirror https://gh-proxy.org/docker
```

安装器会把镜像地址保存为 `.env` 中的 `WAFRED_IMAGE`，以后执行 `docker compose pull` 仍使用该地址。二进制安装器同样支持 `--mirror` / `--mirror-mode`；加 `--version` 可跳过不支持 GitHub API 的加速站。最初的 `curl` 也必须指向加速站。PostgreSQL 镜像仍从 Docker Hub 下载。详细说明见[仓库文档](https://github.com/oyport/wafred/blob/main/docs/zh/install-mirror.md)。

首次用 compose 时最常见的两类报错：

- `permission denied while trying to connect to the Docker API at unix:///var/run/docker.sock`——当前用户不在 `docker` 组。改用 `sudo docker compose up -d`，或把用户加入 `docker` 组（`sudo usermod -aG docker $USER`，重新登录后生效）。
- `failed to bind host port 127.0.0.1:5432/tcp: address already in use`——本机已有 PostgreSQL 占用 5432。在 `.env` 中设置 `POSTGRES_PORT=55432`（或给 `deploy/compose/install.sh` 传 `--db-port 55432`，它会自动从 55432 起选择空闲端口），再重新启动。

> `hostname` 必须保持稳定。控制面按 hostname 与 API key 匹配重新注册，容器 ID 变化会留下「幽灵离线节点」。

## 源码构建

| 工具 | 版本 | 原因 |
| --- | --- | --- |
| Rust | 1.96+（MSRV） | 构建二进制 |
| Node.js | 26.12.1+ | 构建内嵌控制台，`web/.npmrc` 设置了 `engine-strict=true` |
| `protoc` | 较新版本 | gRPC 代码生成——**必需** |
| `cmake` | 较新版本 | 构建 TLS 后端 |
| PostgreSQL | 14+；本机安装以发行版包名为准（Ubuntu 24.04 是 `postgresql-16`，26.04 是 `postgresql-18`） | 控制面存储，角色需要建表权限 |

缺少 `protoc` 时 `pingwaf-proto` 会静默写入占位文件，随后下游 crate 编译失败——构建前先安装它。

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin wafred --features full
./target/release/wafred all-in-one \
  --db-url "postgres://wafred:wafred@localhost:5432/wafred"
```

在 Linux 上，`install.sh` 会下载预编译包、安装到 `/usr/local/bin`、生成 `/etc/wafred/wafred.toml` 与 systemd 单元，并启动服务。在终端上不带参数运行它会进入交互引导（部署模式、管理员凭证、PostgreSQL URL、证书 SAN 列表、版本）；通过管道执行则是一行命令的无人值守安装。

```bash
# 交互安装：打印安装计划并确认
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh -o install.sh && bash install.sh

# 一行命令、无人值守（管道执行没有终端，因此不做任何提问）
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh | bash -s -- --mode all-in-one
```

参数：`--mode all-in-one|server|agent`，`--no-systemd` 跳过单元安装，`--admin-email` / `--admin-password` / `--tls-sans`（或对应的 `WAFRED_*` 环境变量）免提问写入初始设置，`--dry-run` 只预览安装计划不做改动。

## 配置优先级

配置依次从 TOML 文件、`WAFRED_*` 环境变量、CLI 参数读取，后者覆盖前者；未知 TOML 键会被报告并跳过。

```bash
wafred all-in-one --config /etc/wafred/wafred.toml
WAFRED_CONFIG=/etc/wafred/wafred.toml wafred all-in-one   # 等价写法
```

`[server]` 表覆盖 `db_url`、`admin_addr`、`tls_enabled`、`tls_sans`、`grpc_addr`、`jwt_secret`、`admin_email` 与 `serve_frontend`；`[agent]` 表覆盖 `server_url`、`server_ca_cert`、`api_key`、`cache_dir`、`heartbeat_interval_secs`、日志批量参数、`fail_open` 与指标上报。

## 分布式 Agent

Agent 只需要三件事：控制面地址、认证方式与规则缓存目录。

```bash
WAFRED_SERVER_URL="https://control.example.com:9090" \
WAFRED_API_KEY="<enrollment key>" \
WAFRED_CACHE_DIR="/var/lib/wafred/cache" \
wafred agent
```

纳管密钥在控制台创建（`POST /api/v1/agents/enroll` 会返回安装命令）。空的 `WAFRED_API_KEY` 只在 all-in-one 模式的回环自动注册中有效。

Agent 默认接收 API key 所有者的**全部站点**。在 **节点 → 该节点 → 站点范围** 中选择“指定站点”，只向边缘节点下发它需要服务的站点；独立边缘节点通常不应选择控制面自身的控制台站点。

如果控制面是 ACME 签发者，需 **0.32.40+** 才会把内嵌数据面签发的 PEM 同步并推送给 agent。旧控制面只下发 `acme_email`、没有 PEM，每个 agent 会自己发起 HTTP-01，验证请求落到控制面而不是 agent，最终 `acme_failed`。暂不能升级控制面时，可在 agent 单元设置 `PINGAP_DISABLE_ACME=true` 停止重试，并改用上传证书。只有标记为 ACME 签发者的 agent 才会收到 DNS 服务商凭据并发起订单；内嵌 all-in-one 签发者会自动标记，远程签发者需通过 `PATCH /api/v1/agents/{id}` 设置 `{"acme_issuer": true}`。消费型 agent 只使用下发的 PEM，不接触凭据。被标记的远程签发者会通过已认证的控制面通道回传签发的证书，控制面校验指定关系、站点分配、主机名集合与私钥后再分发。

WAFred 支持 Amazon Route 53 的 DNS-01：选择 `dns-01` + `route53`，可用 `acme_dns_config.hosted_zone_id` 指定托管区域，签发进程需具备 AWS 凭证（最简单是 EC2 实例角色）。签发者只需该区域的 `GetHostedZone`、`ListResourceRecordSets`、`ChangeResourceRecordSets`（自动发现还需 `ListHostedZones`），消费型 agent 无需 AWS 权限。安装器会把 `--server-ca-cert` 复制到 `/etc/wafred/grpc-ca.pem`，控制台生成的命令不含 CA / `--server-tls-name`，自签控制面需手动补上。

## 隧道（内网服务免入站端口）

隧道让**内网服务**在不开放入站端口、也不需要公网 IP 的情况下接入：`wafred-tunnel` 连接器主动向控制面与边缘节点拨号，公网侧由边缘数据面终止并经回环桥接转发，WAF、限流、缓存、日志与证书与直连源站完全一致。

**边缘节点**：只在需要终止隧道的边缘开启监听，并把端口限制到连接器所在网络：

```toml
[agent]
tunnel_addr = "0.0.0.0:9443"   # 默认关闭
```

然后在 **边缘节点 → [节点] → 隧道入口地址** 填写连接器拨号的公网地址（`edge1.example.com:9443`）；该面板同时显示监听状态与连接器要固定的证书指纹。

**连接器**：在 **边缘节点 → 隧道** 创建隧道，复制一次性配对命令并在内网主机执行：

```bash
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh \
  | sudo bash -s -- --mode tunnel \
      --server-url https://control-plane:9090 \
      --server-ca-cert control-plane.pem \
      --token <pairing-token>
```

它会安装 `/usr/local/bin/wafred-tunnel`、写入 `/etc/wafred/tunnel.toml`（`0600`）并注册 `wafred-tunnel.service`。内网侧无需开放任何端口：连接器只发起出站连接（控制面 9090、入口边缘 9443）。

**使用**：在站点的源站池对话框里把源站池绑定到该隧道，池内节点地址（`10.0.0.5:8080`、`app.internal:8443`）随后由连接器在内网解析。隧道的目标清单由绑定的源站池推导。

主机退役时吊销隧道：凭据立即失效，所有边缘会在一次规则包重载内拒绝会话；删除隧道前若仍有源站池引用会被拒绝（`409`），`?force=true` 才会解绑并回退为直连源站。

完整操作说明——三个独立状态、请求链路、连接器命令与配置项、无直接出网时的 SOCKS5、以及排查表——见 [隧道](/docs/tunnel/) 页面。

## systemd

仓库自带的 `wafred.service` 以 `wafred` 用户运行，设置 `Restart=always`、`LimitNOFILE=65536`、`ProtectSystem=strict`，只允许写入 `/var/lib/wafred` 与 `/etc/wafred`。没有 reload 信号：配置变更由控制面应用，二进制或单元变更需要 `systemctl restart wafred`。

手动 tarball 安装时，`wafred.service` 与 `wafred.toml` 位于 `wafred-linux-<arch>/` 子目录。unit 已设置 `WorkingDirectory=/var/lib/wafred`，相对 `cache_dir` 才能持久化；否则 `ProtectSystem=strict` 会让缓存只读。数据库变量是 `WAFRED_DB_URL`（不是 `WAFRED_DATABASE_URL`）；首次启动前设置 `WAFRED_SECRET_KEY` 和管理员口令；小于 4 GiB 的主机需固定 `MIMALLOC_ARENA_RESERVE`。把已有 agent 主机切换为 all-in-one 前，先移走 `/var/lib/wafred/cache`，因为 fail-open 快照可能包含另一个控制面的站点与证书。

## 控制面 TLS

控制台从首次启动起就使用生成的自签证书提供 HTTPS。请在生成前用 `WAFRED_TLS_SANS`（逗号分隔）指定实际访问的主机名，或在 **设置 → 控制面 HTTPS** 上传真实证书。若控制台位于 TLS 终止代理之后，设置 `WAFRED_TLS_ENABLED=false`。
