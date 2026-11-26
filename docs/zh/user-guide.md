# WAFred 用户指南（关键章节中文镜像）

> **本文是英文 [`docs/user-guide.md`](../user-guide.md) 的同步镜像，只覆盖关键
> 章节，不是全文翻译。** 两处不一致时，**以英文版为准**。章节标题保留英文原文，
> 便于对照；小节内的「详见」链接指向英文原文或 API 参考对应锚点。
>
> 注意：「证书链接幂等」「`cpu_source`」以及响应替换的 `br`/`zstd` 支持
> 属于 **Unreleased**（见 [`CHANGELOG.md`](../../CHANGELOG.md)）行为；英文版
> 现已同步这些变更，本镜像与之保持一致。

## SSL Certificate Management（SSL 证书管理）

### Upload without a site, bind later

管理员可以**不带站点**上传证书——适用于 PEM 已在手、同一张证书（泛域名或多主机
名 SAN 证书）要服务多个站点的场景。证书落地为**未绑定**状态：没有属主站点、
没有边缘节点在用，`status` 跟随自身有效期。之后：

1. **上传** —— `POST /api/v1/certificates`，带 `domain`、`cert_pem` 与
   `key_pem`（不带 `site_id`）。
2. **逐个绑定站点** —— `POST /api/v1/certificates/{id}/bindings`，带
   `{"site_id": "…"}`。证书不覆盖站点主机名时绑定失败（`400`，列出未覆盖的
   **站点**主机名；证书多出的 SAN 无妨）；站点已拥有该证书时 `409`；幂等——
   重复绑定不改变任何状态。
3. **解绑** —— `DELETE /api/v1/certificates/{id}/bindings/{site_id}`；证书仍是
   该站点当前 TLS 选择时被 `409` 拒绝。

每个证书响应以 `bound_sites` / `bound_count` 展示结果。未绑定证书不能用 ACME
（签发与续期在边缘运行，由承载证书的站点驱动）；仍有绑定的证书删除被 `409`
拒绝，无绑定后立即可删。站点侧的替代入口仍然可用：从站点 SSL 设置的选择器里
发起链接，见 [Sharing certificates between sites](#sharing-certificates-between-sites)。
详见：[Upload without a site, bind later](../user-guide.md#upload-without-a-site-bind-later)。

### Certificate lifecycle

证书在四个状态间流转，每个状态决定你可以对它做什么：

```
              带 site_id 上传              不带 site_id 上传
                     │                            │
                     ▼                            ▼
            ┌─────────────────┐          ┌─────────────────┐
            │  Owner（属主）  │          │  Unbound（未绑定）│
            └─────────────────┘          └─────────────────┘
                     │                            │
        绑定其他站点  │ 共享                       │ 绑定第一个
                     ▼                            │ 站点
            ┌─────────────────┐                    │
            │  Shared（共享）  │ ───────────────────┘
            └─────────────────┘
                     │
   某站点（属主或    │ 站点 SSL 页选择
   已链接）选择其    ▼ 其为 TLS 证书
   为 TLS      ┌─────────────────┐
               │   In use（使用中）│
               └─────────────────┘
```

- **Unbound（未绑定）** —— 不带站点上传（`site_id: null`，`bound_count: 0`）。
  没有边缘在用；ACME 与 `activate` 被拒（`400`），因为二者都是站点级操作。
  任何时候都可删除（`204`），或绑定站点投入使用。
- **Owner（属主）** —— 证书创建时所在的站点。这正是把证书绑定*回*该站点被拒
  （`409`）的原因：它已经拥有它。属主同时驱动续期与 ACME 记账。
- **Shared（共享）** —— 通过证书绑定共享给其他站点（`bound_count` 只统计这些
  **共享站点，不含属主**）。
- **In use（使用中）** —— 至少一个站点已把该证书选为 TLS 证书。这可以是属主
  自己的选择，因此证书可以没有任何共享绑定而处于使用中。

**推荐操作顺序**（控制台引导的同一序列）：

1. **上传** —— 带站点（`Sites → [site] → Certificates → Add`）或不带站点
   （见 [Upload without a site, bind later](#upload-without-a-site-bind-later)）。
2. **绑定** —— 从证书的绑定对话框。自己的站点显示 **owner** 徽标：不可勾选、
   没有解绑按钮。其他站点要么已绑定（可解绑，附带「站点将回退到自身证书或无
   HTTPS」的确认提示），要么可绑定——绑定会校验证书覆盖站点主机名，未覆盖的
   以 `400` 列出。一次绑定多个站点时逐个提交：成功保留，失败以
   `site — reason` 列出，全部成功才关闭对话框。
3. **解绑（409 处理）** —— 证书仍是该站点当前 TLS 选择时被 `409` 拒绝。先去
   该站点的 SSL 页，切换到另一张证书或清除选择，再回来解绑。解绑一个只通过
   链接使用该证书的站点，会让它回退到自身证书材料——或完全没有 HTTPS，这正是
   确认提示存在的原因。
4. **删除** —— 仍有站点选择该证书**或**仍有绑定授予它时被 `409` 拒绝。删除
   对话框先查询证书的 usage：若有站点在使用或已链接，列出受影响站点，按钮变为
   **Go handle**，带你到第一个阻塞站点的 SSL 页。usage 查询本身不可用时，删除
   被保守拒绝而不是放行。没有任何站点选择、没有绑定后，删除立即生效（`204`）。

详见：[Certificate lifecycle](../user-guide.md#certificate-lifecycle)；
`409` 的服务端语义见
[API 参考的证书章节](../api.md#certificates)（含
[GET /certificates/{cert_id}/usage](../api.md#get-certificatescert_idusage)）。

### Sharing certificates between sites

一张泛域名或多主机名证书可以服务多个站点。证书保持唯一**属主**（创建时所在的
站点）；其他站点*链接*到它来使用：

在站点的 **SSL Settings** 页管理（证书选择器）：「链接证书」选项列出可用的
证书，已链接的证书在同一选择器中带共享标记显示。

- **链接** 列出你可读站点拥有、本站点既不拥有也未使用的证书。站点已拥有时失败
  于 `certificate already belongs to this site`。
- **重复链接是幂等的**：同一证书已链接时再次调用返回 **200** 与完整装饰的证书
  对象（首次创建为 `201`），不再报 `409`；仅当站点**拥有**该证书时仍是 `409`。
- **选择** 已链接的证书与自有证书完全一致——SSL 设置选择器同时显示两者，共享的
  带标签。
- **解除链接** 在证书是该站点当前 TLS 证书时被拒
  （`certificate is the site's current TLS certificate; clear or replace it
  first`）——否则站点会静默失去 HTTPS。先清除证书选择（或换一张）。
- **回退服务**：未选择证书、也无内联 PEM、ACME 订单或自签名证书的站点，会自动
  服务覆盖其主机名最多的已链接证书——一张都不覆盖的会被跳过并告警，而不是被
  服务。注入的证书不参与续期：服务非自有证书的站点 ACME 保持关闭。

**属主模型的意义：** 续期、ACME 记账与配置备份都挂在属主站点上，证书只续期一次，
所有已链接站点自动拿到新材料。**谨慎共享**：被链接站点会服务相同的主机名，只把
证书链接给这些主机名的合法承载者。
详见：[Sharing certificates between sites](../user-guide.md#sharing-certificates-between-sites)。

## Origin Pools & Routes（源站池与路由）

### Routes

路由按路径把请求分派到不同池；未匹配流量走默认池。

| 字段 | 说明 |
|-------|-------------|
| 规则名 | 路由标签（如 `api-to-dedicated-pool`） |
| 匹配 | `Prefix`、`Exact` 或 `Regex` |
| 路径 | 以 `/` 开头（如 `/api`），或正则（如 `^/static/.*`） |
| 优先级权重 | 1–60000；留空使用自动权重（exact 1024 / prefix 512 / regex 256） |
| 目标池 | 接收匹配流量的池 |
| Upstream host | 可选；覆盖该路由上游看到的 `Host` 头。空 = 转发客户端的 `Host`（历史行为） |
| 启用 | 不删除即可开关路由 |

`/` 上的前缀路由会被拒绝：会与默认池兜底冲突。

**Upstream host.** 路由的池对接按 `Host` 路由的虚拟主机时填写——例如指向
`google.com` 的镜像路由：不覆盖的话上游看到你的站点域名并返回 404。取值必须是
裸主机名（至多 253 字节，不允许 scheme `://`、路径 `/`、空白或控制字符；接受
端口）。同一路由的其他改写开关：**Strip path prefix** 移除匹配前缀
（`/api/users` → `/users`）；**Rewrite path** 用固定值替换**整个**转发路径，两者
同时设置时 rewrite path 胜出；query string 均保留。`strip_prefix` 只对
`match_type: "prefix"` 路由生效，其他匹配类型组合会 `400`。精确语义见
[API 参考的 Path rewriting](../api.md#path-rewriting-strip_prefix--rewrite_path)
与 [Upstream Host override](../api.md#upstream-host-override-upstream_host)。
详见：[Routes](../user-guide.md#routes)。

## System 节点视图（System node view）

> 英文版用户指南暂无对应小节；本节对应英文 API 参考的
> [GET /system/nodes](../api.md#get-systemnodes) 与控制台 **/system** 页面
> （仅管理员，从账户下拉进入）。

`GET /api/v1/system/nodes` 一次返回机队视图：控制面进程计数器（`control`）+
每个已注册 agent 一行（`agents[]`，按 `name` 排序，轮询时表格不重排）。

**agent CPU 的口径（Unreleased 新增 `cpu_source` 字段）：**

| `cpu_source` | 含义 |
|---|---|
| `probe` | 来自 agent 主机探针的 **5 秒区间差分**样本——瞬时读数，且跨 agent 版本可比（探针口径一致）。轮询之间数值可能剧烈波动，这是预期行为 |
| `heartbeat` | 无探针样本时回退到心跳值。注意：0.28.3 之前的心跳值是**自启动以来的平均**，与探针口径不同，横向比较旧 agent 时要留意 |
| `none` | 探针与心跳都没有读数（`cpu_percent` 为 `null`） |

编排告警或画图时按 `cpu_source` 分组解读：`probe` 与 `heartbeat` 数值不可直接
混排。其余字段沿用既有口径——控制面尚不知道的字段以 `null` 而非 `0` 表达；
`agents.memory_bytes` 在 agent 首次心跳之前携带主机总内存（注册清单值），之后是
探针的使用内存（既知漂移，尚未修复）。新增 `process_rss_bytes`（Unreleased）是
agent 进程自身的 RSS，区别于整机内存；旧版 agent 不上报该字段，响应中为 `null`
（未知，不是 0）。`boots[]` 记录控制面启动史：相邻两行的
间隔即上一进程存活时间；**几分钟内多次启动通常意味着容器被循环杀死**，而一周前
的一次启动只是正常发版。
详见：[GET /system/nodes](../api.md#get-systemnodes)。

## Tunnel（内网服务免入站端口接入）

> 英文原文见 [`docs/user-guide.md`](../user-guide.md#tunnels-internal-services-without-an-inbound-port)。

隧道用于把**内网服务**接入 WAFred 而不在该主机上开放任何入站端口、也不需要
公网 IP：连接器（`wafred-tunnel`）主动向控制面与边缘节点拨号，公网侧由边缘
数据面终止，WAF、限流、挑战、缓存、日志与证书等能力与直连源站完全一致。

**适用场景**

- 源站在 NAT 或无法开放端口的防火墙之后；
- 源站地址只在内网有意义（`10.0.0.5:8080`、`app.internal:8443`）；
- 公网入口希望留在 WAF 上，而不是内网主机。

隧道不是 VPN：它只承载绑定到它的源站池流量。

**三个必须区分开的状态**

| 状态 | 含义 | 来源 |
| --- | --- | --- |
| **已配对** | 凭据已存在，隧道可用 | 连接器兑换配对令牌时写入 |
| **已启用** | 运维的按隧道开关 | `PATCH /tunnels/{id}` 的 `status` |
| **连接器在线** | 当前有连接器持有控制流 | 控制面实时上报 |

「已配对 + 已启用」而连接器离线，是"配置正确但连接器没跑"，不是坏了；反过来不可能
在未配对时显示「连接器在线」。

**操作步骤**

1. **Agents → Tunnels → 创建隧道**：控制台返回一次性配对命令
   （`install.sh --mode tunnel --server-url ... --token ...`），在内网主机执行即可
   安装连接器、配对并注册 `wafred-tunnel.service`。令牌只显示一次（默认 30 分钟
   过期）；重新生成会轮换凭据并断开当前连接器。

   不用安装器时，等价的两步：

   ```bash
   sudo wafred-tunnel pair \
     --config /etc/wafred/tunnel.toml \
     --server-url https://control-plane:9090 \
     --server-ca-cert /etc/wafred/tunnel-ca.pem \
     --token <pairing-token>
   sudo wafred-tunnel run --config /etc/wafred/tunnel.toml
   ```
2. **在边缘开启隧道监听**：`wafred.toml` 的 `[agent] tunnel_addr = "0.0.0.0:9443"`
   （或 `--tunnel-addr` / `WAFRED_TUNNEL_ADDR`），并在 agent 详情里填写
   **隧道入口地址**（连接器拨号的公网 `host:port`）。该面板同时显示监听状态与
   连接器要固定的证书 SHA-256。防火墙只需在边缘放开隧道端口，内网侧无需任何入站。
3. **把源站池绑定到隧道**：站点 → 基础 → 源站池 → 编辑 → **隧道** 选择器。池内的
   节点地址随后由连接器在内网解析。隧道的目标清单由绑定它的源站池推导，无需另配。

**请求如何流转**

```
客户端 ──TLS──► 边缘 :443 ──► WAF 流水线 ──► 绑定隧道的源站池
                                                │
                                     127.0.0.1:<桥接端口>
                                                │
                                       TLS + 多路复用会话
                                                │
                                       连接器（内网）
                                                │
                                       10.0.0.5:8080（源站）
```

桥接就是普通源站，链路里没有特殊分支：WAF 照常判决、缓存照常命中、日志照常记录，
访问日志把源站显示为 `tunnel://<名称>/<目标>`。连接器只拨控制面下发的目标清单
（可被本地 `allowed_targets` 进一步收紧），边缘无法让它访问策略之外的地址。

**验证是否真的通了**（按失败顺序排查）

1. **连接器在线**：**边缘节点 → 隧道** 中该行显示「已配对」+「连接器在线」，详情
   面板的 **边缘节点** 至少有一条；本机可用
   `wafred-tunnel status --config /etc/wafred/tunnel.toml` 看到同样的实时状态
   （已建立会话的 ingress、生效的目标、最近一次吊销原因）。
2. **边缘提供入口**：同一面板能看到边缘与 **目标**；**边缘节点** 为空说明没有边缘
   开启监听或未填入口地址（见上文第 2 步）。
3. **站点经隧道可达**：以站点自己的 Host 访问：
   ```bash
   curl -sv -H 'Host: app.example.com' https://<边缘地址>/ \
     --resolve app.example.com:443:<边缘地址>
   ```
   返回源站的 `200` 即全链路正常；`502/503` 说明边缘没有会话（回到第 1 步），或
   连接器到不了源站（看连接器日志里的 `target is unreachable`）。

详情面板的 **使用该隧道的站点** 列出绑定该隧道的站点——即禁用/删除它的影响面。

**不出网环境：通过 SOCKS5 代理**

只能经 SOCKS5 代理出网的主机（跳板机、企业网关）同样可以运行连接器：指定代理后
**两条通道**（控制面流与所有边缘会话）都走它，没有分通道开关，也不会静默回退直连
——需要代理的主机直连本来就不通。

```toml
# /etc/wafred/tunnel.toml
socks5_proxy    = "10.0.0.1:1080"          # 或 socks5://10.0.0.1:1080
socks5_username = "connector"               # 可选
socks5_password = "…"                       # 可选
```

命令行 / 安装器同样支持：

```bash
wafred-tunnel run --config /etc/wafred/tunnel.toml \
  --socks5-proxy 10.0.0.1:1080 --socks5-username connector

curl -fsSL …/install.sh | sudo bash -s -- --mode tunnel \
  --server-url https://control-plane:9090 --token <pairing-token> \
  --socks5-proxy 10.0.0.1:1080 --socks5-username connector
```

说明：

- **目标主机名由代理解析**（SOCKS5 ATYP 3）——内网里出问题的往往正是本地 DNS；
  目标为 IP 字面量时按地址发送。
- 凭据可写在 `socks5://user:pass@host:port` 里；显式的
  `--socks5-username`/`--socks5-password`（或配置键）优先；密码建议用
  `WAFRED_TUNNEL_SOCKS5_PASSWORD` 传入，避免被 `ps` 看到。
- 握手（greeting、可选认证、CONNECT）有独立超时；代理卡住时报错会指明卡在哪一步
  （拒绝所有认证方式 / 用户名密码被拒 / connection refused / 超时），不会让连接器
  永久挂住。
- 代理只用于连接器的**出站**拨号，不改变边缘访问源站的方式。

**连接器命令与配置**

```bash
wafred-tunnel pair   --token <pairing-token> --server-url https://cp:9090 [--config PATH]
wafred-tunnel run    [--config PATH]
wafred-tunnel status [--config PATH]
```

| `tunnel.toml` 键 | 含义 |
| --- | --- |
| `tunnel_id`、`credential` | 由 `pair` 写入 |
| `server_url`、`server_ca_cert`、`server_tls_name` | 控制面及其 TLS 信任 |
| `ingress` | `host:port[=sha256]` 入口；由控制面下发，也可在本地固定 |
| `allowed_targets` | 可选本地白名单，与策略取交集（绝不合并） |
| `socks5_proxy`、`socks5_username`、`socks5_password` | 经 SOCKS5 代理出网 |
| `session_token` | 给边缘的短期令牌，由控制面刷新 |

`status` 不会另开控制面流（那会占掉正在服务流量的连接器的会话位），而是读取 `run`
发布到 `/var/lib/wafred/tunnel/status.json` 的状态：已连接的入口、生效的目标、
最近一次吊销原因。

**运维动作**

| 动作 | 效果 |
| --- | --- |
| 重新配对 | 生成新令牌并轮换凭据；运行中的连接器被断开，需用新令牌重新接入 |
| 吊销 | 立即作废凭据；绑定站点在重新配对前返回 503 |
| 禁用 | 保留凭据但拒绝新会话（部署级开关或单隧道开关） |
| 删除 | 删除隧道；仍被源站池引用时返回 `409`，`?force=true` 才会解绑并回退为**直连源站** |
| 设置 | 部署级限制：总开关、配对令牌有效期、单会话连接数、单隧道目标数、会话存活、心跳、会话令牌有效期 |

**排障要点**

- 隧道显示「连接器离线」：连接器连不上控制面，检查 `journalctl -u wafred-tunnel`、
  `--server-url` 与 `--server-ca-cert`。
- 连接器在线但「边缘节点 0」：没有边缘提供入口，开启 `tunnel_addr` 并填写入口地址。
- 「目标 无」：还没有源站池绑定该隧道。
- 隧道在线但请求 502/503：该边缘没有会话（监听未开，或证书指纹已变）；agent 详情
  面板可见监听状态与指纹，连接器会在下次配置刷新时取到新指纹。

**本版本的限制**

- 经站点承载 HTTP、HTTPS 与 WebSocket；不暴露裸 TCP。
- 一个隧道即一个信任域：任何服务该隧道所绑定站点的边缘都能请求其任意目标，请按
  网段拆分隧道。
- 单隧道目标数与单会话流数由设置行限制。
- 边缘监听在启动时绑定；入口地址与策略热生效（连通时 ≤5s）。

**安全模型**

- **边缘不会看到连接器凭据。** 连接器出示的是控制面用 Ed25519 签发的**短期
  会话令牌**（签名密钥由部署的 JWT secret 派生）；边缘用规则包下发的公钥校验
  签名、隧道 id 与有效期。凭据本身只用于连接器与**控制面**之间的控制流认证。
- 因此被截获的令牌在有效期内（默认 1 小时，`session_token_ttl_seconds`）之后即
  失效，也无法用于其他隧道。令牌有效期同时决定了**分区边缘**继续接受已吊销隧道
  的上限——若要求更快的吊销收敛，请调小该值。
- 边缘隧道证书本地自签，连接器**固定其 SHA-256**，不匹配即失败关闭。证书会持久化，
  重启后指纹不变。如需轮换：停止边缘、删除其数据目录下的
  `cert.pem` / `key.pem`，再启动即可——新指纹会在下一次心跳到达连接器。
- 边缘只为自身站点引用的目标开流，连接器只拨控制面下发的目标（可被本地
  `allowed_targets` 进一步收紧）。
- 桥接端口仅监听 `127.0.0.1`：边缘主机上的本地进程可以访问，与任何本地代理一致
  ——边缘主机本身是可信的。
- **一个隧道即一个信任域**：任何服务该隧道所绑定站点的边缘，都能向连接器请求该
  隧道目标清单中的任意地址，而不限于自己站点引用的那些。请按网段拆分隧道。
- **吊销在边缘可连通控制面时收敛**：策略（含令牌公钥）会落盘缓存，与控制面分区的
  边缘会继续接受它能校验且未过期的令牌——与本部署对规则本身的 fail-open 行为
  一致。边缘收到下一次规则包后（连通时 ≤5s）吊销即生效。

## Request/Response Rewriting（请求/响应改写）

### Response Body Replacement（响应体替换）

除请求头外，站点还可以重写响应体内的字符串。在站点 **Rewrite Rules** 页配置
（卡片位于规则列表下方），或通过 `PUT /api/v1/sites/{site_id}` 传
`response_replace` 对象——完整字段列表见
[API 参考的 response_replace](../api.md#response-body-replacement-response_replace)：

```json
{
  "path": "^/status",
  "status_codes": [200],
  "rules": [
    { "pattern": "Google", "replacement": "WAFred", "is_regex": false }
  ]
}
```

| 字段 | 含义 |
|-------|---------|
| `path` | 请求路径须匹配的正则；空 = 所有路径 |
| `status_codes` | 需要改写的状态码；空 = 全部。每项 100–599 |
| `rules` | 至多 20 条替换，按顺序应用 |
| `rules[].pattern` | 文本（1–512 字节），字面量匹配；`is_regex` 时按正则编译（必须能编译） |
| `rules[].replacement` | 替换文本（1–2048 字节）；`is_regex` 时 `$1` / `$name` 引用捕获组 |
| `rules[].is_regex` | 将 `pattern` 按正则而非字面量编译 |

两条硬约束，保存时 `400` 强制：pattern 与 replacement 都**不能包含单引号**，
且两侧都不能为空。清除策略用 `null`——或空的 `rules` 列表，同样视为「无策略」。

**压缩响应的编码支持（Unreleased 扩展）：** 替换功能理解 `gzip` / `x-gzip`、
`deflate`（zlib 封装；raw deflate 回退）以及 **`br`（brotli）** 与 **`zstd`**：
正文解压 → 改写 → 以**同一算法**重压缩，`Content-Encoding` 保留。要点：

- 解压后明文上限 **8 MiB**（防压缩炸弹），超限按原始压缩字节透传；
- 解压失败、重压缩失败或**无任何命中**时输出原始压缩字节——无命中时输出与源
  字节逐位一致，ETag 与完整性摘要保持有效；
- 发生改写的响应：删除 `Content-Length`、改为 chunked、强 `ETag` 弱化为 `W/`、
  删除 `Content-MD5` 与 `Digest`、添加 `Vary: Accept-Encoding`；
- 多值编码（如 `gzip, br`）仍按不支持透传，不做替换。

因此：源站若以 brotli 或 zstd 压缩响应（此前会被整体透传、替换不生效），现在
替换照常工作。
详见：[Response Body Replacement](../user-guide.md#response-body-replacement)。

## 安全相关摘要（Security）

> 本节是中文摘要，完整细节以英文原文为准；逐项加固步骤见
> [SECURITY.md 加固清单](../../SECURITY.md#hardening-checklist)。

### 密钥与加固

- `WAFRED_JWT_SECRET` 与 `WAFRED_SECRET_KEY` 都应为 **32 字节随机值**（`openssl rand -hex 32`）。
  前者签名登录 token；后者加密通知渠道口令、AI Provider Key 与备份目标凭据，未设置时这些字段以明文入库（仅 WARN），
  且目前**没有在线轮换**——备份与轮换步骤见 [SECURITY.md](../../SECURITY.md#credentials-and-secrets)。
- 默认管理员口令必须在首次登录时修改；compose 与安装器不提供默认口令（安装器生成随机口令并只打印一次）。
- `.env` 权限 `600`、不入版本库；优先使用 secret manager。详见 [deployment.md](./deployment.md)。

### 日志与敏感数据

访问日志会**原样**保存请求/响应头（含 `Authorization`、`Cookie`、`Set-Cookie`）与最多 8 KiB 的 body，
默认保留 180 天。请把 PostgreSQL 与 Elasticsearch 视作凭据存储：限制读取、加密备份、按需缩短保留期，
不需要 body 时用 `--max-body-log-size 0` 关闭。详见英文
[Log Management](../user-guide.md#log-management) 与 [Log Retention](../user-guide.md#log-retention)。

### MCP 数据边界

MCP 的 `read` key 只能看到**其属主拥有的站点**；只有「key 带 `write` 且属主是管理员」才是 fleet-wide
（可调用控制面审计日志、防御设置等 admin-only 工具）。`write` key 等同管理员凭据，不要交给不受控的 AI 客户端。
详见英文 [MCP Server](../user-guide.md#mcp-server) 与 [api.md 的 MCP 章节](./api.md)。

### AI 助手数据边界

内置 AI 助手调用与 MCP 相同的工具，会把用户消息与工具结果（站点元数据、访问日志、WAF 事件，管理员还包括
控制面审计条目）发送给 **Settings → AI assistant** 配置的第三方 provider。仅在该数据允许离开部署时启用，
并审阅 provider 的保留与数据处理条款；`allow_write_tools` 默认关闭，非必要不要打开。
详见英文 [AI Assistant](../user-guide.md#ai-assistant)。

### Passkey（WebAuthn）

Passkey 需要安全上下文：HTTPS 主机名或 `localhost`；`http://` 或裸 IP 不可用，反代后需设
`WAFRED_PASSKEY_ORIGIN`。丢失设备时用口令登录后在 **Profile** 删除旧 passkey 并重新注册。
详见英文 [Passkeys (WebAuthn)](../user-guide.md#passkeys-webauthn)。

### 安全响应头

控制台与 API 会下发 CSP（`default-src 'self'`、`script-src 'self'`、`frame-ancestors 'none'` 等）、
`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY` 与 `Referrer-Policy`；反向代理不得剥离或放宽，
分源部署只应显式放宽 `connect-src`。详见 [api.md → Response security headers](../api.md#response-security-headers)。
