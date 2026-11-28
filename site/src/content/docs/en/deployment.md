---
title: Deployment
description: Docker Compose and source builds, ports, configuration precedence, systemd units and distributed agent setups.
minutes: 10
---

## Deployment shapes

**All-in-one** runs the control plane and one data plane in a single process. It is the right choice for a single node, for evaluation, and for small deployments where one edge is enough.

**Distributed** runs one `wafred server` and any number of `wafred agent` processes. The control plane keeps state; agents stay stateless apart from their rule cache, so you can add edges without touching the database.

## Ports

| Port | Used by | Notes |
| --- | --- | --- |
| `9080` | REST API + dashboard | HTTPS with a self-signed certificate until you replace it; keep it private |
| `9090` | gRPC control plane | Agents connect here; TLS by default, `grpc_tls_mode = "off"` downgrades to plaintext |
| `80` | Proxied traffic | Bound once the first site exists |
| `443` | Proxied traffic | Bound once the first site exists; a new site is issued a self-signed certificate automatically |

`GET /healthz` answers on both HTTP and HTTPS, which is what the compose health check and most load balancers should probe. Everything else redirects to HTTPS.

## Docker Compose

```bash
git clone https://github.com/oyport/wafred.git
cd wafred
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

The compose file starts `ghcr.io/oyport/wafred:latest` in all-in-one mode next to `postgres:16-alpine`, publishing `80`, `443`, `9080` and `9090`. The database port is bound to `127.0.0.1` by default.

On Debian/Ubuntu, the Compose installer installs missing Docker Engine or Compose v2 from the configured OS repositories and starts Docker. This requires root or passwordless sudo. Use `--no-install-docker` to disable automatic package installation; other distributions need Docker and Compose v2 installed first.

### GitHub and GHCR mirrors

The installers accept `--mirror` for GitHub file downloads and the Compose installer accepts `--image-mirror` for the OCI image path. The default `host-path` mode appends `raw.githubusercontent.com/...` to the mirror; use `--mirror-mode full-url` when the proxy expects the complete original URL. For example, [GH-Proxy's file guide](https://gh-proxy.com/docs/github-accelerator) and [image guide](https://gh-proxy.com/docs/docker-mirror) document different prefixes:

```bash
curl -fsSL https://gh-proxy.org/https://raw.githubusercontent.com/oyport/wafred/main/deploy/compose/install.sh \
  | bash -s -- --mirror https://gh-proxy.org --mirror-mode full-url \
      --image-mirror https://gh-proxy.org/docker
```

The image path is saved as `WAFRED_IMAGE` in `.env`, so later `docker compose pull` calls use it too. The binary installer accepts the same GitHub mirror options; pin `--version` if a chosen proxy does not support the GitHub API. The first `curl` must also use the proxy. PostgreSQL still pulls from Docker Hub. See the [full mirror guide](https://github.com/oyport/wafred/blob/main/docs/deployment.md#github-and-ghcr-mirrors).

Two failures account for most first-run compose errors:

- `permission denied while trying to connect to the Docker API at unix:///var/run/docker.sock` — your user is not in the `docker` group. Run `sudo docker compose up -d`, or add yourself to the group (`sudo usermod -aG docker $USER`, then log in again).
- `failed to bind host port 127.0.0.1:5432/tcp: address already in use` — a local PostgreSQL already owns 5432. Set `POSTGRES_PORT=55432` in `.env` (or pass `--db-port 55432` to `deploy/compose/install.sh`, which picks a free port from 55432 up automatically) and start again.

> Keep `hostname` stable. The control plane matches re-registrations by hostname plus API key, so a changing container ID leaves ghost offline agents behind.

## Source build

| Tool | Version | Why |
| --- | --- | --- |
| Rust | 1.96+ (MSRV) | The binary itself |
| Node.js | 26.12.1+ | Builds the embedded dashboard; `web/.npmrc` sets `engine-strict=true` |
| `protoc` | recent | gRPC code generation — **mandatory** |
| `cmake` | recent | TLS backend build |
| PostgreSQL | 14+; native installs use the distribution's package name (`postgresql-16` on Ubuntu 24.04, `postgresql-18` on 26.04) | Control-plane datastore; the role needs DDL rights |

Without `protoc`, `wafred-proto` silently writes placeholder files and the downstream crates fail to compile — install it before you build.

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin wafred --features full
./target/release/wafred all-in-one \
  --db-url "postgres://wafred:wafred@localhost:5432/wafred"
```

On Linux, `install.sh` downloads the prebuilt archive, installs to `/usr/local/bin`, writes `/etc/wafred/wafred.toml` and a systemd unit, and starts the service. Run it on a terminal with no arguments for guided prompts (deployment mode, admin credentials, PostgreSQL URL, certificate SANs, version), or pipe it for a one-line unattended install.

```bash
# interactive prompts, with an installation plan and confirmation
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh -o install.sh && bash install.sh

# one line, unattended (no prompts — piping means there is no terminal)
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh | bash -s -- --mode all-in-one
```

Flags: `--mode all-in-one|server|agent`, `--no-systemd` to skip the unit, `--admin-email` / `--admin-password` / `--tls-sans` (or the matching `WAFRED_*` environment variables) to seed settings without prompts, and `--dry-run` to preview the plan without installing.

## Configuration precedence

Settings are read from the TOML file first, then `WAFRED_*` environment variables, then CLI flags — later channels win. Unknown TOML keys are reported and skipped.

```bash
wafred all-in-one --config /etc/wafred/wafred.toml
WAFRED_CONFIG=/etc/wafred/wafred.toml wafred all-in-one   # equivalent
```

The `[server]` table covers `db_url`, `admin_addr`, `tls_enabled`, `tls_sans`, `grpc_addr`, `jwt_secret`, `admin_email` and `serve_frontend`. The `[agent]` table covers `server_url`, `server_ca_cert`, `api_key`, `cache_dir`, `heartbeat_interval_secs`, log batching, `fail_open` and metric shipping.

## Distributed agents

An agent needs three things: where the control plane is, how to authenticate, and where to cache rules.

```bash
WAFRED_SERVER_URL="https://control.example.com:9090" \
WAFRED_API_KEY="<enrollment key>" \
WAFRED_CACHE_DIR="/var/lib/wafred/cache" \
wafred agent
```

Enrollment keys are created from the console (`POST /api/v1/agents/enroll` returns an install command). An empty `WAFRED_API_KEY` is only valid for loopback auto-registration in all-in-one mode.

Agent scope defaults to **All sites** owned by its API key. In **Agents → [node] → Site scope**, choose **Selected sites** to send only the sites that edge should serve. Keep the control plane dashboard site out of a separate edge's selection; its loopback dashboard address is not available there.

For ACME, the control plane must be **0.32.40 or newer** so the PEMs issued by its embedded data plane are synced into `site_certificates` and pushed to agents. An older control plane sends `acme_email` without a PEM, so each agent starts its own HTTP-01 order; the CA validation request reaches the host that owns port 80 (usually the control plane), not the agent, and fails. If the control plane cannot be upgraded yet, set `PINGAP_DISABLE_ACME=true` in the agent unit and upload certificates instead.

Only an agent marked as an ACME issuer receives the DNS provider credentials and opens orders; the embedded all-in-one issuer is marked automatically, and a remote issuer is marked with `PATCH /api/v1/agents/{id}` and `{"acme_issuer": true}`. Consumer agents serve the distributed PEM without the credential. A marked remote issuer reports its issued certificate back over the authenticated control-plane channel, and the control plane validates the designation, site assignment, hostname set and key before fanning it out.

DNS-01 with Amazon Route 53 is supported in WAFred: select `dns-01` + `route53`, optionally pin `acme_dns_config.hosted_zone_id`, and give the issuing process an AWS credential (an EC2 instance role is the simplest). The issuer needs `GetHostedZone`, `ListResourceRecordSets` and `ChangeResourceRecordSets` on the zone (plus `ListHostedZones` for discovery); consumer agents need no AWS permission.

The installer copies `--server-ca-cert` to `/etc/wafred/grpc-ca.pem` and references that durable path; the console's generated command does not include the CA or `--server-tls-name`, so add them for a self-signed control plane.

## Tunnels (internal services without an inbound port)

A tunnel reaches a service inside a private network **without an inbound port and without a public IP on that host**. The `wafred-tunnel` connector dials out to the control plane and to the edge; the edge terminates the public side and proxies through a loopback bridge, so the WAF, rate limiting, cache, logs and certificates all apply exactly as they do for a direct origin.

**Edge:** enable the listener only on the edges that should terminate tunnels, and firewall the port to where the connectors run:

```toml
[agent]
tunnel_addr = "0.0.0.0:9443"   # off by default
```

Then give that edge a public ingress address in **Agents → [node] → Tunnel ingress** (`edge1.example.com:9443`); the panel also shows the listener state and the certificate fingerprint connectors pin.

**Connector:** create the tunnel in **Agents → Tunnels**, copy the one-time pairing command and run it inside the private network:

```bash
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh \
  | sudo bash -s -- --mode tunnel \
      --server-url https://control-plane:9090 \
      --server-ca-cert control-plane.pem \
      --token <pairing-token>
```

It installs `/usr/local/bin/wafred-tunnel`, writes `/etc/wafred/tunnel.toml` (`0600`) and registers `wafred-tunnel.service`. Nothing needs to be open on the private-network side; the connector only makes outbound connections (9090 to the control plane, 9443 to the ingress edges).

**Use it:** bind an origin pool to the tunnel in the site's origin-pool dialog. Its node addresses (`10.0.0.5:8080`, `app.internal:8443`) are then resolved by the connector inside the private network instead of by the edge. The tunnel's target list is derived from the bound pools.

Revoke a tunnel when its host is decommissioned: the credential stops working and every edge refuses the session within one rule-bundle reload. Deleting the tunnel is refused while origin pools still reference it (`409`); `?force=true` unbinds them and they fall back to direct origins.

The complete operating guide — the three independent states, the request path, the connector's commands and config keys, SOCKS5 egress for a host with no direct route, and the troubleshooting table — is the [Tunnels](/docs/tunnel/) page.

## systemd

The shipped `wafred.service` runs as the `wafred` user with `Restart=always`, `LimitNOFILE=65536`, `ProtectSystem=strict` and write access limited to `/var/lib/wafred` and `/etc/wafred`. There is no reload signal: configuration changes are applied by the control plane, and a binary or unit change needs `systemctl restart wafred`.

For a manual tarball install, `wafred.service` and `wafred.toml` are inside `wafred-linux-<arch>/`. The unit sets `WorkingDirectory=/var/lib/wafred` so the relative `cache_dir` persists; without it `ProtectSystem=strict` makes the cache read-only. Use `WAFRED_DB_URL` (not `WAFRED_DATABASE_URL`), set `WAFRED_SECRET_KEY` and an admin password before the first start, and pin `MIMALLOC_ARENA_RESERVE` on hosts below 4 GiB. When switching an existing agent host to all-in-one, move `/var/lib/wafred/cache` aside first: the fail-open snapshot can contain another control plane's sites and certificates.

## TLS on the control plane

The dashboard is HTTPS from the first boot with a generated self-signed certificate. Set `WAFRED_TLS_SANS` to the hostname you actually use (comma separated) before generating it, or upload a real certificate under **Settings → Control plane HTTPS**. When the console sits behind a TLS-terminating proxy, set `WAFRED_TLS_ENABLED=false`.
