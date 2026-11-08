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
| `443` | Proxied traffic | Opens only after a certificate is issued or uploaded |

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

### GitHub and GHCR mirrors

The installers accept `--mirror` for GitHub file downloads and the Compose installer accepts `--image-mirror` for the OCI image path. The default `host-path` mode appends `raw.githubusercontent.com/...` to the mirror; use `--mirror-mode full-url` when the proxy expects the complete original URL. For example, [GH-Proxy's file guide](https://gh-proxy.com/docs/github-accelerator) and [image guide](https://gh-proxy.com/docs/docker-mirror) document different prefixes:

```bash
curl -fsSL https://gh-proxy.org/https://raw.githubusercontent.com/oyport/wafred/main/deploy/compose/install.sh \
  | bash -s -- --mirror https://gh-proxy.org --mirror-mode full-url \
      --image-mirror https://gh-proxy.org/docker
```

The image path is saved as `WAFRED_IMAGE` in `.env`, so later `docker compose pull` calls use it too. The binary installer accepts the same GitHub mirror options; pin `--version` if a chosen proxy does not support the GitHub API. The first `curl` must also use the proxy. PostgreSQL still pulls from Docker Hub. See the [full mirror guide](https://github.com/oyport/wafred/blob/main/docs/deployment.md#github-and-ghcr-mirrors).

> Keep `hostname` stable. The control plane matches re-registrations by hostname plus API key, so a changing container ID leaves ghost offline agents behind.

## Source build

| Tool | Version | Why |
| --- | --- | --- |
| Rust | 1.96+ (MSRV) | The binary itself |
| Node.js | 26.12.1+ | Builds the embedded dashboard; `web/.npmrc` sets `engine-strict=true` |
| `protoc` | recent | gRPC code generation — **mandatory** |
| `cmake` | recent | TLS backend build |
| PostgreSQL | 14+ (16 recommended) | Control-plane datastore; the role needs DDL rights |

Without `protoc`, `pingwaf-proto` silently writes placeholder files and the downstream crates fail to compile — install it before you build.

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

## systemd

The shipped `wafred.service` runs as the `wafred` user with `Restart=always`, `LimitNOFILE=65536`, `ProtectSystem=strict` and write access limited to `/var/lib/wafred` and `/etc/wafred`. There is no reload signal: configuration changes are applied by the control plane, and a binary or unit change needs `systemctl restart wafred`.

## TLS on the control plane

The dashboard is HTTPS from the first boot with a generated self-signed certificate. Set `WAFRED_TLS_SANS` to the hostname you actually use (comma separated) before generating it, or upload a real certificate under **Settings → Control plane HTTPS**. When the console sits behind a TLS-terminating proxy, set `WAFRED_TLS_ENABLED=false`.
