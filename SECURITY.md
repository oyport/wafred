# Security Policy

WAFred sits directly in the request path of the applications it protects, so
its own security matters as much as the rules it enforces. We take vulnerability
reports seriously and appreciate the effort of security researchers who disclose
them responsibly.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue, discussion, or pull request for a
security vulnerability.** Public reports put every WAFred deployment at risk
before a fix exists.

Instead, report privately:

| Channel | How to reach us |
| --- | --- |
| **Email (preferred)** | `security@waf.red` |

> **Maintainers:** verify that `security@waf.red` is a real, monitored
> mailbox owned by at least two people before publishing this repository widely.
> Consider publishing a PGP key for that address, and enabling GitHub's
> *Private vulnerability reporting* (Security → Advisories) as a second channel,
> then document it here.

### What to include

The more detail you provide, the faster we can triage:

1. **Summary** of the vulnerability and its impact.
2. **Affected versions** — release tag, or the exact git commit if you built
   from source (`git rev-parse HEAD`).
3. **Deployment context** — run mode (`all-in-one`, `server`, `agent`), OS and
   architecture, TLS backend (`openssl` or `tls-rustls`), feature flags used,
   whether the instance is internet-facing.
4. **Step-by-step reproduction**, including any request payload, configuration
   or rule set required. A minimal, self-contained PoC is ideal.
5. **Attack prerequisites** — unauthenticated remote attacker, authenticated
   dashboard user, agent API key, network position, etc.
6. **Whether the vulnerability is already public** or known to be exploited.
7. Your **handle for credit** (optional) and any **CVE/CNA preference**.

Please redact secrets (JWT tokens, database passwords, agent API keys) from
anything you send us.

### Response timeline

| Stage | Target |
| --- | --- |
| Acknowledge receipt | Within **3 business days** |
| Initial triage and severity assessment | Within **7 business days** |
| Status updates while a fix is developed | At least **weekly** |
| Fix, advisory and release | As soon as practical; coordinated with you |
| Public disclosure | After the fix ships, or **90 days** from the report — whichever comes first |

We will keep you informed, credit you in the advisory if you wish, and never
pursue legal action for good-faith research conducted under this policy.

## Supported Versions

WAFred shares its version lineage with [pingap](https://github.com/vicanso/pingap),
from which it inherits the proxy data plane.

| Version | Status | Receives security fixes |
| --- | --- | --- |
| `main` | Active development | Yes — but expect breaking changes |
| `1.0.x` (current WAFred release line, latest `1.0.7`) | Supported | **Yes** |
| `1.0.0`–`1.0.4` | Superseded; upgrade to the latest `1.0.x` patch | No separate backports |

Only the latest WAFred release line is guaranteed to receive security patches;
older patch versions should be upgraded to the latest release. Security fixes
ship in patch releases of the current line and are listed under
`### Security` in [`CHANGELOG.md`](./CHANGELOG.md). If you run an older version,
please upgrade — see
[`docs/deployment.md` → Upgrade Procedure](./docs/deployment.md#upgrade-procedure).

> **Note:** prebuilt Linux (amd64/arm64) binaries are published on
> [GitHub Releases](https://github.com/oyport/wafred/releases); on macOS,
> build from source. Either way, pin the exact version or commit you deploy so
> you can tell us what you are running.

## Scope

The following are in scope for this policy:

- **WAF bypass** — payloads that evade normalisation, signature matching or the
  rule engine (`wafred-waf`) and reach the origin unblocked.
- **Authentication and authorisation** — JWT issuance/validation, session and
  refresh-token handling, role checks, user registration controls in the
  control-plane REST API (`/api/v1`), and the MCP endpoint's credential
  handling at `/mcp`.
- **Control-plane protocol** — the gRPC channel between agents and the server:
  agent authentication and API keys, rule/config push integrity, command
  execution (block IP, purge cache, restart agent).
- **Tunnel** — the connector-to-edge channel (`wafred-tunnel`): pairing-token
  redemption, connector credential handling, certificate pinning, and the
  target allowlist that decides which internal service a session may reach.
- **Injection and traversal** — SQL injection via SeaORM/raw queries in the
  control plane, path traversal in dashboard asset serving or the local rule
  cache, template or log injection.
- **Credential and secret exposure** — leaked database credentials, ACME/DNS
  provider tokens, TLS private keys, API keys, or secrets written to logs,
  metrics, Elasticsearch documents or error responses.
- **TLS handling** — certificate validation, ACME issuance/renewal, protocol
  and cipher downgrade, SNI handling.
- **Memory safety and DoS** — panics, unbounded allocation, quadratic parsing or
  other resource exhaustion reachable from untrusted HTTP input.
- **Proxy request smuggling** — HTTP/1.1, HTTP/2 or gRPC-Web parsing
  inconsistencies between WAFred and an upstream or downstream hop.

Out of scope (please still tell us if you are unsure):

- Reports that require physical access to the host, or an already-compromised
  server.
- Findings that depend on a deployment running with the documented insecure
  defaults (`wafred123`, `change-me-in-production`, open registration) on a
  public network — these are configuration issues, covered under
  [Hardening](#hardening-checklist) below.
- Missing security headers or TLS best-practice settings on *your* origin.
- Vulnerabilities in third-party dependencies without a demonstrated impact on
  WAFred (please report those upstream, and open an issue for the dependency
  bump).
- Social engineering of maintainers or contributors.

## Disclosure Policy

We follow **coordinated disclosure**:

1. You report privately and give us a reasonable window to fix the issue.
2. We develop the fix on a private branch and prepare a security advisory.
3. We agree on a disclosure date with you, request a CVE where appropriate, and
   publish the advisory together with the patched release.
4. You are credited in the advisory unless you prefer to stay anonymous.
5. We do not disclose report details publicly before the agreed date, and we ask
   you to do the same.

Dependency vulnerabilities found by `cargo audit` are tracked against
[`.cargo/audit.toml`](./.cargo/audit.toml); every accepted exception there must
document why it is not exploitable and when it can be removed.

## Hardening Checklist

WAFred ships with development-friendly defaults so you can evaluate it quickly.
**Change every one of them before exposing an instance to a network you do not
control.**

### Credentials and secrets

- [ ] Set `WAFRED_ADMIN_EMAIL` and a strong `WAFRED_ADMIN_PASSWORD` — never
      leave `admin@wafred.local` / `wafred123`.
- [ ] Set `WAFRED_JWT_SECRET` to at least 16 characters of random data
      (32 random bytes recommended): `openssl rand -hex 32`. Rotate it
      immediately if it was ever committed or logged.
- [ ] Set `WAFRED_ALLOW_REGISTRATION=false` unless you need self-service
      signups.
- [ ] Change the PostgreSQL password away from `wafred`, and use a role with
      the minimum privileges WAFred needs (DDL rights are required at startup
      for migrations).
- [ ] Issue a dedicated agent API key per edge node
      (**Settings → API Keys → Create Key**) and rotate keys on staff or host
      changes.

### Network exposure

- [ ] The console listens on `0.0.0.0:9080` by default so a fresh install is
      reachable. Narrow it: set `admin_addr` to a private interface, or keep the
      bind and restrict the cloud security group / host firewall to known
      administrator addresses (or front it with a VPN, SSH tunnel or reverse
      proxy). Do not leave it reachable from the public internet: it is the
      administrative origin and is continuously scanned.
      The port serves HTTPS by default with a self-signed certificate — upload a
      real one (**Settings → Control plane HTTPS**) or set
      `WAFRED_TLS_ENABLED=false` behind a proxy that terminates TLS.
- [ ] Allow port `9090` (gRPC control plane) only from your agent hosts — it is
      not needed by end users.
- [ ] Use bounded health probes (`curl --connect-timeout 2 --max-time 3`) and an
      external watchdog; a container healthcheck process can itself hang when
      the listener is saturated, leaving the status stale.
- [ ] Never expose PostgreSQL (`5432`) publicly; keep it on a private network or
      the Docker Compose internal network.
- [ ] Restrict `80`/`443` to the sites you intend to serve.
- [ ] Use a host firewall (`ufw`, security groups) in addition to binding
      addresses.

### Transport security

- [ ] Enable TLS for every site (ACME/Let's Encrypt or uploaded certificates)
      and force HTTPS with HSTS — see
      [`docs/user-guide.md` → SSL Certificate Management](./docs/user-guide.md#ssl-certificate-management).
- [ ] Set the minimum TLS version to 1.2 or 1.3 per site.
- [ ] Keep gRPC control-plane TLS enabled (the default; a self-signed CA is
      generated on first boot). Do not set `grpc_tls_mode = "off"` for agents
      connecting over any network you do not fully control — the server warns
      at startup and the console shows a degraded banner while it is off.
- [ ] Protect ACME/DNS provider credentials as you would protect TLS private
      keys.
- [ ] Passkeys (WebAuthn) need a secure context: HTTPS under a hostname, or
      `localhost`. They do not work over plain `http://` or a bare IP. Behind a
      TLS-terminating proxy set `WAFRED_PASSKEY_ORIGIN` to the public origin,
      and set `WAFRED_PASSKEY_TRUST_FORWARDED_PROTO=true` only when that proxy
      is the one terminating TLS — see
      [`docs/deployment.md`](./docs/deployment.md).

### Response security headers

- [ ] Leave the console's built-in security headers in place. Every control-plane
      response carries `Content-Security-Policy` (`default-src 'self'`,
      `script-src 'self'`, `connect-src 'self'`, `frame-ancestors 'none'`,
      `base-uri 'self'`, `form-action 'self'`), `X-Content-Type-Options:
      nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy:
      strict-origin-when-cross-origin`. A reverse proxy or middleware must not
      strip or weaken them.
- [ ] A split-origin deployment is the only reason to widen the policy: add the
      API origin to `connect-src` explicitly and keep `frame-ancestors` and
      `script-src` restrictive. Do not add `'unsafe-inline'` to `script-src`.
- [ ] The headers are applied with "if not present" semantics, so a handler or
      proxy can override them deliberately — audit any override.
- [ ] HSTS is a site-level setting (enable it on every proxied site); the
      control-plane listener does not set it — terminate TLS in a proxy that
      does, or enable HSTS on the sites it serves.
- [ ] See [`docs/api.md` → Response security headers](./docs/api.md#response-security-headers)
      for the exact header values.

### Logging and stored data

- [ ] Treat the log store as a credential store. Access logs keep request and
      response headers **verbatim**, including `Authorization`, `Cookie` and
      `Set-Cookie`, plus up to **8 KiB** of each body (`--max-body-log-size`,
      default `8192`). Elasticsearch receives the same documents when the
      shipper is enabled. The default retention is **180 days**
      (**Settings → Log retention**, 1–3650 days).
- [ ] Restrict who can read PostgreSQL and Elasticsearch, and encrypt their
      backups: a leaked backup hands out replayable end-user credentials —
      including the credentials of requests the WAF blocked before they reached
      the origin.
- [ ] If body capture is not needed, disable it (`--max-body-log-size 0` on the
      agent) and shorten the retention window; the console log pages keep
      working with headers only.
- [ ] Keep `RUST_LOG=info,sqlx=warn` in production; `debug` output includes
      request context. See
      [`docs/user-guide.md` → Log Management](./docs/user-guide.md#log-management).

### MCP and AI data boundary

- [ ] Treat MCP API keys as console credentials. A `read` key is accepted but
      scoped to the sites its owner owns; only a `write` key whose owner is an
      administrator is fleet-wide and can call the admin-only tools (control
      plane audit log, defense settings, site pause). Never hand a `write` key
      to an external AI client you do not control.
- [ ] The built-in AI assistant calls the same tools and sends your messages and
      the tool results — site metadata, access logs, WAF events and, for an
      administrator, control-plane audit entries — to the OpenAI-compatible
      provider configured under **Settings → AI assistant**. Enable it only
      where that data may leave the deployment, and review the provider's
      retention and data-processing terms. Keep **Allow write tools** off unless
      you accept that a prompt-injected model could change live configuration.
- [ ] See [`docs/user-guide.md` → MCP Server](./docs/user-guide.md#mcp-server)
      and [→ AI Assistant](./docs/user-guide.md#ai-assistant).

### Reverse-proxy trust

- [ ] When a site sets `trust_proxy_headers: true`, also list the proxy/CDN
      source ranges in `trusted_proxy_ranges` (or reference an IP group such
      as the built-in Cloudflare subscription via `trusted_proxy_group_ids`).
      Trust is strict: with no ranges configured the forwarded client-IP
      header is ignored and the TCP peer is used, so sites upgraded from
      earlier releases must add their proxy ranges to keep CDN-aware rules
      (rate limiting, allowlists, geo) working.

### Tunnels

- [ ] Enable the tunnel listener (`agent.tunnel_addr`, default
      `0.0.0.0:9443`) only on edges that are meant to be tunnel ingresses, and
      firewall the port to the networks the connectors dial from. Every other
      edge should leave it unset.
- [ ] Pairing tokens are single use and expire
      (`tunnel_settings.pairing_ttl_seconds`, 30 minutes by default). Mint them
      from **Agents → Tunnels** and hand them over out of band; the console
      shows the token exactly once and stores only its SHA-256.
- [ ] **A tunnel ingress never receives the connector's credential.** The
      control plane signs a short-lived Ed25519 session token (key derived from
      `jwt_secret`), the connector presents it, and the edge verifies it against
      the public key in its rule bundle. A compromised edge can capture a token,
      which expires (one hour by default) and is bound to one tunnel — set
      `session_token_ttl_seconds` shorter when revocation must converge faster
      than the rule-bundle push. The credential itself only authenticates the
      connector's control stream to the control plane.
- [ ] Revoke a tunnel when a connector host is decommissioned or lost:
      **Revoke** drops the credential and every edge refuses the session within
      one rule-bundle reload (≤5s). Deleting the tunnel does the same and
      unbinds its origin pools.
- [ ] Set `allowed_targets` in the connector's `tunnel.toml` when the
      control-plane target list is broader than that host should reach. It is
      intersected with the policy, never merged.
- [ ] Treat one tunnel as one trust domain: every edge that serves a site bound
      to a tunnel can ask the connector for any of that tunnel's targets. Split
      network segments across separate tunnels.
- [ ] Revocation converges while the edge can reach the control plane: the
      policy (including the token's public key) is cached on disk, so a
      partitioned edge keeps accepting tokens it can verify until they expire,
      exactly like the deployment's fail-open rule cache. A revoked tunnel stops
      working as soon as that edge receives the next bundle.
- [ ] Deleting a tunnel that origin pools still reference is refused (`409`)
      unless `?force=true` is passed: falling back to direct origins means the
      edge starts dialing the internal addresses itself, which may either fail
      or reach a network the tunnel existed to isolate.
- [ ] Bridge ports are loopback-only (`127.0.0.1`), so a process already running
      on an edge host can reach them. The edge host is trusted — do not run
      untrusted workloads on an edge.
- [ ] The edge's tunnel certificate is self-signed and pinned by SHA-256; it is
      regenerated on the edge when it is within 30 days of expiry, and the
      connector picks up the new fingerprint on its next config refresh. A
      connector that cannot verify an ingress fails closed rather than
      downgrading.

### Availability trade-offs

- [ ] Disconnected behaviour defaults to fail-open at every layer: an agent
      keeps proxying traffic when it cannot reach the control plane, which
      favours availability over enforcement. Per-site failover policies and
      the control-plane-wide default (console → settings) override the
      agent's local `--fail-open` once synced. For high-security deployments
      where unfiltered traffic is unacceptable, set the global default — or
      individual sites — to fail-closed, or start agents with
      `--fail-open=false`, and accept the availability trade-off.
- [ ] Right-size `--log-batch-size`, `--max-body-log-size` and
      `WAFRED_DB_MAX_CONNECTIONS`; consider shipping logs to Elasticsearch
      instead of retaining everything in PostgreSQL.
- [ ] Run the service as an unprivileged user with the hardened
      [`wafred.service`](./wafred.service) unit (`NoNewPrivileges`,
      `ProtectSystem=strict`, read-only paths).

### Operations

- [ ] Track the version/commit you run and upgrade promptly when a security
      advisory is published.
- [ ] Back up PostgreSQL regularly (`pg_dump`) — see
      [`docs/deployment.md` → Backup & Recovery](./docs/deployment.md#backup--recovery).
- [ ] Monitor **Logs → Security**, **Agents** (offline/degraded state) and the
      health endpoint `GET /healthz`.
- [ ] Set `RUST_LOG=info,sqlx=warn` in production; use `debug` only while
      investigating, since debug output is far more verbose.
- [ ] Keep the host patched and verify system clocks are NTP-synchronised —
      skewed clocks weaken token validation.

## Further Reading

- [`docs/quick-start.md`](./docs/quick-start.md) — installation and configuration reference
- [`docs/deployment.md`](./docs/deployment.md) — production deployment, TLS, firewall, upgrades
- [`docs/api.md`](./docs/api.md) — REST API and authentication
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — development setup and code style
