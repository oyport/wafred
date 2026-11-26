---
title: Tunnels
description: Serve a service that lives inside a private network through the WAF data plane — no inbound port, no public IP on that host. Pairing, the edge listener, origin-pool binding, SOCKS5 egress, operations and troubleshooting.
minutes: 12
---

A tunnel exposes a service inside a private network — a NAS, an intranet app, a
database admin page — **without opening an inbound port and without a public IP
on that host**. The connector dials out to the edge; the edge terminates the
public side. Every protection the WAF already applies (rules, rate limiting,
challenges, cache, access control, logs, certificates, TLS to the origin) runs
unchanged, because the edge treats the tunnel exactly like any other origin.

This page is the complete operating guide: what the pieces are, the five steps
that make a tunnel work, how a request flows, what the connector's commands do,
how to run it from a network that has no direct egress, and what to check when
something is wrong.

## The pieces

| Piece | Runs where | Job |
| --- | --- | --- |
| **Connector** (`wafred-tunnel`) | inside the private network | dials the control plane and the edges **outbound only**; forwards each proxied connection to the internal target |
| **Edge listener** | on the WAF edge (`tunnel_addr`, port `9443`) | accepts the connector's TLS session and opens one loopback bridge per target |
| **Bridge** | on the edge, `127.0.0.1:<ephemeral>` | makes the tunnel look like an ordinary origin to the proxy |
| **Origin pool binding** | control plane | says which internal `host:port` values a site's traffic may reach through this tunnel |

A tunnel is **not** a VPN: it carries the traffic of the origin pools bound to
it, nothing else. One tunnel is one trust domain — every edge that serves a site
bound to it can ask the connector for any of that tunnel's targets.

## When to use one

- The origin is behind NAT or a firewall you cannot (or will not) open.
- The origin's address is only meaningful inside that network
  (`10.0.0.5:8080`, `app.internal:8443`).
- The public entry point must stay on the WAF, not on the internal host.

Do not use it as a general egress proxy: v1 carries HTTP, HTTPS and WebSocket
through a site. Raw TCP (SSH, arbitrary ports) is not exposed yet.

## Three states that are not the same

The console shows them separately, and most confusion comes from collapsing
them:

| State | Meaning | Where it comes from |
| --- | --- | --- |
| **Paired** | a credential exists; the tunnel can be used | set when a connector redeems its pairing token |
| **Enabled** | the operator's per-tunnel switch | `PATCH /tunnels/{id}` with `status` |
| **Connector online** | a connector currently holds a control stream | reported live by the control plane |

A tunnel can be *Paired* and *Enabled* while the connector is offline — that is
a working configuration with a disconnected connector, not a broken one. It
cannot be *Connector online* without being paired.

## Set up a tunnel in five steps

### 1. Create the tunnel

**Agents → Tunnels → Create tunnel.** The console creates the tunnel and shows a
one-time pairing command:

```bash
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh \
  | sudo bash -s -- --mode tunnel \
      --server-url https://control-plane:9090 \
      --server-ca-cert control-plane.pem \
      --token <pairing-token>
```

The token is displayed **once** and expires after 30 minutes by default
(`pairing_ttl_seconds`). Minting another one rotates the credential and
disconnects the running connector, so keep the dialog open until the command is
copied — it cannot be reopened without re-pairing.

### 2. Run the connector inside the private network

The command installs `wafred-tunnel`, redeems the token for a long-lived
credential, writes `/etc/wafred/tunnel.toml` (`0600`) and registers
`wafred-tunnel.service`.

Without the installer, the same thing by hand:

```bash
sudo wafred-tunnel pair \
  --config /etc/wafred/tunnel.toml \
  --server-url https://control-plane:9090 \
  --server-ca-cert /etc/wafred/tunnel-ca.pem \
  --token <pairing-token>
sudo wafred-tunnel run --config /etc/wafred/tunnel.toml
```

`run` keeps a control stream to the control plane (for policy, a refreshed
session token and revocation) and one session per edge ingress. It logs at
`warn` when it cannot reach either, which is the line to look for in
`journalctl -u wafred-tunnel`.

### 3. Enable the listener on an edge and give it a public address

At least one edge must accept tunnel connections:

```toml
# wafred.toml on the public edge
[agent]
tunnel_addr = "0.0.0.0:9443"
```

or `--tunnel-addr 0.0.0.0:9443` / `WAFRED_TUNNEL_ADDR`, then open `9443` in the
edge's firewall. The edge generates its own self-signed certificate on first
boot (persisted, so restarts keep the same fingerprint), reports its SHA-256,
and the connector pins it.

In the compose deployment the variable must be listed in the service's
`environment:` block — compose only passes what a service declares, so a value
in `.env` alone never reaches the process. The shipped `docker-compose.yml`
forwards `${WAFRED_TUNNEL_ADDR}` and publishes
`${WAFRED_TUNNEL_BIND:-127.0.0.1}:9443:9443`; set `WAFRED_TUNNEL_BIND=0.0.0.0`
for connectors on other hosts, and open `9443` in the cloud security group as
well as the host firewall.

Now give that edge a **Tunnel ingress** address — the public `host:port`
connectors dial — in **Agents → [node] → Tunnel ingress**. The panel also shows
the listener state and explains a listener that is configured but failed to bind
(for example the port is already taken).

The listener binds at startup, so changing `tunnel_addr` needs an edge restart.
The ingress **address** and the tunnel policy are hot: they reach the connectors
and the edges through the next push (≤5 s on a connected edge), so a new ingress
address or a re-paired credential does not need one.

### 4. Bind an origin pool to the tunnel

**Sites → [site] → Origin pools → [pool] → Tunnel.** The pool's node addresses
are the internal targets the connector will dial; the edge never dials them
itself, it hands the pool a loopback bridge address instead.

A pool bound to a tunnel has no upstream while no edge holds a session. Routes
that point at it answer `503` rather than falling back to the site's default
origin — a request must not silently reach a different backend.

### 5. Verify it works

Three checks, in the order they fail:

1. **The connector is online** — **Agents → Tunnels**: the row shows *Paired*
   and *Connector online*, and the detail panel lists at least one edge under
   **Edges**. `sudo wafred-tunnel status --config /etc/wafred/tunnel.toml`
   prints the same live state locally: connected ingress endpoints, the targets
   in force, the SOCKS5 proxy if one is configured, and the last revocation
   reason.
2. **The edge offers an ingress** — the detail panel shows the edge and the
   tunnel's **Targets**. An empty *Edges* list means no edge has the listener
   enabled or its ingress address set (step 3).
3. **The site answers through it** — request it as a client would, with the
   site's own Host header:

   ```bash
   curl -sv -H 'Host: app.example.com' https://<edge-address>/ \
     --resolve app.example.com:443:<edge-address>
   ```

   A `200` from the origin means the whole path works. A `502/503` means the
   edge has no session (back to check 1) or the connector cannot reach the
   origin (look for `target is unreachable` in its log).

The detail panel's **Used by** list names the sites bound to the tunnel — the
blast radius of disabling or deleting it.

## How a request flows

```
client ──TLS──► edge :443 ──► WAF pipeline ──► origin pool (bound to the tunnel)
                                                    │
                                         127.0.0.1:<bridge>
                                                    │
                                        TLS + multiplexed session
                                                    │
                                       connector (private network)
                                                    │
                                       10.0.0.5:8080 (the origin)
```

Because the bridge is an ordinary origin, nothing in the request path is
special-cased: the WAF decides, the cache caches, the log records the site, and
the access log renders the origin as `tunnel://<name>/<target>` instead of a
loopback port. The connector enforces the target list the control plane pushed
(optionally narrowed by its local `allowed_targets`), so the edge cannot make it
dial an address outside the tunnel's policy.

## Connector reference

```bash
wafred-tunnel pair   --token <pairing-token> --server-url https://cp:9090 [--config PATH]
wafred-tunnel run    [--config PATH]
wafred-tunnel status [--config PATH]
```

| Config key | Meaning |
| --- | --- |
| `tunnel_id`, `credential` | written by `pair` |
| `server_url`, `server_ca_cert`, `server_tls_name` | control plane and its TLS trust |
| `ingress` | `host:port[=sha256]` endpoints; filled from the control plane, can be pinned locally |
| `allowed_targets` | optional local allowlist, intersected with the policy (never merged) |
| `socks5_proxy`, `socks5_username`, `socks5_password` | egress through a SOCKS5 proxy |
| `session_token` | short-lived token for the edges, refreshed by the control plane |

`status` never opens a control-plane stream: doing so would take the session
slot of the connector that is actually serving traffic. It reads the state
`run` publishes to `/var/lib/wafred/tunnel/status.json`.

## No direct egress: SOCKS5

A host that can only reach the internet through a SOCKS5 proxy (a jump host, a
corporate gateway) still works: point the connector at the proxy and **both**
channels — the control-plane stream and every edge session — go through it.

```toml
socks5_proxy    = "10.0.0.1:1080"     # or socks5://user:pass@10.0.0.1:1080
socks5_username = "connector"          # optional
socks5_password = "…"                  # optional
```

- Target names are resolved **by the proxy** (SOCKS5 ATYP 3), which is the point
  in a network where local DNS is the broken part.
- Credentials may be embedded in the URL; explicit keys win, and the password is
  better supplied through `WAFRED_TUNNEL_SOCKS5_PASSWORD` than on a command
  line `ps` can read.
- There is no silent fallback to a direct dial: a host that needs the proxy
  cannot reach anything without it, and a stalled proxy fails the dial with a
  message naming the step.

## Operations

| Action | Effect |
| --- | --- |
| **Re-pair** (`POST /tunnels/{id}/pairing`) | rotates the credential, disconnects the running connector, issues a new one-time command |
| **Revoke** (`POST /tunnels/{id}/revoke`) | removes the credential; the edges refuse the tunnel on the next bundle (≤5 s) and the connector stops |
| **Disable** (`PATCH /tunnels/{id}`) | per-tunnel switch; live sessions close on the next reload |
| **Delete** (`DELETE /tunnels/{id}`) | removes it; refused with `409` while origin pools still reference it — `?force=true` clears them, and those pools fall back to **direct** origins |
| **Settings** (**Tunnels → Settings**) | deployment-wide: master switch, pairing-token lifetime, streams per session, targets per tunnel, session liveness, heartbeat, session-token lifetime |

## Security model

- **The edge never sees the connector's credential.** The connector presents a
  short-lived **Ed25519 session token** minted by the control plane (key derived
  from the deployment's `jwt_secret`); the edge verifies the signature, the
  tunnel id and the expiry against the public key in its rule bundle.
- A captured token is useless after its lifetime (one hour by default,
  `session_token_ttl_seconds`) and cannot be replayed against another tunnel.
- **The connector pins the edge's certificate** (SHA-256) and fails closed on a
  mismatch.
- **Revocation converges while the edge can reach the control plane**: the
  bundle drops the tunnel's key, so the next reload refuses it. A partitioned
  edge keeps the last policy it received, like the deployment's fail-open rule
  cache.
- Bridge ports are loopback-only; the edge host is trusted, exactly as it is for
  any local proxy.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Connector logs `cannot reach the control plane` | `server_url`, `9090` reachability, CA (`--server-ca-cert`), or the SOCKS5 proxy |
| Console shows *Connector online* but *Edges 0* | no edge has `tunnel_addr` enabled, or its **Tunnel ingress** is empty (step 3) |
| Session refused with `the tunnel credential was not accepted` | the token expired or was revoked, or the edge has not received the new public key yet — the connector retries with the next token |
| Site answers `502/503` | the edge has no session, or the connector cannot reach the target (its log says `target is unreachable`) |
| Pool shows a `127.0.0.1:<port>` origin | normal: that is the bridge. Its port changes when the session reconnects |
| Delete is refused with `409` | pools still reference the tunnel; unbind them or pass `?force=true` |
| `status` says `not running` | the connector is not running, or it has not published a status file yet |
| Edge log: `cannot start the tunnel listener` | the port is taken or not permitted; the agent detail panel reports the same reason |

## Limits in this version

- HTTP, HTTPS and WebSocket through a site; raw TCP is not exposed.
- One tunnel is one trust domain (see above).
- Per-tunnel targets and per-session streams are capped by the settings row.
- The listener binds at startup; the policy and the ingress address are hot.