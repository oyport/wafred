# wafred-tunnel

The tunnel connector and the edge-side acceptor that let a service inside a
private network be served through the WAFred data plane **without any inbound
port**.

## How it works

```
private network                          public edge (WAFred agent)
┌──────────────────────────┐             ┌────────────────────────────────┐
│ wafred-tunnel           │  TCP+TLS    │  tunnel listener (:9443)       │
│   connector              │ ──────────► │   acceptor + registry          │
│        │ dial 10.0.0.5:80 │  1.3+yamux  │        │ per (tunnel, target)   │
│        ▼                 │             │        ▼ loopback bridge       │
│   origin service         │             │   pingora → WAF → logs         │
└──────────────────────────┘             └────────────────────────────────┘
```

* The connector dials **out** to the control plane (pairing, policy) and to
  every edge ingress (data plane). Nothing dials in, which is what makes it work
  behind NAT.
* The edge binds one `127.0.0.1` listener per tunnel target and hands pingora
  that port as an ordinary origin, so HTTP/1.1, HTTP/2, WebSocket, TLS to the
  origin, connection pooling, health checks, the WAF, rate limiting and the
  access log are the **untouched request path**.
* A bridge only exists while a connector session is attached. With no session
  the pool simply has no upstream — a health probe then reports the truth
  instead of "port open, backend dead".

## Install

The console (Edge Agents → Tunnels) creates the tunnel and prints a one-time
pairing command:

```bash
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh \
  | sudo bash -s -- --mode tunnel \
      --server-url https://control-plane.example.com:9090 \
      --server-ca-cert control-plane.pem \
      --token <pairing-token>
```

Manual equivalent:

```bash
wafred-tunnel pair --config /etc/wafred/tunnel.toml \
  --token <pairing-token> --server-url https://control-plane.example.com:9090 \
  --server-ca-cert /etc/wafred/tunnel-ca.pem
wafred-tunnel run  --config /etc/wafred/tunnel.toml
wafred-tunnel status --config /etc/wafred/tunnel.toml
```

`status` prints the stored configuration and the live state `run` publishes to
`/var/lib/wafred/tunnel/status.json` (connected ingress endpoints, targets in
force, revocation reason). It does not probe the control plane on purpose: a
second `TunnelControl` stream would displace the connector that is serving.

`pair` redeems the token for a long-lived credential and writes it to the
config file (`0600`). The token itself is never stored.

## Configuration

`/etc/wafred/tunnel.toml` (written by `pair`, owner-readable only):

```toml
tunnel_id     = "…"
credential    = "…"                          # 32 random bytes, hex
server_url    = "https://cp.example.com:9090"
server_ca_cert = "/etc/wafred/tunnel-ca.pem" # optional; webpki roots otherwise
server_tls_name = "cp.example.com"            # optional; when the certificate
                                              # does not name the URL host

# Local second line of defence: when non-empty a target must be both in this
# list and in the control plane's policy.
allowed_targets = ["10.0.0.5:8080", "app.internal:8443"]

# No direct egress? Send both the control-plane channel and every edge session
# through a SOCKS5 proxy. Target names are resolved by the proxy (ATYP 3).
# socks5_proxy    = "10.0.0.1:1080"
# socks5_username = "connector"
# socks5_password = "…"        # prefer WAFRED_TUNNEL_SOCKS5_PASSWORD

[[ingress]]
endpoint     = "edge1.example.com:9443"
fingerprints = ["<sha256 of the edge's tunnel certificate>"]
```

The ingress list (with fingerprints) comes from the control plane at pairing
time; the connector keeps working with its stored copy while the control plane
is unreachable.

## Security notes

* The edge's tunnel certificate is self-signed and generated locally. The
  connector **pins its SHA-256** — it does not build a chain to a CA, and a
  fingerprint mismatch fails the handshake.
* The edge never receives the connector's credential. The connector presents a
  short-lived **Ed25519 session token** minted by the control plane; the edge
  verifies the signature, the tunnel id and the expiry against the public key
  in its rule bundle. A captured token expires (one hour by default) and cannot
  be replayed against another tunnel.
* The connector only dials targets the control plane lists **and** its own
  `allowed_targets` allows; the edge only opens streams for targets its own
  sites reference.
* Revoking a tunnel in the console drops the digest from the next rule bundle
  (the edge closes the live session within one reload, ≤5s) and tells a
  connected connector immediately.
* The tunnel listener must be reachable by the connectors; the bridge ports are
  loopback-only, which means a local process on an edge host can reach them —
  the edge host is trusted, exactly as it is for any local proxy.

## Where the code lives

| Module | Role |
| --- | --- |
| `protocol` | control frames, data-stream preamble, target validation |
| `token` | the short-lived session token: format, parsing, Ed25519 verification |
| `cert` | the edge's self-signed listener certificate (atomic write, `0600`) |
| `registry` | policies, live sessions, and one loopback bridge per `(tunnel, target)` |
| `server` | the edge listener: TLS + yamux + handshake + session driver |
| `session` | a live session handle (open a stream, push a policy, close) |
| `verify` | the connector's fingerprint-pinning TLS verifier |
| `socks5` | SOCKS5 CONNECT client (no-auth and username/password) for hosts without direct egress |
| `client` | the connector (behind the `connector` feature) |
| `runtime` | the process-wide registry the data plane and heartbeat read |