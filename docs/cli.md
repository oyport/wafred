# WAFred CLI — Administrator Handbook

The `wafred` binary is more than the service process: it carries a set of
maintenance subcommands that talk **straight to PostgreSQL** instead of the
REST API. This handbook covers the run modes, the shared options and every
maintenance command, with runbooks for the situations where the web console
cannot help.

The only supported WAFred executable is `wafred`. The old `pingwaf` command
and `PINGWAF_*` environment prefix are not accepted.

New deployments use `WAFRED_*` variables, `wafred.service`, `/etc/wafred`,
`/var/lib/wafred`, the `wafred` PostgreSQL role/database, the `wafred` ES index
prefix and `WAFRED-*` managed rule IDs. Existing PingWAF installations require
manual migration: rename `PINGWAF_*` variables to `WAFRED_*` and update managed
IDs such as `PINGWAF-1001` to `WAFRED-1001`. WAFred does not read old paths,
database identifiers or managed rule IDs automatically.

## When to use the CLI

The web console is an HTTP client of the control plane on `:9080`. It stops
being an option when the control plane itself is the problem. The CLI keeps
working in exactly those situations:

- **The control plane is down** (crash loop, failed migration, wrong
  configuration) and you need to inspect or repair state.
- **The API IP allowlist locked you out** — every source address you can reach
  `:9080` from is refused.
- **You forgot the administrator password** and cannot sign in (or the
  registered e-mail is wrong).
- **You need to roll back a configuration change** and the console rollback
  cannot be reached to push it.

Run `wafred <command> --help` for the exact options of any subcommand. Plain
`wafred --help` answers with the `pingap`-compatible options of the shared
binary, not with this subcommand tree.

## Run modes

Three subcommands start a long-running process; they are what the systemd
unit's `ExecStart` invokes:

| Mode | Command | Role |
| --- | --- | --- |
| Control plane | `wafred server` | REST API + gRPC control plane + embedded dashboard. Does not proxy traffic. |
| Data plane | `wafred agent` | Connects to a remote control plane, enforces its rules, proxies traffic on :80/:443. |
| All-in-one | `wafred all-in-one` | Both of the above in one process (the agent talks to the local server over loopback). |

The mode can also be selected with the `WAFRED_MODE` environment variable
instead of a subcommand, and `wafred --version` (long banner) / `wafred -V`
(bare number) print the version and exit. A systemd install runs
`ExecStart=/usr/local/bin/wafred <mode>` (the mode `install.sh` was asked
for) with `WAFRED_CONFIG=/etc/wafred/wafred.toml` set in the unit;
`systemctl restart wafred` applies any configuration change, and
`journalctl -u wafred -e` shows the legacy-named service logs.

## Global options

`server` and `all-in-one` accept these options (the `agent` has its own set,
listed after the table). Every option also reads a `WAFRED_*` environment
variable.

| Option | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `--db-url` | `WAFRED_DB_URL` | `postgres://wafred:wafred@localhost:5432/wafred` | PostgreSQL connection string |
| `--admin-addr` | `WAFRED_ADMIN_ADDR` | `0.0.0.0:9080` | HTTP admin/API listen address |
| `--grpc-addr` | `WAFRED_GRPC_ADDR` | `0.0.0.0:9090` | gRPC listen (server/all-in-one) or connect (agent) address |
| `--grpc-tls-cert` | `WAFRED_GRPC_TLS_CERT` | — | PEM certificate chain for the gRPC control plane; agents then connect via `https://` |
| `--grpc-tls-key` | `WAFRED_GRPC_TLS_KEY` | — | PEM private key for `--grpc-tls-cert` |
| `--grpc-tls-mode` | `WAFRED_GRPC_TLS_MODE` | `tls` | `tls` serves the configured certificate or, absent one, the self-signed control-plane certificate; `off` serves plaintext (degraded) |
| `--tls-enabled` | `WAFRED_TLS_ENABLED` | `true` | Serve the dashboard and REST API over TLS; a self-signed certificate is generated on first boot. Set `false` behind a TLS-terminating proxy |
| `--tls-sans` | `WAFRED_TLS_SANS` | *(empty)* | Comma-separated SANs (DNS names and IP addresses) of the generated self-signed certificate |
| `--public-host` | `WAFRED_PUBLIC_HOST` | *(unset)* | Host (optionally with port) the dashboard is reached under; pinned into the HTTP→HTTPS redirect target instead of the client's `Host` header |
| `--config` | `WAFRED_CONFIG` | — | TOML configuration file; its `[server]` and `[agent]` tables hold the same settings |

Server-only options (`server` / `all-in-one`): `--jwt-secret`
(`WAFRED_JWT_SECRET`, default `change-me-in-production`, must be ≥ 16
characters), `--admin-email` (`WAFRED_ADMIN_EMAIL`, default
`admin@wafred.local`), `--admin-password` (`WAFRED_ADMIN_PASSWORD`, default
`wafred123`) and `--serve-frontend` (`WAFRED_SERVE_FRONTEND`, default
`true`).

Agent-only options (`agent` / the agent half of `all-in-one`): `--server-url`
(`WAFRED_SERVER_URL`, default `http://localhost:9090`), `--server-ca-cert`
(`WAFRED_SERVER_CA_CERT`), `--api-key` (`WAFRED_API_KEY`), `--cache-dir`
(`WAFRED_CACHE_DIR`, default `./data/cache`), `--fail-open`
(`WAFRED_FAIL_OPEN`, default `true`), `--heartbeat-interval-secs`
(`WAFRED_HEARTBEAT_INTERVAL`, default `30`), `--metrics-ship-interval`
(`WAFRED_METRICS_SHIP_INTERVAL`, default `30`), plus `--log-batch-size`,
`--log-flush-interval-secs` and `--max-body-log-size` (command line only).

### Configuration precedence

Settings are read from the TOML file first, then from the `WAFRED_*`
environment variables, then from the command line — a later channel overrides
an earlier one. An argument repeated on the command line wins over the value
injected from the file, so
`wafred all-in-one --config /etc/wafred/wafred.toml --tls-enabled false`
always disables TLS regardless of what the file says.

## Maintenance commands

All maintenance subcommands take `--db-url` (env `WAFRED_DB_URL`, default
`postgres://wafred:wafred@localhost:5432/wafred`), connect to PostgreSQL
directly, do their work and exit. A **running** control plane notices their
writes within a few seconds, but — unlike the console — the CLI does not push
anything to the agents; see the `config rollback` caveat below.

### `wafred user` — dashboard accounts

| Command | Purpose |
| --- | --- |
| `wafred user list` | List dashboard accounts. |
| `wafred user add-admin --email <addr> [--name <name>] [--password <pw>]` | Create an administrator account. When `--password` is omitted a random one is generated and **printed once**. |
| `wafred user reset-password --email <addr> [--password <pw>]` | Set a new password. An omitted password is generated and printed once. The reset bumps the account's token version, so every existing session of that account is revoked — a leaked session does not survive the reset. |

### `wafred mode` — observation mode

| Command | Purpose |
| --- | --- |
| `wafred mode status` | Print the current observation mode. |
| `wafred mode observe` | Turn observation mode on: every detection runs, nothing is blocked. |
| `wafred mode enforce` | Turn observation mode off: protections enforce again. |

Use `observe` while tuning rules on live traffic; switch back with `enforce`
once the false positives are handled. `mode status` tells you which of the two
is active without trusting anyone's memory.

### `wafred security` — control-plane self-protection

| Command | Purpose |
| --- | --- |
| `wafred security status` | Print the `:9080` protection settings and the effective allowlist. |
| `wafred security allowlist on\|off [--force]` | Turn the API IP allowlist on or off — the break-glass switch when the console is unreachable. |

```bash
wafred security allowlist on           # enable; refused while the list is empty
wafred security allowlist off          # disable
wafred security allowlist on --force   # enable even when empty — see the warning
```

> ⚠️ **`allowlist on --force` is a footgun.** `--force` enables the allowlist
> even when it is empty, and an empty allowlist **refuses every API caller** —
> the console, the dashboard and any scripting against `:9080` all get locked
> out, and you have to come back to this CLI (or the database) to undo it.
> Turn the allowlist on without `--force` first, and add your own addresses
> before relying on it.

### `wafred config` — configuration version history

```bash
wafred config history [--site <uuid|global>] [--limit <n>]   # newest first, default 20
wafred config show <version> [--json]                        # metadata + snapshot summary
wafred config rollback <version> [--yes]                     # prompts unless --yes
```

- `history` lists recorded versions newest first. `--site` filters to one
  site (its UUID) or to the deployment-wide settings (`global`); `--limit`
  caps how many are printed (default 20).
- `show` prints one version's metadata plus a snapshot summary, or the whole
  snapshot as JSON with `--json`.
- `rollback` restores a version and records the restore as a new version
  attributed to `cli`, so rolling back a rollback works and the history stays
  linear. It prompts for confirmation unless `--yes` is given.

> ⚠️ **A CLI rollback does not notify a running control plane.** It writes the
> rows directly to PostgreSQL; the agents pick the restored configuration up
> on their next full sync or restart. When the change has to reach the fleet
> immediately, use the console rollback (`POST /config-versions/{id}/rollback`,
> see [docs/api.md](./api.md)) — it pushes to the agents right away.

## Typical incident runbooks

### Forgot the administrator password

```bash
wafred user reset-password --email admin@wafred.local
# → prints a generated password once
wafred user reset-password --email admin@wafred.local --password 'S3cret-New-Pass'
```

All previous sessions of the account are revoked by the reset; sign in with
the new password and change it in the console afterwards if it was printed.

### Locked out by the API allowlist

```bash
wafred security status          # confirm the allowlist is what blocks you
wafred security allowlist off   # disable it, sign in, fix the list, re-enable
```

If the allowlist was enabled with `--force` while empty, `allowlist off` is
the only way back in short of editing the database directly.

### Temporarily stop blocking (observation mode)

```bash
wafred mode status
wafred mode observe    # detect everything, block nothing
wafred mode enforce    # restore enforcement
```

### Roll back a bad configuration change

```bash
wafred config history --limit 10          # find the version to restore
wafred config show 42                     # inspect it before restoring
wafred config rollback 42                 # prompts; --yes skips the prompt
sudo systemctl restart wafred             # make the running process pick it up now
```

Remember that the CLI rollback reaches agents only on their next full sync or
restart; restarting the service (or using the console rollback when reachable)
propagates it immediately.

### Service will not start or logs look wrong

```bash
journalctl -u wafred -e       # last log lines of the legacy-named unit
systemctl status wafred
```

### Binding 80/443 fails with "Permission denied"

The unit runs as the unprivileged `wafred` user; binding privileged ports
works only while the unit carries `CAP_NET_BIND_SERVICE`. Check it:

```bash
systemctl show wafred -p AmbientCapabilities
# AmbientCapabilities=CAP_NET_BIND_SERVICE
```

If the line is empty (a unit installed by an older `install.sh` run), follow
the `systemctl edit wafred` drop-in snippet the installer prints on upgrade —
see the [upgrade section of the deployment guide](./deployment.md#upgrade-procedure).

## Differences from the web console

| Aspect | CLI | Web console |
| --- | --- | --- |
| How it changes state | Writes directly to PostgreSQL | REST API on `:9080`, subject to the allowlist |
| Control plane down | Keeps working | Unavailable |
| Agents | Does not push anything; agents sync later | Pushes immediately (e.g. console rollback) |
| Authentication | Database credentials (`--db-url`) | Dashboard session / JWT |
| Scope | Single-instance maintenance | Full fleet management |

The two are complementary: manage the fleet through the console, and keep this
CLI for the moments the console is the thing that broke.
