---
title: Security
description: How to report a vulnerability privately, which versions receive security fixes, and the hardening steps to take before exposing WAFred to the internet.
minutes: 8
---

## Reporting a vulnerability

WAFred sits in the request path of the applications it protects, so a
vulnerability in it matters as much as one in the sites behind it. Please
report privately — never in a public issue, discussion or pull request.

- **GitHub private vulnerability reporting (preferred):**
  [Report a vulnerability](https://github.com/shuaiZend/WAFred/security/advisories/new)
  — private, tracked, and the fastest route to a fix.
- **Email:** `security@waf.red`, monitored by at least two maintainers. A
  PGP key is being published; until its fingerprint is listed here, send a
  plain-text summary first and we will reply with a key.

Include the affected version, run mode (`all-in-one`, `server`, `agent`), TLS
backend, reproduction steps and attack prerequisites, and redact tokens and
passwords. We acknowledge within three business days, keep you updated weekly
while a fix is developed, and coordinate disclosure after the fix ships (or at
90 days, whichever comes first). The full policy is in
[SECURITY.md](https://github.com/shuaiZend/WAFred/blob/main/SECURITY.md).

## Supported versions

| Version | Status | Security fixes |
| --- | --- | --- |
| `0.32.x` (current line) | Supported | Yes |
| `0.31.x` | Critical fixes only | On request, best effort |
| `0.30.x` and older | End of life | No |

Only the current release line is guaranteed to receive security patches;
security fixes ship in patch releases and are listed under `### Security` in
the [changelog](https://github.com/shuaiZend/WAFred/blob/main/CHANGELOG.md).

## Hardening before exposure

The console ships with development-friendly defaults. Before exposing an
instance to a network you do not control:

1. **Credentials** — change the seeded administrator password, set
   `WAFRED_JWT_SECRET` and `WAFRED_SECRET_KEY` to 32 random bytes each, close
   self-service registration (`WAFRED_ALLOW_REGISTRATION=false`), and move the
   PostgreSQL password away from the default.
2. **Network** — bind the console (`9080`) to loopback or a private interface
   and reach it through a VPN or reverse proxy; expose the gRPC port (`9090`)
   only to agent hosts; never expose PostgreSQL (`5432`).
3. **TLS** — upload a real certificate for the console or terminate TLS in
   front of it; enable HTTPS and HSTS on every site; keep gRPC TLS on.
4. **Secrets at rest** — `WAFRED_SECRET_KEY` seals notification-channel
   secrets, the AI provider key and backup-target credentials. Without it those
   fields are stored in clear text. Back the key up separately; there is no
   online rotation yet.
5. **Logs** — access logs keep request/response headers verbatim (including
   `Authorization`, `Cookie` and `Set-Cookie`) and up to 8 KiB of each body, for
   180 days by default. Treat PostgreSQL and Elasticsearch as credential
   stores and shorten retention where possible.
6. **MCP and AI** — a `write` MCP key is a fleet-wide administrator
   credential; a `read` key only sees its owner's sites. The built-in AI
   assistant sends tool results (sites, logs, WAF events, audit entries) to the
   provider you configure, so enable it only where that data may leave the
   deployment.

The complete checklist — with the exact environment variables, backup steps and
rotation caveats — is in
[SECURITY.md](https://github.com/shuaiZend/WAFred/blob/main/SECURITY.md#hardening-checklist)
and [docs/deployment.md](https://github.com/shuaiZend/WAFred/blob/main/docs/deployment.md).