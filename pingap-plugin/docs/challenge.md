# challenge

CC protection / "5-second shield". Intercepts requests that look automated or
excessive, serves a JavaScript challenge page, and grants a signed clearance
cookie to visitors that solve it.

- **Step:** `early_request` (default) or `request` — configurable
- **Registered as:** `challenge`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `challenge`. |
| `enabled` | bool | `true` | Master switch. An added challenge plugin is active unless explicitly disabled. |
| `under_attack_mode` | bool | `false` | When `true`, challenge **every** request regardless of rate. |
| `clearance_duration_secs` | int | `1800` | Lifetime of the clearance cookie (seconds). |
| `rate_threshold` | int | `100` | Requests per 60-second window above which a visitor is challenged. |
| `pow_difficulty` | int | `20` | Base proof-of-work difficulty (leading zero bits). Higher = harder for bots, slower for users. |
| `pow_max_difficulty` | int | `24` | Ceiling adaptive difficulty may raise the work to for a host+IP under pressure. Clamped up to `pow_difficulty`. |
| `pow_issue_limit_per_min` | int | `120` | Challenge pages issued per host+IP per 60-second window, shared with the WAF plugin's rule/access/rate-limit challenges. Over it the visitor gets a `429` rate-limit page. |
| `pow_verify_limit_per_min` | int | `300` | Solution submissions accepted per host+IP per 60-second window. Over it verification fails closed without spending the pending nonce. |
| `cookie_secret` | string | *(generated)* | HMAC key used to sign clearance cookies. Leave it unset (or set to the legacy `change-me`) and the process generates a random key instead — set it explicitly only if the secret must survive restarts. |
| `cookie_name` | string | `__pingwaf_clearance` | Name of the clearance cookie. |
| `exempt_paths` | string[] | `[]` | Paths that bypass the challenge (health checks, APIs). |
| `exempt_user_agents` | string[] | `[]` | User-agent substrings that bypass the challenge. |
| `browser_integrity_check` | bool | `true` | Validate browser fingerprint consistency during verification. |
| `submission_max_age_secs` | int | `300` | Maximum age of a valid challenge submission (seconds). |
| `step` | string | `early_request` | `early_request` or `request`. Any other value is a configuration error. |

## Request flow

1. **Verify endpoint** — if the path is `/_pingwaf/challenge/verify` and method
   is `POST`, the plugin parses the proof-of-work submission, validates it, and
   either sets the clearance cookie and returns a redirect to the original URL,
   or returns a `403` block page.
2. **Clearance cookie** — if the request carries a valid, unexpired clearance
   cookie issued for the same site and at a sufficient challenge level, the
   request passes immediately without further checks. A cookie issued by
   another site is ignored even when the signature verifies: the cookie
   secret is per process, so without the site check one solved challenge
   would clear every site served by that process.
3. **Rate tracking** — the per-IP request count in the current 60-second window
   is recorded and fed to the challenge engine.
4. **Engine decision:**

| Decision | Result |
| --- | --- |
| `Pass` | `Continue` — request proceeds. |
| `JsChallenge` | `503` JavaScript challenge page (auto-solve). |
| `ManagedChallenge` | `503` managed challenge page (combined JS + fingerprint). |
| `InteractiveChallenge` | `503` interactive challenge page (user action). |
| `Block` | `403` hard block page. |

## Adaptive difficulty and per-IP limits

Every challenge carries its own difficulty. The page states it, the edge
records it with the pending challenge, and the verifier checks the submission
against **that** value — never against the plugin's current setting, and never
against anything the client sent.

The difficulty starts at `pow_difficulty` and rises per host+IP with:

* **verification failures** — one step per failed submission (a wrong proof, a
  mismatched User-Agent/fingerprint, or a submission from another address),
  forgotten one step per minute without a new failure;
* **request volume** — one step for each `rate_threshold`-worth of requests
  above the threshold (at most four steps).

It is capped at `pow_max_difficulty`, and a successful verification resets the
record to the base. The state is per process, keyed by host + client address
and bounded: past the table ceiling new clients keep the base difficulty
rather than the table growing with an attacker's address space.

Two per-host+IP budgets sit next to it, both on a fixed 60-second window:

| Budget | Over the limit |
| --- | --- |
| `pow_issue_limit_per_min` challenge pages | `429` rate-limit page (`x-pingwaf-mitigated: block`, `Retry-After`), and the request is logged as mitigated. The page is never minted, so the challenge loop cannot be used as an amplifier. |
| `pow_verify_limit_per_min` submissions | `429` rate-limit page, also logged as mitigated. The check runs **before** any verification work, so an over-limit flood cannot spend a legitimate visitor's nonce. |

Both counters are per process: behind N edge instances the effective allowance
is N × the configured value. Set `pow_max_difficulty = pow_difficulty` to pin
the difficulty, or raise the limits for sites whose visitors share one NAT
address.

The two budgets differ deliberately when their table is full of *other* clients
(the bounded table is 8192 keys per window):

* **issuance keeps working** — the page is minted without a budget entry. A
  many-source flood must not turn the burst guard into an outage for every new
  visitor;
* **verification fails closed** — a full table must not become an unmetered
  guessing channel. The pending challenge is left intact, so the visitor can
  retry once the window rolls over.

## Examples

Standard CC protection:

```toml
[plugins.ccShield]
category = "challenge"
rate_threshold = 60
clearance_duration_secs = 3600
cookie_secret = "my-production-secret-key"
exempt_paths = ["/health", "/api/internal"]
```

Under-attack mode (challenge everyone):

```toml
[plugins.underAttack]
category = "challenge"
under_attack_mode = true
pow_difficulty = 22
cookie_secret = "my-production-secret-key"

[locations.site]
upstream = "backend"
path = "/"
plugins = ["underAttack"]
```

## Interaction with the WAF plugin

The [`waf`](waf.md) plugin may answer with a `Challenge` verdict (a rule match,
an IP/geo access rule, bot protection or a rate-limit rule). Every such page is
minted through the same guarded path as this plugin's CC gate, so:

* it carries the **site's** `base_difficulty`/`max_difficulty` and adaptive
  pressure, not a static plugin value;
* it costs the same per-host+IP `pow_issue_limit_per_min` budget, so a rule
  challenge cannot be used to bypass the limit;
* the difficulty it states is recorded with the pending entry and is the value
  the verify endpoint checks.

The WAF plugin's own `pow_difficulty`/`pow_max_difficulty`/
`pow_issue_limit_per_min` only apply when the site carries no challenge settings
(standalone mode). Both plugins share the verify endpoint and the pending store,
so keep `cookie_secret` **consistent** across the two plugins to ensure
challenges issued by the WAF can be verified here.

## Usage notes

- Set `cookie_secret` to a long random value if the clearance cookies must stay
  valid across restarts. When it is unset (or left at the legacy `change-me`),
  the process generates a random secret at startup and logs a warning, so
  cookies are invalidated by a restart but are never signed with a public key.
- `exempt_paths` is a prefix match: `/api` exempts `/api`, `/api/v1`, etc.
- Per-IP rate counters are per-process. Behind a load balancer with N instances
  the effective threshold is N × `rate_threshold`.
- Challenge pages include a `Cache-Control: no-store` header so proxies never
  cache them.
- The verify endpoint body limit is 64 KiB; larger submissions are rejected.
