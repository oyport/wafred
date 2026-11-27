# WAFred 1.0.4 WAF Test Plan

This plan continues the earlier PingWAF-version test corpus and analysis workflow. It records the current WAFred 1.0.4 candidate test setup and the next validation work.

- Test date: 2026-11-22
- Candidate SHA-256: 93b4b6e92e39eb3417dabec510945fe847667660ffad0493c1a3f31d50fc9796
- Dataset: chaitin/blazehttp, commit afc88a94d03db1cd52156c34c3c9c58053c9f658; 33,877 requests, 658 malicious and 33,219 benign
- Environment: five Debian 13 VMs; isolated WAF, mock origin, two load generators and results collector
- Current results: [WAF test report](waf-test-report.md), [full lab report](wafred-baseline-test-report-2026-11-22.md), [benchmark summary and prior-version context](waf-benchmark-report.md)

## Test matrix

| Profile | Malicious intercepted | Benign affected | Replay p50 / p95 | HTTP 500 |
|---|---:|---:|---:|---:|
| Normal | 397/658 (60.33%) | 4/33,219 (0.012%) | 43 / 48 ms | 0 |
| Normal + body | 494/658 (75.08%) | 12/33,219 (0.036%) | 43 / 48 ms | 0 |
| Strict | 501/658 (76.14%) | 4/33,219 (0.012%) | 43 / 48 ms | 0 |
| Strict + body | 632/658 (96.05%) | 19/33,219 (0.057%) | 43 / 48 ms | 0 |

A WAF block (403) or challenge (503) counts as intercepted. The same responses on benign traffic count as affected benign requests. Parser and method responses (400/405), replay errors and 5xx are tracked separately.

## Repeatable checks

- Replayer framing tests: python tools/waf-bench/test_replay.py
- Rust WAF tests: cargo test -p pingwaf-waf
- Formatting: cargo fmt --all -- --check
- Site content, build and internal links: run npm run verify from site/

For full-corpus runs, use the profile files under tools/waf-bench/conf with run_suite.sh and record the exact candidate binary hash, configuration, corpus commit, concurrency, delay and result directory.

The replay harness sends one request per connection. It adds byte-accurate Content-Length when a nonempty body lacks Content-Length and Transfer-Encoding, truncates bytes after a single valid Content-Length, and preserves ambiguous/invalid framing cases for protocol-level testing.

## HTTPS and capacity scope

The isolated candidate passed self-signed HTTPS tests using explicit CA trust. TLS 1.2 and TLS 1.3 handshakes verified; benign HTTP/HTTPS returned 200, targeted HTTPS probes returned 403, and an untrusted client rejected the certificate. The upstream mock origin used HTTP.

The high-concurrency soak and descriptor-limit observations were collected on the original deployed binary, not the patched candidate. Candidate high-concurrency capacity remains a follow-up. HTTP/2, HTTP/3, upstream TLS, production routing, agent-connected behavior, rate limiting and real application origins are also outside this run.

## Acceptance and reporting

Report intercepted attacks, affected benign traffic, replay errors, protocol/method rejects and 5xx separately for each profile. Compare candidate and baseline by sample path under identical framing; record gained/lost detections and benign verdict changes. Keep third-party values labeled as historical references when corpus denominators or network paths differ.