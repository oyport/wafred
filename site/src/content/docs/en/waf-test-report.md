---
title: WAFred 1.0.4 test report
description: Corrected WAFred full-corpus results, missed-request fixes, self-signed HTTPS checks, and historical firewall references.
minutes: 5
---

## Results at a glance

Tested on 2026-11-22 using a locally rebuilt WAFred 1.0.4 candidate and the public chaitin/blazehttp corpus: 33,877 HTTP requests (658 malicious, 33,219 benign). Blocks and challenges count as interceptions; both count as benign traffic affected.

| Tier | Malicious intercepted | Benign affected | Replay p50 / p95 | HTTP 500 |
|---|---:|---:|---:|---:|
| Normal | 397/658 (60.33%) | 4/33,219 (0.012%) | 43 / 48 ms | 0 |
| Normal + body inspection | 494/658 (75.08%) | 12/33,219 (0.036%) | 43 / 48 ms | 0 |
| Strict | 501/658 (76.14%; 491 blocks, 10 challenges) | 4/33,219 (0.012%) | 43 / 48 ms | 0 |
| Strict + body inspection | **632/658 (96.05%; 622 blocks, 10 challenges)** | **19/33,219 (0.057%)** | 43 / 48 ms | 0 |

## Missed requests and fixes

The original replayer sent fixtures unchanged. Requests with a body but no `Content-Length` or `Transfer-Encoding` therefore reached the server as bodyless requests, understating body inspection. The harness now adds an accurate body length and trims bytes after one valid declared length. This also fixed 15 malformed benign fixtures that had produced HTTP 500 during proxying; all four final profiles report zero HTTP 500s.

WAFred now recognizes bounded form-urlencoded and multipart bodies when `Content-Type` is absent, scans bounded Base64 path segments, and adds two Strict-only `alert.call` / `prompt.call` signatures. The Strict + body tier intercepted 632/658 attacks. Nineteen benign requests were blocked or challenged (17 blocks, 2 challenges), so review those pinned samples before enabling the tier.

## Cross-vendor reference

The chart pairs the current WAFred 1.0.4 measurements with the final earlier WAFred-version run (P13), and retains historical SafeLine, ModSecurity and Cloudflare references. The prior run used the same nominal corpus but an earlier body-framing path; the current harness corrected 15 framing-related HTTP 500 responses. These are recorded version results, not a controlled before/after experiment. Third-party products were not retested. WAFred p95 includes the VM, proxy and mock origin, so latency values from different paths are not directly comparable.

## Compressed bodies and TLS

The gzip suite intercepted 0/8 attacks without body inspection, 7/8 with Normal + body inspection and 8/8 with Strict + body inspection; both benign requests passed in every tier.

An isolated HTTPS listener used a self-signed certificate for `wafred-test.local` and `127.0.0.1`. Explicit `curl --cacert` validation passed; the default curl trust store rejected the certificate as expected. OpenSSL SNI handshakes succeeded with TLS 1.2 and TLS 1.3. Benign HTTP and HTTPS returned 200; targeted form and Base64-path attacks over HTTPS returned 403. TLS terminated at WAFred; the mock origin used HTTP.

## Capacity and scope

The separate 256-concurrency, three-minute soak and 512-concurrency file-descriptor findings were measured on the original deployed WAFred binary, not this patched candidate. The original process hit its soft `nofile=1,024` limit at 512 concurrency; an isolated copy at 65,536 had no 502s. The active all-in-one process was not changed.

The security matrix uses an isolated HTTP/1.1 proxy and mock origin. Real application upstreams, HTTP/2/HTTP/3, production routing, rate limiting/CC and a candidate-binary high-concurrency soak remain open. See the [full test report](https://github.com/oyport/wafred/blob/main/docs/wafred-baseline-test-report-2026-11-22.md) for raw-result location, detailed miss attribution and VM setup. This run continues the earlier WAFred test corpus and analysis path; the benchmark appendix presents that context with the current WAFred measurements: [benchmark appendix](https://github.com/oyport/wafred/blob/main/docs/waf-benchmark-report.md).
