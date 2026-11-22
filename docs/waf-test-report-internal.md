# WAFred 1.0.4 Internal Test Notes

This run continues the earlier PingWAF-version test corpus and sample-triage approach. The figures below describe the locally rebuilt WAFred 1.0.4 candidate tested on 2026-11-22, SHA-256: 93b4b6e92e39eb3417dabec510945fe847667660ffad0493c1a3f31d50fc9796.

## Current full-corpus result

Strict + body inspection intercepted 632/658 malicious samples (96.05%) and affected 19/33,219 benign samples (0.057%). The 19 benign outcomes consist of 17 blocks and 2 challenges. The other profiles and methodology are in the [public report](./waf-test-report.md) and [full lab report](./wafred-baseline-test-report-2026-11-22.md).

## Miss attribution

The largest apparent miss source was fixture framing. Several body-bearing samples omitted both Content-Length and Transfer-Encoding; the old replay sent their bytes, but HTTP/1.1 did not deliver them as a request body. The corrected replayer adds the exact body length for those fixtures. For a single valid Content-Length, it drops bytes beyond the declared body. Duplicate or invalid lengths and Transfer-Encoding fixtures remain unchanged for protocol testing.

Fifteen benign fixtures also contained extra bytes after their valid declared length and previously produced proxy HTTP 500 responses. Correct framing removed those 500s from all four profiles.

The candidate adds bounded inspection for untyped URL-encoded and multipart bodies, Base64 decoding of individual path segments, and Strict-only high-severity alert.call and prompt.call signatures.

## Pinned regression sets

| Set | Candidate result | Meaning |
|---|---|---|
| 20 pinned prior misses | 1 blocked, 18 passed, 1 method-layer 405 | The 405 is outside the WAF verdict path |
| 27 pinned benign samples | 17 blocked, 2 challenged, 8 passed | Matches the affected benign samples in the full Strict + body run |
| 8 compressed attacks | Normal 0/8, Normal + body 7/8, Strict 0/8, Strict + body 8/8 | Both benign compressed controls passed at every tier |

The remaining Strict + body outcomes among malicious samples include 23 passed requests, 2 parser-level 400 rejections and 1 method-layer 405. Passed cases are concentrated in multi-layer encoding, application-specific probes, long or truncated URIs and low-evidence payloads.

## HTTPS and capacity notes

The isolated HTTPS listener used a self-signed certificate trusted explicitly with curl --cacert. TLS 1.2 and TLS 1.3 SNI handshakes verified successfully. Benign HTTP and HTTPS returned 200; the targeted HTTPS form and Base64-path probes returned 403. A client without the test CA rejected the certificate.

The 256-concurrency three-minute soak (5,172 RPS, 931,266 2 KiB POSTs, no errors) and the 512-concurrency file-descriptor findings were measured on the original deployed binary. They are not candidate high-concurrency measurements. The candidate was not deployed to the production all-in-one process.

## Verification

- Python replay framing tests: 4/4 passed.
- Rust WAF suite: 271/271 passed.
- Rust formatting check: passed.
- Site content, build and internal-link verification: passed.
- The site content checker emitted non-blocking localization/style warnings.

See the [full report](./wafred-baseline-test-report-2026-11-22.md) for exact TLS versions, residual cases, archive checksums and machine roles.