# WAFred 1.0.4 WAF Test Report

- Test date: 2026-11-22; locally rebuilt test candidate SHA-256 `93b4b6e92e39eb3417dabec510945fe847667660ffad0493c1a3f31d50fc9796`
- Corpus: [chaitin/blazehttp](https://github.com/chaitin/blazehttp), commit `afc88a94d03db1cd52156c34c3c9c58053c9f658` — 33,877 requests (658 malicious / 33,219 benign)
- Environment: five Debian 13 VMs; isolated WAF, mock origin, two load generators and results collector

This run continues the earlier PingWAF-version test corpus and analysis approach, now measured against WAFred 1.0.4. The following tables record this WAFred run. Blocks and challenges count as interceptions; both count as benign traffic affected. The running all-in-one deployment was left untouched.

| Tier | Malicious intercepted | Benign affected | Replay p50 / p95 | HTTP 500 |
|---|---:|---:|---:|---:|
| Normal | 397/658 (60.33%) | 4/33,219 (0.012%) | 43 / 48 ms | 0 |
| Normal + body inspection | 494/658 (75.08%) | 12/33,219 (0.036%) | 43 / 48 ms | 0 |
| Strict | 501/658 (76.14%; 491 blocks, 10 challenges) | 4/33,219 (0.012%) | 43 / 48 ms | 0 |
| Strict + body inspection | **632/658 (96.05%; 622 blocks, 10 challenges)** | **19/33,219 (0.057%)** | 43 / 48 ms | 0 |

## Cross-vendor reference

| Product / mode | Malicious set | Intercepted | Benign set | Affected | Reported p95 |
|---|---:|---:|---:|---:|---:|
| WAFred Normal | 658 | 397 (60.33%) | 33,219 | 4 (0.012%) | 48 ms* |
| WAFred Normal + body | 658 | 494 (75.08%) | 33,219 | 12 (0.036%) | 48 ms* |
| WAFred Strict | 658 | 501 (76.14%) | 33,219 | 4 (0.012%) | 48 ms* |
| WAFred Strict + body | 658 | **632 (96.05%)** | 33,219 | **19 (0.057%)** | 48 ms* |
| PingWAF prior P13 · Normal | 658 | 396 (60.2%) | 33,219 | 5 (0.015%) | 5 ms‡ |
| PingWAF prior P13 · Normal + body | 658 | 473 (71.9%) | 33,219 | 14 (0.042%) | ~3 s‡ |
| PingWAF prior P13 · Strict | 658 | 500 (76.0%) | 33,219 | 5 (0.015%) | 4 ms‡ |
| PingWAF prior P13 · Strict + body | 658 | 617 (93.8%) | 33,219 | 21 (0.063%) | ~3 s‡ |
| SafeLine free · strict | 575 | 438 (76.17%) | 33,094 | 73 (0.22%) | 64.34 ms† |
| SafeLine free · balanced | 575 | 412 (71.65%) | 33,094 | 23 (0.07%) | 70.05 ms† |
| ModSecurity PL4 | 575 | 544 (94.61%) | 33,094 | 17,362 (52.46%) | 28.89 ms† |
| ModSecurity PL1 | 575 | 401 (69.74%) | 33,094 | 5,819 (17.58%) | 31.15 ms† |
| Cloudflare free | 570 | 61 (10.70%) | 32,780 | 23 (0.07%) | 288.96 ms† |

The PingWAF prior P13 rows are from an earlier version run on the same nominal corpus; the old replay framing was incomplete and produced 15 framing-related HTTP 500 responses. WAFred uses the corrected framing in this run, so these are recorded version results rather than a controlled before/after experiment. SafeLine, ModSecurity and Cloudflare are historical values from the [blazehttp benchmark](https://github.com/chaitin/blazehttp); they were not retested and their denominators differ. *WAFred p95 includes the VM, proxy and mock origin. †Other reported p95 values use different paths and are not directly comparable. ‡PingWAF p95 came from its earlier replay environment; body-tier p95 includes client upload effects.

The corpus replayer now adds an accurate `Content-Length` for body-bearing requests missing framing headers and trims surplus bytes beyond one valid length. This corrected 15 malformed fixtures that had produced proxy HTTP 500s; all four full-corpus profiles now have zero HTTP 500s. WAFred request normalization now detects untyped URL-encoded/multipart fields and Base64 path segments. Strict mode adds two high-confidence `alert.call`/`prompt.call` signatures.

The candidate's self-signed HTTPS test passed with explicit `curl --cacert` trust and OpenSSL TLS 1.2/1.3 SNI handshakes. Untrusted curl rejected the self-signed certificate as expected. Benign HTTP/HTTPS both returned 200; the targeted form and Base64-path attacks over HTTPS returned 403. The upstream mock origin used HTTP.

The separate 256-concurrency, three-minute soak and 512-concurrency file-descriptor findings were measured on the original deployed binary, not the patched candidate. See the [full test report](./wafred-baseline-test-report-2026-11-22.md) for the fix attribution, remaining misses, detailed TLS scope and capacity data. The [benchmark appendix](./waf-benchmark-report.md) shows the earlier PingWAF P13 measurements alongside the current WAFred results.
