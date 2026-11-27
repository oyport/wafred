> This is an earlier test run associated with the PingWAF 0.32.4 baseline. For WAFred 1.0.4 results with corrected request framing and the side-by-side P13 comparison, see [the full report](../../../docs/wafred-baseline-test-report-2026-11-22.md) and [the benchmark report](../../../docs/waf-benchmark-report.md).

# waf-bench summary

## Overall (per group)

`blocked` = HTTP 403 block page; `challenged` = HTTP 503 challenge page; `intercepted` = blocked + challenged.

| group | total | black | white | black blocked | black challenged | intercept rate | white blocked | white challenged | FP rate (blocked) | FP rate (intercepted) | p50 ms | p95 ms | error % | status_405 | status_500 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| compressed-strict-body | 10 | 8 | 2 | 8 | 0 | 100.0% | 0 | 0 | 0.00% | 0.00% | 1 | 3 | 0.00% | 0 | 0 |

## compressed-strict-body: black samples by category

| category | n | blocked | challenged | intercepted | +reject/error | intercept rate |
|---|---|---|---|---|---|---|
| other | 8 | 8 | 0 | 8 | 0 | 100.0% |

## compressed-strict-body: white false positives by category

| category | n | blocked | challenged | FP rate (intercepted) | examples |
|---|---|---|---|---|---|

## compressed-strict-body: missed black samples (passed) by category

| category | missed | example files |
|---|---|---|
