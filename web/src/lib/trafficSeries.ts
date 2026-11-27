import type { GeoCountryStat, TimeBucket, TrafficBucket } from '@/api/types'

/**
 * Joins the two traffic series the page receives from two different endpoints
 * onto one bucket grid.
 *
 * `/analytics/requests-over-time` buckets with `date_trunc(interval)` (minute /
 * hour / day) while `/analytics/traffic` buckets egress bytes at a fixed width
 * (`step` seconds, 5 s … 1 h). The widths differ — a 24 h range yields hourly
 * request buckets and 5-minute egress buckets — so a row-by-row `zip` would
 * either truncate the finer series or silently drop buckets when one of the two
 * has a gap (both queries only return buckets that contain rows).
 *
 * This therefore builds the union of the request grid and the egress buckets
 * snapped onto it, summing egress bytes per request bucket and converting them
 * to the mean bit rate over that bucket. Nothing is dropped: an hour with
 * egress but no requests still renders, with `requests: 0`, and vice versa.
 */
export interface MergedTrafficPoint {
  /** Bucket start as an ISO-8601 string (UTC) — the join key. */
  bucket: string
  requests: number
  passed: number
  blocked: number
  /** Mean outbound bit rate over the bucket, bits per second. */
  bps: number
}

export interface EgressSeriesInput {
  buckets: TrafficBucket[]
  step_seconds: number
}

/** Bucket width (ms) of the request series for a preset range, in hours. */
export function requestBucketMs(rangeHours: number): number {
  if (rangeHours <= 2) return 60_000
  if (rangeHours <= 72) return 3_600_000
  return 86_400_000
}

/**
 * Merges requests and egress into one aligned series, ascending by bucket.
 *
 * `bucketMs` is the width the request series is expected to use
 * (`requestBucketMs`). It is only a fallback: the real bucket width is derived
 * from the returned request timestamps, and each egress bucket is assigned to
 * the request bucket that actually contains it. That keeps the join correct
 * even when `date_trunc` is not UTC-aligned (a database session in another
 * time zone truncates `day` buckets at its own midnight) and when the two
 * series have gaps.
 *
 * An egress bucket that falls outside every request bucket — the window starts
 * before the first request row, or a gap in the request series — keeps its own
 * timestamp and native width instead of being folded into a neighbour, so no
 * bytes are lost and no rate is understated.
 */
export function mergeTrafficSeries(
  series: TimeBucket[],
  egress: EgressSeriesInput | undefined,
  bucketMs: number,
): MergedTrafficPoint[] {
  const rows = new Map<number, MergedTrafficPoint>()

  const ensure = (ms: number): MergedTrafficPoint => {
    const existing = rows.get(ms)
    if (existing) return existing
    const row: MergedTrafficPoint = {
      bucket: new Date(ms).toISOString(),
      requests: 0,
      passed: 0,
      blocked: 0,
      bps: 0,
    }
    rows.set(ms, row)
    return row
  }

  const starts: number[] = []
  for (const bucket of series) {
    const ms = Date.parse(bucket.bucket)
    if (!Number.isFinite(ms)) continue
    starts.push(ms)
    const row = ensure(ms)
    row.requests += bucket.requests
    row.blocked += bucket.blocked
    row.passed += Math.max(0, bucket.requests - bucket.blocked)
  }
  starts.sort((a, b) => a - b)
  const width = detectBucketMs(starts, bucketMs)

  if (egress) {
    const egressStepMs =
      egress.step_seconds > 0 ? egress.step_seconds * 1000 : width
    const bytesByRow = new Map<number, number>()
    const rowWidth = new Map<number, number>()
    for (const bucket of egress.buckets) {
      const ms = Date.parse(bucket.bucket)
      if (!Number.isFinite(ms)) continue
      const start = latestAtOrBefore(starts, ms)
      const contained = start !== null && ms - start < width
      const key = contained ? start : ms
      bytesByRow.set(
        key,
        (bytesByRow.get(key) ?? 0) + Math.max(0, bucket.bytes),
      )
      if (!rowWidth.has(key)) rowWidth.set(key, contained ? width : egressStepMs)
    }
    for (const [key, bytes] of bytesByRow) {
      const seconds = (rowWidth.get(key) ?? width) / 1000
      if (seconds <= 0) continue
      ensure(key).bps = (bytes * 8) / seconds
    }
  }

  return [...rows.entries()]
    .sort(([a], [b]) => a - b)
    .map(([, row]) => row)
}

/**
 * Bucket width implied by the request timestamps: the smallest positive gap
 * between adjacent buckets. Gaps in the series only widen a difference, so the
 * minimum is the true width whenever two adjacent buckets exist; otherwise the
 * caller's expected width is used.
 */
function detectBucketMs(starts: number[], fallback: number): number {
  const expected = fallback > 0 ? fallback : 60_000
  let min = Number.POSITIVE_INFINITY
  for (let i = 1; i < starts.length; i += 1) {
    const gap = starts[i] - starts[i - 1]
    if (gap > 0 && gap < min) min = gap
  }
  return Number.isFinite(min) ? min : expected
}

/** Index of the last element `<= value`, or null when all are greater. */
function latestAtOrBefore(sorted: number[], value: number): number | null {
  let low = 0
  let high = sorted.length - 1
  let found: number | null = null
  while (low <= high) {
    const mid = (low + high) >> 1
    if (sorted[mid] <= value) {
      found = sorted[mid]
      low = mid + 1
    } else {
      high = mid - 1
    }
  }
  return found
}

/** One row of the country breakdown next to the globe. */
export interface CountryTrafficRow {
  /** ISO 3166-1 alpha-2, upper-cased. */
  code: string
  requests: number
  /** Share of the countries in this list (0…1). */
  share: number
}

/**
 * Normalises the country stats for the list: drops unresolved/empty codes,
 * folds duplicate codes, sorts by requests descending and computes the share
 * of the listed set.
 *
 * The endpoints return a bounded top-N (site: 20, fleet: up to 250), so the
 * share denominator is that list, not the site's whole traffic — the column is
 * labelled accordingly.
 */
export function countryTrafficRows(
  stats: GeoCountryStat[],
): CountryTrafficRow[] {
  const totals = new Map<string, number>()
  for (const row of stats) {
    const code = (row.country_code ?? '').trim().toUpperCase()
    if (!code) continue
    if (!Number.isFinite(row.requests) || row.requests <= 0) continue
    totals.set(code, (totals.get(code) ?? 0) + row.requests)
  }
  let total = 0
  for (const requests of totals.values()) total += requests
  return [...totals.entries()]
    .map(([code, requests]) => ({
      code,
      requests,
      share: total > 0 ? requests / total : 0,
    }))
    .sort((a, b) => b.requests - a.requests || a.code.localeCompare(b.code))
}