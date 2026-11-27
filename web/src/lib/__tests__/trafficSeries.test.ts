import { describe, expect, it } from 'vitest'
import {
  countryTrafficRows,
  mergeTrafficSeries,
  requestBucketMs,
} from '../trafficSeries'
import type { TimeBucket, TrafficBucket } from '@/api/types'

function requestBucket(bucket: string, requests: number, blocked = 0): TimeBucket {
  return {
    bucket,
    requests,
    cache_hits: 0,
    cache_saved_bytes: 0,
    client_errors: 0,
    server_errors: 0,
    avg_latency_ms: 0,
    p50_latency_ms: 0,
    p90_latency_ms: 0,
    p99_latency_ms: 0,
    blocked,
  }
}

function egressBucket(bucket: string, bytes: number): TrafficBucket {
  return { bucket, bytes }
}

describe('requestBucketMs', () => {
  it('matches the interval the analytics endpoint truncates to', () => {
    // `rangeQueryFor` asks for minute buckets up to 2 h, hour buckets up to
    // 72 h and day buckets beyond that.
    expect(requestBucketMs(1)).toBe(60_000)
    expect(requestBucketMs(6)).toBe(3_600_000)
    expect(requestBucketMs(24)).toBe(3_600_000)
    expect(requestBucketMs(168)).toBe(86_400_000)
    expect(requestBucketMs(720)).toBe(86_400_000)
  })
})

describe('mergeTrafficSeries', () => {
  it('sums finer egress buckets into the request bucket they fall in', () => {
    // 24 h range: hourly request buckets, 5-minute egress buckets.
    const series = [
      requestBucket('2026-11-22T10:00:00Z', 120, 20),
      requestBucket('2026-11-22T11:00:00Z', 60, 0),
    ]
    const egress = {
      step_seconds: 300,
      buckets: [
        egressBucket('2026-11-22T10:00:00Z', 300),
        egressBucket('2026-11-22T10:05:00Z', 300),
        // Only one of the two 5-minute buckets in the 11:00 hour has traffic;
        // the hour is still emitted with the bytes it did record.
        egressBucket('2026-11-22T11:30:00Z', 450),
      ],
    }

    const merged = mergeTrafficSeries(series, egress, requestBucketMs(24))

    expect(merged.map((p) => p.bucket)).toEqual([
      '2026-11-22T10:00:00.000Z',
      '2026-11-22T11:00:00.000Z',
    ])
    // 600 bytes over 3600 s → 1.33 bit/s; 450 bytes → 1 bit/s.
    expect(merged[0].bps).toBeCloseTo((600 * 8) / 3600, 10)
    expect(merged[1].bps).toBeCloseTo((450 * 8) / 3600, 10)
    // Request counts are untouched by the join.
    expect(merged[0]).toMatchObject({ requests: 120, blocked: 20, passed: 100 })
    expect(merged[1]).toMatchObject({ requests: 60, blocked: 0, passed: 60 })
  })

  it('keeps buckets that only one of the two series has', () => {
    const series = [
      requestBucket('2026-11-22T10:00:00Z', 10),
      // 11:00 has requests but no egress row at all.
      requestBucket('2026-11-22T11:00:00Z', 5),
    ]
    const egress = {
      step_seconds: 300,
      buckets: [
        egressBucket('2026-11-22T10:00:00Z', 900),
        // 12:00 has egress but no request row (a gap in the request series).
        egressBucket('2026-11-22T12:00:00Z', 1800),
      ],
    }

    const merged = mergeTrafficSeries(series, egress, requestBucketMs(24))

    expect(merged.map((p) => p.bucket)).toEqual([
      '2026-11-22T10:00:00.000Z',
      '2026-11-22T11:00:00.000Z',
      '2026-11-22T12:00:00.000Z',
    ])
    expect(merged[1]).toMatchObject({ requests: 5, bps: 0 })
    expect(merged[2]).toMatchObject({ requests: 0, blocked: 0, passed: 0 })
    // The 12:00 row has no containing request bucket, so it keeps its own
    // 5-minute width — dividing by the request width would understate the rate
    // by 12× and hide a spike that the request series simply did not record.
    expect(merged[2].bps).toBeCloseTo((1800 * 8) / 300, 10)
  })

  it('aligns on the returned bucket starts, not on an assumed UTC grid', () => {
    // A database session outside UTC truncates `day` at its own midnight: the
    // request buckets start at 16:00Z (local midnight in UTC+8). Flooring the
    // egress buckets onto a UTC midnight grid would split every day in two.
    const series = [
      requestBucket('2026-11-21T16:00:00Z', 100),
      requestBucket('2026-11-22T16:00:00Z', 200),
    ]
    const egress = {
      step_seconds: 3600,
      buckets: [
        egressBucket('2026-11-21T16:00:00Z', 3600),
        egressBucket('2026-11-22T00:00:00Z', 3600),
        egressBucket('2026-11-22T16:00:00Z', 7200),
      ],
    }

    const merged = mergeTrafficSeries(series, egress, requestBucketMs(720))

    expect(merged.map((p) => p.bucket)).toEqual([
      '2026-11-21T16:00:00.000Z',
      '2026-11-22T16:00:00.000Z',
    ])
    // 7200 bytes over the 24 h bucket (detected from the request starts).
    expect(merged[0].bps).toBeCloseTo((7200 * 8) / 86_400, 10)
    expect(merged[1].bps).toBeCloseTo((7200 * 8) / 86_400, 10)
    expect(merged[0].requests).toBe(100)
    expect(merged[1].requests).toBe(200)
  })

  it('renders a bandwidth-only window at the egress step', () => {
    // No request rows at all: keep the native egress width so the chart is not
    // flattened into a single point.
    const merged = mergeTrafficSeries(
      [],
      {
        step_seconds: 300,
        buckets: [
          egressBucket('2026-11-22T10:00:00Z', 3000),
          egressBucket('2026-11-22T10:05:00Z', 6000),
        ],
      },
      requestBucketMs(24),
    )

    expect(merged).toHaveLength(2)
    expect(merged[0].bps).toBeCloseTo((3000 * 8) / 300, 10)
    expect(merged[1].bps).toBeCloseTo((6000 * 8) / 300, 10)
  })

  it('sorts ascending by bucket and survives an empty payload', () => {
    const merged = mergeTrafficSeries(
      [
        requestBucket('2026-11-22T12:00:00Z', 1),
        requestBucket('2026-11-22T10:00:00Z', 1),
      ],
      undefined,
      requestBucketMs(24),
    )
    expect(merged.map((p) => p.bucket)).toEqual([
      '2026-11-22T10:00:00.000Z',
      '2026-11-22T12:00:00.000Z',
    ])
    expect(mergeTrafficSeries([], undefined, requestBucketMs(24))).toEqual([])
  })

  it('never produces negative pass counts', () => {
    // Defensive: the aggregate endpoint can report blocked > requests for a
    // bucket after a late block write; the chart must not plot a negative.
    const merged = mergeTrafficSeries(
      [requestBucket('2026-11-22T10:00:00Z', 2, 5)],
      undefined,
      requestBucketMs(24),
    )
    expect(merged[0].passed).toBe(0)
  })
})

describe('countryTrafficRows', () => {
  it('sorts by requests descending, ties broken by code', () => {
    const rows = countryTrafficRows([
      { country_code: 'us', requests: 10 },
      { country_code: 'CN', requests: 40 },
      { country_code: 'DE', requests: 10 },
      { country_code: 'JP', requests: 30 },
    ])
    expect(rows.map((r) => r.code)).toEqual(['CN', 'JP', 'DE', 'US'])
    expect(rows.map((r) => r.requests)).toEqual([40, 30, 10, 10])
  })

  it('folds duplicate codes, drops unresolved/empty/non-positive rows', () => {
    const rows = countryTrafficRows([
      { country_code: 'CN', requests: 10 },
      { country_code: ' cn ', requests: 5 },
      { country_code: '', requests: 99 },
      { country_code: 'US', requests: 0 },
      { country_code: 'DE', requests: 5 },
    ])
    expect(rows).toHaveLength(2)
    expect(rows[0]).toMatchObject({ code: 'CN', requests: 15 })
    expect(rows[1]).toMatchObject({ code: 'DE', requests: 5 })
  })

  it('computes the share over the listed set', () => {
    const rows = countryTrafficRows([
      { country_code: 'CN', requests: 60 },
      { country_code: 'US', requests: 30 },
      { country_code: 'JP', requests: 10 },
    ])
    expect(rows[0].share).toBeCloseTo(0.6, 10)
    expect(rows[1].share).toBeCloseTo(0.3, 10)
    expect(rows[2].share).toBeCloseTo(0.1, 10)
    expect(rows.reduce((sum, row) => sum + row.share, 0)).toBeCloseTo(1, 10)
  })

  it('returns an empty list for an empty payload', () => {
    expect(countryTrafficRows([])).toEqual([])
  })
})