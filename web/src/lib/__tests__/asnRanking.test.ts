import { describe, expect, it } from 'vitest'
import {
  asnTrafficRows,
  formatAsn,
  isUnknownAsnName,
} from '../asnRanking'

describe('formatAsn', () => {
  it('prefixes the number, never renders it bare', () => {
    expect(formatAsn(13335)).toBe('AS13335')
    expect(formatAsn(64512)).toBe('AS64512')
  })
})

describe('isUnknownAsnName', () => {
  it('recognises the control plane fallback in any casing', () => {
    expect(isUnknownAsnName('Unknown (AS64512)')).toBe(true)
    expect(isUnknownAsnName('unknown (as64512)')).toBe(true)
  })

  it('treats a blank name as unknown', () => {
    expect(isUnknownAsnName('')).toBe(true)
    expect(isUnknownAsnName('   ')).toBe(true)
    expect(isUnknownAsnName(null)).toBe(true)
    expect(isUnknownAsnName(undefined)).toBe(true)
  })

  it('keeps a real organization name', () => {
    expect(isUnknownAsnName('Cloudflare, Inc.')).toBe(false)
    expect(isUnknownAsnName('Amazon.com, Inc.')).toBe(false)
  })
})

describe('asnTrafficRows', () => {
  it('sorts by requests descending, ties by AS number ascending', () => {
    const rows = asnTrafficRows([
      { asn: 64512, asn_name: 'B', requests: 10 },
      { asn: 13335, asn_name: 'Cloudflare, Inc.', requests: 40 },
      { asn: 15169, asn_name: 'Google LLC', requests: 10 },
      { asn: 16509, asn_name: 'Amazon.com, Inc.', requests: 30 },
    ])
    // 64512 and 15169 both have 10 requests: the lower AS number comes first.
    expect(rows.map((r) => r.asn)).toEqual([13335, 16509, 15169, 64512])
    expect(rows.map((r) => r.requests)).toEqual([40, 30, 10, 10])
  })

  it('folds duplicate AS numbers and drops unusable rows', () => {
    const rows = asnTrafficRows([
      { asn: 13335, asn_name: 'Cloudflare, Inc.', requests: 10 },
      { asn: 13335, asn_name: 'Cloudflare, Inc.', requests: 5 },
      { asn: 0, asn_name: 'not a network', requests: 99 },
      { asn: 64512, asn_name: '', requests: 0 },
      { asn: 64513, asn_name: 'Unknown (AS64513)', requests: 5 },
    ])
    expect(rows).toHaveLength(2)
    expect(rows[0]).toMatchObject({ asn: 13335, requests: 15 })
    expect(rows[1]).toMatchObject({ asn: 64513, requests: 5 })
  })

  it('computes the share against the window total when it is known', () => {
    const rows = asnTrafficRows(
      [
        { asn: 13335, asn_name: 'Cloudflare, Inc.', requests: 300 },
        { asn: 16509, asn_name: 'Amazon.com, Inc.', requests: 200 },
      ],
      1000,
    )
    expect(rows[0].share).toBeCloseTo(0.3, 10)
    expect(rows[1].share).toBeCloseTo(0.2, 10)
  })

  it('falls back to the listed set as the denominator', () => {
    const rows = asnTrafficRows([
      { asn: 13335, asn_name: 'Cloudflare, Inc.', requests: 300 },
      { asn: 16509, asn_name: 'Amazon.com, Inc.', requests: 200 },
    ])
    expect(rows[0].share).toBeCloseTo(0.6, 10)
    expect(rows[1].share).toBeCloseTo(0.4, 10)
  })

  it('trims names and keeps an empty name for the UI to localise', () => {
    const rows = asnTrafficRows([
      { asn: 64512, asn_name: '  ', requests: 3 },
      { asn: 13335, asn_name: ' Cloudflare, Inc. ', requests: 4 },
    ])
    expect(rows[0].name).toBe('Cloudflare, Inc.')
    expect(rows[1].name).toBe('')
    expect(rows[1].share).toBeCloseTo(3 / 7, 10)
  })

  it('returns an empty ranking for an empty payload', () => {
    expect(asnTrafficRows([])).toEqual([])
  })
})