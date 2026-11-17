import { describe, expect, it } from 'vitest'

import { isLegacyTab, parseTab } from '../protectionTab'

describe('parseTab', () => {
  it('keeps the canonical tabs', () => {
    expect(parseTab('overview')).toBe('overview')
    expect(parseTab('engine')).toBe('engine')
    expect(parseTab('managed')).toBe('managed')
    expect(parseTab('custom')).toBe('custom')
    expect(parseTab('paths')).toBe('paths')
    expect(parseTab('cc')).toBe('cc')
  })

  it('normalizes the legacy tab names', () => {
    // Pre-0.22 vocabulary.
    expect(parseTab('settings')).toBe('engine')
    expect(parseTab('rules')).toBe('custom')
    // Shorthand names used in older links.
    expect(parseTab('detection')).toBe('engine')
    expect(parseTab('waf')).toBe('engine')
    expect(parseTab('rate')).toBe('cc')
    expect(parseTab('challenge')).toBe('cc')
    expect(parseTab('exceptions')).toBe('paths')
  })

  it('defaults to the overview for unknown or missing values', () => {
    expect(parseTab('nope')).toBe('overview')
    expect(parseTab('')).toBe('overview')
    expect(parseTab(null)).toBe('overview')
  })
})

describe('isLegacyTab', () => {
  it('flags only names that need rewriting in the URL', () => {
    expect(isLegacyTab('settings')).toBe(true)
    expect(isLegacyTab('rules')).toBe(true)
    expect(isLegacyTab('challenge')).toBe(true)
    expect(isLegacyTab('overview')).toBe(false)
    expect(isLegacyTab('engine')).toBe(false)
    expect(isLegacyTab(null)).toBe(false)
  })
})