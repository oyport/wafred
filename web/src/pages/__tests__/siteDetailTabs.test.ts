import { describe, expect, it } from 'vitest'
import { centeredTabScrollLeft } from '../siteDetailTabs'

/**
 * UX-19: the nine site tabs overflow on a phone, so the bar scrolls the active
 * tab into view. The clamping at both ends is what keeps the first tab from
 * scrolling into negative space and the last one from overshooting the list.
 */
describe('centeredTabScrollLeft', () => {
  it('centres a tab that sits in the middle of the strip', () => {
    expect(
      centeredTabScrollLeft({
        offsetLeft: 300,
        itemWidth: 80,
        clientWidth: 400,
        scrollWidth: 1000,
      }),
    ).toBe(140)
  })

  it('clamps to the start when the active tab is the first one', () => {
    expect(
      centeredTabScrollLeft({
        offsetLeft: 0,
        itemWidth: 80,
        clientWidth: 400,
        scrollWidth: 1000,
      }),
    ).toBe(0)
  })

  it('clamps to the end so the last tab cannot overshoot the list', () => {
    expect(
      centeredTabScrollLeft({
        offsetLeft: 960,
        itemWidth: 80,
        clientWidth: 400,
        scrollWidth: 1000,
      }),
    ).toBe(600)
  })

  it('stays at 0 when every tab already fits', () => {
    expect(
      centeredTabScrollLeft({
        offsetLeft: 120,
        itemWidth: 80,
        clientWidth: 500,
        scrollWidth: 500,
      }),
    ).toBe(0)
  })

  it('never returns a non-finite offset for an unmeasured element', () => {
    expect(
      centeredTabScrollLeft({
        offsetLeft: Number.NaN,
        itemWidth: 0,
        clientWidth: 0,
        scrollWidth: 0,
      }),
    ).toBe(0)
  })
})