/**
 * Scroll maths for the site-detail tab bar (UX-19).
 *
 * The nine site tabs overflow on a phone. When the active tab changes — a deep
 * link, a keyboard selection, or navigating between tabs — the bar scrolls so
 * that tab is centred, which is what makes the remaining tabs discoverable.
 *
 * Kept as a pure function (and out of the component) so the clamping at both
 * ends is unit-testable without a DOM: a naive `scrollLeft = offset - width/2`
 * scrolls past the end for the last tab and into negative values for the first.
 */
export interface TabScrollInput {
  /** `offsetLeft` of the active tab inside the scroll container. */
  offsetLeft: number
  /** Rendered width of the active tab. */
  itemWidth: number
  /** Visible width of the scroll container. */
  clientWidth: number
  /** Full scrollable width of the container. */
  scrollWidth: number
}

export function centeredTabScrollLeft({
  offsetLeft,
  itemWidth,
  clientWidth,
  scrollWidth,
}: TabScrollInput): number {
  const maxScroll = Math.max(0, scrollWidth - clientWidth)
  const centered = offsetLeft - (clientWidth - itemWidth) / 2
  if (!Number.isFinite(centered)) return 0
  return Math.min(Math.max(0, centered), maxScroll)
}