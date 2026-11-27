import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { GlobeChart } from '../GlobeChart'
import type { GeoCountryStat } from '@/api/types'

// The globe only needs `t` and the language tag for country names; a stub keeps
// this a pure render test (no i18n instance, no DOM).
vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
    i18n: { language: 'en' },
  }),
}))

function render(data: GeoCountryStat[]): string {
  return renderToStaticMarkup(<GlobeChart data={data} />)
}

/** Countries near the initial projection centre (12°E, 18°N) are in front. */
const VISIBLE: GeoCountryStat[] = [
  { country_code: 'FR', requests: 900 },
  { country_code: 'DZ', requests: 400 },
  { country_code: 'US', requests: 100 },
]

describe('GlobeChart', () => {
  it('renders an accessible SVG globe with a bubble per visible country', () => {
    const html = render(VISIBLE)

    expect(html).toContain('role="img"')
    expect(html).toContain('aria-label="pages.traffic.geoMap.globeLabel"')
    expect(html).toContain('viewBox="0 0 360 360"')
    // FR and DZ face the initial rotation; the US is on the far hemisphere and
    // must not be drawn (that is what makes it read as a sphere).
    const bubbles = html.match(/<circle/g) ?? []
    expect(bubbles.length).toBe(2)
    // ...but nothing is lost for assistive tech: every country is listed.
    expect(html.match(/<li/g) ?? []).toHaveLength(3)
    expect(html).toContain('United States')
  })

  it('lists a far-side country without drawing it', () => {
    const html = render([{ country_code: 'NZ', requests: 7 }])

    expect(html.match(/<circle/g) ?? []).toHaveLength(0)
    expect(html.match(/<li/g) ?? []).toHaveLength(1)
    expect(html).toContain('New Zealand')
  })

  it('offers a pause control while the idle rotation is running', () => {
    const html = render(VISIBLE)
    expect(html).toContain('aria-label="pages.traffic.geoMap.pauseRotation"')
  })

  it('offers a fullscreen control next to the pause button', () => {
    const html = render(VISIBLE)
    expect(html).toContain('aria-label="pages.traffic.geoMap.fullscreen"')
  })

  it('draws a red threat bubble for a country the WAF refused requests from', () => {
    const html = render([
      { country_code: 'FR', requests: 900, blocked: 40 },
      { country_code: 'DZ', requests: 400 },
    ])

    // Two request bubbles plus one threat bubble on the visible hemisphere.
    expect(html.match(/<circle/g) ?? []).toHaveLength(3)
    // Deeper red as the count climbs — the hue stays 0 and only lightness moves.
    expect(html).toMatch(/fill="hsl\(0 72% [\d.]+%\)"/)
    expect(html).toContain('pages.traffic.blocked')
  })

  it('draws no threat bubble when nothing was blocked', () => {
    const html = render(VISIBLE)
    expect(html).not.toMatch(/hsl\(0 72%/)
  })

  it('renders an empty globe without crashing', () => {
    const html = render([])
    expect(html).toContain('role="img"')
    expect(html.match(/<circle/g) ?? []).toHaveLength(0)
    expect(html.match(/<li/g) ?? []).toHaveLength(0)
  })
})