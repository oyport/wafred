import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { CountryTrafficList } from '../CountryTrafficList'
import { countryTrafficRows } from '@/lib/trafficSeries'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
    i18n: { language: 'en' },
  }),
}))

const ROWS = countryTrafficRows([
  { country_code: 'US', requests: 30 },
  { country_code: 'CN', requests: 60 },
  { country_code: 'JP', requests: 10 },
])

describe('CountryTrafficList', () => {
  it('renders the sorted ranking with flag, code and share', () => {
    const html = renderToStaticMarkup(<CountryTrafficList rows={ROWS} />)

    // Descending by requests, regardless of the API's order.
    expect(html.indexOf('🇨🇳')).toBeLessThan(html.indexOf('🇺🇸'))
    expect(html.indexOf('🇺🇸')).toBeLessThan(html.indexOf('🇯🇵'))
    expect(html).toContain('China')
    expect(html).toContain('United States')
    expect(html).toContain('>CN<')
    expect(html).toContain('>US<')
    // The share bar is drawn from the computed ratio (60 / 100 = 60 %).
    expect(html).toContain('width:60%')
  })

  it('drills into the logs when a handler is given', () => {
    const html = renderToStaticMarkup(
      <CountryTrafficList rows={ROWS} onSelect={() => {}} />,
    )
    expect(html.match(/<button/g) ?? []).toHaveLength(3)
    expect(html).toContain('aria-label="China (CN)')
    expect(html).toContain('title="pages.traffic.countryList.viewLogs"')
  })

  it('stays a plain list without a handler', () => {
    const html = renderToStaticMarkup(<CountryTrafficList rows={ROWS} />)
    expect(html.match(/<button/g) ?? []).toHaveLength(0)
  })

  it('renders an empty list body for no rows', () => {
    const html = renderToStaticMarkup(<CountryTrafficList rows={[]} />)
    expect(html.match(/<li/g) ?? []).toHaveLength(0)
    expect(html).toContain('pages.traffic.countryList.country')
  })
})