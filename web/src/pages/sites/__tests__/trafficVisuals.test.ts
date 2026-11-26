import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

/**
 * The traffic page used to carry three separate geographic/bandwidth widgets:
 * a full-width world map, a standalone bandwidth chart and a requests chart
 * whose buckets did not line up with the egress buckets. This pins the shape of
 * the replacement so a later edit cannot quietly reintroduce the split:
 *
 *  - one composed chart with a request axis and a bit-rate axis,
 *  - the globe plus the country ranking (not a map that dwarfs the numbers),
 *  - both fed by the same aligned/merged series helper.
 */
describe('traffic visualization contract', () => {
  const src = read('src/pages/sites/TrafficPage.tsx')

  it('renders one composed requests + bandwidth chart', () => {
    expect(src).toContain('ComposedChart')
    expect(src).toContain("yAxisId=\"requests\"")
    expect(src).toContain("yAxisId=\"bitrate\"")
    expect(src).toContain('mergeTrafficSeries')
    expect(src).toContain('requestBucketMs')
    // The separate bandwidth card is gone; "Bandwidth" only names a series.
    expect(src).not.toContain("title={t('pages.traffic.bandwidth')}")
    expect(src.match(/pages\.traffic\.requestsAndBandwidth/g)).toHaveLength(2)
  })

  it('replaces the world map with the globe and a country list', () => {
    expect(src).toContain('GlobeChart')
    expect(src).toContain('CountryTrafficList')
    expect(src).toContain('countryTrafficRows')
    expect(src).not.toContain('WorldMapChart')
    // The globe column is capped so the ranking keeps the wider column.
    expect(src).toContain('lg:grid-cols-[minmax(0,360px)_minmax(0,1fr)]')
  })

  it('drills from a country row into that country’s access logs', () => {
    expect(src).toContain('country:${code}')
    // The site-scoped geo endpoint is fixed at 24 h, so the drill-down window
    // must follow the data rather than the range selector.
    expect(src).toContain('const geoHours = scoped ? 24 : RANGE_HOURS[range]')
  })

  it('carries the new copy in every locale', () => {
    const keys = [
      'requestsAndBandwidth',
      'requestsAndBandwidthHint',
      'geoMap.globeLabel',
      'geoMap.globeHint',
      'geoMap.pauseRotation',
      'geoMap.resumeRotation',
      'countryList.country',
      'countryList.requests',
      'countryList.share',
      'countryList.viewLogs',
    ]
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(
        read(`src/i18n/locales/${lang}/common.json`),
      ) as { pages: { traffic: Record<string, unknown> } }
      const traffic = parsed.pages.traffic as Record<string, unknown> & {
        geoMap: Record<string, string>
        countryList: Record<string, string>
      }
      for (const key of keys) {
        const [head, tail] = key.split('.')
        const value =
          tail === undefined
            ? (traffic[head] as string | undefined)
            : (traffic[head] as Record<string, string>)[tail]
        expect(value, `${lang}.pages.traffic.${key}`).toBeTruthy()
      }
    }
  })
})