import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

/**
 * The ASN ranking is fed by `GET /analytics/top-asns` (shipped with the ASN
 * persistence work) through the same traffic fan-out as every other widget, so
 * the range selector and the tenant visibility rules apply for free. These are
 * source-level assertions because importing `TopRankingTables.tsx` in the node
 * test environment would pull the whole UI tree and i18n bootstrap with it;
 * the sorting/fallback behaviour itself is covered by
 * `src/lib/__tests__/asnRanking.test.ts`.
 */
describe('ASN ranking wiring', () => {
  const tables = read('src/components/waf/TopRankingTables.tsx')
  const tableBlock = tables.slice(tables.indexOf('export function TopAsnsTable'))

  it('is rendered on the traffic page from the overview payload', () => {
    const page = read('src/pages/sites/TrafficPage.tsx')
    expect(page).toContain('TopAsnsTable')
    expect(page).toContain('rows={data?.topAsns}')
    // Share denominator: the window's total requests.
    expect(page).toContain('totalRequests={summary?.requests}')
    expect(page).toContain("t('pages.traffic.topAsns')")
  })

  it('comes from the shared traffic fan-out, scoped and range-aware', () => {
    const traffic = read('src/api/traffic.ts')
    expect(traffic).toContain('analyticsApi.topAsns')
    // The fan-out receives the same `params` (site_id + range window) as the
    // other widgets, which is what makes a range change refresh the ranking.
    expect(traffic).toContain('topAsns,')
    const analytics = read('src/api/analytics.ts')
    expect(analytics).toContain("'/analytics/top-asns'")
  })

  it('shows name, AS number, requests and share in sortable columns', () => {
    for (const column of ["key: 'asn_name'", "key: 'asn'", "key: 'requests'", "key: 'share'"]) {
      expect(tableBlock).toContain(column)
    }
    // Name, number, requests and share can all be sorted client-side.
    expect(tableBlock.match(/sortable: true/g) ?? []).toHaveLength(4)
    // The AS number is rendered as `ASxxxxx`, never bare.
    expect(tableBlock).toContain('formatAsn(r.asn)')
    // Unknown networks are localised instead of leaking the English fallback.
    expect(tableBlock).toContain('isUnknownAsnName')
    expect(tableBlock).toContain("t('pages.traffic.asnUnknown', { asn: r.asn })")
  })

  it('has no row drill-down: the logs API has no ASN filter', () => {
    // `country:`/`client_ip:`/`rule:` are parsed by the logs page, but
    // `GET /logs/*` accepts no `asn` parameter — a row click would land on an
    // empty result set. Re-add both sides together if that ever changes.
    expect(tableBlock).not.toContain('onRowClick')
    expect(read('src/lib/logQuery.ts')).not.toContain('asn')
  })

  it('carries the copy in every locale', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(
        read(`src/i18n/locales/${lang}/common.json`),
      ) as { pages: { traffic: Record<string, string> } }
      for (const key of [
        'topAsns',
        'topAsnsHint',
        'topAsnsEmpty',
        'asnName',
        'asnNumber',
        'share',
        'asnUnknown',
      ]) {
        expect(parsed.pages.traffic[key], `${lang}.pages.traffic.${key}`).toBeTruthy()
      }
      // The fallback label keeps the AS number in its text.
      expect(parsed.pages.traffic.asnUnknown).toContain('{{asn}}')
    }
  })
})