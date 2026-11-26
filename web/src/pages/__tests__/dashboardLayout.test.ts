import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

/**
 * Dashboard 的「Status codes 饼图 / 站点总数与在线访客卡片 / 威胁 IP 的 ASN 列」
 * 这三处外观要求同一个来源：
 *
 * - 饼图必须复用 traffic 页的分组函数与配色，否则两页会把 4xx 画成不同的颜色；
 * - 在线访客必须走上方 KPI 卡片同一条渲染路径（`stats` 数组），不能再退回去
 *   当一张单独的大数字卡片；
 * - ASN 列只在 Dashboard 的威胁表出现，并且列定义仍然只有
 *   `TopRankingTables.tsx` 那一份（两页不允许各自重写列）。
 *
 * 这些都是源码级契约断言（测试跑在 node 环境，没有 DOM），行为断言由
 * `TopRankingTables.test.ts` 与组件测试覆盖。
 */
describe('dashboard distributions, KPIs and the threat-table ASN column', () => {
  it('groups status codes through the shared traffic helper, with the same palette', () => {
    const dashboard = read('src/pages/DashboardPage.tsx')
    const traffic = read('src/pages/sites/TrafficPage.tsx')

    expect(dashboard).toContain("from '@/api/traffic'")
    expect(dashboard).toContain('groupStatusCodes(statusCodes.data')

    const colors = (source: string, name: string) => {
      const match = new RegExp(`const ${name} = \\[([^\\]]+)\\]`).exec(source)
      return match?.[1].replace(/\s/g, '')
    }
    const dashboardColors = colors(dashboard, 'STATUS_PIE_COLORS')
    expect(dashboardColors).toBeTruthy()
    // 两页同一套四个色值：谁改了其中一处，这条断言就会失败。
    expect(dashboardColors).toBe(colors(traffic, 'PIE_COLORS'))
  })

  it('renders sites and live visitors as the same stat card as requests', () => {
    const dashboard = read('src/pages/DashboardPage.tsx')

    expect(dashboard).toContain("key: 'sites'")
    expect(dashboard).toContain("key: 'visitors'")
    expect(dashboard).toContain('metricHelp(\'sites\'')
    expect(dashboard).toContain('metricHelp(\'visitors\'')

    // 旧的「Live Visitors 单独大数字卡片」必须消失：它的 CardHeader 标题是
    // 唯一能区分两种渲染方式的标记（KPI 卡片用 label，而不是 title）。
    expect(dashboard).not.toContain("title={t('pages.dashboard.activeVisitors')}")
  })

  it('shows the ASN only where the caller asks, from the shared column list', () => {
    const table = read('src/components/waf/TopRankingTables.tsx')

    expect(table).toContain('showAsn')
    expect(table).toContain("t('pages.dashboard.asn')")
    expect(table).toContain('formatAsn(')
    expect(table).toContain('isUnknownAsnName(')

    const dashboard = read('src/pages/DashboardPage.tsx')
    expect(dashboard).toMatch(/<TopIpsTable[\s\S]{0,600}?showAsn/)
    // 站点流量页的「热门 IP」不要求这一列，保持原样。
    expect(read('src/pages/sites/TrafficPage.tsx')).not.toContain('showAsn')
  })
})
