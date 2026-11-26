import { useTranslation } from 'react-i18next'
import { CaretRight } from '@phosphor-icons/react'
import { countryFlag } from '@/api/geo'
import { countryName } from '@/lib/countryNames'
import type { CountryTrafficRow } from '@/lib/trafficSeries'
import { formatCompactNumber, formatNumber, formatPercent, formatRawValue } from '@/lib/format'
import { cn } from '@/lib/utils'

/**
 * The country breakdown that sits next to the globe.
 *
 * Deliberately a compact, scrollable list rather than a second chart: the globe
 * answers "where", this answers "how many, and how does it compare". The share
 * bar keeps the ranking readable for the long tail without the list pushing the
 * globe off screen, and each row drills into the access logs filtered to that
 * country (`country:XX` in the logs page's search grammar) when the page has a
 * drill-down to give.
 */
export function CountryTrafficList({
  rows,
  onSelect,
  className,
  maxHeightClass = 'max-h-[360px]',
}: {
  rows: CountryTrafficRow[]
  onSelect?: (code: string) => void
  className?: string
  maxHeightClass?: string
}) {
  const { t, i18n } = useTranslation()
  const language = i18n?.language ?? 'en'
  const interactive = typeof onSelect === 'function'

  return (
    <div className={cn('flex min-w-0 flex-col', className)}>
      <div className="flex items-center gap-3 border-b border-line px-1 pb-2 text-[11px] font-medium uppercase tracking-wide text-fg-subtle">
        <span className="w-5 shrink-0" aria-hidden="true" />
        <span className="min-w-0 flex-1">
          {t('pages.traffic.countryList.country')}
        </span>
        <span className="shrink-0 text-right">
          {t('pages.traffic.countryList.requests')}
        </span>
        <span className="w-28 shrink-0 text-right">
          {t('pages.traffic.countryList.share')}
        </span>
        {interactive && <span className="h-3 w-3 shrink-0" aria-hidden="true" />}
      </div>
      <ul
        className={cn(
          'min-h-0 divide-y divide-line overflow-y-auto overscroll-contain',
          maxHeightClass,
        )}
      >
        {rows.map((row) => {
          const name = countryName(row.code, language)
          const label = `${name} (${row.code}) — ${formatNumber(row.requests)} ${t(
            'pages.traffic.countryList.requests',
          )}, ${formatPercent(row.share)}`
          const content = (
            <>
              <span className="w-5 shrink-0 text-center text-sm leading-none" aria-hidden="true">
                {countryFlag(row.code)}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[13px] font-medium text-fg-strong">
                  {name}
                </span>
                <span className="block text-[11px] uppercase tracking-wide text-fg-subtle">
                  {row.code}
                </span>
              </span>
              <span
                className="shrink-0 text-right text-[13px] tabular-nums text-fg"
                title={formatRawValue(row.requests) ?? undefined}
              >
                {formatCompactNumber(row.requests)}
              </span>
              <span className="flex w-28 shrink-0 items-center justify-end gap-2">
                <span className="h-1.5 w-14 overflow-hidden rounded-full bg-recessed">
                  <span
                    className="block h-full rounded-full bg-brand"
                    style={{ width: `${Math.max(2, Math.min(100, row.share * 100))}%` }}
                  />
                </span>
                <span className="w-11 text-right text-[11px] tabular-nums text-fg-subtle">
                  {formatPercent(row.share)}
                </span>
              </span>
              {interactive && (
                <CaretRight
                  weight="bold"
                  aria-hidden="true"
                  className="h-3 w-3 shrink-0 text-fg-subtle opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100"
                />
              )}
            </>
          )
          return (
            <li key={row.code}>
              {interactive ? (
                <button
                  type="button"
                  onClick={() => onSelect?.(row.code)}
                  aria-label={label}
                  title={t('pages.traffic.countryList.viewLogs', { country: name })}
                  className="group flex w-full items-center gap-3 px-1 py-2 text-left transition-colors hover:bg-recessed"
                >
                  {content}
                </button>
              ) : (
                <div className="flex items-center gap-3 px-1 py-2">{content}</div>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export default CountryTrafficList