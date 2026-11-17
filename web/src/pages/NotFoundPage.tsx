import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowSquareOut, Compass, Globe } from '@phosphor-icons/react'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'

/** Public product site, offered from the 404 as the way out of a dead link. */
export const WEBSITE_URL = 'https://www.pingwaf.com'

/**
 * Full 404 page for the console router.
 *
 * Extracted from the inline copy that used to live in `router/index.tsx` so the
 * page has a real `<h1>` (L1-002): accessibility scanners read the heading, and
 * the empty-state title alone was rendering as a `<p>`.
 *
 * The actions are deliberately ordered "recover, then leave": back to the
 * dashboard (primary), back to the previous console page when there is one, and
 * the official site for someone who arrived from an external link.
 */
export function NotFoundPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  // React Router records the history index on `window.history.state.idx`; 0
  // means this entry is the first one, so "back" would leave the console (or
  // do nothing in a fresh tab) and the button is not offered.
  // Guarded for non-browser renders (SSR tests): the button simply is not
  // offered when there is no history to go back to.
  const historyIdx =
    typeof window === 'undefined'
      ? 0
      : ((window.history.state as { idx?: number } | null)?.idx ?? 0)
  const canGoBack = historyIdx > 0

  return (
    <div className="animate-slide-up">
      <h1 className="text-2xl font-semibold text-fg-strong">
        {t('notFound.title', t('pages.notFound.title'))}
      </h1>
      <EmptyState
        icon={<Compass weight="duotone" />}
        title={<span className="sr-only">{t('pages.notFound.title')}</span>}
        description={t('pages.notFound.description')}
        action={
          <div className="flex flex-wrap items-center justify-center gap-2">
            <Button variant="primary" onClick={() => navigate('/dashboard')}>
              {t('pages.notFound.backToDashboard')}
            </Button>
            {canGoBack && (
              <Button variant="secondary" onClick={() => navigate(-1)}>
                {t('common.back')}
              </Button>
            )}
            <a
              href={WEBSITE_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-md border border-line bg-elevated px-3 py-2 text-sm font-medium text-fg transition-colors hover:bg-recessed"
            >
              <Globe weight="duotone" className="h-4 w-4" />
              {t('sidebar.website')}
              <ArrowSquareOut weight="duotone" className="h-3.5 w-3.5 text-fg-subtle" />
            </a>
          </div>
        }
      />
    </div>
  )
}

export default NotFoundPage