import { useEffect, useMemo, useState } from 'react'
import { Navigate, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Cloud,
  Eye,
  Gauge,
  Lightning,
  Path as PathIcon,
  Pulse,
  ShieldCheck,
  Sliders,
  Timer,
  Warning,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Tabs } from '@/components/ui/Tabs'
import { Switch } from '@/components/ui/Switch'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { Input } from '@/components/ui/Input'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { wafSettingsApi, wafSettingsKeys } from '@/api/wafSettings'
import { configVersionsApi } from '@/api/configVersions'
import { ruleKeys, rulesApi } from '@/api/rules'
import { RULE_MODES, type RuleMode, type WafSettings } from '@/api/types'
import { useCanWrite, useSiteDetail, useWafSettingsMutation } from '@/hooks'
import { cn } from '@/lib/utils'
import { formatDateTime } from '@/lib/format'
import { PostureOverview, type PostureTarget } from './PostureOverview'
import { ManagedRulesPanel } from './ManagedRulesPanel'
import { CustomRulesPanel } from './CustomRulesPanel'
import { MitigationPanel } from './MitigationPanel'
import { PathExceptionsPanel } from './PathExceptionsPanel'
import { PathRestrictionsPanel } from './PathRestrictionsPanel'
import {
  BODY_STAGE_TIMEOUT_DEFAULT,
  BODY_STAGE_TIMEOUT_MAX,
  BODY_STAGE_TIMEOUT_MIN,
  normaliseBodyStageTimeout,
} from '@/lib/bodyStageTimeout'
import { isLegacyTab, parseTab, type ProtectionTab } from '@/lib/protectionTab'

/** How many recent configuration versions the overview lists. */
const RECENT_CHANGES_LIMIT = 5

function SectionHeading({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="mb-3">
      <h2 className="text-sm font-semibold text-fg-strong">{title}</h2>
      {hint && <p className="mt-0.5 text-[13px] text-fg-subtle">{hint}</p>}
    </div>
  )
}

/**
 * Web protection for one site, organised as six entries (UX-09):
 *
 * - **Overview** — the live posture card, the site-wide enforcement-mode
 *   switch (the downgrade path carries a confirmation) and the recent
 *   configuration changes.
 * - **Engine & detection** — the WAF engine switch, deep inspection, detection
 *   sensitivity, the body-stage budget and the deployment-wide observation
 *   mode.
 * - **Managed rules / Custom rules / Path exceptions / Rate limiting &
 *   challenge** — the enforcement surfaces, one per tab.
 *
 * `?tab=` remains the deep-link contract: older values are translated by
 * `parseTab` and rewritten in place, so a bookmark keeps working and the
 * address bar always shows the current vocabulary.
 */
export function ProtectionPage() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const navigate = useNavigate()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const siteDetail = useSiteDetail(siteId)
  const siteDomain = siteDetail.data?.site.domain ?? siteId
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = parseTab(searchParams.get('tab'))

  const setTab = (next: string) => {
    const params = new URLSearchParams(searchParams)
    params.set('tab', next)
    setSearchParams(params, { replace: true })
  }

  const handlePostureNavigate = (target: PostureTarget) => {
    if (target === 'bot') {
      navigate(`/sites/${siteId}/security/bot`)
    } else {
      setTab(target)
    }
  }

  // Rewrite a legacy `?tab=` link in place so the address bar always shows the
  // current vocabulary — every other param (`?rule=`) stays.
  useEffect(() => {
    const raw = searchParams.get('tab')
    if (!isLegacyTab(raw)) return
    const params = new URLSearchParams(searchParams)
    params.set('tab', parseTab(raw))
    setSearchParams(params, { replace: true })
  }, [searchParams, setSearchParams])

  const settingsQuery = useQuery({
    queryKey: wafSettingsKeys.settings(siteId),
    queryFn: () => wafSettingsApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const settings = settingsQuery.data
  const updateSettings = useWafSettingsMutation(siteId)
  const engineOn = settings?.waf_enabled ?? true

  // UX-04: turning the engine off is the one switch that disables every other
  // protection control, so it takes an explicit acknowledgement first.
  const [confirmEngineOff, setConfirmEngineOff] = useState(false)
  const [engineOffAck, setEngineOffAck] = useState(false)

  const tabLabels: Record<ProtectionTab, string> = {
    // The overview reuses the site-detail "Overview" label.
    overview: t('pages.siteDetail.overview'),
    engine: `${t('pages.protection.engineTitle')} · ${t('pages.protection.detectionTitle')}`,
    managed: t('pages.protection.tabManaged'),
    custom: t('pages.protection.tabCustom'),
    paths: t('pages.protection.tabPaths'),
    cc: t('pages.protection.tabCc'),
  }

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.protection.title')}
        description={t('pages.protection.description')}
      />

      {/* UX-04: a disabled engine is a persistent, page-level state — keep it
          visible on every tab instead of hiding it inside the engine card. */}
      {!settingsQuery.isPending && !engineOn && (
        <div
          role="status"
          className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-warning/45 bg-warning/10 px-4 py-3"
        >
          <span className="flex items-start gap-2.5 text-[13px] leading-relaxed text-fg">
            <Warning weight="fill" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
            <span>
              <span className="block font-semibold">
                {t('pages.protection.engineOffBannerTitle')}
              </span>
              <span className="mt-0.5 block">
                {t('pages.protection.engineOffWarn')}
              </span>
            </span>
          </span>
          {canWrite && (
            <Button
              size="sm"
              variant="secondary"
              loading={updateSettings.isPending}
              onClick={() => updateSettings.mutate({ waf_enabled: true })}
            >
              {t('pages.protection.engineOffBannerAction')}
            </Button>
          )}
        </div>
      )}

      {/* Sticky so the entry points stay reachable while a long rule list
          scrolls; the wrapper scrolls horizontally on narrow screens because
          six labels do not fit a phone. The Tabs component already renders
          real `role="tab"` buttons, so keyboard focus/activation is native. */}
      <Tabs
        variant="pill"
        className="sticky top-0 z-20 mb-5 overflow-x-auto bg-base py-2"
        value={tab}
        onChange={setTab}
        items={[
          {
            value: 'overview',
            label: tabLabels.overview,
            icon: <Pulse weight="duotone" className="h-4 w-4" />,
          },
          {
            value: 'engine',
            label: tabLabels.engine,
            icon: <Lightning weight="duotone" className="h-4 w-4" />,
          },
          {
            value: 'managed',
            label: tabLabels.managed,
            icon: <Sliders weight="duotone" className="h-4 w-4" />,
          },
          {
            value: 'custom',
            label: tabLabels.custom,
            icon: <ShieldCheck weight="duotone" className="h-4 w-4" />,
          },
          {
            value: 'paths',
            label: tabLabels.paths,
            icon: <PathIcon weight="duotone" className="h-4 w-4" />,
          },
          {
            value: 'cc',
            label: tabLabels.cc,
            icon: <Cloud weight="duotone" className="h-4 w-4" />,
          },
        ]}
      />

        <Tabs
          variant="pill"
          className="mb-5"
          value={tab}
          onChange={setTab}
          items={[
            {
              value: 'managed',
              label: t('pages.protection.tabManaged'),
              icon: <Sliders weight="duotone" className="h-4 w-4" />,
            },
            {
              value: 'custom',
              label: t('pages.protection.tabCustom'),
              icon: <ShieldCheck weight="duotone" className="h-4 w-4" />,
            },
            {
              value: 'cc',
              label: t('pages.protection.tabCc'),
              icon: <Cloud weight="duotone" className="h-4 w-4" />,
            },
            {
              value: 'paths',
              label: t('pages.protection.tabPaths'),
              icon: <PathIcon weight="duotone" className="h-4 w-4" />,
            },
            {
              value: 'restrictions',
              label: t('pages.protection.tabPathRestrictions'),
              icon: <ShieldCheck weight="duotone" className="h-4 w-4" />,
            },
          ]}
        />

        {tab === 'managed' && <ManagedRulesPanel />}
        {tab === 'custom' && <CustomRulesPanel />}
        {tab === 'cc' && <MitigationPanel />}
        {tab === 'paths' && <PathExceptionsPanel />}
        {tab === 'restrictions' && <PathRestrictionsPanel />}
      </section>

      <ConfirmDialog
        open={confirmEngineOff}
        onClose={() => {
          setConfirmEngineOff(false)
          setEngineOffAck(false)
        }}
        onConfirm={() => {
          setConfirmEngineOff(false)
          setEngineOffAck(false)
          updateSettings.mutate({ waf_enabled: false })
        }}
        tone="danger"
        title={t('pages.protection.engineOffConfirmTitle')}
        description={t('pages.protection.engineOffConfirmDescription', {
          domain: siteDomain,
        })}
        confirmLabel={t('pages.protection.engineOffConfirmCta')}
        loading={updateSettings.isPending}
        disabled={!engineOffAck}
      >
        <label className="flex items-start gap-2.5 text-[13px] pw-touch-check">
          <input
            type="checkbox"
            className="mt-0.5 rounded border-border accent-brand"
            checked={engineOffAck}
            onChange={(e) => setEngineOffAck(e.target.checked)}
          />
          <span>{t('pages.protection.engineOffAck')}</span>
        </label>
      </ConfirmDialog>
    </div>
  )
}

/**
 * The deployment-wide observation mode, reported on the engine tab.
 *
 * The switch itself is global (Settings → defense), not per site, so this card
 * only states the state and what it means: with it on, every rule on this page
 * detects but nothing is blocked.
 */
function ObservationModeCard() {
  const { t } = useTranslation()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const query = useQuery({
    queryKey: wafSettingsKeys.posture(siteId),
    queryFn: () => wafSettingsApi.posture(siteId),
    enabled: Boolean(siteId),
    staleTime: 30_000,
  })
  if (query.isPending) return <SkeletonCard className="h-16" />
  const on = query.data?.enforcement.observation_mode ?? false

  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-between gap-4 rounded-lg border px-4 py-3',
        on ? 'border-warning/45 bg-warning/10' : 'border-line bg-elevated',
      )}
    >
      <span className="flex min-w-0 items-center gap-3">
        <span
          className={cn(
            'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
            on ? 'bg-warning/15 text-fg-warning' : 'bg-recessed text-fg-subtle',
          )}
        >
          <Eye weight="duotone" className="h-5 w-5" />
        </span>
        <span className="min-w-0">
          <span className="block text-sm font-semibold text-fg-strong">
            {t('pages.protection.postureObservation')}
          </span>
          {on && (
            <span className="mt-0.5 block text-[13px] text-fg-subtle">
              {t('pages.protection.observationModeHint')}
            </span>
          )}
        </span>
      </span>
      <span className={cn('text-sm font-semibold', on ? 'text-fg-warning' : 'text-fg-subtle')}>
        {on ? t('pages.protection.postureOn') : t('pages.protection.postureOff')}
      </span>
    </div>
  )
}

/**
 * The overview's "what changed lately" list: the newest configuration versions
 * recorded for this site.
 *
 * `GET /config-versions` is administrator-only, so the card (and its request)
 * is hidden for read-only accounts. It uses its own query key on purpose: the
 * versions page caches a larger page under the shared
 * `configVersionKeys.list(siteId)` key, and reusing that key here would
 * truncate the other page's list to five rows.
 */
function RecentChangesCard({ siteId, canWrite }: { siteId: string; canWrite: boolean }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const query = useQuery({
    queryKey: ['protection', 'recent-changes', siteId] as const,
    queryFn: () => configVersionsApi.list(siteId, RECENT_CHANGES_LIMIT),
    enabled: Boolean(siteId) && canWrite,
  })

  if (!canWrite) return null
  const rows = query.data ?? []

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 pt-4">
        <h3 className="text-sm font-semibold text-fg-strong">
          {t('common.lastUpdated')}
        </h3>
        <Button size="sm" variant="secondary" onClick={() => navigate('/config-versions')}>
          {t('common.viewAll')}
        </Button>
      </div>
      <CardBody className="flex flex-col gap-2">
        {query.isPending ? (
          <SkeletonCard className="h-16" />
        ) : query.isError ? (
          <ErrorState
            error={query.error}
            onRetry={() => void query.refetch()}
            variant="inline"
          />
        ) : rows.length === 0 ? (
          <p className="text-[13px] text-fg-subtle">
            {t('pages.configVersions.emptyTitle')}
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {rows.map((row) => (
              <li
                key={row.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-line bg-recessed px-3 py-2 text-[13px]"
              >
                <span className="text-fg">{formatDateTime(row.created_at)}</span>
                <span className="text-fg-subtle">
                  {t(`pages.configVersions.sources.${row.source}`, row.source)}
                  {' · '}
                  {row.actor ?? t('pages.configVersions.actorUnknown')}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  )
}

/**
 * Site-level enforcement mode — the master switch the WAF engine runs in
 * (block > monitor > off), stored on the site's WAF settings row and shipped
 * to the data plane verbatim. Custom rules keep their per-rule mode; a
 * monitor-mode rule only downgrades its own action while the site is in
 * block. Lives on the overview: it is the site-wide downgrade switch, so it is
 * surfaced next to the posture it changes.
 */
function EnforcementModeCard() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const settingsQuery = useQuery({
    queryKey: wafSettingsKeys.settings(siteId),
    queryFn: () => wafSettingsApi.get(siteId),
    enabled: Boolean(siteId),
  })
  // Allow rules are rejected in block mode — a legacy allow+block pair stops
  // blocking the moment the site does. Warn before switching to block.
  const rulesQuery = useQuery({
    queryKey: ruleKeys.list(siteId),
    queryFn: () => rulesApi.list(siteId, { page_size: 200 }),
    enabled: Boolean(siteId),
  })
  const allowRuleCount = useMemo(
    () => (rulesQuery.data?.items ?? []).filter((r) => r.action === 'allow').length,
    [rulesQuery.data],
  )
  const loading = settingsQuery.isPending
  // The stored value is authoritative; legacy rows without it read as off.
  const mode = settingsQuery.data?.mode ?? 'off'
  const [confirmBlockWithAllow, setConfirmBlockWithAllow] = useState(false)
  // UX-04: leaving Block mode is a downgrade of enforcement (monitor only logs,
  // off disables the engine), so it needs the same explicit acknowledgement as
  // switching the engine off.
  const [confirmDowngrade, setConfirmDowngrade] = useState<RuleMode | null>(null)
  const [downgradeAck, setDowngradeAck] = useState(false)

  const applyMode = useMutation({
    mutationFn: async (next: RuleMode) => {
      await wafSettingsApi.update(siteId, { mode: next })
      return next
    },
    onSuccess: (next) => {
      toast.success(t('pages.waf.modeApplied'), t(`pages.waf.mode_${next}`))
      void queryClient.invalidateQueries({
        queryKey: wafSettingsKeys.settings(siteId),
      })
      void queryClient.invalidateQueries({
        queryKey: wafSettingsKeys.posture(siteId),
      })
      // A mode change is recorded as a configuration version, so the overview's
      // "recent changes" list is stale too.
      void queryClient.invalidateQueries({
        queryKey: ['protection', 'recent-changes', siteId],
      })
    },
    onError: (error) => {
      toast.error(
        t('pages.protection.updateFailed'),
        error instanceof Error ? error.message : undefined,
      )
    },
  })

  const requestMode = (next: RuleMode) => {
    if (
      next === 'block' &&
      mode !== 'block' &&
      allowRuleCount > 0
    ) {
      // Advisory only: the operator may proceed.
      setConfirmBlockWithAllow(true)
      return
    }
    // block > monitor > off: moving down that ladder lowers enforcement.
    const rank: Record<string, number> = { block: 2, monitor: 1, off: 0 }
    if ((rank[next] ?? 0) < (rank[mode] ?? 0)) {
      setDowngradeAck(false)
      setConfirmDowngrade(next)
      return
    }
    applyMode.mutate(next)
  }

  return (
    <Card className="mb-0 max-w-none">
      <div className="flex items-center justify-between gap-3 px-4 pt-4">
        <div>
          <h3 className="text-sm font-semibold text-fg-strong">
            {t('pages.waf.mode')}
          </h3>
          <p className="mt-0.5 text-[13px] text-fg-subtle">
            {t('pages.waf.modeCardHint')}
          </p>
        </div>
        {settingsQuery.isFetching && (
          <span className="text-xs text-fg-subtle">{t('pages.waf.applyingMode')}</span>
        )}
      </div>
      <CardBody className="flex flex-col gap-3">
        <div className="flex flex-col gap-2">
          {RULE_MODES.map((m) => {
            const active = mode === m
            return (
              <button
                key={m}
                type="button"
                disabled={!canWrite || applyMode.isPending || loading}
                onClick={() => requestMode(m as RuleMode)}
                className={cn(
                  'flex items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-all disabled:cursor-not-allowed disabled:opacity-60',
                  active
                    ? 'border-brand bg-brand-soft'
                    : 'border-line hover:border-fill hover:bg-recessed',
                )}
              >
                <span className="min-w-0">
                  <span
                    className={cn(
                      'block text-sm font-medium',
                      active ? 'text-brand' : 'text-fg',
                    )}
                  >
                    {t(`pages.waf.mode_${m}`)}
                  </span>
                  <span className="block text-xs text-fg-subtle">
                    {t(`pages.waf.modeHint_${m}`)}
                  </span>
                </span>
                {active && <ShieldCheck weight="fill" className="h-4 w-4 shrink-0 text-brand" />}
              </button>
            )
          })}
        </div>
        <div className="rounded-md border border-line bg-recessed px-3 py-2">
          <p className="text-xs leading-relaxed text-fg-subtle">
            {t('pages.waf.modeExplainer')}
          </p>
        </div>
      </CardBody>

      <ConfirmDialog
        open={confirmBlockWithAllow}
        onClose={() => setConfirmBlockWithAllow(false)}
        onConfirm={() => {
          setConfirmBlockWithAllow(false)
          applyMode.mutate('block')
        }}
        tone="danger"
        title={t('pages.waf.blockWithAllowTitle', { count: allowRuleCount })}
        description={t('pages.waf.blockWithAllowDescription', { count: allowRuleCount })}
        confirmLabel={t('pages.waf.mode_block')}
        loading={applyMode.isPending}
      />

      <ConfirmDialog
        open={confirmDowngrade !== null}
        onClose={() => {
          setConfirmDowngrade(null)
          setDowngradeAck(false)
        }}
        onConfirm={() => {
          const next = confirmDowngrade
          setConfirmDowngrade(null)
          setDowngradeAck(false)
          if (next) applyMode.mutate(next)
        }}
        tone="danger"
        title={t('pages.protection.modeDowngradeTitle', {
          mode: t(`pages.waf.mode_${confirmDowngrade ?? 'monitor'}`),
        })}
        description={t('pages.protection.modeDowngradeDescription', {
          mode: t(`pages.waf.mode_${confirmDowngrade ?? 'monitor'}`),
        })}
        confirmLabel={t(`pages.waf.mode_${confirmDowngrade ?? 'monitor'}`)}
        loading={applyMode.isPending}
        disabled={!downgradeAck}
      >
        <label className="flex items-start gap-2.5 text-[13px] pw-touch-check">
          <input
            type="checkbox"
            className="mt-0.5 rounded border-border accent-brand"
            checked={downgradeAck}
            onChange={(e) => setDowngradeAck(e.target.checked)}
          />
          <span>{t('pages.protection.modeDowngradeAck')}</span>
        </label>
      </ConfirmDialog>
    </Card>
  )
}

/**
 * Body-stage inspection budget — how long the data plane may hold a request
 * while inspecting its body before failing open. Not a downstream timeout.
 */
function BodyStageTimeoutCard({
  settings,
  canWrite,
  pending,
  onCommit,
}: {
  settings?: WafSettings
  canWrite: boolean
  pending: boolean
  onCommit: (secs: number) => void
}) {
  const { t } = useTranslation()
  const serverValue = settings?.body_stage_timeout_secs
  const committed = serverValue && serverValue > 0 ? serverValue : BODY_STAGE_TIMEOUT_DEFAULT
  // `draft === null` means "no local edit": the field renders the committed
  // value, so a settings refresh is reflected without a syncing effect.
  const [draft, setDraft] = useState<string | null>(null)
  const shown = draft ?? String(committed)

  const commit = () => {
    const next = normaliseBodyStageTimeout(shown, committed)
    if (next === null) {
      // Empty or non-numeric input: revert to the committed value, no mutation.
      setDraft(null)
      return
    }
    setDraft(String(next))
    if (next !== committed) onCommit(next)
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-line bg-elevated px-4 py-3">
      <span className="flex min-w-0 items-center gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-recessed text-fg-subtle">
          <Timer weight="duotone" className="h-5 w-5" />
        </span>
        <span className="min-w-0">
          <span className="block text-sm font-semibold text-fg-strong">
            {t('pages.waf.bodyStageTimeout')}
          </span>
          <span className="mt-0.5 block max-w-md text-[13px] text-fg-subtle">
            {t('pages.waf.bodyStageTimeoutHint')}
          </span>
        </span>
      </span>
      <Input
        type="number"
        className="w-24 text-right"
        min={BODY_STAGE_TIMEOUT_MIN}
        max={BODY_STAGE_TIMEOUT_MAX}
        step={1}
        disabled={!canWrite || pending}
        aria-label={t('pages.waf.bodyStageTimeout')}
        value={shown}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.currentTarget.blur()
          }
        }}
      />
    </div>
  )
}

/** Forwards a pre-merge route (`/security/waf`, `/security/cc`) here, query intact. */
export function LegacyProtectionRedirect({ tab }: { tab: ProtectionTab }) {
  const { siteId = '' } = useParams<{ siteId: string }>()
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  params.set('tab', tab)
  return (
    <Navigate to={`/sites/${siteId}/security/protection?${params.toString()}`} replace />
  )
}

export default ProtectionPage