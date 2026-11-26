import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  ArrowRight,
  Gauge,
  ShieldCheck,
  Warning,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { useRegisterUnsaved } from '@/hooks/useUnsavedGuard'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { TagInput } from '@/components/ui/MultiSelect'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { challengeApi, challengeKeys, defaultChallengeConfig } from '@/api/challenge'
import {
  MAX_DIFFICULTY,
  MAX_LIMIT_PER_MIN,
  MIN_DIFFICULTY,
  MIN_LIMIT_PER_MIN,
  validatePow,
} from '@/lib/challengePow'
import { rateLimitApi, rateLimitKeys } from '@/api/rateLimiting'
import { useCanWrite } from '@/hooks'
import { cn } from '@/lib/utils'
import { CHALLENGE_LEVELS, type ChallengeConfig } from '@/api/types'

const MIN_CLEARANCE_SECS = 60
const MAX_CLEARANCE_SECS = 86_400

/** Bounds mirrored from the server's `exempt_paths` validation. */
const EXEMPT_PATHS_MAX_COUNT = 100
const EXEMPT_PATH_MAX_LENGTH = 512

/**
 * Mirrors the server-side `exempt_paths` checks: each entry must start with
 * `/`, contain no whitespace or control characters, be at most 512 characters,
 * and the list at most 100 entries. Returns an i18n key suffix or `null`.
 */
function validateExemptPaths(paths: string[]): string | null {
  if (paths.length > EXEMPT_PATHS_MAX_COUNT) return 'tooMany'
  for (const p of paths) {
    if (p.length > EXEMPT_PATH_MAX_LENGTH) return 'tooLong'
    if (!p.startsWith('/')) return 'invalid'
    // Whitespace plus C0 control characters and DEL, spelled out via code
    // points (an explicit control-character regex trips ESLint's
    // `no-control-regex`).
    const hasControlOrSpace = [...p].some((ch) => {
      const cp = ch.codePointAt(0) ?? 0
      return /\s/.test(ch) || cp <= 0x1f || cp === 0x7f
    })
    if (hasControlOrSpace) return 'invalid'
  }
  return null
}

/**
 * The mitigation module of the protection page ("Rate limiting & challenge"):
 * an entry card into the dedicated rate-limiting page, the site's emergency
 * under-attack switch, and the challenge configuration.
 *
 * Under-attack mode used to live in the page-level detection section; it is a
 * challenge control, so it belongs on this tab. It stays a separate card
 * rather than a field of the challenge form so the two controls cannot fight
 * each other (the server forces the gate on while under-attack is on).
 */
export function MitigationPanel() {
  const { siteId = '' } = useParams<{ siteId: string }>()
  return (
    <div className="flex flex-col gap-4">
      <RateLimitingEntryCard siteId={siteId} />
      <UnderAttackCard siteId={siteId} />
      <ChallengeConfigCard siteId={siteId} />
    </div>
  )
}

/**
 * Under Attack Mode: challenge every visitor while an attack is in progress.
 *
 * Enabling is a deliberate emergency action (every visitor is challenged), so
 * it goes through a confirmation; disabling is immediate. Turning it on also
 * forces the challenge gate on — the server applies the same pairing.
 */
function UnderAttackCard({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const [confirmEnable, setConfirmEnable] = useState(false)

  const configQuery = useQuery({
    queryKey: challengeKeys.config(siteId),
    queryFn: () => challengeApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const active = configQuery.data?.under_attack_mode ?? false

  const setUnderAttack = useMutation({
    mutationFn: (enabled: boolean) =>
      challengeApi.update(siteId, {
        // The challenge gate must be on for the banner to mean anything; the
        // server forces the same pairing.
        under_attack_mode: enabled,
        ...(enabled ? { enabled: true } : {}),
      }),
    onSuccess: (saved) => {
      queryClient.setQueryData(challengeKeys.config(siteId), saved)
      toast.success(
        saved.under_attack_mode
          ? t('pages.protection.underAttackOn')
          : t('pages.protection.underAttackOff'),
      )
      void queryClient.invalidateQueries({ queryKey: challengeKeys.all(siteId) })
    },
    onError: (error) => {
      toast.error(
        t('pages.protection.updateFailed'),
        error instanceof Error ? error.message : undefined,
      )
    },
  })

  if (configQuery.isPending) return <SkeletonCard className="h-20" />

  return (
    <Card>
      <CardBody
        className={cn(
          'flex flex-wrap items-center justify-between gap-4',
          active && 'rounded-lg bg-danger/10',
        )}
      >
        <span className="flex min-w-0 items-center gap-3">
          <span
            className={cn(
              'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
              active
                ? 'bg-danger/15 text-fg-danger'
                : 'bg-recessed text-fg-subtle',
            )}
          >
            {active ? (
              <Warning weight="fill" className="h-5 w-5" />
            ) : (
              <ShieldCheck weight="duotone" className="h-5 w-5" />
            )}
          </span>
          <span className="min-w-0">
            <span className="block text-sm font-semibold text-fg-strong">
              {active
                ? t('pages.protection.underAttackActive')
                : t('pages.protection.underAttackTitle')}
            </span>
            <span className="mt-0.5 block text-[13px] text-fg-subtle">
              {active
                ? t('pages.protection.underAttackActiveHint')
                : t('pages.protection.underAttackHint')}
            </span>
          </span>
        </span>
        {canWrite && (
          <Switch
            size="md"
            checked={active}
            disabled={setUnderAttack.isPending}
            aria-label={t('pages.protection.underAttackTitle')}
            onCheckedChange={(enabled) => {
              if (enabled) {
                setConfirmEnable(true)
              } else {
                setUnderAttack.mutate(false)
              }
            }}
          />
        )}
      </CardBody>

      <ConfirmDialog
        open={confirmEnable}
        onClose={() => setConfirmEnable(false)}
        onConfirm={() => {
          setConfirmEnable(false)
          setUnderAttack.mutate(true)
        }}
        tone="danger"
        title={t('pages.protection.underAttackConfirmTitle')}
        description={t('pages.protection.underAttackConfirmDescription')}
        confirmLabel={t('pages.protection.underAttackCta')}
        loading={setUnderAttack.isPending}
      />
    </Card>
  )
}

/** Shortcut to the rate-limiting page, with a live count of that site's rules. */
function RateLimitingEntryCard({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const navigate = useNavigate()

  const rulesQuery = useQuery({
    queryKey: rateLimitKeys.list(siteId),
    queryFn: () => rateLimitApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const rules = rulesQuery.data?.items ?? []
  const enabled = rules.filter((r) => r.enabled).length

  return (
    <Card>
      <CardBody className="flex flex-wrap items-center gap-4">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-recessed text-fg-subtle">
          <Gauge weight="duotone" className="h-5 w-5" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-fg-strong">
            {t('pages.protection.rateLimitingEntry.title')}
          </span>
          <span className="mt-0.5 block text-[13px] text-fg-subtle">
            {t('pages.protection.rateLimitingEntry.description')}
          </span>
          {!rulesQuery.isPending && !rulesQuery.isError && rules.length > 0 && (
            <span className="mt-1 block text-xs text-fg-subtle">
              {t('pages.protection.rateLimitingEntry.ruleCount', {
                enabled,
                total: rules.length,
              })}
            </span>
          )}
        </span>
        <Button
          variant="secondary"
          onClick={() => navigate(`/sites/${siteId}/security/rate-limiting`)}
          icon={<ArrowRight weight="duotone" className="h-4 w-4" />}
        >
          {t('pages.protection.rateLimitingEntry.cta')}
        </Button>
      </CardBody>
    </Card>
  )
}

function ChallengeConfigCard({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const [config, setConfig] = useState<ChallengeConfig | null>(null)
  const [dirty, setDirty] = useState(false)
  // UX-04: the challenge gate is the site's CC protection; turning it off is a
  // protection downgrade, so it needs an explicit acknowledgement.
  const [confirmDisable, setConfirmDisable] = useState(false)
  const [disableAck, setDisableAck] = useState(false)

  const configQuery = useQuery({
    queryKey: challengeKeys.config(siteId),
    queryFn: () => challengeApi.get(siteId),
    enabled: Boolean(siteId),
  })

  // Seed the form from the query (render-phase reset on new data / first
  // failure), so nothing flashes stale values on the first paint.
  const serverConfig = configQuery.data
  const loadFailed = configQuery.isError && Boolean(siteId)
  // `null` until the first seed: cached query data present at mount must still
  // reach the form.
  const [sync, setSync] = useState<{ config: typeof serverConfig; failed: boolean } | null>(null)
  if (!sync || sync.config !== serverConfig || sync.failed !== loadFailed) {
    setSync({ config: serverConfig, failed: loadFailed })
    if (serverConfig) {
      setConfig(serverConfig)
      setDirty(false)
    } else if (loadFailed) {
      setConfig(defaultChallengeConfig())
    }
  }

  const patch = (part: Partial<ChallengeConfig>) => {
    setConfig((c) => (c ? { ...c, ...part } : c))
    setDirty(true)
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: challengeKeys.all(siteId) })
  }

  const save = useMutation({
    mutationFn: (payload: ChallengeConfig) =>
      challengeApi.update(siteId, {
        enabled: payload.enabled,
        default_level: payload.default_level,
        clearance_duration_secs: payload.clearance_duration_secs,
        rate_threshold: payload.rate_threshold,
        exempt_paths: payload.exempt_paths,
        browser_integrity_check: payload.browser_integrity_check,
        tls_fingerprint_check: payload.tls_fingerprint_check,
        base_difficulty: payload.base_difficulty,
        max_difficulty: payload.max_difficulty,
        issue_limit_per_min: payload.issue_limit_per_min,
        verify_limit_per_min: payload.verify_limit_per_min,
      }),
    onSuccess: (saved) => {
      setConfig(saved)
      setDirty(false)
      toast.success(t('pages.cc.saved'))
      invalidate()
    },
  })

  useRegisterUnsaved(dirty)

  if (configQuery.isPending) {
    return <SkeletonCard className="h-64" />
  }
  if (configQuery.isError && !config) {
    return (
      <ErrorState
        error={configQuery.error}
        onRetry={() => configQuery.refetch()}
        retrying={configQuery.isFetching}
      />
    )
  }

  const exemptPathsIssue = config ? validateExemptPaths(config.exempt_paths) : null
  const powIssue = config ? validatePow(config) : null

  return (
    <div>
      {config ? (
        <div className="flex flex-col gap-4">
          {/* Under-attack mode is a sibling card on this tab, not a field of
              this form, so the two controls cannot fight each other. */}
          <Card>
            <CardHeader
              title={t('pages.cc.general')}
              action={
                <span className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    loading={configQuery.isFetching}
                    onClick={() => configQuery.refetch()}
                    icon={<ArrowClockwise weight="duotone" className="h-3.5 w-3.5" />}
                  >
                    {t('common.refresh')}
                  </Button>
                  {canWrite && (
                    <Button
                      size="sm"
                      variant="primary"
                      disabled={
                        !dirty ||
                        save.isPending ||
                        exemptPathsIssue !== null ||
                        powIssue !== null
                      }
                      loading={save.isPending}
                      onClick={() => config && save.mutate(config)}
                    >
                      {t('common.save')}
                    </Button>
                  )}
                </span>
              }
            />
            <CardBody className="flex flex-col gap-5">
              <Switch
                checked={config.enabled}
                disabled={!canWrite}
                onCheckedChange={(enabled) => {
                  if (enabled) {
                    patch({ enabled: true })
                    return
                  }
                  setDisableAck(false)
                  setConfirmDisable(true)
                }}
                label={t('pages.cc.enable')}
                description={t('pages.cc.enableHint')}
              />
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <Select
                  label={t('pages.cc.challengeLevel')}
                  value={config.default_level}
                  disabled={!canWrite || !config.enabled}
                  options={CHALLENGE_LEVELS.map((l) => ({
                    value: l,
                    label: t(`challengeLevels.${l}`, l),
                  }))}
                  onChange={(e) => patch({ default_level: e.target.value })}
                />
                <Input
                  type="number"
                  label={t('pages.cc.clearanceDuration')}
                  value={Math.round(config.clearance_duration_secs / 60)}
                  min={MIN_CLEARANCE_SECS / 60}
                  max={MAX_CLEARANCE_SECS / 60}
                  disabled={!canWrite || !config.enabled}
                  hint={t('pages.cc.minutes')}
                  onChange={(e) =>
                    patch({
                      clearance_duration_secs: Math.min(
                        MAX_CLEARANCE_SECS,
                        Math.max(MIN_CLEARANCE_SECS, Number(e.target.value) * 60),
                      ),
                    })
                  }
                />
                <Input
                  type="number"
                  label={t('pages.cc.rateThreshold')}
                  value={config.rate_threshold}
                  min={1}
                  disabled={!canWrite || !config.enabled}
                  hint={t('pages.cc.rateThresholdHint')}
                  onChange={(e) => patch({ rate_threshold: Number(e.target.value) })}
                />
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t('pages.cc.pow')}
              description={t('pages.cc.powHint')}
            />
            <CardBody className="flex flex-col gap-5">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Input
                  type="number"
                  label={t('pages.cc.baseDifficulty')}
                  value={config.base_difficulty}
                  min={MIN_DIFFICULTY}
                  max={MAX_DIFFICULTY}
                  disabled={!canWrite || !config.enabled}
                  hint={t('pages.cc.baseDifficultyHint')}
                  onChange={(e) => patch({ base_difficulty: Number(e.target.value) })}
                />
                <Input
                  type="number"
                  label={t('pages.cc.maxDifficulty')}
                  value={config.max_difficulty}
                  min={MIN_DIFFICULTY}
                  max={MAX_DIFFICULTY}
                  disabled={!canWrite || !config.enabled}
                  hint={t('pages.cc.maxDifficultyHint')}
                  onChange={(e) => patch({ max_difficulty: Number(e.target.value) })}
                />
                <Input
                  type="number"
                  label={t('pages.cc.issueLimit')}
                  value={config.issue_limit_per_min}
                  min={MIN_LIMIT_PER_MIN}
                  max={MAX_LIMIT_PER_MIN}
                  disabled={!canWrite || !config.enabled}
                  hint={t('pages.cc.issueLimitHint')}
                  onChange={(e) => patch({ issue_limit_per_min: Number(e.target.value) })}
                />
                <Input
                  type="number"
                  label={t('pages.cc.verifyLimit')}
                  value={config.verify_limit_per_min}
                  min={MIN_LIMIT_PER_MIN}
                  max={MAX_LIMIT_PER_MIN}
                  disabled={!canWrite || !config.enabled}
                  hint={t('pages.cc.verifyLimitHint')}
                  onChange={(e) => patch({ verify_limit_per_min: Number(e.target.value) })}
                />
              </div>
              {powIssue && (
                <p className="text-xs text-fg-danger">{t(`pages.cc.pow_${powIssue}`)}</p>
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t('pages.cc.checks')}
              description={t('pages.cc.checksHint')}
            />
            <CardBody className="flex flex-col gap-5">
              <Switch
                checked={config.browser_integrity_check}
                disabled={!canWrite || !config.enabled}
                onCheckedChange={(browser_integrity_check) => patch({ browser_integrity_check })}
                label={t('pages.cc.browserIntegrity')}
                description={t('pages.cc.browserIntegrityHint')}
              />
              <Switch
                checked={config.tls_fingerprint_check}
                disabled={!canWrite || !config.enabled}
                onCheckedChange={(tls_fingerprint_check) => patch({ tls_fingerprint_check })}
                label={t('pages.cc.tlsFingerprint')}
                description={t('pages.cc.tlsFingerprintHint')}
              />
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t('pages.cc.exemptPaths')}
              description={t('pages.cc.exemptPathsHint')}
              action={
                <span className="flex items-center gap-1.5 text-xs text-fg-subtle">
                  {config.exempt_paths.length}
                </span>
              }
            />
            <CardBody>
              <TagInput
                value={config.exempt_paths}
                disabled={!canWrite || !config.enabled}
                placeholder="/health"
                suggestions={['/health', '/status', '/api/heartbeat']}
                onChange={(exempt_paths) => patch({ exempt_paths })}
              />
              {exemptPathsIssue && (
                <p className="mt-2 text-xs text-fg-danger">
                  {t(`pages.cc.exemptPaths_${exemptPathsIssue}`)}
                </p>
              )}
            </CardBody>
          </Card>
        </div>
      ) : null}

      <ConfirmDialog
        open={confirmDisable}
        onClose={() => {
          setConfirmDisable(false)
          setDisableAck(false)
        }}
        onConfirm={() => {
          setConfirmDisable(false)
          setDisableAck(false)
          patch({ enabled: false })
        }}
        tone="danger"
        title={t('pages.cc.disableConfirmTitle')}
        description={t('pages.cc.disableConfirmDescription')}
        confirmLabel={t('pages.cc.disableConfirmTitle')}
        disabled={!disableAck}
      >
        <label className="flex items-start gap-2.5 text-[13px] pw-touch-check">
          <input
            type="checkbox"
            className="mt-0.5 rounded border-border accent-brand"
            checked={disableAck}
            onChange={(e) => setDisableAck(e.target.checked)}
          />
          <span>{t('pages.cc.disableAck')}</span>
        </label>
      </ConfirmDialog>
    </div>
  )
}

export default MitigationPanel
