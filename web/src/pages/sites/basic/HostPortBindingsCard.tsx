import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Button } from '@/components/ui/Button'
import { useToast } from '@/components/ui/Toast'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'
import { useRegisterUnsaved } from '@/hooks/useUnsavedGuard'
import type { SiteHostBinding } from '@/api/types'

interface DraftBinding {
  hostname: string
  http_port: string
  https_port: string
}

function toDraft(bindings: SiteHostBinding[]): DraftBinding[] {
  return bindings.map((binding) => ({
    hostname: binding.hostname,
    http_port: binding.http_port == null ? '' : String(binding.http_port),
    https_port: binding.https_port == null ? '' : String(binding.https_port),
  }))
}

/** Per-host listener ports for HTTP and HTTPS, synced to every edge agent. */
export function HostPortBindingsCard({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const [edited, setEdited] = useState<{ siteId: string; bindings: DraftBinding[] } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const query = useQuery({
    queryKey: siteKeys.hostBindings(siteId),
    queryFn: () => sitesApi.getHostBindings(siteId),
    enabled: Boolean(siteId),
  })

  const savedDraft = useMemo(
    () => toDraft(query.data?.bindings ?? []),
    [query.data],
  )
  const draft = edited?.siteId === siteId ? edited.bindings : savedDraft
  const dirty = Boolean(query.data) &&
    JSON.stringify(draft) !== JSON.stringify(savedDraft)
  useRegisterUnsaved(dirty)

  const rangeStart = query.data?.allowed_port_start ?? 7000
  const rangeEnd = query.data?.allowed_port_end ?? 7777
  const parsePort = (value: string) => {
    if (value.trim() === '') return null
    if (!/^\d+$/.test(value.trim())) return Number.NaN
    const port = Number(value)
    return Number.isInteger(port) && port >= 1 && port <= 65535
      ? port
      : Number.NaN
  }
  const parsed = draft.map((binding) => ({
    hostname: binding.hostname,
    http_port: parsePort(binding.http_port),
    https_port: parsePort(binding.https_port),
  }))
  const valid = parsed.every((binding) => {
    const httpValid = binding.http_port == null ||
      (Number.isFinite(binding.http_port) &&
        (binding.http_port === 80 ||
          (binding.http_port >= rangeStart && binding.http_port <= rangeEnd)))
    const httpsValid = binding.https_port == null ||
      (Number.isFinite(binding.https_port) &&
        (binding.https_port === 443 ||
          (binding.https_port >= rangeStart && binding.https_port <= rangeEnd)))
    return httpValid && httpsValid &&
      (binding.http_port != null || binding.https_port != null)
  })
  const usedHttpPorts = new Set(
    parsed.map((binding) => binding.http_port).filter((port) => port != null),
  )
  const protocolCollision = parsed.some(
    (binding) => binding.https_port != null && usedHttpPorts.has(binding.https_port),
  )

  const save = useMutation({
    mutationFn: () =>
      sitesApi.updateHostBindings(siteId, {
        bindings: parsed.map((binding) => ({
          hostname: binding.hostname,
          http_port: binding.http_port,
          https_port: binding.https_port,
        })),
      }),
    onSuccess: (result) => {
      queryClient.setQueryData(siteKeys.hostBindings(siteId), result)
      setEdited(null)
      setError(null)
      toast.success(
        result.restart_required
          ? t('pages.basic.hostBindings.savedRestart', {
              sent: result.restart_commands_sent,
              queued: result.restart_commands_queued,
            })
          : t('pages.basic.hostBindings.saved'),
      )
      void queryClient.invalidateQueries({
        queryKey: siteKeys.hostBindings(siteId),
      })
    },
    onError: (e) => setError(errorMessage(e)),
  })

  const updateDraft = (
    hostname: string,
    protocol: 'http_port' | 'https_port',
    value: string,
  ) => {
    setEdited((current) => ({
      siteId,
      bindings: (current?.siteId === siteId ? current.bindings : savedDraft).map((binding) =>
        binding.hostname === hostname
          ? { ...binding, [protocol]: value }
          : binding,
      ),
    }))
    setError(null)
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.basic.hostBindings.title')}
        description={t('pages.basic.hostBindings.description')}
      />
      <CardBody className="space-y-4">
        <p className="text-xs leading-relaxed text-fg-subtle">
          {t('pages.basic.hostBindings.rangeHint', {
            min: rangeStart,
            max: rangeEnd,
          })}
        </p>
        <p className="text-xs leading-relaxed text-fg-subtle">
          {t('pages.basic.hostBindings.restartHint')}
        </p>
        {query.isLoading ? (
          <p className="text-sm text-fg-subtle">{t('common.loading')}</p>
        ) : query.isError ? (
          <p className="text-sm text-danger">{errorMessage(query.error)}</p>
        ) : (
          <div className="space-y-3">
            {draft.map((binding) => (
              <div
                key={binding.hostname}
                className="grid gap-3 rounded-md border border-line p-3 sm:grid-cols-[minmax(12rem,1fr)_minmax(8rem,10rem)_minmax(8rem,10rem)] sm:items-end"
              >
                <div className="pb-2 text-sm font-medium text-fg-strong">
                  {binding.hostname}
                </div>
                <Input
                  type="number"
                  min={1}
                  max={65535}
                  step={1}
                  className="text-right"
                  label={t('pages.basic.hostBindings.http')}
                  placeholder={t('pages.basic.hostBindings.disabled')}
                  disabled={!canWrite || save.isPending}
                  value={binding.http_port}
                  onChange={(event) =>
                    updateDraft(binding.hostname, 'http_port', event.target.value)
                  }
                />
                <Input
                  type="number"
                  min={1}
                  max={65535}
                  step={1}
                  className="text-right"
                  label={t('pages.basic.hostBindings.https')}
                  placeholder={t('pages.basic.hostBindings.disabled')}
                  disabled={!canWrite || save.isPending}
                  value={binding.https_port}
                  onChange={(event) =>
                    updateDraft(binding.hostname, 'https_port', event.target.value)
                  }
                />
              </div>
            ))}
          </div>
        )}
        {dirty && !valid && (
          <p className="text-xs text-danger">
            {t('pages.basic.hostBindings.invalidPort', {
              min: rangeStart,
              max: rangeEnd,
            })}
          </p>
        )}
        {dirty && protocolCollision && (
          <p className="text-xs text-danger">
            {t('pages.basic.hostBindings.protocolCollision')}
          </p>
        )}
        {error && <p className="text-[13px] text-danger">{error}</p>}
        <div className="flex justify-end">
          <Button
            variant="primary"
            disabled={!canWrite || !dirty || !valid || protocolCollision || save.isPending}
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
        </div>
      </CardBody>
    </Card>
  )
}
