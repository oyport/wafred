import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  Copy,
  Gear,
  PencilSimple,
  Plus,
  Prohibit,
  Trash,
  Warning,
} from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody } from '@/components/ui/Card'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { Input } from '@/components/ui/Input'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { Table, type Column } from '@/components/ui/Table'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { errorMessage } from '@/api/errors'
import { tunnelKeys, tunnelsApi } from '@/api/tunnels'
import type { Tunnel, TunnelPairing, TunnelSettings } from '@/api/types'
import { useCanWrite, useNow } from '@/hooks'
import { cn } from '@/lib/utils'
import { formatDateTime, formatRelative } from '@/lib/format'

/** 30s — the tunnel list is a live status view, like the agent inventory. */
const REFRESH_MS = 30_000

const STATUS_TONE: Record<string, 'success' | 'warning' | 'neutral' | 'danger'> = {
  active: 'success',
  pending: 'warning',
  disabled: 'neutral',
}

/**
 * The state a row actually is in.
 *
 * `status` alone is not enough: a tunnel that was never paired is `pending`,
 * and one whose credential was revoked goes back to `pending` too — rendering
 * `status` verbatim as "Paired" would claim a connector that cannot connect.
 * `paired` is the field that answers "is there a credential at all".
 */
function stateOf(tunnel: Tunnel): 'active' | 'pending' | 'disabled' {
  if (!tunnel.paired) return 'pending'
  if (tunnel.status === 'disabled' || !tunnel.enabled) return 'disabled'
  return 'active'
}

/**
 * Tunnel connectors, managed next to the edge agents.
 *
 * A tunnel is the way a service inside a private network is reached without
 * opening a port: the connector dials out to the edge, and the site's origin
 * pool is bound to it. Creating one here is a pairing operation — the console
 * mints a one-time token and shows the command that installs the connector.
 */
interface TunnelsTabProps {
  /** Owned by the page so the shared header can open the create dialog. */
  createOpen: boolean
  onCreateOpenChange: (open: boolean) => void
}

export function TunnelsTab({
  createOpen,
  onCreateOpenChange,
}: TunnelsTabProps) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const now = useNow(15_000)

  const [pairing, setPairing] = useState<TunnelPairing | null>(null)
  const [detail, setDetail] = useState<Tunnel | null>(null)
  const [renaming, setRenaming] = useState<Tunnel | null>(null)
  const [renameValue, setRenameValue] = useState('')
  const [pendingDelete, setPendingDelete] = useState<Tunnel | null>(null)
  const [pendingRevoke, setPendingRevoke] = useState<Tunnel | null>(null)
  const [pendingRepair, setPendingRepair] = useState<Tunnel | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)

  const listQuery = useQuery({
    queryKey: tunnelKeys.list(),
    queryFn: () => tunnelsApi.list(),
    refetchInterval: REFRESH_MS,
  })
  const tunnels = useMemo(() => listQuery.data?.items ?? [], [listQuery.data])
  // The detail dialog must follow the 30s refresh, not the row object captured
  // when it was opened: an operator watching "Edges 0" turn into "Edges 1"
  // would otherwise never see it change.
  const liveDetail = detail ? (tunnels.find((item) => item.id === detail.id) ?? detail) : null
  const settingsQuery = useQuery({
    queryKey: tunnelKeys.settings(),
    queryFn: () => tunnelsApi.settings(),
    enabled: canWrite,
    staleTime: 60_000,
  })
  const tunnelsDisabled = settingsQuery.data ? !settingsQuery.data.enabled : false

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: tunnelKeys.all })
  }

  const copyText = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success(t('pages.tunnels.copied'))
    } catch {
      toast.error(t('pages.tunnels.copyFailed'))
    }
  }

  const update = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { name?: string; description?: string; status?: string } }) =>
      tunnelsApi.update(id, data),
    onSuccess: () => invalidate(),
    onError: (error) => toast.error(errorMessage(error)),
  })

  const remove = useMutation({
    mutationFn: (id: string) => tunnelsApi.remove(id, true),
    onSuccess: () => {
      toast.success(t('pages.tunnels.removed'))
      setPendingDelete(null)
      setDetail(null)
      invalidate()
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const revoke = useMutation({
    mutationFn: (id: string) => tunnelsApi.revoke(id),
    onSuccess: () => {
      toast.success(t('pages.tunnels.revoked'))
      setPendingRevoke(null)
      setDetail(null)
      invalidate()
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const rotate = useMutation({
    mutationFn: (id: string) => tunnelsApi.pairing(id),
    onSuccess: (data) => {
      setPairing(data)
      setDetail(null)
      invalidate()
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const columns: Column<Tunnel>[] = [
    {
      key: 'name',
      header: t('common.name'),
      accessor: (tunnel) => tunnel.name,
      sortable: true,
      cell: (tunnel) => (
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-fg-strong">{tunnel.name}</p>
          {tunnel.description ? (
            <p className="truncate text-xs text-fg-subtle">{tunnel.description}</p>
          ) : (
            <p className="pw-mono truncate text-xs text-fg-subtle">{tunnel.id.slice(0, 8)}</p>
          )}
        </div>
      ),
    },
    {
      key: 'status',
      header: t('common.status'),
      accessor: (tunnel) => tunnel.status,
      cell: (tunnel) => (
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge tone={STATUS_TONE[stateOf(tunnel)] ?? 'neutral'}>
            {t(`pages.tunnels.status_${stateOf(tunnel)}`, stateOf(tunnel))}
          </Badge>
          {tunnelsDisabled && tunnel.status !== 'disabled' && (
            <Badge tone="neutral">{t('pages.tunnels.disabledGlobally')}</Badge>
          )}
          {tunnel.connector_online ? (
            <Badge tone="success">{t('pages.tunnels.connectorOnline')}</Badge>
          ) : (
            <Badge tone="neutral">{t('pages.tunnels.connectorOffline')}</Badge>
          )}
        </div>
      ),
    },
    {
      key: 'targets',
      header: t('pages.tunnels.targets'),
      accessor: (tunnel) => tunnel.targets.length,
      cell: (tunnel) =>
        tunnel.targets.length === 0 ? (
          <span className="text-[13px] text-fg-subtle" title={t('pages.tunnels.noTargetsHint')}>
            {t('pages.tunnels.noTargets')}
          </span>
        ) : (
          <span className="pw-mono text-[13px] text-fg" title={tunnel.targets.join('\n')}>
            {tunnel.targets.length}
          </span>
        ),
    },
    {
      key: 'edges',
      header: t('pages.tunnels.edges'),
      accessor: (tunnel) => tunnel.sessions.length,
      cell: (tunnel) => (
        <span
          className={cn(
            'tabular-nums text-[13px]',
            tunnel.sessions.length > 0 ? 'text-fg' : 'text-fg-subtle',
          )}
          title={tunnel.sessions.map((session) => session.agent_name).join('\n')}
        >
          {tunnel.sessions.length}
        </span>
      ),
    },
    {
      key: 'lastSeen',
      header: t('pages.tunnels.lastSeen'),
      accessor: (tunnel) => tunnel.last_seen_at ?? '',
      cell: (tunnel) => (
        <span className="text-[13px] text-fg-subtle">
          {tunnel.last_seen_at ? formatRelative(tunnel.last_seen_at, now) : '—'}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (tunnel) => (
        <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          {canWrite && (
            <>
              <Button
                size="sm"
                variant="ghost"
                title={t('pages.tunnels.repair')}
                onClick={() => setPendingRepair(tunnel)}
              >
                {t('pages.tunnels.repair')}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                title={t('common.rename')}
                aria-label={t('common.rename')}
                onClick={() => {
                  setRenameValue(tunnel.name)
                  setRenaming(tunnel)
                }}
              >
                <PencilSimple weight="duotone" className="h-4 w-4" />
              </Button>
              <Button
                size="sm"
                variant="ghost"
                title={
                  tunnel.status === 'disabled'
                    ? t('pages.tunnels.enable')
                    : t('pages.tunnels.disable')
                }
                aria-label={
                  tunnel.status === 'disabled'
                    ? t('pages.tunnels.enable')
                    : t('pages.tunnels.disable')
                }
                onClick={() =>
                  update.mutate({
                    id: tunnel.id,
                    data: { status: tunnel.status === 'disabled' ? 'active' : 'disabled' },
                  })
                }
              >
                {tunnel.status === 'disabled' ? (
                  <ArrowClockwise weight="duotone" className="h-4 w-4" />
                ) : (
                  <Prohibit weight="duotone" className="h-4 w-4" />
                )}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                title={t('pages.tunnels.revoke')}
                onClick={() => setPendingRevoke(tunnel)}
              >
                {t('pages.tunnels.revoke')}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="text-fg-danger"
                title={t('common.delete')}
                aria-label={t('common.delete')}
                onClick={() => setPendingDelete(tunnel)}
              >
                <Trash weight="duotone" className="h-4 w-4" />
              </Button>
            </>
          )}
        </div>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      {!listQuery.isLoading && tunnels.length > 0 && !tunnels[0]?.ingress?.length && (
        <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] leading-relaxed text-fg">
          <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
          <span>{t('pages.tunnels.noIngressBanner')}</span>
        </div>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-[13px] leading-relaxed text-fg-subtle">
          {t('pages.tunnels.description')}
        </p>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            loading={listQuery.isFetching}
            onClick={() => listQuery.refetch()}
            icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
          >
            {t('common.refresh')}
          </Button>
          {canWrite && (
            <Button
              variant="secondary"
              icon={<Gear weight="duotone" className="h-4 w-4" />}
              onClick={() => setSettingsOpen(true)}
            >
              {t('pages.tunnels.settings')}
            </Button>
          )}
        </div>
      </div>

      {tunnelsDisabled && (
        <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] leading-relaxed text-fg">
          <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
          {t('pages.tunnels.disabledBanner')}
        </p>
      )}

      {listQuery.isError && !listQuery.data ? (
        <ErrorState
          error={listQuery.error}
          onRetry={() => listQuery.refetch()}
          retrying={listQuery.isFetching}
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            {listQuery.isPending ? (
              <SkeletonRows rows={4} columns={5} />
            ) : tunnels.length === 0 ? (
              <EmptyState
                className="py-14"
                icon={<Prohibit weight="duotone" className="h-8 w-8" />}
                title={t('pages.tunnels.empty')}
                description={t('pages.tunnels.emptyDescription')}
                action={
                  canWrite ? (
                    <Button
                      variant="primary"
                      icon={<Plus weight="bold" className="h-4 w-4" />}
                      onClick={() => onCreateOpenChange(true)}
                    >
                      {t('pages.tunnels.create')}
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <Table
                columns={columns}
                data={tunnels}
                rowKey={(tunnel) => tunnel.id}
                onRowClick={(tunnel) => setDetail(tunnel)}
              />
            )}
          </CardBody>
        </Card>
      )}

      {/* Create → pairing command */}
      <CreateTunnelDialog
        open={createOpen}
        onClose={() => onCreateOpenChange(false)}
        onPaired={(result) => {
          onCreateOpenChange(false)
          setPairing(result)
          invalidate()
        }}
      />

      <PairingDialog
        pairing={pairing}
        onClose={() => setPairing(null)}
        onCopy={copyText}
      />

      {/* Detail */}
      <Dialog
        open={detail !== null}
        onClose={() => setDetail(null)}
        size="lg"
        title={liveDetail?.name}
        description={liveDetail?.description ?? undefined}
        footer={
          <Button variant="ghost" onClick={() => setDetail(null)}>
            {t('common.close')}
          </Button>
        }
      >
        {liveDetail && (
          <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-2">
              <Badge tone={STATUS_TONE[stateOf(liveDetail)] ?? 'neutral'}>
                {t(`pages.tunnels.status_${stateOf(liveDetail)}`, stateOf(liveDetail))}
              </Badge>
              <Badge tone={liveDetail.connector_online ? 'success' : 'neutral'}>
                {liveDetail.connector_online
                  ? t('pages.tunnels.connectorOnline')
                  : t('pages.tunnels.connectorOffline')}
              </Badge>
              {liveDetail.connector_version && (
                <span className="pw-mono text-xs text-fg-subtle">{liveDetail.connector_version}</span>
              )}
              {liveDetail.connector_hostname && (
                <span className="pw-mono text-xs text-fg-subtle">{liveDetail.connector_hostname}</span>
              )}
            </div>

            <div>
              <p className="mb-1.5 text-[13px] font-medium text-fg">
                {t('pages.tunnels.ingress')}
              </p>
              {(liveDetail.ingress ?? []).length === 0 ? (
                <p className="text-xs text-fg-subtle">
                  {t('pages.tunnels.noIngressShort')}
                </p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {(liveDetail.ingress ?? []).map((endpoint) => (
                    <Badge key={endpoint} tone="neutral">
                      {endpoint}
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            <div>
              <p className="mb-1.5 text-[13px] font-medium text-fg">
                {t('pages.tunnels.usedBy')}
              </p>
              {(liveDetail.sites ?? []).length === 0 ? (
                <p className="text-xs text-fg-subtle">
                  {t('pages.tunnels.usedByNone')}
                </p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {(liveDetail.sites ?? []).map((domain) => (
                    <Badge key={domain} tone="neutral">
                      {domain}
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            <div>
              <p className="mb-1.5 text-[13px] font-medium text-fg">
                {t('pages.tunnels.targets')}
              </p>
              {liveDetail.targets.length === 0 ? (
                <div className="flex flex-col gap-1.5">
                  <p className="rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-xs leading-relaxed text-fg">
                    {t('pages.tunnels.noTargetsHint')}
                  </p>
                  <p className="text-xs leading-relaxed text-fg-subtle">
                    {t('pages.tunnels.targetsHint')}
                  </p>
                </div>
              ) : (
                <ul className="divide-y divide-line rounded-md border border-line">
                  {liveDetail.targets.map((target) => (
                    <li key={target} className="pw-mono px-3 py-2 text-xs text-fg">
                      {target}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <p className="mb-1.5 text-[13px] font-medium text-fg">
                {t('pages.tunnels.edges')}
              </p>
              {liveDetail.sessions.length === 0 ? (
                <div className="flex flex-col gap-1.5">
                  <p className="text-xs text-fg-subtle">{t('pages.tunnels.noSessions')}</p>
                  <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-xs leading-relaxed text-fg">
                    <Warning
                      weight="duotone"
                      className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning"
                    />
                    <span>{t('pages.tunnels.noIngressHint')}</span>
                  </p>
                </div>
              ) : (
                <ul className="divide-y divide-line rounded-md border border-line">
                  {liveDetail.sessions.map((session) => (
                    <li
                      key={session.agent_id}
                      className="flex flex-wrap items-center justify-between gap-2 px-3 py-2"
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-[13px] text-fg">{session.agent_name}</span>
                        <span className="pw-mono block truncate text-xs text-fg-subtle">
                          {session.hostname ?? session.agent_id}
                          {session.version ? ` · ${session.version}` : ''}
                        </span>
                      </span>
                      <span className="text-xs text-fg-subtle">
                        {t('pages.tunnels.streams', { count: session.streams_active })}
                        {session.rtt_ms > 0 ? ` · ${session.rtt_ms} ms` : ''}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <p className="text-xs text-fg-subtle">
              {t('pages.tunnels.createdAt')}: {formatDateTime(liveDetail.created_at)}
              {' · '}
              {t('pages.tunnels.lastSeen')}:{' '}
              {liveDetail.last_seen_at ? formatDateTime(liveDetail.last_seen_at) : '—'}
            </p>
          </div>
        )}
      </Dialog>

      {/* Rename */}
      <Dialog
        open={renaming !== null}
        onClose={() => setRenaming(null)}
        size="md"
        title={t('pages.tunnels.renameTitle')}
        footer={
          <>
            <Button variant="ghost" onClick={() => setRenaming(null)}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              loading={update.isPending}
              onClick={() => {
                if (!renaming) return
                update.mutate(
                  { id: renaming.id, data: { name: renameValue.trim() } },
                  {
                    onSuccess: () => {
                      toast.success(t('pages.tunnels.renamed'))
                      setRenaming(null)
                    },
                  },
                )
              }}
            >
              {t('common.save')}
            </Button>
          </>
        }
      >
        <Input
          label={t('common.name')}
          value={renameValue}
          autoFocus
          maxLength={120}
          onChange={(e) => setRenameValue(e.target.value)}
        />
      </Dialog>

      <ConfirmDialog
        open={pendingRepair !== null}
        onClose={() => setPendingRepair(null)}
        onConfirm={() => pendingRepair && rotate.mutate(pendingRepair.id)}
        tone="danger"
        title={t('pages.tunnels.repairTitle')}
        description={t('pages.tunnels.repairDescription')}
        confirmLabel={t('pages.tunnels.repair')}
        loading={rotate.isPending}
      />

      <ConfirmDialog
        open={pendingRevoke !== null}
        onClose={() => setPendingRevoke(null)}
        onConfirm={() => pendingRevoke && revoke.mutate(pendingRevoke.id)}
        tone="danger"
        title={t('pages.tunnels.revokeTitle')}
        description={t('pages.tunnels.revokeDescription')}
        confirmLabel={t('pages.tunnels.revoke')}
        loading={revoke.isPending}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        tone="danger"
        title={t('pages.tunnels.deleteTitle')}
        description={t('pages.tunnels.deleteDescription', {
          count: pendingDelete?.sites?.length ?? 0,
        })}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
      />

      <TunnelSettingsDialog
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
      />
    </div>
  )
}

/** Create a tunnel and show the pairing command it returns. */
function CreateTunnelDialog({
  open,
  onClose,
  onPaired,
}: {
  open: boolean
  onClose: () => void
  onPaired: (pairing: TunnelPairing) => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  const create = useMutation({
    mutationFn: () =>
      tunnelsApi.create({
        name: name.trim(),
        description: description.trim() || undefined,
      }),
    onSuccess: (data) => {
      setName('')
      setDescription('')
      onPaired(data)
    },
  })

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="md"
      title={t('pages.tunnels.createTitle')}
      description={t('pages.tunnels.createDescription')}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={name.trim().length === 0}
            onClick={() => create.mutate()}
          >
            {t('pages.tunnels.create')}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {create.isError && <ErrorState variant="inline" error={create.error} />}
        <Input
          label={t('common.name')}
          value={name}
          autoFocus
          maxLength={120}
          placeholder={t('pages.tunnels.namePlaceholder')}
          onChange={(e) => setName(e.target.value)}
        />
        <Input
          label={t('pages.tunnels.descriptionLabel')}
          value={description}
          maxLength={500}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
    </Dialog>
  )
}

/** The one-time pairing command, with a warning that it cannot be shown again. */
function PairingDialog({
  pairing,
  onClose,
  onCopy,
}: {
  pairing: TunnelPairing | null
  onClose: () => void
  onCopy: (value: string) => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog
      open={pairing !== null}
      onClose={onClose}
      // The token in here is shown exactly once: a stray overlay click or Esc
      // would destroy it. Only the explicit Done button closes this dialog.
      dismissible={false}
      size="lg"
      title={t('pages.tunnels.pairingTitle')}
      description={pairing?.tunnel.name}
      footer={
        <Button variant="primary" onClick={onClose}>
          {t('pages.tunnels.done')}
        </Button>
      }
    >
      {pairing && (
        <div className="flex flex-col gap-4">
          <p className="text-[13px] leading-relaxed text-fg-subtle">
            {t('pages.tunnels.pairingIntro')}
          </p>
          <div className="rounded-md border border-line bg-recessed">
            <div className="flex items-center justify-between gap-2 border-b border-line px-3 py-2">
              <span className="text-xs font-medium text-fg-subtle">
                {t('pages.tunnels.pairingCommand')}
              </span>
              <Button
                size="sm"
                variant="ghost"
                icon={<Copy weight="duotone" className="h-4 w-4" />}
                onClick={() => onCopy(pairing.pairing_command)}
              >
                {t('common.copy')}
              </Button>
            </div>
            <pre className="overflow-x-auto px-3 py-2 text-xs leading-relaxed text-fg">
              <code className="pw-mono whitespace-pre-wrap break-all">
                {pairing.pairing_command}
              </code>
            </pre>
          </div>
          <p className="flex items-start gap-2 rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-xs leading-relaxed text-fg">
            <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
            <span>{t('pages.tunnels.pairingOnce', { expires: formatDateTime(pairing.expires_at) })}</span>
          </p>
          <p className="text-xs leading-relaxed text-fg-subtle">
            {t('pages.tunnels.selfSignedHint')}
          </p>

          <div className="rounded-md border border-line">
            <p className="border-b border-line px-3 py-2 text-xs font-medium text-fg-subtle">
              {t('pages.tunnels.checklistTitle')}
            </p>
            <ol className="flex flex-col gap-2 px-3 py-2.5 text-xs leading-relaxed text-fg">
              <li className="flex gap-2">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-success/15 text-[10px] font-semibold text-fg-success">
                  1
                </span>
                <span>{t('pages.tunnels.checklistStep1')}</span>
              </li>
              <li className="flex gap-2">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-recessed text-[10px] font-semibold text-fg-subtle">
                  2
                </span>
                <span>{t('pages.tunnels.checklistStep2')}</span>
              </li>
              <li className="flex gap-2">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-recessed text-[10px] font-semibold text-fg-subtle">
                  3
                </span>
                <span>{t('pages.tunnels.checklistStep3')}</span>
              </li>
            </ol>
          </div>
        </div>
      )}
    </Dialog>
  )
}

/** Deployment-wide tunnel limits. */
function TunnelSettingsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const settingsQuery = useQuery({
    queryKey: tunnelKeys.settings(),
    queryFn: () => tunnelsApi.settings(),
    enabled: open,
  })

  const save = useMutation({
    mutationFn: (data: Partial<TunnelSettings>) => tunnelsApi.updateSettings(data),
    onSuccess: () => {
      toast.success(t('pages.tunnels.settingsSaved'))
      void queryClient.invalidateQueries({ queryKey: tunnelKeys.all })
      onClose()
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="md"
      title={t('pages.tunnels.settingsTitle')}
      description={t('pages.tunnels.settingsDescription')}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={save.isPending}
            disabled={!settingsQuery.data}
            onClick={() => {
              const data = settingsQuery.data
              if (!data) return
              save.mutate({
                enabled: data.enabled,
                pairing_ttl_seconds: data.pairing_ttl_seconds,
                max_streams_per_session: data.max_streams_per_session,
                max_targets_per_tunnel: data.max_targets_per_tunnel,
                idle_timeout_seconds: data.idle_timeout_seconds,
                heartbeat_seconds: data.heartbeat_seconds,
                session_token_ttl_seconds: data.session_token_ttl_seconds,
              })
            }}
          >
            {t('common.save')}
          </Button>
        </>
      }
    >
      {settingsQuery.isPending ? (
        <SkeletonRows rows={4} columns={2} />
      ) : settingsQuery.data ? (
        <TunnelSettingsForm
          settings={settingsQuery.data}
          onChange={(next) => queryClient.setQueryData(tunnelKeys.settings(), next)}
        />
      ) : (
        <ErrorState variant="inline" error={settingsQuery.error} />
      )}
    </Dialog>
  )
}

function TunnelSettingsForm({
  settings,
  onChange,
}: {
  settings: TunnelSettings
  onChange: (next: TunnelSettings) => void
}) {
  const { t } = useTranslation()
  const number = (key: keyof TunnelSettings, label: string, min: number, max: number) => (
    <Input
      label={label}
      type="number"
      min={min}
      max={max}
      value={String(settings[key] ?? '')}
      onChange={(e) => {
        const value = Number(e.target.value)
        if (Number.isFinite(value)) {
          onChange({ ...settings, [key]: value })
        }
      }}
    />
  )
  return (
    <div className="flex flex-col gap-4">
      <label className="flex items-center gap-2 text-[13px] text-fg">
        <input
          type="checkbox"
          className="h-4 w-4 accent-[var(--color-brand)]"
          checked={settings.enabled}
          onChange={(e) => onChange({ ...settings, enabled: e.target.checked })}
        />
        {t('pages.tunnels.settingsEnabled')}
      </label>
      <div className="grid grid-cols-2 gap-3">
        {number('pairing_ttl_seconds', t('pages.tunnels.settingsPairingTtl'), 60, 86400)}
        {number('max_streams_per_session', t('pages.tunnels.settingsMaxStreams'), 1, 4096)}
        {number('max_targets_per_tunnel', t('pages.tunnels.settingsMaxTargets'), 1, 4096)}
        {number('idle_timeout_seconds', t('pages.tunnels.settingsIdleTimeout'), 10, 86400)}
        {number('heartbeat_seconds', t('pages.tunnels.settingsHeartbeat'), 5, 300)}
        {number(
          'session_token_ttl_seconds',
          t('pages.tunnels.settingsTokenTtl'),
          60,
          86400,
        )}
      </div>
    </div>
  )
}