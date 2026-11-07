import { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { LockKey, PencilSimple, Plus, ShieldCheck, Trash } from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Textarea } from '@/components/ui/Textarea'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { errorMessage } from '@/api/errors'
import { pathRestrictionsApi, pathRestrictionKeys } from '@/api/pathRestrictions'
import { useCanWrite } from '@/hooks'
import { validatePathExceptionPath } from '@/lib/pathException'
import type {
  CreatePathRestrictionRequest,
  PathMatchType,
  PathRestriction,
  PathRestrictionAction,
} from '@/api/types'

const WEEKDAYS = [1, 2, 3, 4, 5, 6, 7] as const
const MATCH_TYPES: PathMatchType[] = ['prefix', 'exact', 'wildcard', 'regex']

type FormState = CreatePathRestrictionRequest

const emptyForm = (): FormState => ({
  name: '',
  path: '',
  match_type: 'prefix',
  expression: '',
  action: 'block',
  threshold: 0,
  period_seconds: 60,
  block_duration_seconds: 60,
  schedule_enabled: false,
  schedule_timezone: 'Asia/Shanghai',
  schedule_days: [1, 2, 3, 4, 5],
  schedule_start: '09:00',
  schedule_end: '18:00',
  enabled: true,
  priority: 100,
})

function formFromRule(rule: PathRestriction): FormState {
  return {
    name: rule.name,
    path: rule.path,
    match_type: rule.match_type as PathMatchType,
    expression: rule.expression,
    action: rule.action as PathRestrictionAction,
    threshold: rule.threshold,
    period_seconds: rule.period_seconds,
    block_duration_seconds: rule.block_duration_seconds,
    schedule_enabled: rule.schedule_enabled,
    schedule_timezone: rule.schedule_timezone,
    schedule_days: [...rule.schedule_days],
    schedule_start: rule.schedule_start,
    schedule_end: rule.schedule_end,
    enabled: rule.enabled,
    priority: rule.priority,
  }
}

export function PathRestrictionsPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<PathRestriction | null>(null)
  const [pendingDelete, setPendingDelete] = useState<PathRestriction | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [formError, setFormError] = useState<string | null>(null)

  const rulesQuery = useQuery({
    queryKey: pathRestrictionKeys.list(siteId),
    queryFn: () => pathRestrictionsApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const rules = useMemo(() => rulesQuery.data ?? [], [rulesQuery.data])
  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: pathRestrictionKeys.all(siteId) })
  }

  const save = useMutation({
    mutationFn: (payload: CreatePathRestrictionRequest) =>
      editing
        ? pathRestrictionsApi.update(siteId, editing.id, payload)
        : pathRestrictionsApi.create(siteId, payload),
    onSuccess: (saved) => {
      toast.success(
        editing ? t('pages.pathRestrictions.updated') : t('pages.pathRestrictions.created'),
        saved.name,
      )
      setDialogOpen(false)
      invalidate()
    },
    onError: (error) => setFormError(errorMessage(error)),
  })
  const remove = useMutation({
    mutationFn: (id: string) => pathRestrictionsApi.remove(siteId, id),
    onSuccess: (_data, id) => {
      const removed = rules.find((rule) => rule.id === id)
      toast.success(t('pages.pathRestrictions.deleted'), removed?.name)
      setPendingDelete(null)
      invalidate()
    },
    onError: (error) =>
      toast.error(t('pages.pathRestrictions.deleteFailed'), errorMessage(error)),
  })

  const openNew = () => {
    setEditing(null)
    setForm(emptyForm())
    setFormError(null)
    setDialogOpen(true)
  }
  const openEdit = (rule: PathRestriction) => {
    setEditing(rule)
    setForm(formFromRule(rule))
    setFormError(null)
    setDialogOpen(true)
  }
  const updateForm = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((current) => ({ ...current, [key]: value }))

  const submit = () => {
    const pathError = validatePathExceptionPath(form.path, form.match_type)
    if (pathError) {
      setFormError(t(pathError))
      return
    }
    if (!form.name.trim()) {
      setFormError(t('pages.pathRestrictions.errorNameRequired'))
      return
    }
    if (form.schedule_enabled && form.schedule_days.length === 0) {
      setFormError(t('pages.pathRestrictions.errorDaysRequired'))
      return
    }
    setFormError(null)
    save.mutate({
      ...form,
      name: form.name.trim(),
      path: form.path.trim(),
      expression: form.expression.trim(),
      schedule_timezone: form.schedule_timezone.trim() || 'UTC',
      schedule_days: [...form.schedule_days].sort((a, b) => a - b),
    })
  }

  const columns: Column<PathRestriction>[] = [
    {
      key: 'name',
      header: t('pages.pathRestrictions.name'),
      accessor: (rule) => rule.name,
      sortable: true,
      minWidth: '12rem',
      cell: (rule) => (
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-fg-strong">{rule.name}</p>
          {rule.expression && (
            <p className="truncate font-mono text-xs text-fg-subtle">{rule.expression}</p>
          )}
        </div>
      ),
    },
    {
      key: 'path',
      header: t('pages.pathRestrictions.path'),
      accessor: (rule) => rule.path,
      sortable: true,
      minWidth: '13rem',
      cell: (rule) => (
        <div className="min-w-0">
          <p className="truncate font-mono text-[13px] text-fg-strong">{rule.path}</p>
          <span className="text-xs text-fg-subtle">
            {t(`pages.pathRestrictions.match_${rule.match_type}`, rule.match_type)}
          </span>
        </div>
      ),
    },
    {
      key: 'action',
      header: t('pages.pathRestrictions.action'),
      accessor: (rule) => rule.action,
      width: '1%',
      cell: (rule) => (
        <Badge tone={rule.action === 'block' ? 'danger' : 'info'} size="sm">
          {t(`pages.pathRestrictions.action_${rule.action}`, rule.action)}
        </Badge>
      ),
    },
    {
      key: 'threshold',
      header: t('pages.pathRestrictions.threshold'),
      accessor: (rule) => rule.threshold,
      width: '1%',
      cell: (rule) => (
        <span className="whitespace-nowrap text-[13px] text-fg-subtle">
          {rule.action !== 'block' || rule.threshold === 0
            ? t('pages.pathRestrictions.immediate')
            : `${rule.threshold} / ${rule.period_seconds}s`}
        </span>
      ),
    },
    {
      key: 'schedule',
      header: t('pages.pathRestrictions.schedule'),
      minWidth: '11rem',
      cell: (rule) => (
        <span className="text-xs text-fg-subtle">
          {rule.schedule_enabled
            ? `${rule.schedule_start}–${rule.schedule_end} · ${rule.schedule_timezone}`
            : t('pages.pathRestrictions.always')}
        </span>
      ),
    },
    {
      key: 'enabled',
      header: t('common.enabled'),
      width: '1%',
      cell: (rule) => (
        <Badge tone={rule.enabled ? 'success' : 'neutral'} size="sm" dot>
          {rule.enabled ? t('common.enabled') : t('common.disabled')}
        </Badge>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (rule) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.edit')}
            disabled={!canWrite}
            onClick={() => openEdit(rule)}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDelete(rule)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  return (
    <Card>
      <CardHeader
        title={t('pages.pathRestrictions.title')}
        description={t('pages.pathRestrictions.description')}
        action={
          <Button
            variant="primary"
            size="sm"
            icon={<Plus weight="bold" className="h-4 w-4" />}
            disabled={!canWrite}
            onClick={openNew}
          >
            {t('pages.pathRestrictions.add')}
          </Button>
        }
      />
      <CardBody className="p-0">
        {rulesQuery.isPending ? (
          <SkeletonRows rows={3} columns={6} />
        ) : rules.length === 0 ? (
          <EmptyState
            className="border-0 py-12"
            icon={<ShieldCheck weight="duotone" className="h-8 w-8" />}
            title={t('pages.pathRestrictions.empty')}
            description={t('pages.pathRestrictions.emptyDescription')}
            action={
              canWrite ? (
                <Button
                  variant="primary"
                  icon={<Plus weight="bold" className="h-4 w-4" />}
                  onClick={openNew}
                >
                  {t('pages.pathRestrictions.add')}
                </Button>
              ) : undefined
            }
          />
        ) : (
          <Table columns={columns} data={rules} rowKey={(rule) => rule.id} dense />
        )}
      </CardBody>

      <Dialog
        open={dialogOpen}
        onClose={save.isPending ? () => undefined : () => setDialogOpen(false)}
        size="lg"
        title={editing ? t('pages.pathRestrictions.edit') : t('pages.pathRestrictions.add')}
        description={t('pages.pathRestrictions.dialogDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDialogOpen(false)} disabled={save.isPending}>
              {t('common.cancel')}
            </Button>
            <Button variant="primary" onClick={submit} loading={save.isPending}>
              {editing ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex max-h-[70vh] flex-col gap-4 overflow-y-auto pr-1">
          <div className="grid gap-4 sm:grid-cols-2">
            <Input
              label={t('pages.pathRestrictions.name')}
              value={form.name}
              autoFocus
              onChange={(event) => updateForm('name', event.target.value)}
              required
            />
            <Input
              label={t('pages.pathRestrictions.priority')}
              type="number"
              min={0}
              value={form.priority}
              hint={t('pages.pathRestrictions.priorityHint')}
              onChange={(event) => updateForm('priority', Number(event.target.value))}
            />
          </div>
          <Input
            label={t('pages.pathRestrictions.path')}
            value={form.path}
            placeholder={form.match_type === 'regex' ? '^/api/(v1|v2)/' : '/admin/*'}
            hint={t('pages.pathRestrictions.pathHint')}
            className="pw-mono"
            onChange={(event) => updateForm('path', event.target.value)}
            required
          />
          <Select
            label={t('pages.pathRestrictions.matchType')}
            value={form.match_type}
            onChange={(event) => updateForm('match_type', event.target.value as PathMatchType)}
            options={MATCH_TYPES.map((matchType) => ({
              value: matchType,
              label: t(`pages.pathRestrictions.match_${matchType}`),
            }))}
          />
          <Textarea
            label={t('pages.pathRestrictions.expression')}
            value={form.expression}
            rows={3}
            className="font-mono"
            hint={t('pages.pathRestrictions.expressionHint')}
            onChange={(event) => updateForm('expression', event.target.value)}
          />
          <Select
            label={t('pages.pathRestrictions.action')}
            value={form.action}
            onChange={(event) => {
              const action = event.target.value as PathRestrictionAction
              setForm((current) => ({
                ...current,
                action,
                threshold: action === 'block' ? current.threshold : 0,
              }))
            }}
            options={(['block', 'basic_auth', 'oidc'] as const).map((action) => ({
              value: action,
              label: t(`pages.pathRestrictions.action_${action}`),
            }))}
          />

          {form.action === 'block' && (
            <div className="grid gap-4 rounded-md border border-line bg-recessed/50 p-3 sm:grid-cols-3">
              <Input
                label={t('pages.pathRestrictions.threshold')}
                type="number"
                min={0}
                value={form.threshold}
                hint={t('pages.pathRestrictions.thresholdHint')}
                onChange={(event) => updateForm('threshold', Number(event.target.value))}
              />
              <Input
                label={t('pages.pathRestrictions.period')}
                type="number"
                min={1}
                max={86400}
                value={form.period_seconds}
                hint={t('pages.pathRestrictions.periodHint')}
                onChange={(event) => updateForm('period_seconds', Number(event.target.value))}
              />
              <Input
                label={t('pages.pathRestrictions.blockDuration')}
                type="number"
                min={0}
                max={604800}
                value={form.block_duration_seconds}
                hint={t('pages.pathRestrictions.blockDurationHint')}
                onChange={(event) => updateForm('block_duration_seconds', Number(event.target.value))}
              />
              <p className="text-xs text-fg-subtle sm:col-span-3">
                {t('pages.pathRestrictions.noBlacklist')}
              </p>
            </div>
          )}

          {form.action === 'basic_auth' && (
            <div className="flex items-start gap-2 rounded-md border border-line bg-recessed/50 p-3 text-xs text-fg-subtle">
              <LockKey weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
              {t('pages.pathRestrictions.basicAuthHint')}
            </div>
          )}
          {form.action === 'oidc' && (
            <div className="flex items-start gap-2 rounded-md border border-line bg-recessed/50 p-3 text-xs text-fg-subtle">
              <ShieldCheck weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
              {t('pages.pathRestrictions.oidcHint')}
            </div>
          )}

          <div className="rounded-md border border-line p-3">
            <Switch
              checked={form.schedule_enabled}
              onCheckedChange={(value) => updateForm('schedule_enabled', value)}
              label={t('pages.pathRestrictions.scheduleEnabled')}
              description={t('pages.pathRestrictions.scheduleEnabledHint')}
            />
            {form.schedule_enabled && (
              <div className="mt-4 flex flex-col gap-4">
                <Input
                  label={t('pages.pathRestrictions.timezone')}
                  value={form.schedule_timezone}
                  placeholder="Asia/Shanghai"
                  hint={t('pages.pathRestrictions.timezoneHint')}
                  onChange={(event) => updateForm('schedule_timezone', event.target.value)}
                />
                <div>
                  <p className="mb-1.5 text-[13px] font-medium text-fg-subtle">
                    {t('pages.pathRestrictions.weekdays')}
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {WEEKDAYS.map((day) => {
                      const active = form.schedule_days.includes(day)
                      return (
                        <button
                          key={day}
                          type="button"
                          aria-pressed={active}
                          onClick={() =>
                            updateForm(
                              'schedule_days',
                              active
                                ? form.schedule_days.filter((value) => value !== day)
                                : [...form.schedule_days, day],
                            )
                          }
                          className={`rounded-md border px-2.5 py-1.5 text-xs font-medium ${active ? 'border-brand bg-brand-soft text-brand' : 'border-line text-fg-subtle hover:text-fg'}`}
                        >
                          {t(`pages.pathRestrictions.day_${day}`)}
                        </button>
                      )
                    })}
                  </div>
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Input
                    label={t('pages.pathRestrictions.start')}
                    type="time"
                    value={form.schedule_start}
                    onChange={(event) => updateForm('schedule_start', event.target.value)}
                  />
                  <Input
                    label={t('pages.pathRestrictions.end')}
                    type="time"
                    value={form.schedule_end}
                    onChange={(event) => updateForm('schedule_end', event.target.value)}
                  />
                </div>
              </div>
            )}
          </div>
          <Switch
            checked={form.enabled}
            onCheckedChange={(value) => updateForm('enabled', value)}
            label={t('common.enabled')}
          />
          {formError && (
            <p role="alert" className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger">
              {formError}
            </p>
          )}
        </div>
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.pathRestrictions.deleteTitle')}
        description={t('pages.pathRestrictions.deleteDescription', { name: pendingDelete?.name ?? '' })}
        confirmLabel={t('common.delete')}
        tone="danger"
        loading={remove.isPending}
      />
    </Card>
  )
}

export default PathRestrictionsPanel
