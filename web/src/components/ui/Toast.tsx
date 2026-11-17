import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'
import {
  CheckCircle,
  WarningCircle,
  XCircle,
  Info,
  X,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'
import { onErrorNotice } from '@/api/errors'

export type ToastTone = 'success' | 'error' | 'warning' | 'info'

/** Optional inline action, e.g. "View logs" after a failed batch delete. */
export interface ToastAction {
  label: string
  href: string
}

export interface ToastInput {
  title: string
  description?: string
  tone?: ToastTone
  /** Milliseconds before auto-dismiss; `0` keeps the toast until dismissed. */
  duration?: number
  action?: ToastAction
}

interface ToastItem extends Required<Omit<ToastInput, 'description' | 'action'>> {
  id: number
  description?: string
  action?: ToastAction
}

interface ToastContextValue {
  toast: (input: ToastInput) => void
  success: (title: string, description?: string) => void
  error: (title: string, description?: string) => void
  warning: (title: string, description?: string) => void
  info: (title: string, description?: string) => void
  dismiss: (id: number) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

/** Auto-dismiss window (UX-13: five seconds, long enough to be read). */
const DEFAULT_DURATION_MS = 5000
/** Identical notices inside this window collapse into one (UX-13). */
const DEDUPE_WINDOW_MS = 3000

const toneConfig: Record<ToastTone, { icon: ReactNode; accent: string }> = {
  success: { icon: <CheckCircle weight="fill" className="h-5 w-5" />, accent: 'text-fg-success' },
  error: { icon: <XCircle weight="fill" className="h-5 w-5" />, accent: 'text-fg-danger' },
  warning: { icon: <WarningCircle weight="fill" className="h-5 w-5" />, accent: 'text-warning' },
  info: { icon: <Info weight="fill" className="h-5 w-5" />, accent: 'text-link' },
}

/**
 * ARIA role of one toast: a failure interrupts and must be announced
 * assertively (`role=alert`), everything else is polite (`role=status`).
 */
export function toastRole(tone: ToastTone): 'alert' | 'status' {
  return tone === 'error' ? 'alert' : 'status'
}

/** `aria-live` value paired with {@link toastRole}. */
export function toastLive(tone: ToastTone): 'assertive' | 'polite' {
  return tone === 'error' ? 'assertive' : 'polite'
}

interface DedupeCandidate {
  title: string
  description?: string
}

/**
 * True when an identical toast is already visible. The control plane can fan a
 * single failure out to several queries; four identical toasts help nobody.
 */
export function isDuplicateToast(
  existing: DedupeCandidate[],
  next: DedupeCandidate,
): boolean {
  return existing.some(
    (item) => item.title === next.title && item.description === next.description,
  )
}

/** One toast row, exported so its ARIA contract can be tested without a DOM. */
export function ToastCard({
  item,
  onDismiss,
}: {
  item: ToastItem
  onDismiss: (id: number) => void
}) {
  const { t } = useTranslation()
  const cfg = toneConfig[item.tone]
  const role = toastRole(item.tone)

  return (
    <div
      role={role}
      aria-live={toastLive(item.tone)}
      aria-atomic="true"
      className="pointer-events-auto flex animate-toast-in items-start gap-3 rounded-lg border border-line bg-elevated p-3 shadow-lg"
    >
      <span className={cn('mt-0.5 shrink-0', cfg.accent)}>{cfg.icon}</span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-fg-strong">{item.title}</p>
        {item.description && (
          <p className="mt-0.5 text-[13px] leading-relaxed text-fg-subtle">
            {item.description}
          </p>
        )}
        {item.action && (
          <a
            href={item.action.href}
            target="_blank"
            rel="noreferrer noopener"
            className="mt-1 inline-block text-[13px] font-medium text-link hover:underline"
          >
            {item.action.label}
          </a>
        )}
      </div>
      <button
        onClick={() => onDismiss(item.id)}
        aria-label={t('a11y.dismissNotification')}
        className="shrink-0 rounded p-0.5 text-fg-subtle transition-colors hover:bg-recessed hover:text-fg"
      >
        <X weight="bold" className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const counter = useRef(0)
  const timers = useRef(new Map<number, number>())
  // Recent notices for duplicate suppression. Kept in a ref and mutated inside
  // the event callback (never during render), which the react-hooks
  // immutability rule accepts.
  const recentNotices = useRef<(DedupeCandidate & { at: number })[]>([])

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id)
    if (timer !== undefined) {
      window.clearTimeout(timer)
      timers.current.delete(id)
    }
    setToasts((prev) => prev.filter((item) => item.id !== id))
  }, [])

  const toast = useCallback(
    (input: ToastInput) => {
      // Collapse an identical notice shown moments ago (UX-13).
      const now = Date.now()
      recentNotices.current = recentNotices.current.filter(
        (notice) => now - notice.at < DEDUPE_WINDOW_MS,
      )
      if (isDuplicateToast(recentNotices.current, input)) return
      recentNotices.current.push({
        title: input.title,
        description: input.description,
        at: now,
      })
      const id = ++counter.current
      const item: ToastItem = {
        id,
        title: input.title,
        description: input.description,
        tone: input.tone ?? 'info',
        duration: input.duration ?? DEFAULT_DURATION_MS,
        action: input.action,
      }
      // Cap the stack: a flapping endpoint must not bury the screen.
      setToasts((prev) => [...prev.slice(-3), item])
      if (item.duration > 0) {
        const timer = window.setTimeout(() => dismiss(id), item.duration)
        timers.current.set(id, timer)
      }
    },
    [dismiss],
  )

  // Bridge for errors raised outside React (the API client, query defaults).
  useEffect(
    () =>
      onErrorNotice((notice) =>
        toast({
          title: notice.title,
          description: notice.description,
          tone: notice.tone,
          duration: notice.tone === 'error' ? 6000 : DEFAULT_DURATION_MS,
        }),
      ),
    [toast],
  )

  const value = useMemo<ToastContextValue>(
    () => ({
      toast,
      dismiss,
      success: (title, description) => toast({ title, description, tone: 'success' }),
      error: (title, description) => toast({ title, description, tone: 'error' }),
      warning: (title, description) => toast({ title, description, tone: 'warning' }),
      info: (title, description) => toast({ title, description, tone: 'info' }),
    }),
    [toast, dismiss],
  )

  return (
    <ToastContext.Provider value={value}>
      {children}
      {createPortal(
        <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2">
          {toasts.map((item) => (
            <ToastCard key={item.id} item={item} onDismiss={dismiss} />
          ))}
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  )
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a ToastProvider')
  return ctx
}