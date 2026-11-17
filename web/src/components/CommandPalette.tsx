import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  MagnifyingGlass,
  Globe,
  ChartLine,
  List,
  FlowArrow,
  FunnelSimple,
  Prohibit,
  Lock,
  Desktop,
  Bell,
  ClockCounterClockwise,
  UserCircle,
  Gear,
  House,
  MoonStars,
  Translate,
  BookOpen,
  Plus,
  type Icon,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'
import { useSitesList } from '@/hooks'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'
import { supportedLanguages } from '@/i18n'
import { webStorage } from '@/lib/storage'

const MAX_RESULTS = 10
/** How many recently-run commands are remembered and shown on an empty query. */
const RECENT_LIMIT = 5
const RECENT_KEY = 'wafred.palette.recent'
/** Official docs entry point, opened by the "documentation" action. */
const DOCS_URL = 'https://waf.red/docs'

interface Command {
  id: string
  label: string
  group: string
  icon: Icon
  run: () => void
}

/** All top-level navigation destinations, grouped like the sidebar. */
const NAV_PAGES: { to: string; labelKey: string; icon: Icon }[] = [
  { to: '/dashboard', labelKey: 'nav.dashboard', icon: House },
  { to: '/traffic', labelKey: 'nav.traffic', icon: ChartLine },
  { to: '/logs', labelKey: 'nav.logs', icon: List },
  { to: '/lifecycle', labelKey: 'nav.lifecycle', icon: FlowArrow },
  { to: '/sites', labelKey: 'nav.sites', icon: Globe },
  { to: '/ip-groups', labelKey: 'nav.ipGroups', icon: FunnelSimple },
  { to: '/blocked-ips', labelKey: 'nav.blockedIps', icon: Prohibit },
  { to: '/ssl', labelKey: 'nav.ssl', icon: Lock },
  { to: '/agents', labelKey: 'nav.agents', icon: Desktop },
  { to: '/notifications', labelKey: 'nav.notifications', icon: Bell },
  { to: '/config-versions', labelKey: 'nav.configVersions', icon: ClockCounterClockwise },
  { to: '/account', labelKey: 'nav.account', icon: UserCircle },
  { to: '/settings', labelKey: 'nav.settings', icon: Gear },
]

/** Top-level routes gated by `RequireAdmin` in the router — never listed. */
const ADMIN_ONLY_PATHS = new Set(['/lifecycle', '/config-versions'])

const NAV_GROUPS: { key: string; tos: string[] }[] = [
  { key: 'nav.group.overview', tos: ['/dashboard'] },
  { key: 'nav.group.trafficLogs', tos: ['/traffic', '/logs', '/lifecycle'] },
  {
    key: 'nav.group.securityAssets',
    tos: ['/sites', '/ip-groups', '/blocked-ips', '/ssl'],
  },
  {
    key: 'nav.group.platform',
    tos: ['/agents', '/notifications', '/config-versions', '/account', '/settings'],
  },
]

function groupFor(to: string): string {
  return NAV_GROUPS.find((g) => g.tos.includes(to))?.key ?? 'nav.group.platform'
}

/* ── Recently used commands (UX-11) ──────────────────────────────────── */

/** Last commands the operator ran, newest first; tolerant of bad storage. */
function readRecent(): string[] {
  const storage = webStorage()
  if (!storage) return []
  try {
    const raw = storage.getItem(RECENT_KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter((value): value is string => typeof value === 'string')
      .slice(0, RECENT_LIMIT)
  } catch {
    return []
  }
}

function rememberCommand(id: string): string[] {
  const next = [id, ...readRecent().filter((value) => value !== id)].slice(
    0,
    RECENT_LIMIT,
  )
  const storage = webStorage()
  if (storage) {
    try {
      storage.setItem(RECENT_KEY, JSON.stringify(next))
    } catch {
      /* private mode / quota — the palette still works, it just forgets */
    }
  }
  return next
}

/**
 * Global ⌘K command palette: jump to any page, search sites by name/domain,
 * run quick actions and re-run the most recent commands. Plain substring
 * matching keeps it fast and dependency-free.
 */
export function CommandPalette({ onClose }: { onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const toggleTheme = useThemeStore((s) => s.toggle)
  // Must mirror router/index.tsx's RequireAdmin, matching the Sidebar.
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const [recentIds, setRecentIds] = useState<string[]>(readRecent)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const restoreRef = useRef<HTMLElement | null>(null)

  // The full site list is shared with pages via the TanStack Query cache.
  const { data: sites } = useSitesList()

  // Open/close lifecycle is pure DOM side effects: the parent mounts the
  // palette only while open, so state starts fresh on every mount and no
  // state resets are needed here.
  useEffect(() => {
    restoreRef.current = document.activeElement as HTMLElement | null
    const raf = requestAnimationFrame(() => inputRef.current?.focus())
    return () => {
      cancelAnimationFrame(raf)
      restoreRef.current?.focus?.()
    }
  }, [])

  const commands = useMemo<Command[]>(() => {
    const go = (to: string) => {
      onClose()
      navigate(to)
    }
    const openDocs = () => {
      onClose()
      // A docs page opens in a new tab; the console keeps its state.
      window.open(DOCS_URL, '_blank', 'noopener,noreferrer')
    }
    const navCmds: Command[] = NAV_PAGES.filter(
      (p) => isAdmin || !ADMIN_ONLY_PATHS.has(p.to),
    ).map((p) => ({
      id: `nav:${p.to}`,
      label: t(p.labelKey),
      group: t(groupFor(p.to)),
      icon: p.icon,
      run: () => go(p.to),
    }))
    const siteCmds: Command[] = (sites ?? []).map((s) => ({
      id: `site:${s.id}`,
      label: s.domain || s.name,
      group: t('palette.sites'),
      icon: Globe,
      run: () => go(`/sites/${s.id}/basic`),
    }))
    const actionCmds: Command[] = [
      {
        id: 'action:new-site',
        label: t('palette.newSite'),
        group: t('palette.actions'),
        icon: Plus,
        // SitesListPage opens its create dialog for `?new=1`.
        run: () => go('/sites?new=1'),
      },
      {
        id: 'action:open-logs',
        label: t('palette.openLogs'),
        group: t('palette.actions'),
        icon: List,
        run: () => go('/logs'),
      },
      {
        id: 'action:unblock-ip',
        label: t('palette.unblockIp'),
        group: t('palette.actions'),
        icon: Prohibit,
        run: () => go('/blocked-ips'),
      },
      {
        id: 'action:theme',
        label: t('palette.toggleTheme'),
        group: t('palette.actions'),
        icon: MoonStars,
        run: () => {
          onClose()
          toggleTheme()
        },
      },
      {
        id: 'action:lang',
        label: t('palette.toggleLanguage'),
        group: t('palette.actions'),
        icon: Translate,
        run: () => {
          onClose()
          const idx = supportedLanguages.indexOf(
            supportedLanguages.find((l) => i18n.language?.startsWith(l)) ?? 'en',
          )
          void i18n.changeLanguage(supportedLanguages[(idx + 1) % supportedLanguages.length])
        },
      },
      {
        id: 'action:docs',
        label: t('palette.openDocs'),
        group: t('palette.docs'),
        icon: BookOpen,
        run: openDocs,
      },
      {
        id: 'action:settings',
        label: t('palette.goToSettings'),
        group: t('palette.actions'),
        icon: Gear,
        run: () => go('/settings'),
      },
    ]
    return [...navCmds, ...siteCmds, ...actionCmds]
  }, [t, sites, navigate, onClose, toggleTheme, i18n, isAdmin])

  const commandById = useMemo(
    () => new Map(commands.map((cmd) => [cmd.id, cmd])),
    [commands],
  )

  const q = query.trim().toLowerCase()
  const results = useMemo(() => {
    if (!q) {
      // Empty query: the recently used commands first (UX-11), then everything
      // else in registry order.
      const recent: Command[] = recentIds
        .map((id) => commandById.get(id))
        .filter((cmd): cmd is Command => Boolean(cmd))
        .map((cmd) => ({ ...cmd, group: t('palette.recent') }))
      const seen = new Set(recent.map((cmd) => cmd.id))
      const rest = commands.filter((cmd) => !seen.has(cmd.id))
      return [...recent, ...rest].slice(0, MAX_RESULTS)
    }
    const filtered = commands.filter(
      (c) =>
        c.label.toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q.replace(/^nav:|^site:/, '')),
    )
    return filtered.slice(0, MAX_RESULTS)
  }, [commands, commandById, q, recentIds, t])

  // Derived (not an effect): keep the active row in range when the result
  // set shrinks without a cascading setState.
  const activeIndex = results.length ? Math.min(active, results.length - 1) : 0

  const runCommand = (cmd: Command) => {
    setRecentIds(rememberCommand(cmd.id))
    cmd.run()
  }

  useEffect(() => {
    const rows = listRef.current?.querySelectorAll('[data-command]')
    rows?.[activeIndex]?.scrollIntoView({ block: 'nearest' })
  }, [activeIndex])

  // Bound on the panel container so ↑↓/Esc/Enter keep working when focus
  // leaves the input (e.g. after clicking somewhere in the list).
  const handlePanelKey = (e: ReactKeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((a) => (results.length ? (a + 1) % results.length : 0))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => (results.length ? (a - 1 + results.length) % results.length : 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const cmd = results[activeIndex]
      if (cmd) runCommand(cmd)
    }
  }

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-overlay p-4 pt-[12vh] animate-fade-in"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
      role="dialog"
      aria-modal="true"
      aria-label={t('search.placeholder')}
    >
      <div
        className="w-full max-w-lg overflow-hidden rounded-xl border border-line bg-elevated shadow-lg animate-scale-in"
        onKeyDown={handlePanelKey}
      >
        <div className="flex items-center gap-2 border-b border-line px-4">
          <MagnifyingGlass weight="duotone" className="h-4 w-4 shrink-0 text-fg-subtle" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            role="combobox"
            aria-expanded="true"
            aria-controls="command-palette-results"
            aria-autocomplete="list"
            aria-activedescendant={results[activeIndex] ? `command-${results[activeIndex].id}` : undefined}
            onChange={(e) => {
              setQuery(e.target.value)
              setActive(0)
            }}
            placeholder={t('search.placeholder')}
            className="h-11 w-full bg-transparent text-sm text-fg placeholder:text-fg-subtle focus:outline-none"
          />
          <kbd className="rounded border border-line bg-recessed px-1.5 py-0.5 font-mono text-[10px] text-fg-subtle">
            esc
          </kbd>
        </div>
        <div
          ref={listRef}
          id="command-palette-results"
          role="listbox"
          aria-label={t('search.placeholder')}
          className="max-h-[50vh] overflow-y-auto p-1.5"
        >
          {results.length === 0 ? (
            <p className="px-3 py-8 text-center text-sm text-fg-subtle">
              {t('palette.noResults')}
            </p>
          ) : (
            results.map((cmd, i) => {
              const IconCmp = cmd.icon
              const newGroup = i === 0 || results[i - 1].group !== cmd.group
              return (
                <div key={cmd.id}>
                  {newGroup && (
                    <p
                      role="presentation"
                      className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-fg-subtle"
                    >
                      {cmd.group}
                    </p>
                  )}
                  <button
                    id={`command-${cmd.id}`}
                    data-command
                    role="option"
                    aria-selected={i === activeIndex}
                    onMouseEnter={() => setActive(i)}
                    // Keep focus on the input so the panel-level keydown
                    // handler (and its initial focus) is never lost.
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => runCommand(cmd)}
                    className={cn(
                      'flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors',
                      i === activeIndex ? 'bg-brand-soft text-fg-brand-strong' : 'text-fg',
                    )}
                  >
                    <IconCmp weight="duotone" className="h-4 w-4 shrink-0 text-fg-subtle" />
                    <span className="truncate">{cmd.label}</span>
                    {i === activeIndex && (
                      <kbd className="ml-auto shrink-0 rounded border border-line bg-recessed px-1.5 py-0.5 font-mono text-[10px] text-fg-subtle">
                        ↵
                      </kbd>
                    )}
                  </button>
                </div>
              )
            })
          )}
        </div>
        <div className="flex items-center justify-between border-t border-line px-4 py-2 text-[11px] text-fg-subtle">
          <span>{t('palette.shortcuts')}</span>
          {!q && recentIds.length > 0 && (
            <span className="shrink-0">{t('palette.recent')}</span>
          )}
        </div>
      </div>
    </div>
  )
}
