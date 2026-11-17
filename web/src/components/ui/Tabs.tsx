import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface TabItem {
  value: string
  label: ReactNode
  icon?: ReactNode
  content?: ReactNode
  disabled?: boolean
}

export interface TabsProps {
  items: TabItem[]
  value?: string
  defaultValue?: string
  onChange?: (value: string) => void
  variant?: 'underline' | 'pill'
  className?: string
  /**
   * Keep the tab bar pinned below the console header while the page scrolls
   * (mobile only, UX-19). Defaults to on for the underline variant; the pill
   * variant is a compact in-card control and stays static.
   */
  sticky?: boolean
}

export function Tabs({
  items,
  value,
  defaultValue,
  onChange,
  variant = 'underline',
  className,
  sticky,
}: TabsProps) {
  const isControlled = value !== undefined
  const [internal, setInternal] = useState(defaultValue ?? items[0]?.value ?? '')
  const active = isControlled ? value : internal

  const listRef = useRef<HTMLDivElement>(null)
  const [overflow, setOverflow] = useState({ left: false, right: false })

  const select = (v: string) => {
    if (!isControlled) setInternal(v)
    onChange?.(v)
  }

  // Edge state for the scroll affordance (UX-19): a horizontal fade appears
  // on the side that still has tabs out of view.
  const updateOverflow = useCallback(() => {
    const el = listRef.current
    if (!el) return
    setOverflow({
      left: el.scrollLeft > 2,
      right: el.scrollWidth - el.clientWidth - el.scrollLeft > 2,
    })
  }, [])

  useEffect(() => {
    updateOverflow()
    if (typeof ResizeObserver === 'undefined') return
    const el = listRef.current
    if (!el) return
    const observer = new ResizeObserver(updateOverflow)
    observer.observe(el)
    return () => observer.disconnect()
  }, [updateOverflow, items.length])

  // Bring the active tab into view when it changes (deep links, keyboard
  // selection, `?tab=` navigation). Manual scroll maths keeps the page from
  // jumping vertically, which `scrollIntoView` would do.
  useEffect(() => {
    const el = listRef.current
    if (!el) return
    const activeEl = el.querySelector<HTMLElement>('[aria-selected="true"]')
    if (!activeEl) return
    const target =
      activeEl.offsetLeft - (el.clientWidth - activeEl.clientWidth) / 2
    if (typeof el.scrollTo === 'function') {
      try {
        el.scrollTo({ left: Math.max(0, target), behavior: 'smooth' })
      } catch {
        el.scrollLeft = Math.max(0, target)
      }
    } else {
      el.scrollLeft = Math.max(0, target)
    }
    updateOverflow()
  }, [active, updateOverflow])

  const activeItem = items.find((i) => i.value === active)
  const isSticky = sticky ?? variant === 'underline'

  return (
    <div className={cn('flex flex-col', className)}>
      <div
        className={cn(
          'relative',
          isSticky &&
            'sticky top-0 z-20 -mx-4 bg-base/95 px-4 backdrop-blur md:static md:mx-0 md:bg-transparent md:px-0 md:backdrop-blur-none',
        )}
      >
        <div
          ref={listRef}
          role="tablist"
          onScroll={updateOverflow}
          className={cn(
            'flex gap-1 overflow-x-auto',
            variant === 'underline'
              ? 'border-b border-line'
              : 'w-fit rounded-lg bg-recessed p-1',
          )}
        >
          {items.map((item) => {
            const isActive = item.value === active
            return (
              <button
                key={item.value}
                role="tab"
                type="button"
                aria-selected={isActive}
                disabled={item.disabled}
                onClick={() => select(item.value)}
                className={cn(
                  'pw-touch-target inline-flex shrink-0 items-center gap-2 whitespace-nowrap text-sm font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50',
                  variant === 'underline'
                    ? cn(
                        '-mb-px border-b-2 px-3 py-2.5',
                        isActive
                          ? 'border-brand text-fg-strong'
                          : 'border-transparent text-fg-subtle hover:text-fg',
                      )
                    : cn(
                        'rounded-md px-3 py-1.5',
                        isActive
                          ? 'bg-elevated text-fg-strong shadow-sm'
                          : 'text-fg-subtle hover:text-fg',
                      ),
                )}
              >
                {item.icon}
                {item.label}
              </button>
            )
          })}
        </div>
        {overflow.left && (
          <div
            aria-hidden
            className="pointer-events-none absolute inset-y-0 left-0 w-6 bg-gradient-to-r from-base to-transparent"
          />
        )}
        {overflow.right && (
          <div
            aria-hidden
            className="pointer-events-none absolute inset-y-0 right-0 w-6 bg-gradient-to-l from-base to-transparent"
          />
        )}
      </div>
      {activeItem?.content !== undefined && (
        <div role="tabpanel" className="pt-4">
          {activeItem.content}
        </div>
      )}
    </div>
  )
}