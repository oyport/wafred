import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import {
  ToastCard,
  isDuplicateToast,
  toastLive,
  toastRole,
  type ToastTone,
} from '../Toast'

// `ToastCard` only needs `t` for the dismiss label; a stub keeps this a pure
// markup test (no i18n instance). The provider's error-notice bridge is not
// exercised here, so the module that boots i18n is stubbed out as well.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))
vi.mock('@/api/errors', () => ({
  onErrorNotice: () => () => undefined,
}))

function item(tone: ToastTone, extra: Partial<Parameters<typeof ToastCard>[0]['item']> = {}) {
  return {
    id: 1,
    title: 'Saved',
    description: 'The rule was stored',
    tone,
    duration: 5000,
    ...extra,
  }
}

function render(tone: ToastTone, extra?: Parameters<typeof item>[1]): string {
  return renderToStaticMarkup(
    <ToastCard item={item(tone, extra)} onDismiss={() => undefined} />,
  )
}

describe('Toast accessibility contract (UX-13)', () => {
  it('announces errors assertively through role=alert', () => {
    expect(toastRole('error')).toBe('alert')
    expect(toastLive('error')).toBe('assertive')

    const html = render('error')
    expect(html).toContain('role="alert"')
    expect(html).toContain('aria-live="assertive"')
    expect(html).toContain('aria-atomic="true"')
  })

  it.each<ToastTone>(['success', 'warning', 'info'])(
    'announces %s politely through role=status',
    (tone) => {
      expect(toastRole(tone)).toBe('status')
      expect(toastLive(tone)).toBe('polite')

      const html = render(tone)
      expect(html).toContain('role="status"')
      expect(html).toContain('aria-live="polite"')
      expect(html).toContain('aria-atomic="true"')
    },
  )

  it('renders an optional action link with safe target attributes', () => {
    const html = render('error', {
      action: { label: 'View logs', href: '/logs?status=blocked' },
    })
    expect(html).toContain('href="/logs?status=blocked"')
    expect(html).toContain('View logs')
    expect(html).toContain('rel="noreferrer noopener"')
    expect(html).toContain('target="_blank"')
  })

  it('keeps the dismiss control labelled for screen readers', () => {
    expect(render('info')).toContain('aria-label="a11y.dismissNotification"')
  })

  it('collapses an identical toast that is already on screen', () => {
    const existing = [{ title: 'Save failed', description: 'HTTP 500' }]
    expect(isDuplicateToast(existing, { title: 'Save failed', description: 'HTTP 500' })).toBe(true)
    // A different detail is a different notice and must not be swallowed.
    expect(isDuplicateToast(existing, { title: 'Save failed', description: 'HTTP 403' })).toBe(false)
    expect(isDuplicateToast([], { title: 'Save failed' })).toBe(false)
  })
})