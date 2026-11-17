import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { NotFoundPage, WEBSITE_URL } from '../NotFoundPage'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

const render = () =>
  renderToStaticMarkup(
    <MemoryRouter>
      <NotFoundPage />
    </MemoryRouter>,
  )

describe('console 404 page', () => {
  it('offers the official site in a new window with noopener', () => {
    const html = render()
    expect(WEBSITE_URL).toBe('https://www.pingwaf.com')
    expect(html).toContain(`href="${WEBSITE_URL}"`)
    expect(html).toContain('target="_blank"')
    expect(html).toContain('rel="noopener noreferrer"')
  })

  it('keeps a single recover action and no nested interactive elements', () => {
    const html = render()
    // The primary action is a real button that navigates, not a <button>
    // wrapped in an <a> (invalid nested interactive content).
    expect(html).not.toMatch(/<a[^>]*>\s*<button/)
    expect(html).toContain('pages.notFound.backToDashboard')
  })
})