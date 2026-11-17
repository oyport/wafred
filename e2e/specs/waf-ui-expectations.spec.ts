import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/app'
import { requiredEnv } from '../support/env'

/**
 * "Would a real operator understand this page?" — UI expectations for the
 * Web Protection surface.
 *
 * These checks are deliberately about what the console *shows*: labels, the
 * defaults a fresh site starts from, empty states, dialog validation, save
 * round-trips, confirmation before a dangerous downgrade, cross-page
 * consistency and localisation. Every key page is screenshotted into
 * `e2e/artifacts/waf-03231/` (git-ignored) so a reviewer can compare the
 * assertion with what the operator sees.
 *
 * A fresh site is created for each test and deleted in `finally`; the suite is
 * serialised by playwright.config.ts (workers=1).
 */

const SHOT_DIR = 'artifacts/waf-03231'
const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const origin = requiredEnv('E2E_ORIGIN_URL')

async function shot(page: Page, name: string) {
  await page.screenshot({ path: `${SHOT_DIR}/${name}.png`, fullPage: true })
}

function toast(page: Page, title: string) {
  return page.getByRole('status').filter({ hasText: title })
}

/**
 * Cleanup that cannot leak a test site: the shared fixture's
 * `deleteSiteIfPresent` checks the row count before the site list has loaded
 * and can return early, leaving the site behind. Wait for the row first, then
 * delete through the confirmation dialog.
 */
async function deleteSiteIfPresent(
  page: Page,
  adminUrl: (path: string) => string,
  domain: string,
) {
  await page.goto(adminUrl('/sites'))
  const search = page.getByRole('textbox', { name: 'Search' })
  if (await search.count()) await search.fill(domain)
  const row = page.getByRole('row').filter({ hasText: domain }).first()
  try {
    await expect(row).toBeVisible({ timeout: 20_000 })
  } catch {
    return
  }
  await row.getByRole('button', { name: 'Delete' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText(domain)
  await dialog.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page.getByRole('row').filter({ hasText: domain })).toHaveCount(
    0,
    { timeout: 30_000 },
  )
}

/**
 * Untranslated i18n keys (`pages.waf.addRule`), unresolved placeholders
 * (`{{count}}`), `undefined`, `NaN` or a stringified object must never reach
 * the operator.
 */
const I18N_LEAK =
  /\b(?:pages|common|actions|components|nav|sidebar|a11y|errors|auth|status|pagination|format|logs)\.[a-zA-Z][\w.]*|\{\{[^}]+\}\}|\bundefined\b|\bNaN\b|\[object Object\]/

async function expectCleanText(page: Page, where: string) {
  const text = await page.locator('body').innerText()
  expect(
    text,
    `${where}: visible text must not contain untranslated keys or placeholders`,
  ).not.toMatch(I18N_LEAK)
  const badValues = await page
    .locator('input, select, textarea')
    .evaluateAll((elements) =>
      elements
        .map(
          (element) =>
            (element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement)
              .value,
        )
        .filter(
          (value) => value === 'undefined' || value === 'NaN' || value === 'null',
        ),
    )
  expect(badValues, `${where}: no form control may show undefined/NaN/null`).toEqual(
    [],
  )
}

async function openProtection(page: Page, adminUrl: (p: string) => string, siteId: string, tab?: string) {
  await page.goto(
    adminUrl(`/sites/${siteId}/security/protection${tab ? `?tab=${tab}` : ''}`),
  )
}

/** The paranoia level the Engine tab currently has pressed. */
async function pressedParanoia(page: Page): Promise<number> {
  for (const level of [1, 2, 3, 4]) {
    const button = page.getByRole('button', {
      name: `Detection sensitivity ${level}`,
    })
    if ((await button.getAttribute('aria-pressed')) === 'true') return level
  }
  throw new Error('the Engine tab exposes no pressed detection-sensitivity level')
}

/** The value of one PostureStat (value above, label below). */
async function postureStat(page: Page, label: string): Promise<string> {
  const stat = page.getByText(label, { exact: true }).locator('..')
  return (await stat.locator('p').first().innerText()).trim()
}

/** The banner's rule counter, e.g. "11 rules". */
async function ruleCount(page: Page): Promise<number> {
  const text = await page.getByText(/^\d+ rules$/).first().innerText()
  const match = text.match(/^(\d+)/)
  if (!match) throw new Error(`unexpected rule counter: ${text}`)
  return Number(match[1])
}

/** Whether the Engine tab's global observation-mode card says ON. */
async function siteObservationOn(page: Page): Promise<boolean> {
  const label = page.getByText('Global observation mode', { exact: true })
  const card = label.locator('xpath=ancestor::div[1]')
  const value = (await card.locator('span').last().innerText()).trim()
  return value === 'ON'
}

test.describe('WAF protection page — UI expectations', () => {
  test('shows the documented fields, defaults and dialog defaults', async ({
    app,
  }) => {
    test.setTimeout(300_000)
    const { page } = app
    const domain = `waf-ui-${run}-a.e2e.test`
    const siteId = await app.createSite({
      name: `E2E waf ui ${run} a`,
      domain,
      upstream: origin,
    })
    try {
      /* ── Overview ───────────────────────────────────────────────────── */
      await openProtection(page, app.adminUrl, siteId)
      await expect(page.getByRole('heading', { name: 'Web Protection' })).toBeVisible()

      // WAFred adds path restrictions alongside the upstream protection tabs.
      await expect(page.getByRole('tab')).toHaveCount(7)
      await expect(page.getByRole('tab', { name: 'Overview' })).toHaveAttribute(
        'aria-selected',
        'true',
      )
      for (const name of [
        'Managed rules',
        'Custom rules',
        'Path exceptions',
        'Path restrictions',
        'Rate limiting & challenge',
      ]) {
        await expect(page.getByRole('tab', { name })).toBeVisible()
      }
      await expect(page.getByRole('tab', { name: /WAF Engine/ })).toBeVisible()

      // Effective-posture card: the four badges an operator checks first.
      await expect(
        page.getByRole('heading', { name: 'Current effective posture' }),
      ).toBeVisible()
      await expect(page.getByText(/Site mode\s+Block/)).toBeVisible()
      await expect(page.getByText(/WAF\s+ON/)).toBeVisible()
      await expect(page.getByText(/Deep inspection\s+OFF/)).toBeVisible()
      await expect(page.getByText(/Under Attack Mode\s+OFF/)).toBeVisible()

      // Enforcement mode card: three choices with hints, Block highlighted.
      await expect(page.getByRole('heading', { name: 'Protection mode' })).toBeVisible()
      const blockMode = page.getByRole('button', { name: /^Block\b/ })
      await expect(blockMode).toBeVisible()
      await expect(blockMode).toHaveClass(/border-brand/)
      await expect(page.getByRole('button', { name: /^Monitor\b/ })).toBeVisible()
      await expect(page.getByRole('button', { name: /^Off\b/ })).toBeVisible()
      await shot(page, 'ui-01-overview')

      /* ── Engine & detection ─────────────────────────────────────────── */
      await page.getByRole('tab', { name: /WAF Engine/ }).click()
      await expect(page.getByRole('tabpanel', { name: /WAF Engine/ })).toBeVisible()
      await expect(page.getByRole('switch', { name: 'WAF Engine' })).toHaveAttribute(
        'aria-checked',
        'true',
      )
      await expect(
        page.getByRole('switch', { name: 'Deep inspection' }),
      ).toHaveAttribute('aria-checked', 'false')
      // Default sensitivity is 2, and the level buttons are toggle buttons.
      expect(await pressedParanoia(page)).toBe(2)
      await expect(
        page.getByRole('spinbutton', { name: 'Body inspection timeout (seconds)' }),
      ).toHaveValue('30')
      await expect(
        page.getByText('Global observation mode', { exact: true }),
      ).toBeVisible()
      await shot(page, 'ui-02-engine-detection')

      /* ── Managed rules ──────────────────────────────────────────────── */
      await page.getByRole('tab', { name: 'Managed rules' }).click()
      await expect(page.getByRole('heading', { name: 'Attack categories' })).toBeVisible()
      await expect(page.getByRole('heading', { name: 'Built-in rules' })).toBeVisible()
      // Nine attack categories, each a Block / Log-only switch.
      for (const category of [
        'SQL injection',
        'Cross-site scripting',
        'Remote code execution',
        'Local file inclusion',
        'Server-side request forgery',
        'Insecure deserialization',
        'CRLF injection',
        'XML external entity (XXE)',
        'Template injection (SSTI)',
      ]) {
        await expect(
          page.getByRole('switch', { name: category, exact: true }),
        ).toBeVisible()
      }
      await shot(page, 'ui-03-managed-rules')

      /* ── Custom rules: banner, groups, table, counter ───────────────── */
      await page.getByRole('tab', { name: 'Custom rules' }).click()
      await expect(
        page.getByRole('tabpanel', { name: 'Custom rules' }),
      ).toBeVisible()
      await expect(page.getByText('Blocking mode active')).toBeVisible()
      expect(await postureStat(page, 'Paranoia level')).toBe('2')
      expect(await postureStat(page, 'Active rules')).toMatch(/^\d+\/\d+$/)
      // The seeded built-in group is visible and explained (phase + priority).
      await expect(page.getByRole('heading', { name: 'Rule groups' })).toBeVisible()
      await expect(page.getByText('WAFred 内置防护').first()).toBeVisible()

      // Column headers an operator needs to read a rule at a glance.
      for (const header of [
        'Priority',
        'Name',
        'Action',
        'Protection mode',
        'Severity',
        'Tags',
        'Enabled',
      ]) {
        await expect(
          page.getByRole('columnheader', { name: header, exact: true }),
        ).toBeVisible()
      }

      // The counter must match the number of rendered rows (no empty table
      // while the page claims there are rules).
      const seededCount = await ruleCount(page)
      expect(seededCount).toBeGreaterThan(0)
      await expect(page.locator('tbody tr')).toHaveCount(seededCount)
      await expect(page.getByText('No data')).toHaveCount(0)
      await shot(page, 'ui-04-custom-rules')

      /* ── Add-rule dialog defaults ───────────────────────────────────── */
      await page.getByRole('button', { name: 'Add', exact: true }).click()
      const dialog = page.getByRole('dialog', { name: 'Add rule' })
      await expect(dialog).toBeVisible()
      await expect(dialog.getByRole('textbox', { name: /Name/ })).toHaveValue('')
      await expect(
        dialog.getByRole('combobox', { name: 'Field' }),
      ).toHaveValue('http.request.uri.path')
      await expect(
        dialog.getByRole('combobox', { name: 'Operator' }),
      ).toHaveValue('contains')
      await expect(
        dialog.getByRole('combobox', { name: 'Action' }),
      ).toHaveValue('block')
      await expect(
        dialog.getByRole('combobox', { name: 'Protection mode' }),
      ).toHaveValue('block')
      await expect(
        dialog.getByRole('spinbutton', { name: /Priority/ }),
      ).toHaveValue('100')
      await expect(
        dialog.getByRole('button', { name: 'Severity 3' }),
      ).toHaveAttribute('aria-pressed', 'true')
      await expect(dialog.getByRole('switch', { name: 'Enabled' })).toHaveAttribute(
        'aria-checked',
        'true',
      )
      await expect(dialog.getByPlaceholder('Add tag…')).toBeVisible()
      await expect(
        dialog.getByRole('button', { name: 'Create', exact: true }),
      ).toBeVisible()
      await shot(page, 'ui-06-add-rule-dialog-defaults')
      await dialog.getByRole('button', { name: 'Cancel' }).click()
      await expect(dialog).toHaveCount(0)
    } finally {
      await deleteSiteIfPresent(page, app.adminUrl, domain)
    }
  })

  test('validates the rule dialog, round-trips saved settings and confirms dangerous downgrades', async ({
    app,
  }) => {
    test.setTimeout(300_000)
    const { page } = app
    const domain = `waf-ui-${run}-b.e2e.test`
    const siteId = await app.createSite({
      name: `E2E waf ui ${run} b`,
      domain,
      upstream: origin,
    })
    try {
      await openProtection(page, app.adminUrl, siteId, 'custom')
      await expect(page.getByRole('heading', { name: 'Custom rules' })).toBeVisible()

      /* ── Dialog validation: name, then expression ───────────────────── */
      await page.getByRole('button', { name: 'Add', exact: true }).click()
      const dialog = page.getByRole('dialog', { name: 'Add rule' })
      await expect(dialog).toBeVisible()
      await dialog.getByRole('button', { name: 'Create', exact: true }).click()
      await expect(dialog.getByRole('alert')).toHaveText('Rule name is required')
      await dialog.getByRole('textbox', { name: /Name/ }).fill(`validation ${run}`)
      await dialog.getByRole('button', { name: 'Create', exact: true }).click()
      await expect(dialog.getByRole('alert')).toHaveText('Expression is required')
      await shot(page, 'ui-07-rule-dialog-validation')
      await dialog.getByRole('button', { name: 'Cancel' }).click()
      await expect(dialog).toHaveCount(0)
      // Nothing was created by the failed submissions.
      await expect(page.getByRole('status').filter({ hasText: 'Rule created' })).toHaveCount(0)

      /* ── Dangerous downgrade #1: turning the engine off ─────────────── */
      await page.getByRole('tab', { name: /WAF Engine/ }).click()
      const engine = page.getByRole('switch', { name: 'WAF Engine' })
      await expect(engine).toHaveAttribute('aria-checked', 'true')
      await engine.click()
      const offDialog = page.getByRole('dialog')
      await expect(offDialog).toContainText('Turn off the WAF engine?')
      await expect(offDialog).toContainText(
        'I understand this site will run without WAF protection',
      )
      const offConfirm = offDialog.getByRole('button', {
        name: 'Turn off WAF engine',
      })
      await expect(offConfirm).toBeDisabled()
      await offDialog.getByRole('checkbox').check()
      await expect(offConfirm).toBeEnabled()
      await shot(page, 'ui-08-engine-off-confirm')
      await offDialog.getByRole('button', { name: 'Cancel' }).click()
      await expect(page.getByRole('dialog')).toHaveCount(0)
      await expect(engine).toHaveAttribute('aria-checked', 'true')

      /* ── Save round-trip: deep inspection survives a reload ─────────── */
      const deep = page.getByRole('switch', { name: 'Deep inspection' })
      await expect(deep).toHaveAttribute('aria-checked', 'false')
      await deep.click()
      await expect(toast(page, 'Protection settings saved')).toBeVisible()
      await expect(deep).toHaveAttribute('aria-checked', 'true')
      await page.reload()
      await expect(page.getByRole('switch', { name: 'Deep inspection' })).toHaveAttribute(
        'aria-checked',
        'true',
      )

      // Detection sensitivity saves and reads back too (toast dedupe needs the
      // previous notice to be gone first).
      await expect(toast(page, 'Protection settings saved')).toHaveCount(0, {
        timeout: 10_000,
      })
      await page.getByRole('button', { name: 'Detection sensitivity 3' }).click()
      await expect(toast(page, 'Protection settings saved')).toBeVisible()
      await page.reload()
      await expect(
        page.getByRole('button', { name: 'Detection sensitivity 3' }),
      ).toHaveAttribute('aria-pressed', 'true')
      await shot(page, 'ui-09-engine-settings-roundtrip')

      /* ── Dangerous downgrade #2: site mode Block → Monitor ──────────── */
      await openProtection(page, app.adminUrl, siteId)
      await page.getByRole('button', { name: /^Monitor\b/ }).click()
      const modeDialog = page.getByRole('dialog')
      await expect(modeDialog).toContainText('Switch protection to Monitor?')
      await expect(modeDialog).toContainText(
        'I understand attacks will no longer be blocked',
      )
      const modeConfirm = modeDialog.getByRole('button', {
        name: 'Monitor',
        exact: true,
      })
      await expect(modeConfirm).toBeDisabled()
      await modeDialog.getByRole('checkbox').check()
      await expect(modeConfirm).toBeEnabled()
      await modeDialog.getByRole('button', { name: 'Cancel' }).click()
      await expect(page.getByText(/Site mode\s+Block/)).toBeVisible()

      /* ── CC tab: defaults, save toast, disable confirmation ─────────── */
      await page.getByRole('tab', { name: 'Rate limiting & challenge' }).click()
      const underAttack = page.getByRole('switch', { name: 'Under Attack Mode' })
      await expect(underAttack).toHaveAttribute('aria-checked', 'false')
      await underAttack.click()
      const underAttackDialog = page.getByRole('dialog')
      await expect(underAttackDialog).toContainText('Enable Under Attack Mode?')
      await expect(
        underAttackDialog.getByRole('button', {
          name: 'Enable Under Attack Mode',
        }),
      ).toBeVisible()
      await underAttackDialog.getByRole('button', { name: 'Cancel' }).click()
      await expect(underAttack).toHaveAttribute('aria-checked', 'false')

      const cc = page.getByRole('switch', { name: 'Enable CC protection' })
      await expect(cc).toHaveAttribute('aria-checked', 'false')
      // Server-side defaults for a fresh site.
      await expect(
        page.getByRole('spinbutton', { name: 'Clearance duration' }),
      ).toHaveValue('30')
      await expect(
        page.getByRole('spinbutton', { name: 'Rate threshold' }),
      ).toHaveValue('100')
      await cc.click()
      await expect(cc).toHaveAttribute('aria-checked', 'true')
      await page.getByRole('button', { name: 'Save', exact: true }).click()
      await expect(toast(page, 'CC protection saved')).toBeVisible()

      await cc.click()
      const ccDialog = page.getByRole('dialog')
      await expect(ccDialog).toContainText('Turn off challenge protection?')
      await expect(ccDialog).toContainText(
        'I understand the challenge will stop protecting this site',
      )
      const ccConfirm = ccDialog.getByRole('button', {
        name: 'Turn off challenge protection?',
      })
      await expect(ccConfirm).toBeDisabled()
      await ccDialog.getByRole('checkbox').check()
      await expect(ccConfirm).toBeEnabled()
      await shot(page, 'ui-10-cc-disable-confirm')
      await ccDialog.getByRole('button', { name: 'Cancel' }).click()
      await expect(cc).toHaveAttribute('aria-checked', 'true')

      await expectCleanText(page, 'protection pages (en)')
    } finally {
      await deleteSiteIfPresent(page, app.adminUrl, domain)
    }
  })

  test('custom-rules search keeps the posture banner and the empty state honest', async ({
    app,
  }) => {
    test.setTimeout(300_000)
    const { page } = app
    const domain = `waf-ui-${run}-d.e2e.test`
    const siteId = await app.createSite({
      name: `E2E waf ui ${run} d`,
      domain,
      upstream: origin,
    })
    try {
      await openProtection(page, app.adminUrl, siteId, 'custom')
      await expect(page.getByRole('heading', { name: 'Custom rules' })).toBeVisible()

      // Baseline before filtering: the banner describes the site's whole rule set.
      const seededCount = await ruleCount(page)
      expect(seededCount).toBeGreaterThan(0)
      const bannerBefore = (
        await page.getByText(/^\d+ of \d+ rules enabled$/).first().innerText()
      ).trim()
      expect(bannerBefore).toBe(`${seededCount} of ${seededCount} rules enabled`)

      // A search that matches nothing: the list must say "no matching rules"
      // and the posture banner must keep describing the site rather than the
      // (empty) filtered result.
      await page.getByRole('textbox', { name: 'Search' }).fill(`zz-no-such-${run}`)
      await expect(page.getByText(/^\d+ rules$/).first()).toHaveText('0 rules')
      await shot(page, 'ui-05-custom-rules-search')

      expect
        .soft(
          await page.getByText('No matching rules').count(),
          'a filtered-empty list must show the no-results state, not claim the rule pack is missing',
        )
        .toBeGreaterThan(0)
      expect
        .soft(
          await page.getByText('No WAF rules').count(),
          'a search must not claim the site has no rules at all',
        )
        .toBe(0)
      expect
        .soft(
          (
            await page
              .getByText(/^\d+ of \d+ rules enabled$/)
              .first()
              .innerText()
          ).trim(),
          'the posture banner must keep reporting the site rule set while a search filter is active',
        )
        .toBe(bannerBefore)
      await page.getByRole('button', { name: 'Reset', exact: true }).click()
      await expect(page.getByText(/^\d+ rules$/).first()).toHaveText(`${seededCount} rules`)
    } finally {
      await deleteSiteIfPresent(page, app.adminUrl, domain)
    }
  })

  test('keeps site and global settings consistent and localises the page (en/zh)', async ({
    app,
  }) => {
    test.setTimeout(300_000)
    const { page } = app
    const domain = `waf-ui-${run}-c.e2e.test`
    const siteId = await app.createSite({
      name: `E2E waf ui ${run} c`,
      domain,
      upstream: origin,
    })
    try {
      /* ── Site page: banner ↔ engine tab agree ───────────────────────── */
      await openProtection(page, app.adminUrl, siteId, 'custom')
      await expectCleanText(page, 'custom rules (en)')
      const bannerParanoia = await postureStat(page, 'Paranoia level')
      const bannerActive = await postureStat(page, 'Active rules')
      const bannerCount = await ruleCount(page)
      expect(bannerActive).toBe(`${bannerCount}/${bannerCount}`)
      await shot(page, 'ui-11-custom-rules-consistency')

      await page.getByRole('tab', { name: /WAF Engine/ }).click()
      expect(String(await pressedParanoia(page))).toBe(bannerParanoia)
      const deepOn =
        (await page
          .getByRole('switch', { name: 'Deep inspection' })
          .getAttribute('aria-checked')) === 'true'
      const siteObsOn = await siteObservationOn(page)

      await page.getByRole('tab', { name: 'Overview' }).click()
      await expect(
        page.getByText(new RegExp(`Deep inspection\\s+${deepOn ? 'ON' : 'OFF'}`)),
      ).toBeVisible()
      await expect(page.getByText(/Site mode\s+Block/)).toBeVisible()

      /* ── Global settings page agrees with the site card ─────────────── */
      await page.goto(app.adminUrl('/settings'))
      await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible()
      await expect(
        page.getByRole('heading', { name: 'Observation mode' }),
      ).toBeVisible()
      await expect(
        page.getByRole('heading', { name: 'API protection' }),
      ).toBeVisible()
      const globalStatus = (
        await page.getByText(/^(Observing|Enforcing)$/).first().innerText()
      ).trim()
      expect(globalStatus === 'Observing').toBe(siteObsOn)
      // The control-plane WAF is a global WAF surface too; it must render its
      // switch instead of an empty card.
      await expect(page.getByRole('switch', { name: /^WAF\s/ })).toBeVisible()
      await expectCleanText(page, 'settings (en)')
      await shot(page, 'ui-12-settings-observation-api-waf')

      /* ── Chinese locale: the same page must be translated ───────────── */
      await page.getByRole('button', { name: '中文', exact: true }).click()
      await openProtection(page, app.adminUrl, siteId, 'custom')
      await expect(page.getByRole('heading', { name: 'Web 防护' })).toBeVisible()
      await expect(page.getByRole('tab', { name: '自定义规则' })).toBeVisible()
      await expect(page.getByRole('heading', { name: '自定义规则' })).toBeVisible()
      await expect(page.getByRole('button', { name: '添加', exact: true })).toBeVisible()
      await expect(page.getByText('拦截模式已激活')).toBeVisible()
      await expectCleanText(page, 'custom rules (zh)')
      await shot(page, 'ui-13-custom-rules-zh')

      // Back to English so a later run on the same browser profile starts
      // from the documented locale (the fixture also pins it per test).
      await page.goto(app.adminUrl('/settings'))
      await page.getByRole('button', { name: 'English', exact: true }).click()
      await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible()
    } finally {
      await deleteSiteIfPresent(page, app.adminUrl, domain)
    }
  })
})
