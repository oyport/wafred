import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/app'
import { requiredEnv } from '../support/env'

/**
 * WAF custom rules, end to end through the browser only.
 *
 * Flow: create a site in the UI → turn deep inspection on (advanced mode) →
 * add a `block` custom rule that matches a query marker → verify the list row →
 * edit the rule (name + action) and back → hit the edge (403 + block page with
 * a Request ID) → downgrade the site to monitor through the confirmation
 * dialog → the same request now returns 200 and a monitor security event
 * appears in Logs with the configured rule name/id → delete the rule and the
 * site.
 *
 * Everything is serialised (workers=1 in playwright.config.ts) and the site is
 * removed in `finally`, even when an assertion fails.
 */

const SHOT_DIR = 'artifacts/waf-03231'

async function shot(page: Page, name: string) {
  await page.screenshot({ path: `${SHOT_DIR}/${name}.png`, fullPage: true })
}

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const domain = `waf-rules-${run}.e2e.test`
const origin = requiredEnv('E2E_ORIGIN_URL')
const marker = `e2e-attack-${run}`
const ruleName = `E2E block query ${run}`
const editedName = `${ruleName} (edited)`

/** The visible toast for a title, e.g. "Rule created". */
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
 * Waits for one security-event row matching `query` (a log search expression)
 * to appear on the Logs page, reloading the filtered view until it does.
 */
async function waitForEventRow(
  page: Page,
  adminUrl: (path: string) => string,
  siteId: string,
  query: string,
  expectedText: string,
  timeout = 150_000,
) {
  // The Logs page's default window ends at the current minute (`datetime-local`
  // has no seconds), which hides an event from the current minute for up to
  // 60 s. Pin an explicit window around "now" so the assertion sees the event
  // as soon as the agent pushes it, instead of depending on the minute tick.
  const to = new Date(Date.now() + 5 * 60_000).toISOString().slice(0, 16)
  const from = new Date(Date.now() - 60 * 60_000).toISOString().slice(0, 16)
  const url = adminUrl(
    `/logs?tab=security&site_id=${siteId}&q=${encodeURIComponent(query)}` +
      `&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
  )
  const deadline = Date.now() + timeout
  for (;;) {
    await page.goto(url)
    // Let the page's query settle after the navigation: checking immediately
    // would only ever see the loading skeleton.
    await page.waitForTimeout(2_500)
    // `tbody tr` excludes the header; the "No data" placeholder row means the
    // filtered query has not returned our event yet.
    const rows = page.locator('tbody tr').filter({ hasNotText: 'No data' })
    if ((await rows.count()) > 0) {
      const row = rows.filter({ hasText: expectedText }).first()
      if (await row.count()) return row
      const texts = await rows.allInnerTexts()
      throw new Error(
        `security event for "${query}" arrived without "${expectedText}":\n${texts.join('\n---\n')}`,
      )
    }
    if (Date.now() > deadline) {
      throw new Error(`security event not found for "${query}" (${expectedText})`)
    }
    await page.waitForTimeout(1_500)
  }
}

test.describe('WAF custom rules', () => {
  test('creates, enforces, downgrades and audits a custom rule through the UI', async ({
    app,
  }) => {
    test.setTimeout(600_000)
    const { page } = app
    const siteId = await app.createSite({
      name: `E2E waf rules ${run}`,
      domain,
      upstream: origin,
    })

    try {
      await app.waitForSite(domain)

      /* ── 1. Advanced mode ("deep inspection") through the UI ─────────── */
      await page.goto(
        app.adminUrl(`/sites/${siteId}/security/protection?tab=engine`),
      )
      const deepInspection = page.getByRole('switch', { name: 'Deep inspection' })
      await expect(deepInspection).toHaveAttribute('aria-checked', 'false')
      await deepInspection.click()
      await expect(toast(page, 'Protection settings saved')).toBeVisible()
      await expect(deepInspection).toHaveAttribute('aria-checked', 'true')
      await shot(page, 'custom-rules-01-advanced-mode-on')

      /* ── 2. Create the custom rule in the UI ─────────────────────────── */
      await page.goto(
        app.adminUrl(`/sites/${siteId}/security/protection?tab=custom`),
      )
      await expect(
        page.getByRole('heading', { name: 'Custom rules' }),
      ).toBeVisible()
      const countBefore = await page
        .getByText(/^\d+ rules$/)
        .first()
        .innerText()

      await page.getByRole('button', { name: 'Add', exact: true }).click()
      const dialog = page.getByRole('dialog', { name: 'Add rule' })
      await expect(dialog).toBeVisible()

      await dialog.getByRole('textbox', { name: /Name/ }).fill(ruleName)
      await dialog
        .getByRole('combobox', { name: 'Field' })
        .selectOption('http.request.uri.query')
      await dialog
        .getByRole('combobox', { name: 'Operator' })
        .selectOption('contains')
      await dialog.getByRole('textbox', { name: 'Value' }).fill(marker)

      // The builder must show the expression it will store, so the operator
      // can read what will be enforced before saving.
      await expect(
        dialog.getByText(`http.request.uri.query contains "${marker}"`, {
          exact: true,
        }),
      ).toBeVisible()

      await dialog.getByRole('combobox', { name: 'Action' }).selectOption('block')
      await dialog
        .getByRole('combobox', { name: 'Protection mode' })
        .selectOption('block')
      await dialog.getByRole('spinbutton', { name: /Priority/ }).fill('10')
      await dialog.getByRole('button', { name: 'Severity 5' }).click()
      await expect(
        dialog.getByRole('button', { name: 'Severity 5' }),
      ).toHaveAttribute('aria-pressed', 'true')
      await dialog.getByPlaceholder('Add tag…').fill('e2e')
      await dialog.getByPlaceholder('Add tag…').press('Enter')
      await shot(page, 'custom-rules-02-rule-dialog-filled')

      await dialog.getByRole('button', { name: 'Create', exact: true }).click()
      await expect(dialog).toHaveCount(0)
      await expect(toast(page, 'Rule created')).toBeVisible()

      /* ── 3. The list echoes every field the user configured ──────────── */
      const row = page.getByRole('row').filter({ hasText: ruleName })
      await expect(row).toBeVisible()
      await expect(row.getByRole('cell').first()).toHaveText('10')
      await expect(row).toContainText(marker)
      await expect(row.locator('[title="5/5"]')).toBeVisible()
      await expect(
        row.getByRole('switch', { name: `Enabled: ${ruleName}` }),
      ).toHaveAttribute('aria-checked', 'true')
      // Both the action badge and the rule-mode badge read "Block".
      await expect(row.getByText('Block', { exact: true })).toHaveCount(2)
      await expect(page.getByText(/^\d+ rules$/).first()).not.toHaveText(
        countBefore,
      )
      await shot(page, 'custom-rules-03-rule-listed')

      /* ── 4. Edit the rule: rename + action, then back to block ───────── */
      await row.getByRole('button', { name: 'Edit' }).click()
      const editDialog = page.getByRole('dialog', { name: 'Edit rule' })
      await expect(editDialog).toBeVisible()
      const nameField = editDialog.getByRole('textbox', { name: /Name/ })
      await expect(nameField).toHaveValue(ruleName)
      await expect(
        editDialog.getByRole('combobox', { name: 'Field' }),
      ).toHaveValue('http.request.uri.query')
      await expect(
        editDialog.getByRole('combobox', { name: 'Operator' }),
      ).toHaveValue('contains')
      await expect(
        editDialog.getByRole('textbox', { name: 'Value' }),
      ).toHaveValue(marker)

      await nameField.fill(editedName)
      await editDialog
        .getByRole('combobox', { name: 'Action' })
        .selectOption('log')
      await editDialog.getByRole('button', { name: 'Save', exact: true }).click()
      await expect(editDialog).toHaveCount(0)
      await expect(toast(page, 'Rule updated')).toBeVisible()

      const logRow = page.getByRole('row').filter({ hasText: editedName })
      await expect(logRow).toBeVisible()
      await expect(logRow.getByText('Log', { exact: true })).toBeVisible()

      await logRow.getByRole('button', { name: 'Edit' }).click()
      await expect(editDialog).toBeVisible()
      await editDialog
        .getByRole('combobox', { name: 'Action' })
        .selectOption('block')
      await editDialog.getByRole('button', { name: 'Save', exact: true }).click()
      await expect(editDialog).toHaveCount(0)
      await expect(
        page
          .getByRole('row')
          .filter({ hasText: editedName })
          .getByText('Block', { exact: true }),
      ).toHaveCount(2)
      await shot(page, 'custom-rules-04-rule-edited')

      /* ── 5. Edge: a normal request passes, the marked one is blocked ─── */
      const normal = await page.goto(`http://${domain}/?e2e-normal=${run}`)
      expect(normal?.status()).toBe(200)

      const attackUrl = `http://${domain}/?${marker}=1`
      let blockedBody = ''
      await expect
        .poll(
          async () => {
            const response = await page.goto(attackUrl)
            const status = response?.status() ?? 0
            if (status === 403) blockedBody = await page.locator('body').innerText()
            return status
          },
          {
            message:
              'the custom block rule must reach the edge and return 403',
            timeout: 150_000,
            intervals: [2_000, 5_000],
          },
        )
        .toBe(403)

      // The branded block page must name WAFred, the rule that fired and the
      // request id the operator can quote in a support ticket.
      expect(blockedBody).toContain('Request Blocked')
      expect(blockedBody).toContain('WAFred Security')
      expect(blockedBody).toContain(editedName)
      const requestIdMatch = blockedBody.match(
        /Request ID\s*\n?\s*([0-9a-fA-F]{8,64})/,
      )
      expect(
        requestIdMatch?.[1],
        `block page must show a Request ID; body was:\n${blockedBody}`,
      ).toBeTruthy()
      const blockedRequestId = requestIdMatch![1]
      await shot(page, 'custom-rules-05-edge-blocked')

      /* ── 6. Downgrade the site to monitor via the confirmation dialog ── */
      await page.goto(app.adminUrl(`/sites/${siteId}/security/protection`))
      await expect(
        page.getByRole('heading', { name: 'Protection mode' }),
      ).toBeVisible()
      await page.getByRole('button', { name: /^Monitor/ }).click()
      const downgradeDialog = page.getByRole('dialog')
      await expect(downgradeDialog).toContainText(
        'Switch protection to Monitor?',
      )
      const confirmMonitor = downgradeDialog.getByRole('button', {
        name: 'Monitor',
        exact: true,
      })
      await expect(confirmMonitor).toBeDisabled()
      await downgradeDialog.getByRole('checkbox').check()
      await expect(confirmMonitor).toBeEnabled()
      await confirmMonitor.click()
      await expect(toast(page, 'Mode applied to all rules')).toBeVisible()
      await expect(page.getByText(/Site mode\s+Monitor/)).toBeVisible({
        timeout: 30_000,
      })
      await shot(page, 'custom-rules-06-site-monitor')

      // Monitor mode must stop enforcing but keep detecting: 200 + event.
      let monitorRequestId = ''
      await expect
        .poll(
          async () => {
            const response = await page.goto(attackUrl)
            const status = response?.status() ?? 0
            if (status === 200) {
              monitorRequestId =
                (await response?.headerValue('x-request-id')) ?? ''
            }
            return status
          },
          {
            message:
              'with the site in monitor mode the marked request must be allowed',
            timeout: 150_000,
            intervals: [2_000, 5_000],
          },
        )
        .toBe(200)
      expect(
        monitorRequestId,
        'a proxied response must carry the WAF request id',
      ).toMatch(/^[0-9a-fA-F]{8,64}$/)

      /* ── 7. Security events: block event, then monitor event ─────────── */
      // The block event is keyed by the request id printed on the block page.
      const blockEvent = await waitForEventRow(
        page,
        app.adminUrl,
        siteId,
        `request_id:${blockedRequestId}`,
        editedName,
      )
      await expect(blockEvent).toContainText('Block')
      await blockEvent.click()
      const blockDetail = page.getByRole('dialog')
      await expect(blockDetail).toContainText('Security event details')
      await expect(blockDetail).toContainText(blockedRequestId)
      await expect(blockDetail).toContainText(editedName)
      await expect(blockDetail.locator('pre').first()).toContainText(
        'rule_action=block',
      )
      await expect(blockDetail.locator('pre').first()).toContainText('sev=5')
      await shot(page, 'custom-rules-07-block-event-detail')
      await page.keyboard.press('Escape')

      // The monitor event must say the block was downgraded, not configured
      // away: `action: monitor` alone would hide a broken block rule.
      const monitorEvent = await waitForEventRow(
        page,
        app.adminUrl,
        siteId,
        `request_id:${monitorRequestId}`,
        editedName,
      )
      await expect(monitorEvent).toContainText('Monitor')
      await monitorEvent.click()
      const monitorDetail = page.getByRole('dialog')
      await expect(monitorDetail).toContainText(monitorRequestId)
      await expect(monitorDetail).toContainText(editedName)
      await expect(monitorDetail.locator('pre').first()).toContainText(
        'downgraded=true',
      )
      await expect(monitorDetail.locator('pre').first()).toContainText(
        'would_enforce=block',
      )
      await expect(monitorDetail.locator('pre').first()).toContainText(
        'cause=site-mode-monitor',
      )

      // The rule id shown in the event is a deep link back to the rule dialog:
      // the log and the configuration must agree on what fired.
      const ruleLink = monitorDetail.getByRole('link', {
        name: /^[0-9a-f-]{36}$/,
      })
      await expect(ruleLink).toBeVisible()
      const ruleId = (await ruleLink.innerText()).trim()
      expect(ruleId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
      await shot(page, 'custom-rules-08-monitor-event-detail')
      await ruleLink.click()
      await expect(page).toHaveURL(
        new RegExp(`/sites/${siteId}/security/protection`),
      )
      const deepLinkDialog = page.getByRole('dialog', { name: 'Edit rule' })
      await expect(deepLinkDialog).toBeVisible()
      await expect(
        deepLinkDialog.getByRole('textbox', { name: /Name/ }),
      ).toHaveValue(editedName)
      await shot(page, 'custom-rules-09-event-rule-deeplink')
      await deepLinkDialog.getByRole('button', { name: 'Cancel' }).click()
      await expect(deepLinkDialog).toHaveCount(0)

      /* ── 8. Delete the rule through its confirmation dialog ──────────── */
      const deleteRow = page.getByRole('row').filter({ hasText: editedName })
      await expect(deleteRow).toBeVisible()
      await deleteRow.getByRole('button', { name: 'Delete' }).click()
      const deleteDialog = page.getByRole('dialog')
      await expect(deleteDialog).toContainText('Delete rule')
      await expect(deleteDialog).toContainText(editedName)
      await expect(deleteDialog).toContainText(marker)
      await shot(page, 'custom-rules-10-delete-rule-confirm')
      await deleteDialog.getByRole('button', { name: 'Delete', exact: true }).click()
      await expect(toast(page, 'Rule deleted')).toBeVisible()
      await expect(
        page.getByRole('row').filter({ hasText: editedName }),
      ).toHaveCount(0, { timeout: 30_000 })
    } finally {
      await deleteSiteIfPresent(page, app.adminUrl, domain)
    }
  })
})
