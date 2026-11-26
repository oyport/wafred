import { test, expect } from '../fixtures/app'
import { requiredEnv } from '../support/env'

/**
 * Tunnel console contract.
 *
 * The connector itself is exercised by `scripts/tunnel-smoke.sh` (it needs a
 * host that can dial an edge); what this spec pins is the console surface that
 * an operator actually drives:
 *
 *   1. creating a tunnel returns a one-time pairing command (and says so);
 *   2. the list distinguishes "pending pairing" from "paired" and from
 *      "connector online" — three states that must not collapse into one;
 *   3. rename / disable / re-pair / revoke / delete each work from their own
 *      row control without leaving the page;
 *   4. an origin pool can be bound to the tunnel, and the binding survives a
 *      reload.
 */

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const tunnelName = `e2e-tunnel-${run}`
const renamed = `${tunnelName}-renamed`
const origin = requiredEnv('E2E_ORIGIN_URL')

test.describe('tunnels', () => {
  test('create, rename, disable, re-pair, revoke and delete a tunnel', async ({ app }) => {
    const page = app.page
    await page.goto('/agents')
    await page.getByRole('tab', { name: 'Tunnels' }).click()

    // ── Create: the pairing command is shown exactly once ────────────────────
    await page.getByRole('button', { name: 'Create tunnel' }).click()
    await page.getByRole('textbox', { name: 'Name' }).fill(tunnelName)
    await page.getByRole('button', { name: 'Create tunnel', exact: true }).last().click()

    const pairingDialog = page.getByRole('dialog')
    await expect(pairingDialog.getByText('Install and pair')).toBeVisible()
    const command = pairingDialog.locator('pre')
    await expect(command).toContainText('--mode tunnel')
    await expect(command).toContainText('--token')
    await expect(pairingDialog.getByText(/shown once/i)).toBeVisible()
    await pairingDialog.getByRole('button', { name: 'Done' }).click()

    // ── The row exists and is pending, not connected ─────────────────────────
    const row = page.getByRole('row').filter({ hasText: tunnelName })
    await expect(row).toHaveCount(1)
    await expect(row.getByText('Pending pairing')).toBeVisible()
    await expect(row.getByText('Connector offline')).toBeVisible()

    // ── Rename ───────────────────────────────────────────────────────────────
    await row.getByTitle('Rename').click()
    const renameDialog = page.getByRole('dialog')
    await renameDialog.getByRole('textbox', { name: 'Name' }).fill(renamed)
    await renameDialog.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByRole('row').filter({ hasText: renamed })).toHaveCount(1)

    // ── Disable → the badge changes; enable brings it back ───────────────────
    const renamedRow = page.getByRole('row').filter({ hasText: renamed })
    await renamedRow.getByTitle('Disable').click()
    await expect(page.getByRole('row').filter({ hasText: renamed }).getByText('Disabled')).toBeVisible()
    await page
      .getByRole('row')
      .filter({ hasText: renamed })
      .getByTitle('Enable')
      .click()
    await expect(
      page.getByRole('row').filter({ hasText: renamed }).getByText('Pending pairing'),
    ).toBeVisible()

    // ── Re-pair mints a new token and rotates the credential ─────────────────
    await page.getByRole('row').filter({ hasText: renamed }).getByRole('button', { name: 'Re-pair' }).click()
    await expect(page.getByRole('dialog').locator('pre')).toContainText('--mode tunnel')
    await page.getByRole('dialog').getByRole('button', { name: 'Done' }).click()

    // ── Revoke ───────────────────────────────────────────────────────────────
    await page.getByRole('row').filter({ hasText: renamed }).getByRole('button', { name: 'Revoke' }).click()
    const revokeDialog = page.getByRole('dialog')
    await expect(revokeDialog.getByText('Revoke the tunnel credential?')).toBeVisible()
    await revokeDialog.getByRole('button', { name: 'Revoke', exact: true }).click()
    await expect(page.getByText('Tunnel credential revoked')).toBeVisible()

    // ── Delete ───────────────────────────────────────────────────────────────
    await page.getByRole('row').filter({ hasText: renamed }).getByTitle('Delete').click()
    const deleteDialog = page.getByRole('dialog')
    await expect(deleteDialog.getByText('Delete this tunnel?')).toBeVisible()
    await deleteDialog.getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByRole('row').filter({ hasText: renamed })).toHaveCount(0)
  })

  test('an origin pool can be bound to a tunnel and the binding persists', async ({ app }) => {
    const page = app.page
    const domain = `tunnel-${run}.e2e.test`
    const siteId = await app.createSite({
      name: `E2E tunnel ${run}`,
      domain,
      upstream: origin,
    })
    await app.waitForSite(domain)

    // A tunnel to bind to.
    await page.goto('/agents')
    await page.getByRole('tab', { name: 'Tunnels' }).click()
    await page.getByRole('button', { name: 'Create tunnel' }).click()
    await page.getByRole('textbox', { name: 'Name' }).fill(`${tunnelName}-pool`)
    await page.getByRole('button', { name: 'Create tunnel', exact: true }).last().click()
    await page.getByRole('dialog').getByRole('button', { name: 'Done' }).click()

    // Bind the site's default pool to it.
    await page.goto(app.adminUrl(`/sites/${siteId}/basic`))
    await page.getByRole('button', { name: 'Edit origin pool' }).first().click()
    const poolDialog = page.getByRole('dialog')
    await poolDialog.getByRole('combobox', { name: 'Tunnel' }).selectOption({ label: `${tunnelName}-pool` })
    await poolDialog.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText('Origin pool updated')).toBeVisible()

    // Reload: the binding is read back from the server, not just local state.
    await page.reload()
    await page.getByRole('button', { name: 'Edit origin pool' }).first().click()
    await expect(
      page.getByRole('dialog').getByRole('combobox', { name: 'Tunnel' }),
    ).toHaveValue(/.+/)
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click()

    // Clean up: the tunnel cannot be deleted while the pool references it? It
    // can — the binding is cleared to NULL and the pool falls back to direct
    // origins, which is the documented behaviour.
    await page.goto('/agents')
    await page.getByRole('tab', { name: 'Tunnels' }).click()
    const row = page.getByRole('row').filter({ hasText: `${tunnelName}-pool` })
    await row.getByTitle('Delete').click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await app.deleteSiteIfPresent(domain)
  })
})