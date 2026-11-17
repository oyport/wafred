import { test, expect } from '../fixtures/app'

function contrast(foreground: string, background: string): number {
  const luminance = (color: string) => {
    const channels = color.match(/[\d.]+/g)?.slice(0, 3).map(Number)
    if (!channels || channels.length !== 3) throw new Error(`Unexpected color: ${color}`)
    const linear = channels.map((channel) => {
      const value = channel / 255
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4
    })
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
  }
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a)
  return (values[0] + 0.05) / (values[1] + 0.05)
}

for (const theme of ['light', 'dark'] as const) {
  test(`${theme} theme keeps action labels readable`, async ({ app }) => {
    const { page } = app
    await page.evaluate((mode) => localStorage.setItem('wafred.theme', mode), theme)
    await page.goto(app.adminUrl('/ssl'))
    const primary = page.getByRole('button', { name: 'Apply or upload', exact: true }).first()
    await expect(primary).toBeVisible()

    const colors = (button: typeof primary) => button.evaluate((element) => {
      const style = getComputedStyle(element)
      return { foreground: style.color, background: style.backgroundColor, opacity: style.opacity }
    })
    let current = await colors(primary)
    expect(contrast(current.foreground, current.background)).toBeGreaterThanOrEqual(4.5)
    await primary.hover()
    // Wait for the CSS color transition before measuring the hover state.
    await page.waitForTimeout(200)
    current = await colors(primary)
    expect(contrast(current.foreground, current.background)).toBeGreaterThanOrEqual(4.5)

    await primary.click()
    const dialog = page.getByRole('dialog', { name: 'Apply for or upload a certificate' })
    const save = dialog.getByRole('button', { name: 'Submit application' })
    await expect(save).toBeDisabled()
    current = await colors(save)
    expect(Number(current.opacity)).toBe(1)
    expect(contrast(current.foreground, current.background)).toBeGreaterThanOrEqual(3)
    const [red, green, blue] = current.background.match(/[\d.]+/g)!.slice(0, 3).map(Number)
    expect(Math.max(red, green, blue) - Math.min(red, green, blue)).toBeLessThan(35)
  })
}
