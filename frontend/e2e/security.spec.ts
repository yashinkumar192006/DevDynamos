/**
 * Authorization and visibility enforcement as observed through the UI.
 *
 * Every assertion is about server-produced state: the console renders what
 * the backend released, and scope boundaries (own events vs. full trail,
 * admin-only controls) must be visible at the interface level too.
 *
 * Precondition: gateway on http://localhost:8000 with the seeded demo
 * database.
 */

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

async function loginAs(page: Page, username: string, password: string) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  // After a sign-out the app returns you to the route you left (by design),
  // so the tests navigate explicitly to whatever they need next.
  await expect(page).not.toHaveURL(/\/login/)
}

async function signOut(page: Page) {
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login/)
}

test('blocked decision displays no stored values and no records section', async ({
  page,
}) => {
  await loginAs(page, 'mia.torres', 'MiaIntern@2024!')
  await page.goto('/simulator')
  await page.getByRole('button', { name: /Intern peeks at salary/ }).click()
  await page.getByRole('button', { name: 'Send secure request' }).click()

  const banner = page.getByTestId('result-banner')
  await expect(banner).toBeVisible()
  await expect(banner).toContainText('BLOCK')
  // The denial is still auditable — but nothing was retrieved or released.
  await expect(banner).toContainText('retrieved: no')

  // A blocked request releases nothing: no records table is rendered at all.
  await expect(page.getByText(/Authorized records/)).toHaveCount(0)
  await expect(page.getByText('Field decisions')).toBeVisible()
})

test('audit trail is scope-isolated: own events only, full trail for admin', async ({
  page,
}) => {
  // Sarah generates fresh, identifiable activity.
  await loginAs(page, 'sarah.chen', 'SarahHR@2024!')
  await page.goto('/simulator')
  await page.getByRole('button', { name: /HR salary review/ }).click()
  await page.getByRole('button', { name: 'Send secure request' }).click()
  await expect(page.getByTestId('result-banner')).toContainText('ALLOW')

  // As the customer, the trail contains her own events and none of Sarah's.
  await signOut(page)
  await loginAs(page, 'natalie.brooks', 'NatalieCust@2024!')
  await page.goto('/audit')
  await expect(page.getByTestId('audit-row').first()).toBeVisible()
  await expect(page.getByText('Sarah Chen')).toHaveCount(0)

  // As the administrator, the same event is part of the full trail.
  await signOut(page)
  await loginAs(page, 'admin', 'Admin@2024!')
  await page.goto('/audit')
  await expect(page.getByText('Sarah Chen').first()).toBeVisible()
})

test('admin-only policy control is absent for regular users', async ({ page }) => {
  await loginAs(page, 'natalie.brooks', 'NatalieCust@2024!')
  await page.goto('/policies')
  await expect(page.getByText('Include inactive versions')).toHaveCount(0)

  await signOut(page)
  await loginAs(page, 'admin', 'Admin@2024!')
  await page.goto('/policies')
  await expect(page.getByText('Include inactive versions')).toBeVisible()
})
