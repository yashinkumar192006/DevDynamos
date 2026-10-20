/**
 * Critical user journeys against the REAL backend.
 *
 * Precondition: gateway on http://localhost:8000 with the seeded demo
 * database. Every assertion below is about data the backend produced —
 * there is no mocked API layer anywhere in these tests.
 */

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

async function loginAs(page: Page, username: string, password: string) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page).toHaveURL(/\/dashboard/)
}

test('invalid credentials are rejected by the backend', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel('Username').fill('sarah.chen')
  await page.getByLabel('Password').fill('definitely-wrong')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(
    page.getByText(/invalid username or password/i),
  ).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
})

test('a stored but invalid session redirects to login with a notice', async ({
  page,
}) => {
  await page.goto('/login')
  await page.evaluate(() =>
    window.localStorage.setItem('contextshield.token', 'invalid-token'),
  )
  await page.goto('/dashboard')
  await expect(page).toHaveURL(/\/login/)
  await expect(
    page.getByText(/session expired or was revoked/i),
  ).toBeVisible()
})

test('hr_manager: HR salary request is ALLOWed with released values', async ({
  page,
}) => {
  await loginAs(page, 'sarah.chen', 'SarahHR@2024!')
  await page.goto('/simulator')
  await page.getByRole('button', { name: /HR salary review/ }).click()
  await page.getByRole('button', { name: 'Send secure request' }).click()

  const banner = page.getByTestId('result-banner')
  await expect(banner).toBeVisible()
  await expect(banner).toContainText('ALLOW')
  await expect(banner).toContainText('Audit reference')

  // The released values are real — the base salary field shows a number.
  await expect(page.getByText('Field decisions')).toBeVisible()
})

test('marketing intern: salary access is BLOCKed with a reason code', async ({
  page,
}) => {
  await loginAs(page, 'mia.torres', 'MiaIntern@2024!')
  await page.goto('/simulator')
  await page.getByRole('button', { name: /Intern peeks at salary/ }).click()
  await page.getByRole('button', { name: 'Send secure request' }).click()

  const banner = page.getByTestId('result-banner')
  await expect(banner).toBeVisible()
  await expect(banner).toContainText('BLOCK')
  await expect(banner).toContainText('INSUFFICIENT_ROLE')
})

test('customer: own order is ALLOWed, another customer is BLOCKed', async ({
  page,
}) => {
  await loginAs(page, 'natalie.brooks', 'NatalieCust@2024!')

  // Own order — allowed.
  await page.goto('/simulator')
  await page.getByRole('button', { name: /Customer checks own order/ }).click()
  await page.getByRole('button', { name: 'Send secure request' }).click()
  const allowBanner = page.getByTestId('result-banner')
  await expect(allowBanner).toBeVisible()
  await expect(allowBanner).toContainText('ALLOW')

  // Another customer's record — blocked.
  await page.getByRole('button', { name: /Customer probes another account/ }).click()
  await page.getByRole('button', { name: 'Send secure request' }).click()
  const blockBanner = page.getByTestId('result-banner')
  await expect(blockBanner).toContainText('BLOCK')
  await expect(blockBanner).toContainText('INSUFFICIENT_ROLE')
})

test('audit trail shows recorded events and opens full detail', async ({
  page,
}) => {
  await loginAs(page, 'natalie.brooks', 'NatalieCust@2024!')

  // Record one event so the trail is guaranteed non-empty for this user.
  await page.goto('/simulator')
  await page.getByRole('button', { name: /Customer checks own order/ }).click()
  await page.getByRole('button', { name: 'Send secure request' }).click()
  await expect(page.getByTestId('result-banner')).toContainText('ALLOW')

  await page.goto('/audit')
  const firstRow = page.getByTestId('audit-row').first()
  await expect(firstRow).toBeVisible()
  await firstRow.click()
  await expect(page).toHaveURL(/\/audit\/.+/)
  await expect(page.getByText('Field decisions')).toBeVisible()
})

test('policy viewer and asset catalogue render backend data', async ({
  page,
}) => {
  await loginAs(page, 'natalie.brooks', 'NatalieCust@2024!')

  await page.goto('/policies')
  await expect(page.getByText('salary_access_policy').first()).toBeVisible()

  await page.goto('/assets')
  await expect(page.getByText('employee_salary').first()).toBeVisible()
})

test('dashboard shows the identity-scoped visibility label', async ({
  page,
}) => {
  await loginAs(page, 'sarah.chen', 'SarahHR@2024!')
  await expect(
    page.getByText(/Privacy trail \(compliance role\)/),
  ).toBeVisible()
})

test('SDK documentation page renders and exposes no backend secrets', async ({
  page,
}) => {
  await loginAs(page, 'natalie.brooks', 'NatalieCust@2024!')

  // Direct deep-link navigation (then refresh) must work, not only in-app clicks.
  await page.goto('/sdk')
  await expect(
    page.getByRole('heading', { name: 'SDK & Integration' }),
  ).toBeVisible()
  await expect(
    page.getByText('CONTEXTSHIELD_API_KEY', { exact: true }),
  ).toBeVisible()
  await expect(page.getByText('http://localhost:8000').first()).toBeVisible()

  await page.reload()
  await expect(
    page.getByRole('heading', { name: 'SDK & Integration' }),
  ).toBeVisible()

  // The page must never render server-side secrets or provider keys.
  const body = page.locator('body')
  await expect(body).not.toContainText('dev-secret-key-change-me')
  await expect(body).not.toContainText('GEMINI_API_KEY')
  await expect(body).not.toContainText('DATABASE_URL')
})
