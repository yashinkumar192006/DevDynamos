import { defineConfig, devices } from '@playwright/test'

/**
 * End-to-end configuration for the ContextShield console.
 *
 * Prerequisites:
 *   1. The backend running on http://localhost:8000 with the migrated +
 *      seeded demo database (see frontend/README.md).
 *   2. Chromium installed once: `npx playwright install chromium`.
 *
 * The Vite dev server is started automatically (or reused when already
 * running). Journeys run sequentially against the real backend — the
 * demo database is shared state, so parallel workers are disabled.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'npm run dev -- --port 5173 --strictPort',
    url: 'http://localhost:5173',
    reuseExistingServer: true,
    timeout: 60_000,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
