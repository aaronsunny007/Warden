import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:3100', trace: 'on-first-retry' },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // The sandbox ships a Chromium that this Playwright version did not download itself; use it.
        launchOptions: {
          executablePath: process.env.WARDEN_CHROMIUM || undefined,
          args: ['--no-sandbox', '--headless=new'],
        },
      },
    },
  ],
  webServer: {
    // The e2e suite runs against a stub API server (no live gateway needed).
    command: 'NEXT_PUBLIC_WARDEN_API_BASE=http://127.0.0.1:3101 next build && node e2e/stub-server.mjs',
    url: 'http://127.0.0.1:3100',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
