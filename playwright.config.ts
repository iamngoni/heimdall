import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.E2E_APP_PORT ?? 18080);
const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? `http://127.0.0.1:${port}`;
const databaseURL =
  process.env.DATABASE_URL ?? 'postgres://heimdall:heimdall@localhost:5432/heimdall_test';

process.env.DATABASE_URL = databaseURL;

const inheritedEnv = Object.fromEntries(
  Object.entries(process.env).filter((entry): entry is [string, string] => {
    return typeof entry[1] === 'string';
  }),
);

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL,
    trace: 'on-first-retry',
  },
  webServer: {
    command: 'cargo run --bin heimdall',
    url: `${baseURL}/health`,
    timeout: 120_000,
    reuseExistingServer: !process.env.CI,
    env: {
      ...inheritedEnv,
      APP_HOST: '127.0.0.1',
      APP_PORT: String(port),
      CORS_ALLOWED_ORIGIN: baseURL,
      DATABASE_URL: databaseURL,
      ENCRYPTION_KEY:
        process.env.ENCRYPTION_KEY ?? '0000000000000000000000000000000000000000000000000000000000000000',
      RUST_LOG: process.env.RUST_LOG ?? 'warn',
      SEMGREP_BIN: process.env.SEMGREP_BIN ?? 'node',
      SQLX_OFFLINE: 'false',
      WORKER_ENABLED: 'false',
    },
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],
});
