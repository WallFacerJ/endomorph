import {
  defineConfig,
  devices,
} from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",

  /*
    The default 30s is too tight for this suite. A single scenario mounts in
    about 1.2s, but the default scenario compiles 20,053 events in the
    browser and several workers do that at once against a dev server, which
    pushed the slowest test to 27s and made it flake. The headroom is for
    contention, not for a slow app -- if a test genuinely approaches this,
    something has regressed.
  */
  timeout: 60_000,

  /*
    And the same for assertions. The failure this fixes was an expect
    timeout, not a test timeout: the first assertion after landing on the
    default scenario waits for the scenario picker, which does not paint
    until 20,053 events have been compiled in the browser. Under parallel
    workers that exceeded the 5s default while the test itself had plenty of
    time left.
  */
  expect: { timeout: 15_000 },

  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI
    ? "github"
    : "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
      },
    },
  ],
  webServer: {
    command:
      "pnpm build && pnpm --filter @endomorph/web exec vite --host 127.0.0.1 --port 4173",
    url: "http://127.0.0.1:4173",
    reuseExistingServer:
      !process.env.CI,
    timeout: 120_000,
  },
});
