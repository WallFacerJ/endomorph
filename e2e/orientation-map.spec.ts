import { expect, test } from "@playwright/test";

/**
 * The orientation doubles as a map of the sidebar.
 *
 * That is its stated purpose -- each step names the console the step happens
 * in -- so a step naming a console that is not in the navigation is worse than
 * no label at all: it sends someone arriving cold looking for a button that
 * does not exist. One step said "Investigation" for some time after that
 * console was renamed to "Brief".
 */
test("every orientation step names a console in the sidebar", async ({ page }) => {
  await page.goto("/?scenario=/scenarios/generated-macro.json");

  // The orientation does not paint until the scenario has compiled in the
  // browser, and under parallel workers that can lag the bare goto. Collecting
  // step text before then returns an empty list and fails the count assertion
  // for a reason that has nothing to do with the orientation -- so wait for
  // the first step to be visible rather than racing it.
  await expect(
    page.locator(".first-run-where").first(),
  ).toBeVisible();

  const steps = await page
    .locator(".first-run-where")
    .allTextContents();

  expect(steps.length).toBeGreaterThan(0);

  const nav = await page
    .getByRole("navigation")
    .getByRole("button")
    .evaluateAll((els) =>
      els.map((el) => (el.querySelector("span,strong")?.textContent ?? el.textContent ?? "").trim()),
    );

  for (const step of steps) {
    // A step may name more than one console, e.g. "Endpoint / Identity".
    for (const named of step.split("/").map((s) => s.trim())) {
      expect(
        nav.some((label) => label.startsWith(named)),
        `orientation names "${named}", sidebar has ${JSON.stringify(nav)}`,
      ).toBe(true);
    }
  }
});
