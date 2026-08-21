import {
  expect,
  test,
} from "@playwright/test";

const GENERATED_SCENARIO =
  "/?scenario=/scenarios/generated-enterprise.json";

test("generated enterprise scenario loads and renders", async ({
  page,
}) => {
  await page.goto(GENERATED_SCENARIO);

  // Regression guard. The first generated scenario failed to load at all:
  // background noise continued past the alert, so response actions were
  // dated before the newest opening event and the event store rejected
  // them. A green unit suite did not catch it -- only mounting the real
  // workspace did.
  await expect(
    page.getByText(
      "SCENARIO VALIDATION FAILED",
    ),
  ).toHaveCount(0);

  await expect(
    page.getByRole("button", {
      name: "Endpoint",
    }),
  ).toBeVisible();
});

test("generated enterprise gives the SIEM a real noise floor", async ({
  page,
}) => {
  await page.goto(GENERATED_SCENARIO);

  await page
    .getByRole("button", {
      name: "SIEM Search",
    })
    .click();

  // The volume is the product requirement: an analyst must have to search
  // rather than scroll a curated list.
  await expect(
    page.getByText(
      "MATCHING EVENTS",
    ),
  ).toBeVisible();

  const body = await page
    .locator("body")
    .innerText();

  const matched = body.match(
    /([\d,]+)\s*\n?\s*MATCHING EVENTS/i,
  );

  expect(matched).not.toBeNull();

  expect(
    Number(
      (matched?.[1] ?? "0").replace(
        /,/g,
        "",
      ),
    ),
  ).toBeGreaterThan(3000);
});
