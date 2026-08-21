import {
  expect,
  test,
} from "@playwright/test";

/**
 * "Response selection resembles an entry-level multiple-choice course."
 *
 * Professional runs no longer show a row of response cards beside the
 * timeline. Response work happens on the console where the analyst formed
 * the judgement. These assert the whole run remains completable that way --
 * an action with no console would be a silent, total failure.
 */

async function openInvestigation(
  page: import("@playwright/test").Page,
) {
  await page.goto("/");
  await page
    .getByRole("button", {
      name: "Open investigation",
    })
    .click();
}

test("professional runs relocate response work into the consoles", async ({
  page,
}) => {
  await openInvestigation(page);

  await expect(
    page.getByRole("region", {
      name: "Response actions",
    }),
  ).toHaveCount(0);

  await expect(
    page.locator(".response-relocated"),
  ).toBeVisible();
});

test("identity operations are performed from the identity console", async ({
  page,
}) => {
  await openInvestigation(page);

  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Identity",
    })
    .click();

  const operations = page.locator(
    ".identity-action",
  );

  await expect(
    operations.first(),
  ).toBeVisible();

  const before =
    await operations.count();

  expect(before).toBeGreaterThan(0);

  await operations.first().click();

  await expect(
    page
      .locator(".identity-action")
      .first(),
  ).toBeDisabled();
});

test("endpoint operations are performed from the endpoint console", async ({
  page,
}) => {
  await openInvestigation(page);

  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Endpoint",
    })
    .click();

  await expect(
    page.getByText(
      "Endpoint response",
    ),
  ).toBeVisible();
});

test("guided runs keep the response cards", async ({
  page,
}) => {
  await openInvestigation(page);

  await page
    .getByLabel("Select assistance mode")
    .selectOption("guided");

  await expect(
    page.getByRole("region", {
      name: "Response actions",
    }),
  ).toBeVisible();

  await expect(
    page.locator(".response-relocated"),
  ).toHaveCount(0);
});
