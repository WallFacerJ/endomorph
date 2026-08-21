import {
  expect,
  test,
} from "@playwright/test";

/**
 * An investigation is meant to take thirty minutes or more. Losing all of it
 * to a stray refresh is the cheapest possible way to make a product feel
 * disposable, and the failure most likely to end a real evaluation early.
 */

test("a run survives a reload", async ({
  page,
}) => {
  await page.goto("/");
  await page
    .getByRole("button", {
      name: "Open investigation",
    })
    .click();

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

  const label = await operations
    .first()
    .innerText();

  await operations.first().click();

  await page.reload();

  // The performed operation is still performed after a reload.
  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Identity",
    })
    .click();

  const restored = page
    .locator(".identity-action")
    .filter({
      hasText: label.split("\n")[0],
    });

  await expect(
    restored.first(),
  ).toBeDisabled();

  await expect(
    page.getByText("Run resumed"),
  ).toBeVisible();
});

test("resetting the scenario clears the saved run", async ({
  page,
}) => {
  await page.goto("/");
  await page
    .getByRole("button", {
      name: "Open investigation",
    })
    .click();

  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Identity",
    })
    .click();

  await page
    .locator(".identity-action")
    .first()
    .click();

  await page
    .getByRole("button", {
      name: "Reset scenario",
    })
    .click();

  await page.reload();

  await expect(
    page.getByText("Run resumed"),
  ).toHaveCount(0);
});

test("a fresh scenario does not claim to be resumed", async ({
  page,
}) => {
  await page.goto("/");

  await expect(
    page.getByText("Run resumed"),
  ).toHaveCount(0);
});
