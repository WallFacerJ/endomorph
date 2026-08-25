import {
  expect,
  test,
} from "@playwright/test";

/**
 * The root front door. A bare visit shows the landing page; any deep link with
 * a param still goes straight to the app or the lab, so no existing link moves.
 */

test("the bare root shows the landing page, not an investigation", async ({
  page,
}) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", {
      level: 1,
      name: /ships with the answer key/i,
    }),
  ).toBeVisible();

  // The two doors are present.
  await expect(
    page.getByRole("link", {
      name: /Open the Detection Lab/i,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", {
      name: /Try an investigation/i,
    }),
  ).toBeVisible();
});

test("the landing page's lab door opens the Detection Lab", async ({
  page,
}) => {
  await page.goto("/");

  await page
    .getByRole("link", {
      name: /Open the Detection Lab/i,
    })
    .click();

  await expect(page).toHaveURL(/\?lab/);

  await expect(
    page.getByRole("region", {
      name: "Test your own detection rule",
    }),
  ).toBeVisible({ timeout: 20000 });
});

test("a deep link with a param still lands in the app, not the landing", async ({
  page,
}) => {
  await page.goto("/?app");

  await expect(
    page.getByRole("heading", {
      level: 1,
      name: /ships with the answer key/i,
    }),
  ).toHaveCount(0);
});
