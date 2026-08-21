import {
  expect,
  test,
} from "@playwright/test";

/**
 * "It feels like an entry-level multiple-choice course" was the most
 * repeated tester complaint. A live objective checklist and a running score
 * above the response cards are what produce that feeling: they turn
 * remediation into optimising a number instead of judging an incident.
 *
 * Professional mode is the default and hides both during active work.
 * Guided mode keeps them, layered onto the same environment rather than
 * split into a separate shallow product.
 */

async function openInvestigation(
  page: import("@playwright/test").Page,
) {
  await page.goto("/?scenario=/scenarios/account-compromise.json");

  await page
    .getByRole("button", {
      name: "Open investigation",
    })
    .click();
}

test("professional mode is the default and hides objectives during active work", async ({
  page,
}) => {
  await openInvestigation(page);

  await expect(
    page
      .getByRole("radiogroup", {
        name: "Assistance level",
      })
      .getByRole("radio", {
        name: "Professional",
      }),
  ).toHaveAttribute(
    "aria-checked",
    "true",
  );

  await expect(
    page.getByRole("region", {
      name: "Response objectives",
    }),
  ).toHaveCount(0);

  await expect(
    page.locator(".response-score"),
  ).toHaveCount(0);

  // The work itself is untouched: responses are still available, just from
  // the console that owns them rather than a row of cards.
  await expect(
    page.locator(".response-relocated"),
  ).toBeVisible();
});

test("guided mode restores the scaffolding on the same environment", async ({
  page,
}) => {
  await openInvestigation(page);

  await page
    .getByRole("radiogroup", {
      name: "Assistance level",
    })
    .getByRole("radio", { name: "Guided" })
    .click();

  await expect(
    page.getByRole("region", {
      name: "Response objectives",
    }),
  ).toBeVisible();

  await expect(
    page.locator(".response-score"),
  ).toBeVisible();
});

test("professional mode still reports the result after finalization", async ({
  page,
}) => {
  await openInvestigation(page);

  // Hiding the score during work must not hide the assessment afterwards.
  await expect(
    page.getByRole("region", {
      name: "Response objectives",
    }),
  ).toHaveCount(0);

  await page
    .getByRole("button", {
      name: "Finalize investigation",
    })
    .click();

  await expect(
    page.getByRole("region", {
      name: "Response objectives",
    }),
  ).toBeVisible();

  await expect(
    page.locator(".response-score"),
  ).toBeVisible();
});

test("the assistance choice survives a reload", async ({
  page,
}) => {
  await openInvestigation(page);

  await page
    .getByRole("radiogroup", {
      name: "Assistance level",
    })
    .getByRole("radio", { name: "Guided" })
    .click();

  await page.reload();

  await expect(
    page
      .getByRole("radiogroup", {
        name: "Assistance level",
      })
      .getByRole("radio", {
        name: "Guided",
      }),
  ).toHaveAttribute(
    "aria-checked",
    "true",
  );
});
