import {
  expect,
  test,
} from "@playwright/test";

/**
 * The previous instructor mode was unusable for two reasons, both reported
 * by the first person to try it: the toggle labelled its destination rather
 * than its current state, and everything it unlocked sat behind
 * finalization, so during the investigation it did nothing observable.
 */

test("the role control states which role you are in", async ({
  page,
}) => {
  await page.goto("/");

  const control = page.locator(
    ".mode-button",
  );

  // Not "Instructor mode", which reads as a claim about where you are.
  await expect(control).toContainText(
    "Student",
  );

  await expect(control).toContainText(
    "answers hidden",
  );

  await control.click();

  await expect(control).toContainText(
    "Instructor",
  );

  await expect(control).toContainText(
    "answers visible",
  );
});

test("instructors get the walkthrough during the investigation", async ({
  page,
}) => {
  await page.goto("/?mode=instructor");

  await page
    .getByRole("button", {
      name: "Walkthrough",
    })
    .click();

  const panel = page.getByRole(
    "region",
    { name: "Incident walkthrough" },
  );

  await expect(panel).toBeVisible();

  // Nothing is spoiled until asked for.
  await expect(
    panel.getByText("0/", {
      exact: false,
    }),
  ).toBeVisible();

  const steps = panel.locator(
    ".walkthrough-step",
  );

  expect(
    await steps.count(),
  ).toBeGreaterThan(3);

  await expect(
    panel.locator(
      ".walkthrough-step-body",
    ),
  ).toHaveCount(0);

  await steps
    .first()
    .locator(".walkthrough-step-head")
    .click();

  await expect(
    panel
      .locator(".walkthrough-step-body")
      .first(),
  ).toBeVisible();
});

test("students do not get the walkthrough before finalizing", async ({
  page,
}) => {
  await page.goto("/");

  await expect(
    page.getByRole("button", {
      name: "Walkthrough",
    }),
  ).toHaveCount(0);
});

test("reveal all opens every step and can be undone", async ({
  page,
}) => {
  await page.goto("/?mode=instructor");

  await page
    .getByRole("button", {
      name: "Walkthrough",
    })
    .click();

  const panel = page.getByRole(
    "region",
    { name: "Incident walkthrough" },
  );

  const stepCount = await panel
    .locator(".walkthrough-step")
    .count();

  await panel
    .getByRole("button", {
      name: "Reveal all steps",
    })
    .click();

  await expect(
    panel.locator(
      ".walkthrough-step-body",
    ),
  ).toHaveCount(stepCount);

  await panel
    .getByRole("button", {
      name: "Hide all steps",
    })
    .click();

  await expect(
    panel.locator(
      ".walkthrough-step-body",
    ),
  ).toHaveCount(0);
});

test("each step names the console to look in", async ({
  page,
}) => {
  await page.goto("/?mode=instructor");

  await page
    .getByRole("button", {
      name: "Walkthrough",
    })
    .click();

  const panel = page.getByRole(
    "region",
    { name: "Incident walkthrough" },
  );

  await panel
    .getByRole("button", {
      name: "Reveal all steps",
    })
    .click();

  // A walkthrough that says what happened but not where to see it leaves
  // the reader to hunt for it themselves.
  const bodies = panel.locator(
    ".walkthrough-step-body",
  );

  for (
    let index = 0;
    index < Math.min(await bodies.count(), 5);
    index += 1
  ) {
    await expect(
      bodies.nth(index),
    ).toContainText("Look in");
  }
});
