import {
  expect,
  test,
} from "@playwright/test";

/**
 * Orientation feedback from first use: "what is any of the stuff on the
 * side" was a fair question, and Mode versus Role was indistinguishable.
 */

test("navigation groups tools by phase and says what each is for", async ({
  page,
}) => {
  await page.goto("/");

  const nav = page.getByRole(
    "navigation",
  );

  for (const phase of [
    "Triage",
    "Investigate",
    "Coordinate",
  ]) {
    await expect(nav).toContainText(
      phase,
    );
  }

  // Every entry states its purpose, not just its name.
  await expect(nav).toContainText(
    "What fired, and on which host",
  );

  await expect(nav).toContainText(
    "Query all telemetry",
  );

  await expect(nav).toContainText(
    "Sign-in history, sessions, and privilege",
  );
});

test("assistance is one scale, not two overlapping controls", async ({
  page,
}) => {
  await page.goto("/");

  const group = page.getByRole(
    "radiogroup",
    { name: "Assistance level" },
  );

  await expect(group).toBeVisible();

  // The old Mode + Role pair is gone.
  await expect(
    page.locator(".mode-button"),
  ).toHaveCount(0);

  await expect(
    group.getByRole("radio", {
      name: "Professional",
    }),
  ).toHaveAttribute(
    "aria-checked",
    "true",
  );

  await expect(page.locator("body")).toContainText(
    "Work the incident with no assistance",
  );

  await group
    .getByRole("radio", {
      name: "Instructor",
    })
    .click();

  await expect(page.locator("body")).toContainText(
    "Adds the answers and the incident walkthrough",
  );

  // Instructor strictly adds to Guided: scaffolding and answers both on.
  await expect(
    page.getByRole("button", {
      name: "Walkthrough",
    }),
  ).toBeVisible();

  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Investigation",
    })
    .click();

  await expect(
    page.getByRole("region", {
      name: "Response objectives",
    }),
  ).toBeVisible();
});

test("guided sits between professional and instructor", async ({
  page,
}) => {
  await page.goto("/");

  const group = page.getByRole(
    "radiogroup",
    { name: "Assistance level" },
  );

  await group
    .getByRole("radio", {
      name: "Guided",
    })
    .click();

  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Investigation",
    })
    .click();

  // Scaffolding yes, answers no.
  await expect(
    page.getByRole("region", {
      name: "Response objectives",
    }),
  ).toBeVisible();

  await expect(
    page.getByRole("button", {
      name: "Walkthrough",
    }),
  ).toHaveCount(0);
});

test("walkthrough steps explain reasoning, not just what happened", async ({
  page,
}) => {
  // Reasoning is authored on generated attack plans. The hand-authored v1
  // scenarios predate the field and render without it, which the panel
  // handles by omitting the block rather than showing an empty one.
  await page.goto(
    "/?mode=instructor&scenario=/scenarios/generated-enterprise.json",
  );

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
    .locator(".walkthrough-step-head")
    .first()
    .click();

  const body = panel
    .locator(".walkthrough-step-body")
    .first();

  await expect(body).toContainText(
    "What happened",
  );

  // The part that transfers: why it is suspicious and where it points.
  await expect(body).toContainText(
    "How to reason about it",
  );

  const reasoning = await body
    .locator(".walkthrough-block.reasoning")
    .innerText();

  expect(
    reasoning.length,
  ).toBeGreaterThan(150);
});

test("the result reports coverage and names what was missed", async ({
  page,
}) => {
  await page.goto("/");

  // Finalize immediately: correct containment is possible without ever
  // scoping the intrusion, and objective scoring cannot tell the two apart.
  await page
    .getByRole("button", {
      name: "Open investigation",
    })
    .click();

  await page
    .getByRole("button", {
      name: "Finalize investigation",
    })
    .click();

  const result = page.getByRole(
    "region",
    { name: "Post-incident result" },
  );

  await expect(result).toContainText(
    "Incident coverage",
  );

  // Naming what was never opened is what makes the number explainable
  // rather than opaque.
  await expect(result).toContainText(
    "Never opened",
  );
});
