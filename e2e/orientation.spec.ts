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
  await page.goto("/?scenario=/scenarios/account-compromise.json");

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
  await page.goto("/?scenario=/scenarios/account-compromise.json");

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
  await page.goto("/?scenario=/scenarios/account-compromise.json");

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
  await page.goto("/?scenario=/scenarios/account-compromise.json");

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

test("the default scenario is a generated one", async ({
  page,
}) => {
  await page.goto("/");

  // The hand-authored v1 scenarios carry no ATT&CK mapping, no questions,
  // and no analytical reasoning. Landing a first-time visitor on one showed
  // them the thinnest version of the product.
  await expect(
    page.getByRole("combobox", {
      name: "Select training scenario",
    }),
  ).toHaveValue(
    "/scenarios/generated-enterprise.json",
  );

  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Investigation",
    })
    .click();

  // The depth that makes it worth defaulting to.
  await expect(
    page.getByRole("region", {
      name: "Investigation brief",
    }),
  ).toBeVisible();

  await expect(
    page.locator("body"),
  ).toContainText("MITRE ATT&CK");
});

test("the result explains what other response paths would have scored", async ({
  page,
}) => {
  await page.goto(
    "/?scenario=/scenarios/account-compromise.json",
  );

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

  const comparison = page.getByRole(
    "region",
    {
      name: "Response path comparison",
    },
  );

  await expect(comparison).toBeVisible();

  // Finalizing without acting cannot be optimal, so a better path exists
  // and its score is stated rather than implied.
  await expect(comparison).toContainText(
    "Best available",
  );

  // Each decision carries an attributed delta, which is what makes the
  // final score explainable rather than opaque.
  const influences = comparison.locator(
    ".comparison-influence",
  );

  expect(
    await influences.count(),
  ).toBeGreaterThan(1);

  await expect(
    comparison.locator(
      ".comparison-influence.positive",
    ).first(),
  ).toBeVisible();
});

test("the scenario selector separates generated from hand-authored", async ({
  page,
}) => {
  await page.goto("/");

  const selector = page.getByRole(
    "combobox",
    {
      name: "Select training scenario",
    },
  );

  // Generated scenarios carry ATT&CK mapping and scored questions; the v1
  // ones predate all of it. Grouping states that instead of letting a user
  // discover it by switching and finding the brief gone.
  const markup =
    await selector.innerHTML();

  expect(markup).toContain("optgroup");

  await expect(
    selector.locator(
      'optgroup[label*="Generated"]',
    ),
  ).toHaveCount(1);

  await expect(
    selector.locator(
      'optgroup[label*="Hand-authored"]',
    ),
  ).toHaveCount(1);

  // The generated group leads, because that is what the product is now.
  expect(
    markup.indexOf("Generated"),
  ).toBeLessThan(
    markup.indexOf("Hand-authored"),
  );
});

test("finalizing is reachable without scrolling past the brief", async ({
  page,
}) => {
  // Placement is identical across scenarios, so use a small one rather than
  // paying 20 seconds to compile 17.9k events to assert where a button is.
  await page.goto(
    "/?scenario=/scenarios/account-compromise.json",
  );

  await page
    .getByRole("button", {
      name: "Open investigation",
    })
    .click();

  const finalize = page.getByRole(
    "button",
    {
      name: "Finalize investigation",
    },
  );

  // It used to sit below the brief, which on a generated scenario is an
  // ATT&CK matrix and six questions tall. The action that completes the run
  // has to be reachable without hunting for it.
  await expect(
    finalize,
  ).toBeInViewport();

  await finalize.click();

  await expect(
    page.getByRole("button", {
      name: "Investigation finalized",
    }),
  ).toBeDisabled();
});
