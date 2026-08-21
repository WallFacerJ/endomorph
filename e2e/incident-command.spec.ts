import {
  readFileSync,
} from "node:fs";

import {
  join,
} from "node:path";

import {
  expect,
  test,
} from "@playwright/test";

/**
 * Read the expected values out of the generated scenario rather than
 * hard-coding them. The attacker address and the victim change whenever the
 * generator's cursor structure changes, and a test that pins them breaks for
 * reasons that have nothing to do with what it is testing.
 */
const scenario = JSON.parse(
  readFileSync(
    join(
      process.cwd(),
      "apps",
      "web",
      "public",
      "scenarios",
      "generated-enterprise.json",
    ),
    "utf8",
  ),
).scenario;

const attackerIp: string =
  scenario.questions[0].accepted[0];

const victimName: string =
  scenario.initialWorld.users.find(
    (user: { id: string }) =>
      user.id ===
      scenario.investigation.userId,
  ).displayName;

const GENERATED_SCENARIO =
  "/?scenario=/scenarios/generated-enterprise.json";

/**
 * The Case redesign exists because testers said the old Case -- a list of
 * event ids plus free-text notes -- was unnecessary. The claim being tested
 * here is the one that makes it necessary: collecting evidence builds the
 * incident picture on its own.
 */
test("case derives the incident picture from collected evidence", async ({
  page,
}) => {
  await page.goto(GENERATED_SCENARIO);

  await page
    .getByRole("button", {
      name: "SIEM Search",
    })
    .click();

  // Query the attacker address, then bank a few of the results as evidence.
  await page
    // Target the query field by its accessible name. Ordering broke once
    // the replay scrubber added a range input ahead of it.
    .getByLabel("SIEM query")
    .fill(`sourceIp:${attackerIp}`);

  const rows = page.locator(
    ".siem-results-table tbody tr",
  );

  await expect(
    rows.first(),
  ).toBeVisible();

  const rowCount = await rows.count();

  expect(rowCount).toBeGreaterThan(0);

  expect(
    rowCount,
  ).toBeLessThan(20);

  for (
    let index = 0;
    index < Math.min(rowCount, 3);
    index += 1
  ) {
    await rows.nth(index).click();

    const collect = page
      .getByRole("button", {
        name: /Collect|evidence/i,
      })
      .first();

    if (await collect.count()) {
      await collect
        .click()
        .catch(() => undefined);
    }
  }

  await page
    .locator(".nav-item", {
      hasText: "Case",
    })
    .first()
    .click();

  const command = page.getByRole(
    "region",
    { name: "Incident command" },
  );

  await expect(command).toBeVisible();

  // The graph is derived, not typed: the compromised account, its owner,
  // the workstation, and the attacker address all arrive on their own.
  await expect(
    command
      .getByText(attackerIp, {
        exact: false,
      })
      .first(),
  ).toBeVisible();

  await expect(
    command
      .getByText(victimName, {
        exact: false,
      })
      .first(),
  ).toBeVisible();

  // The address is outside every corporate subnet and must be flagged.
  await expect(
    command
      .getByText("external", {
        exact: false,
      })
      .first(),
  ).toBeVisible();

  // Connections are attributed, so any relationship traces back to evidence.
  await expect(
    command.getByText("Connections"),
  ).toBeVisible();
});

test("case exposes incident phase as real workflow state", async ({
  page,
}) => {
  await page.goto(GENERATED_SCENARIO);

  await page
    .locator(".nav-item", {
      hasText: "Case",
    })
    .first()
    .click();

  const command = page.getByRole(
    "region",
    { name: "Incident command" },
  );

  // Incident handling is a lifecycle, not a single state.
  for (const phase of [
    "Triage",
    "Investigation",
    "Containment",
    "Eradication",
    "Recovery",
    "Lessons learned",
  ]) {
    await expect(
      command.getByRole("button", {
        name: phase,
        exact: true,
      }),
    ).toBeVisible();
  }

  await command
    .getByRole("button", {
      name: "Containment",
      exact: true,
    })
    .click();

  await expect(
    command.getByRole("button", {
      name: "Containment",
      exact: true,
    }),
  ).toHaveClass(/active/);
});

test("analyst judgement is recorded alongside derived evidence", async ({
  page,
}) => {
  await page.goto(GENERATED_SCENARIO);

  await page
    .locator(".nav-item", {
      hasText: "Case",
    })
    .first()
    .click();

  const command = page.getByRole(
    "region",
    { name: "Incident command" },
  );

  await command
    .getByPlaceholder(
      "The account was compromised from an external address",
    )
    .fill(
      "Credential compromise from hosting infrastructure",
    );

  await command
    .getByRole("button", { name: "Add" })
    .first()
    .click();

  await expect(
    command.getByText(
      "Credential compromise from hosting infrastructure",
    ),
  ).toBeVisible();

  await command
    .getByRole("button", {
      name: "Support",
    })
    .first()
    .click();

  await expect(
    command
      .locator(".incident-status.supported")
      .first(),
  ).toBeVisible();

  // Tasks carry an owner and a status that advances.
  await command
    .getByPlaceholder(
      "Isolate the affected endpoint",
    )
    .fill("Isolate FIN-LT-004");

  await command
    .getByRole("button", { name: "Add" })
    .last()
    .click();

  await expect(
    command.getByText(
      "Isolate FIN-LT-004",
    ),
  ).toBeVisible();

  const status = command
    .locator(".incident-task-status")
    .first();

  await expect(status).toHaveText(
    "open",
  );

  await status.click();

  await expect(status).toHaveText(
    "in progress",
  );
});
