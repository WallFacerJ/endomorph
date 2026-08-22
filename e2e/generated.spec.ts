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
    page.getByText("matching events", {
      exact: true,
    }),
  ).toBeVisible();

  // Rendering a row per match locked the workspace for 6.5s at this volume.
  // The result page is capped; the count is not.
  await expect(
    page.getByText(
      /Showing the first \d+ of/,
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

test("the endpoint names what launched each process", async ({
  page,
}) => {
  // The walkthrough tells the analyst to read the parent process. For a long
  // time the corpus had only a parent pid pointing at a process with no start
  // event, so the column showed a bare number and the instruction could not
  // be followed.
  await page.goto(GENERATED_SCENARIO);

  await page.getByRole(
    "button",
    { name: "Endpoint" },
  ).click();

  const workspace = page.getByRole(
    "region",
    { name: "EDR endpoint workspace" },
  );

  await expect(workspace).toBeVisible();

  const rows = workspace.locator(
    ".edr-process-row",
  );

  await expect(
    rows.first(),
  ).toBeVisible();

  // Benign PowerShell is launched by the task scheduler, exactly as a great
  // deal of malicious PowerShell is. If this ever stops being true the
  // lineage field has become a giveaway rather than evidence.
  await expect(
    workspace.locator(
      ".edr-process-parent",
      { hasText: "svchost.exe" },
    ).first(),
  ).toBeVisible();

  await expect(
    workspace.locator(
      ".edr-process-parent",
      { hasText: "explorer.exe" },
    ).first(),
  ).toBeVisible();
});
