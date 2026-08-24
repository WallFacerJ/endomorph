import {
  expect,
  test,
} from "@playwright/test";

/**
 * The detection-data pitch, made interactive: paste a Sigma rule and score it
 * against the scenario's labelled corpus. It lives under the shipped-ruleset
 * review, after finalizing, so the labels it needs are no longer a spoiler.
 */
test("a pasted Sigma rule is scored against the labelled corpus", async ({
  page,
}) => {
  await page.goto(
    "/?scenario=/scenarios/generated-enterprise.json",
  );

  await page
    .getByRole("button", {
      name: "Open investigation",
    })
    .click();

  // Finalizing is what unlocks the labels: during the run they would spoil
  // the exercise, so the tester only appears once the run is over.
  await page
    .getByRole("button", {
      name: "Finalize investigation",
    })
    .click();

  const tester = page.getByRole(
    "region",
    {
      name: "Test your own detection rule",
    },
  );

  await tester.scrollIntoViewIfNeeded();
  await expect(tester).toBeVisible();

  // The example rule ships in the box; scoring it should catch the encoded
  // PowerShell the generator planted -- a true positive against known truth,
  // not an estimate.
  await tester
    .getByRole("button", {
      name: "Score rule",
    })
    .click();

  const row = tester
    .locator(
      ".rule-tester-table tbody tr",
    )
    .first();

  await expect(row).toBeVisible();
  await expect(row).toContainText(
    "T1059.001",
  );
  await expect(row).toContainText(
    "100.0%",
  );
});

test("a rule the Sigma subset cannot express is reported, not silently ignored", async ({
  page,
}) => {
  await page.goto(
    "/?scenario=/scenarios/generated-enterprise.json",
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

  const tester = page.getByRole(
    "region",
    {
      name: "Test your own detection rule",
    },
  );

  await tester.scrollIntoViewIfNeeded();

  // An aggregation condition the supported subset does not implement. A rule
  // that quietly matched nothing would look exactly like one that works, so
  // it has to come back named as unscored rather than as a clean zero.
  await tester
    .getByRole("textbox")
    .fill(
      [
        "title: Unsupported aggregation",
        "logsource:",
        "  category: authentication",
        "detection:",
        "  selection:",
        "    event.type: 'AUTH_LOGIN_FAILED'",
        "  condition: selection | count() > 5",
      ].join("\n"),
    );

  await tester
    .getByRole("button", {
      name: "Score rule",
    })
    .click();

  await expect(
    tester.locator(
      ".rule-tester-skipped",
    ),
  ).toBeVisible();
});

test("the lab has a front door at ?lab, reached without an investigation", async ({
  page,
}) => {
  // The detection-engineer audience is not playing the investigation, so the
  // scorer has to be reachable without one. This opens straight into the lab.
  await page.goto("/?lab");

  await expect(
    page.getByRole("heading", {
      name: /Score a detection rule against ground truth/i,
    }),
  ).toBeVisible();

  const tester = page.getByRole(
    "region",
    {
      name: "Test your own detection rule",
    },
  );

  // No "Open investigation" or "Finalize" in between -- the tester is right
  // there once the corpus compiles.
  await expect(tester).toBeVisible({
    timeout: 20000,
  });

  await tester
    .getByRole("button", {
      name: "Score rule",
    })
    .click();

  await expect(
    tester
      .locator(
        ".rule-tester-table tbody tr",
      )
      .first(),
  ).toContainText("100.0%");
});

test("opening a noisy rule shows the exact benign events it fired on", async ({
  page,
}) => {
  // The question a detection engineer actually has is not the precision number
  // but why: which benign events is my rule catching. A labelled corpus can
  // answer it exactly, and this is where it does.
  await page.goto("/?lab");

  const tester = page.getByRole(
    "region",
    {
      name: "Test your own detection rule",
    },
  );

  await tester.waitFor({
    state: "visible",
    timeout: 20000,
  });

  // A rule keyed on any PowerShell launch: it catches the malicious encoded
  // command and a great deal of benign administrative scripting with it.
  await tester
    .getByRole("textbox")
    .fill(
      [
        "title: Any PowerShell launch",
        "logsource:",
        "  category: process_creation",
        "detection:",
        "  selection:",
        "    Image|endswith: 'powershell.exe'",
        "  condition: selection",
        "tags:",
        "  - attack.t1059.001",
      ].join("\n"),
    );

  await tester
    .getByRole("button", {
      name: "Score rule",
    })
    .click();

  const row = tester
    .locator(
      ".rule-tester-table tbody tr.rule-tester-row-clickable",
    )
    .first();

  await expect(row).toBeVisible();
  await row.click();

  // The expanded detail names the false positives by their event, not by an
  // id, so the noise is legible.
  const matches = tester.locator(
    ".rule-tester-matches li",
  );

  await expect(
    matches.first(),
  ).toBeVisible();

  await expect(
    matches.first(),
  ).toContainText("FP");

  await expect(
    tester.locator(
      ".rule-tester-matchgroup-head",
    ),
  ).toContainText("False positives");
});
