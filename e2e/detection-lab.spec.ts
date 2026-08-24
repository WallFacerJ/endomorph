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
