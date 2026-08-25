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

test("the investigation app offers a door to the detection lab", async ({
  page,
}) => {
  await page.goto(
    "/?scenario=/scenarios/generated-enterprise.json",
  );

  const link = page
    .getByRole("link", {
      name: /Detection Lab/i,
    })
    .first();

  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute(
    "href",
    /\?lab/,
  );
});

test("loading an example rule fills the box and scores it", async ({
  page,
}) => {
  // A visitor who does not want to hand-write Sigma can pick an example and
  // see the point immediately -- here the noisy one, which fires on benign
  // administrative PowerShell as well as the malicious command.
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

  await tester
    .getByRole("combobox", {
      name: "Load an example rule",
    })
    .selectOption({
      label:
        "Any PowerShell — right technique, noisy rule",
    });

  await expect(
    tester.getByRole("textbox"),
  ).toHaveValue(
    /Any PowerShell launch/,
  );

  await tester
    .getByRole("button", {
      name: "Score rule",
    })
    .click();

  // The noisy rule is dominated by false positives, so opening it is offered.
  await expect(
    tester
      .locator(
        ".rule-tester-table tbody tr.rule-tester-row-clickable",
      )
      .first(),
  ).toBeVisible();
});

test("switching to KQL scores a Kusto query against the same corpus", async ({
  page,
}) => {
  // Most detection engineers write Kusto, not Sigma. Switching the language
  // loads a KQL example and scores it against the same labelled records.
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

  await tester
    .getByRole("button", { name: "KQL" })
    .click();

  await expect(
    tester.getByRole("textbox"),
  ).toHaveValue(
    /DeviceProcessEvents/,
  );

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
  ).toContainText("T1059.001");
});

test("switching to SPL scores a Splunk search against the same corpus", async ({
  page,
}) => {
  // Splunk is the largest SIEM. Switching the language loads an SPL example and
  // scores its base-search wildcards against the same labelled records.
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

  await tester
    .getByRole("button", { name: "SPL" })
    .click();

  await expect(
    tester.getByRole("textbox"),
  ).toHaveValue(/index=edr/);

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
  ).toContainText("T1059.001");
});

test("a shared result link reopens the rule and auto-scores it", async ({
  page,
}) => {
  // A scored rule is shareable: the language and the rule text ride in the URL,
  // so a recipient opening the link lands on the result, not an empty form.
  const rule = [
    "title: Encoded PowerShell Command Line",
    "logsource:",
    "  category: process_creation",
    "detection:",
    "  selection:",
    "    Image|endswith: 'powershell.exe'",
    "    CommandLine|contains: '-enc'",
    "  condition: selection",
    "tags:",
    "  - attack.t1059.001",
  ].join("\n");

  const encoded = Buffer.from(rule, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  await page.goto(
    `/?lab&lang=sigma&rule=${encoded}`,
  );

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

  // The rule text is hydrated from the link...
  await expect(
    tester.getByRole("textbox"),
  ).toHaveValue(/CommandLine\|contains/);

  // ...and the result is already there without a click on Score.
  await expect(
    tester
      .locator(
        ".rule-tester-table tbody tr",
      )
      .first(),
  ).toContainText("T1059.001", {
    timeout: 20000,
  });
});

test("the share link round-trips through the clipboard", async ({
  page,
  context,
}) => {
  // Clicking "Copy share link" writes a URL that reproduces the current rule.
  await context.grantPermissions([
    "clipboard-read",
    "clipboard-write",
  ]);

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

  await tester
    .getByRole("button", {
      name: "Copy share link",
    })
    .click();

  const shared = await page.evaluate(() =>
    navigator.clipboard.readText(),
  );

  expect(shared).toContain("lab");
  expect(shared).toContain("rule=");

  // Opening the copied link reproduces the scored rule.
  await page.goto(shared);

  await expect(
    tester
      .locator(
        ".rule-tester-table tbody tr",
      )
      .first(),
  ).toContainText("T1059.001", {
    timeout: 20000,
  });
});

test("switching to EQL scores an Elastic query against the same corpus", async ({
  page,
}) => {
  // Elastic is a top-tier SIEM whose detections are written as EQL. Switching
  // the language loads an EQL example and scores its condition against the same
  // labelled records.
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

  await tester
    .getByRole("button", { name: "EQL" })
    .click();

  await expect(
    tester.getByRole("textbox"),
  ).toHaveValue(/process where/);

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
  ).toContainText("T1059.001");
});

test("switching to ES|QL scores an Elastic piped query against the same corpus", async ({
  page,
}) => {
  // ES|QL is Elastic's piped query language. Switching the language loads an
  // ES|QL example and scores its WHERE filter against the same labelled records.
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

  await tester
    .getByRole("button", { name: "ES|QL" })
    .click();

  await expect(
    tester.getByRole("textbox"),
  ).toHaveValue(/FROM logs/);

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
  ).toContainText("T1059.001");
});
