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

const generated = JSON.parse(
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
  generated.questions[0].accepted[0];

test("SIEM search filters noisy telemetry and preserves evidence in Case", async ({
  page,
}) => {
  await page.goto("/?scenario=/scenarios/account-compromise.json");

  await page.getByRole(
    "button",
    { name: "SIEM Search" },
  ).click();

  const workspace = page.getByRole(
    "region",
    { name: "SIEM search workspace" },
  );

  await expect(workspace).toBeVisible();
  await expect(workspace).toContainText(
    "Search security telemetry",
  );

  const query = page.getByLabel("SIEM query");
  await query.fill(
    "destinationIp:203.0.113.77",
  );

  const resultCount = workspace.locator(
    ".siem-result-count",
  );
  await expect(
    resultCount.locator("strong"),
  ).toHaveText("1");
  await expect(
    resultCount.locator("span"),
  ).toHaveText("matching events");
  await expect(workspace).toContainText(
    "Network connection 10.20.30.44 -> 203.0.113.77",
  );
  await expect(workspace).not.toContainText(
    "Get-Service AcmeBackupAgent",
  );

  await page.getByText(
    "Network connection 10.20.30.44 -> 203.0.113.77",
    { exact: true },
  ).click();

  const detail = page.getByRole(
    "complementary",
    { name: "SIEM event detail" },
  );

  await expect(detail).toContainText(
    "event-compromise-network",
  );
  await expect(detail).toContainText(
    "destinationIp",
  );

  await detail.getByRole(
    "button",
    { name: "Collect evidence" },
  ).click();

  await expect(detail).toContainText(
    "Evidence collected",
  );

  await detail.getByRole(
    "button",
    { name: "Open case evidence" },
  ).click();

  await expect(
    page.getByRole("heading", {
      name: "Build your evidence-backed finding",
    }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "event-compromise-network",
      { exact: false },
    ),
  ).toBeVisible();
});

test("SIEM supports field pivots and run-local saved searches", async ({
  page,
}) => {
  await page.goto("/?scenario=/scenarios/account-compromise.json");
  await page.getByRole(
    "button",
    { name: "SIEM Search" },
  ).click();

  const query = page.getByLabel("SIEM query");
  await query.fill("family:process");

  await page.getByRole(
    "button",
    { name: "Save query" },
  ).click();

  await expect(
    page.getByRole("region", {
      name: "Saved SIEM queries",
    }),
  ).toContainText("family:process");

  await expect(
    page.getByRole("region", {
      name: "SIEM search workspace",
    }),
  ).toContainText("powershell.exe");
});

test("search says whether a value has any history behind it", async ({
  page,
}) => {
  /*
    The instructor content asks for this constantly -- "compare against where
    this account normally authenticates", "determine whether the account ever
    legitimately touched this document before", "build that baseline from the
    account's own history first" -- and the console could not answer any of
    it. The generated enterprise is built so the question has an answer:
    several days of ordinary history precede the intrusion. That property was
    in the data and unreachable from the interface.
  */
  await page.goto(
    "/?scenario=/scenarios/generated-enterprise.json",
  );

  await page
    .getByRole("button", {
      name: "Got it",
    })
    .click();

  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: /^SIEM Search/,
    })
    .click();

  const query = page.getByPlaceholder(
    /Try:/,
  );

  // The address the intrusion came from: no history at all.
  await query.fill("193.32.127.201");

  await expect(
    page.locator(".siem-baseline.new"),
  ).toContainText(
    /Nothing like it appears in the \d+ day/,
  );

  // The victim's own workstation: entirely routine, and must not be
  // flagged, or the reading would mean nothing.
  await query.fill(
    "sourceIp:10.20.123.235",
  );

  await expect(
    page.locator(".siem-baseline"),
  ).toBeVisible();

  await expect(
    page.locator(".siem-baseline.new"),
  ).toHaveCount(0);
});

test("SIEM results flag the rows that touch a critical asset", async ({
  page,
}) => {
  // Scanning two hundred rows, an analyst should see which of them involve a
  // consequential asset rather than treating every subject as equal weight.
  // The hand-authored scenarios carry no asset context, so this runs against
  // a generated one and filters to endpoint process events, which are keyed
  // to a device the generator has graded.
  await page.goto(
    "/?scenario=/scenarios/generated-enterprise.json",
  );

  await page
    .getByRole("button", {
      name: "SIEM Search",
    })
    .click();

  const workspace = page.getByRole(
    "region",
    { name: "SIEM search workspace" },
  );

  await expect(workspace).toBeVisible();

  await page
    .getByLabel("SIEM query")
    .fill("family:process");

  const dots = workspace.locator(
    ".siem-criticality-dot",
  );

  await expect(
    dots.first(),
  ).toBeVisible();

  // The mark explains itself: tier and the generator's rationale ride on the
  // title rather than being inferred a second time in the console.
  await expect(
    dots.first(),
  ).toHaveAttribute(
    "title",
    /Severe|High/,
  );
});

test("a classified address carries its reputation where the analyst inspects it", async ({
  page,
}) => {
  // The access address is not merely external -- the generator planted it from
  // anonymising infrastructure. Searching it and opening a result should say
  // so on the address field itself, so "external" becomes "and here is what
  // kind of external" at the point of inspection.
  await page.goto(
    "/?scenario=/scenarios/generated-enterprise.json",
  );

  await page
    .getByRole("button", {
      name: "SIEM Search",
    })
    .click();

  await page
    .getByLabel("SIEM query")
    .fill(`sourceIp:${attackerIp}`);

  const rows = page.locator(
    ".siem-results-table tbody tr",
  );

  await expect(
    rows.first(),
  ).toBeVisible();

  await rows.first().click();

  const intel = page.locator(
    ".siem-field-intel",
  );

  await expect(
    intel.first(),
  ).toBeVisible();

  await expect(
    intel.first(),
  ).toHaveAttribute("title", /.+/);
});
