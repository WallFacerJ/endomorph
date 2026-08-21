import {
  expect,
  test,
} from "@playwright/test";

test("SIEM search filters noisy telemetry and preserves evidence in Case", async ({
  page,
}) => {
  await page.goto("/");

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
  await page.goto("/");
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
