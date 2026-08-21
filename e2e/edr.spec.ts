import {
  expect,
  test,
} from "@playwright/test";

test("EDR traces process ancestry and pivots the same event into SIEM and Case", async ({
  page,
}) => {
  await page.goto("/");

  await page.getByRole(
    "button",
    { name: "Endpoint" },
  ).click();

  const workspace = page.getByRole(
    "region",
    { name: "EDR endpoint workspace" },
  );

  await expect(workspace).toBeVisible();
  await expect(workspace).toContainText("FIN-LT-04");
  await expect(workspace).toContainText("IT-LT-02");
  await expect(workspace).toContainText("HR-LT-07");
  await expect(workspace).toContainText("explorer.exe");
  await expect(workspace).toContainText("WINWORD.EXE");
  await expect(workspace).toContainText("powershell.exe");

  await workspace.getByRole(
    "button",
    { name: /powershell\.exe.*8420.*6172/i },
  ).click();

  const detail = page.getByRole(
    "complementary",
    { name: "EDR observation detail" },
  );

  await expect(detail).toContainText(
    "event-compromise-powershell",
  );
  await expect(detail).toContainText("6172");
  await expect(detail).toContainText(
    "EncodedCommand",
  );

  await detail.getByRole(
    "button",
    { name: "Search event in SIEM" },
  ).click();

  const siem = page.getByRole(
    "region",
    { name: "SIEM search workspace" },
  );
  await expect(siem).toBeVisible();
  await expect(
    page.getByLabel("SIEM query"),
  ).toHaveValue(
    "eventId:event-compromise-powershell",
  );
  await expect(
    siem.locator(".siem-result-count strong"),
  ).toHaveText("1");
  await siem.getByText(
    /Process started on device-fin-lt-04/,
  ).click();
  await expect(
    page.getByRole("complementary", {
      name: "SIEM event detail",
    }),
  ).toContainText("event-compromise-powershell");

  await page.getByRole(
    "button",
    { name: "Endpoint" },
  ).click();

  const edrAgain = page.getByRole(
    "region",
    { name: "EDR endpoint workspace" },
  );
  await edrAgain.getByRole(
    "button",
    { name: /powershell\.exe.*8420.*6172/i },
  ).click();

  const detailAgain = page.getByRole(
    "complementary",
    { name: "EDR observation detail" },
  );
  await detailAgain.getByRole(
    "button",
    { name: "Collect evidence" },
  ).click();
  await expect(detailAgain).toContainText(
    "Evidence collected",
  );

  await detailAgain.getByRole(
    "button",
    { name: "Open in Case" },
  ).click();

  await expect(
    page.getByRole("heading", {
      name: "Build your evidence-backed finding",
    }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "event-compromise-powershell",
      { exact: false },
    ),
  ).toBeVisible();
});

test("EDR endpoint activity separates process, network, file, and alert investigations", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole(
    "button",
    { name: "Endpoint" },
  ).click();

  const workspace = page.getByRole(
    "region",
    { name: "EDR endpoint workspace" },
  );

  await workspace.getByRole(
    "tab",
    { name: /Network/ },
  ).click();
  await expect(workspace).toContainText(
    "203.0.113.77:443",
  );

  await workspace.getByRole(
    "tab",
    { name: /Files/ },
  ).click();
  await expect(workspace).toContainText(
    "file-fin-quarterly-review-docm",
  );
  await expect(workspace).toContainText("execute");

  await workspace.getByRole(
    "tab",
    { name: /Alerts/ },
  ).click();
  await expect(workspace).toContainText(
    "Suspicious encoded PowerShell after unusual login",
  );
});
