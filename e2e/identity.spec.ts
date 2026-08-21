import {
  expect,
  test,
} from "@playwright/test";

test("Identity distinguishes authentication provenance and pivots the same event into SIEM and Case", async ({
  page,
}) => {
  await page.goto("/");

  await page.getByRole(
    "button",
    { name: "Identity", exact: true },
  ).click();

  const workspace = page.getByRole(
    "region",
    { name: "Identity investigation workspace" },
  );

  await expect(workspace).toBeVisible();
  await expect(workspace).toContainText("Sarah Martinez");
  await expect(workspace).toContainText("Mark Chen");
  await expect(workspace).toContainText("Jordan Lee");
  await expect(workspace).toContainText("finance-user");
  await expect(workspace).toContainText("10.20.30.44");
  await expect(workspace).toContainText("185.220.101.42");
  await expect(workspace).toContainText("FAILED");
  await expect(workspace).toContainText("SUCCESS");

  await workspace.getByRole(
    "button",
    { name: /185\.220\.101\.42/ },
  ).click();

  const detail = page.getByRole(
    "complementary",
    { name: "Identity event detail" },
  );

  await expect(detail).toContainText(
    "event-compromise-login",
  );
  await expect(detail).toContainText(
    "Successful authentication",
  );
  await expect(detail).toContainText("FIN-LT-04");
  await expect(detail).toContainText("Acme Identity");

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
    "eventId:event-compromise-login",
  );
  await expect(
    siem.locator(".siem-result-count strong"),
  ).toHaveText("1");

  await page.getByRole(
    "button",
    { name: "Identity", exact: true },
  ).click();

  const identityAgain = page.getByRole(
    "region",
    { name: "Identity investigation workspace" },
  );
  await identityAgain.getByRole(
    "button",
    { name: /185\.220\.101\.42/ },
  ).click();

  const detailAgain = page.getByRole(
    "complementary",
    { name: "Identity event detail" },
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
      "event-compromise-login",
      { exact: false },
    ),
  ).toBeVisible();
});

test("Identity performs session and account containment from the affected account context", async ({
  page,
}) => {
  await page.goto("/");

  await page.getByRole(
    "button",
    { name: "Identity", exact: true },
  ).click();

  let workspace = page.getByRole(
    "region",
    { name: "Identity investigation workspace" },
  );

  await workspace.getByRole(
    "tab",
    { name: /Sessions/ },
  ).click();
  await expect(workspace).toContainText(
    "session-smartinez-compromised",
  );
  await expect(workspace).toContainText("active");

  await workspace.getByRole(
    "button",
    { name: /Revoke compromised session/ },
  ).click();

  await page.getByRole(
    "button",
    { name: "Identity", exact: true },
  ).click();
  workspace = page.getByRole(
    "region",
    { name: "Identity investigation workspace" },
  );
  await workspace.getByRole(
    "tab",
    { name: /Sessions/ },
  ).click();
  await expect(workspace).toContainText("revoked");

  await workspace.getByRole(
    "button",
    { name: /Disable compromised account/ },
  ).click();

  await page.getByRole(
    "button",
    { name: "Identity", exact: true },
  ).click();
  workspace = page.getByRole(
    "region",
    { name: "Identity investigation workspace" },
  );
  await expect(workspace).toContainText("disabled");
  await expect(workspace).toContainText("Performed");
});
