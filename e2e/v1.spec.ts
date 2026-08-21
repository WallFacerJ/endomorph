import {
  expect,
  test,
  type Page,
} from "@playwright/test";

async function openInvestigation(
  page: Page,
) {
  await page.goto("/");
  await page.getByRole(
    "button",
    { name: "Open investigation" },
  ).click();
}

function responseAction(
  page: Page,
  label: string,
) {
  return page
    .getByRole("region", {
      name: "Response actions",
    })
    .locator("article")
    .filter({ hasText: label })
    .getByRole("button");
}

async function performCleanResponse(
  page: Page,
) {
  await responseAction(
    page,
    "Revoke compromised session",
  ).click();
  await responseAction(
    page,
    "Disable compromised account",
  ).click();
}

test("loads and switches among the shipped v1 scenarios", async ({
  page,
}) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", {
      name: "Suspicious PowerShell after account compromise",
    }),
  ).toBeVisible();

  const selector = page.getByLabel(
    "Select training scenario",
  );

  await selector.selectOption(
    "/scenarios/hr-malware-beacon.json",
  );
  await expect(page).toHaveURL(
    /hr-malware-beacon\.json/,
  );
  await expect(
    page.getByRole("heading", {
      name: "Unsigned HR updater with outbound beacon",
    }),
  ).toBeVisible();

  await page
    .getByLabel("Select training scenario")
    .selectOption(
      "/scenarios/cloud-admin-compromise.json",
    );
  await expect(
    page.getByRole("heading", {
      name: "Suspicious cloud-admin login and tooling",
    }),
  ).toBeVisible();
});

test("clean response finalizes successfully at 100 percent", async ({
  page,
}) => {
  await openInvestigation(page);
  await performCleanResponse(page);

  await expect(
    page.getByText("Objectives met", {
      exact: true,
    }),
  ).toBeVisible();

  await page.getByRole(
    "button",
    { name: "Finalize investigation" },
  ).click();

  const result = page.getByRole(
    "region",
    { name: "Post-incident result" },
  );

  await expect(result).toContainText(
    "Investigation succeeded",
  );
  await expect(result).toContainText("100%");
  await expect(result).toContainText(
    "Response penalty",
  );
});

test("partial response finalizes as failed with preserved objective score", async ({
  page,
}) => {
  await openInvestigation(page);
  await responseAction(
    page,
    "Revoke compromised session",
  ).click();

  await page.getByRole(
    "button",
    { name: "Finalize investigation" },
  ).click();

  const result = page.getByRole(
    "region",
    { name: "Post-incident result" },
  );

  await expect(result).toContainText(
    "Investigation failed",
  );
  await expect(result).toContainText("50%");
});

test("harmful response is hidden during work and penalized after submission", async ({
  page,
}) => {
  await openInvestigation(page);

  await expect(page.getByText(
    "Re-enabling a known compromised account during incident response creates avoidable exposure and can undo containment.",
  )).toHaveCount(0);

  await responseAction(
    page,
    "Restore account access",
  ).click();
  await performCleanResponse(page);

  await expect(
    page.getByRole("region", {
      name: "Response actions",
    }),
  ).toContainText("100%");

  await page.getByRole(
    "button",
    { name: "Finalize investigation" },
  ).click();

  const result = page.getByRole(
    "region",
    { name: "Post-incident result" },
  );

  await expect(result).toContainText("75%");
  await expect(result).toContainText("−25");
});

test("finalized analyst case is read-only until reset", async ({
  page,
}) => {
  await openInvestigation(page);

  await page.getByRole(
    "button",
    { name: "Collect evidence" },
  ).first().click();

  await page.getByRole(
    "button",
    { name: "Case" },
  ).click();

  const evidenceCheckbox =
    page.locator(
      '.case-evidence-item input[type="checkbox"]',
    ).first();
  await evidenceCheckbox.check();
  await page.getByLabel("Finding title")
    .fill("Validated compromise");
  await page.getByLabel("Analyst summary")
    .fill(
      "Collected telemetry supports a synthetic account compromise finding.",
    );
  await page.getByRole(
    "button",
    { name: "Save finding" },
  ).click();

  await page.getByRole(
    "button",
    { name: "Investigation" },
  ).click();
  await page.getByRole(
    "button",
    { name: "Finalize investigation" },
  ).click();

  await page.getByRole(
    "button",
    { name: "Case" },
  ).click();

  await expect(evidenceCheckbox)
    .toBeDisabled();
  await expect(
    page.getByLabel("Finding title"),
  ).toBeDisabled();
  await expect(
    page.getByLabel("Analyst summary"),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", {
      name: "Save finding",
    }),
  ).toBeDisabled();

  await page.getByRole(
    "button",
    { name: "Reset scenario" },
  ).click();

  await expect(
    page.getByText("Needs action", {
      exact: true,
    }),
  ).toBeVisible();
});

test("instructor mode reveals ground truth only after finalization", async ({
  page,
}) => {
  await page.goto("/?mode=instructor");
  await page.getByRole(
    "button",
    { name: "Open investigation" },
  ).click();

  await expect(
    page.getByRole("region", {
      name: "Instructor review",
    }),
  ).toHaveCount(0);

  await performCleanResponse(page);
  await page.getByRole(
    "button",
    { name: "Finalize investigation" },
  ).click();

  const instructor = page.getByRole(
    "region",
    { name: "Instructor review" },
  );

  await expect(instructor).toBeVisible();
  await expect(instructor).toContainText(
    "Ground truth and response assessment",
  );
  await expect(instructor).toContainText(
    "The successful authentication from an unusual source is the initial compromise signal.",
  );

  await page.getByRole(
    "button",
    { name: "Student mode" },
  ).click();
  await expect(page).not.toHaveURL(
    /mode=instructor/,
  );
});

test("quick test instructions are available in product", async ({
  page,
}) => {
  await page.goto("/");

  await page.getByText(
    "Quick test",
    { exact: true },
  ).click();

  await expect(
    page.getByText(
      "First time? Five minutes is enough.",
    ),
  ).toBeVisible();
  await expect(
    page.getByText(
      "Finalize the investigation.",
      { exact: true },
    ),
  ).toBeVisible();
});

test("interface style persists across reloads", async ({
  page,
}) => {
  await page.goto("/");

  const styleSelector = page.getByLabel(
    "Select interface style",
  );

  await styleSelector.selectOption(
    "graphite",
  );
  await expect(
    page.locator("html"),
  ).toHaveAttribute(
    "data-theme",
    "graphite",
  );

  await page.reload();

  await expect(
    page.getByLabel(
      "Select interface style",
    ),
  ).toHaveValue("graphite");
  await expect(
    page.locator("html"),
  ).toHaveAttribute(
    "data-theme",
    "graphite",
  );
});
