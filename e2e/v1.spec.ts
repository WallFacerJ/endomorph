import {
  expect,
  test,
  type Page,
} from "@playwright/test";

async function openInvestigation(
  page: Page,
) {
  await page.goto("/?scenario=/scenarios/account-compromise.json");
  await page.getByRole(
    "button",
    { name: "Open investigation" },
  ).click();

}

/**
 * Guided mode keeps the response cards on the investigation view.
 *
 * Professional runs relocate response work into the tool consoles, so any
 * test driving the response -> outcome -> score pipeline through the cards
 * has to ask for them. Placement in professional mode is covered by
 * response-in-context.spec.ts.
 */
async function useGuidedMode(page: Page) {
  const group = page.getByRole(
    "radiogroup",
    { name: "Assistance level" },
  );

  // Assistance is a monotonic scale and Instructor already includes
  // everything Guided provides, so raise to Guided only when below it.
  // Clicking Guided unconditionally would silently downgrade an instructor
  // run and hide the panels the caller is about to assert on.
  const instructor = group.getByRole(
    "radio",
    { name: "Instructor" },
  );

  if (
    (await instructor.getAttribute(
      "aria-checked",
    )) === "true"
  ) {
    return;
  }

  await group
    .getByRole("radio", { name: "Guided" })
    .click();
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
  await useGuidedMode(page);
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
  await page.goto("/?scenario=/scenarios/account-compromise.json");

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
  await useGuidedMode(page);
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
  await useGuidedMode(page);

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

  // Scoped to the nav landmark: the incident-command panel also has an
  // The nav's brief view, distinguished from the Case view's "Investigation"
  // phase control of the same name.
  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Brief",
    })
    .click();
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
  await page.goto("/?scenario=/scenarios/account-compromise.json&mode=instructor");
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

  // Dropping to Professional hides the review again. The ?mode= parameter
  // is an entry point rather than a live mirror of the control, so the URL
  // is deliberately not rewritten mid-run -- doing so would reload and
  // discard the investigation.
  await page
    .getByRole("radiogroup", {
      name: "Assistance level",
    })
    .getByRole("radio", {
      name: "Professional",
    })
    .click();

  await expect(instructor).toHaveCount(0);
});

test("first-run orientation is present and dismissible", async ({
  page,
}) => {
  await page.goto("/?scenario=/scenarios/account-compromise.json");

  // Onboarding used to hide behind a "Quick test" dropdown in the control
  // row, which made it look like a setting and gave someone arriving cold
  // no reason to open it. It is now the first thing on the alert queue.
  const orientation = page.getByRole(
    "region",
    {
      name: "How to work this incident",
    },
  );

  await expect(orientation).toBeVisible();

  // Each step names the console it happens in, so it doubles as a map of
  // the sidebar.
  for (const where of [
    "Alerts",
    "SIEM Search",
    "Case",
  ]) {
    await expect(
      orientation,
    ).toContainText(where);
  }

  await orientation
    .getByRole("button", {
      name: "Got it",
    })
    .click();

  await expect(
    orientation,
  ).toHaveCount(0);

  // The dismissal sticks.
  await page.reload();

  await expect(
    page.getByRole("region", {
      name: "How to work this incident",
    }),
  ).toHaveCount(0);
});

test("interface style persists across reloads", async ({
  page,
}) => {
  await page.goto("/?scenario=/scenarios/account-compromise.json");

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
