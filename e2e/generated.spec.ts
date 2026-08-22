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

test("the entity inventories are filterable and do not stretch the page", async ({
  page,
}) => {
  // Both consoles listed their whole inventory unbounded: Identity ran to
  // 23,377px and Endpoint to 16,284px, so every other panel sat far below the
  // fold and an analyst holding a hostname or a username had to scroll for
  // it. The lists now scroll inside their own pane and can be filtered.
  await page.goto(GENERATED_SCENARIO);

  await page.getByRole(
    "button",
    { name: "Got it" },
  ).click();

  await page.getByRole("button", {
    name: /^Identity/,
  }).click();

  const directoryFilter =
    page.getByLabel(
      "Filter the directory",
    );

  await expect(
    directoryFilter,
  ).toBeVisible();

  await directoryFilter.fill("simone");

  await expect(
    page.locator(
      ".identity-user-group",
    ),
  ).toHaveCount(1);

  await directoryFilter.fill(
    "no-such-person",
  );

  await expect(
    page.locator(
      ".identity-directory-empty",
    ),
  ).toBeVisible();

  expect(
    await page.evaluate(
      () =>
        document.documentElement
          .scrollHeight,
    ),
  ).toBeLessThan(6000);

  await page.getByRole("button", {
    name: /^Endpoint/,
  }).click();

  await page
    .getByLabel(
      "Filter the endpoint inventory",
    )
    .fill("FIN-LT-004");

  await expect(
    page.locator(".edr-endpoint-row"),
  ).toHaveCount(1);

  expect(
    await page.evaluate(
      () =>
        document.documentElement
          .scrollHeight,
    ),
  ).toBeLessThan(6000);
});

test("no console scrolls the page sideways at laptop widths", async ({
  page,
}) => {
  // The three-column consoles have minimum column widths totalling ~1100px
  // and sit inside a 260px nav, so they need roughly 1400px of viewport. The
  // breakpoint that stacked them was set at 1180, which left a band where the
  // grid could not fit and pushed the document sideways instead -- 1358px of
  // content in a 1280px window, an entirely ordinary laptop.
  for (const width of [
    1920, 1440, 1366, 1280, 1024,
  ]) {
    await page.setViewportSize({
      width,
      height: 900,
    });

    await page.goto(GENERATED_SCENARIO);

    const dismiss = page.getByRole(
      "button",
      { name: "Got it" },
    );

    if (
      await dismiss
        .isVisible()
        .catch(() => false)
    ) {
      await dismiss.click();
    }

    for (const console of [
      "Alerts",
      "SIEM Search",
      "Endpoint",
      "Identity",
      "Case",
    ]) {
      await page
        .getByRole("button", {
          name: new RegExp(
            `^${console}`,
          ),
        })
        .click();

      const overflow =
        await page.evaluate(() => ({
          scroll:
            document.documentElement
              .scrollWidth,
          client:
            document.documentElement
              .clientWidth,
        }));

      expect(
        `${width} ${console}: ${overflow.scroll}`,
      ).toBe(
        `${width} ${console}: ${overflow.client}`,
      );
    }
  }
});

test("no console renders the whole event stream", async ({
  page,
}) => {
  /*
    The correlated timeline rendered a row per event. On the default
    generated scenario that was 20,053 rows: 200,743 DOM nodes, a page 2.4
    million pixels tall -- roughly two and a half thousand screens -- and
    several seconds to open the view. The SIEM had the identical defect and
    was capped months earlier; the view beside it was not.

    Nobody scrolls that, so the cost bought nothing. The bound is asserted
    rather than the row count, because the row count is a detail and the page
    height is the thing that was actually wrong.
  */
  await page.goto(GENERATED_SCENARIO);

  await page
    .getByRole("button", {
      name: "Got it",
    })
    .click();

  for (const view of [
    "Alerts",
    "Brief",
    "SIEM Search",
    "Endpoint",
    "Identity",
    "Answers",
    "Case",
  ]) {
    await page
      .getByRole("navigation")
      .getByRole("button", {
        name: new RegExp(`^${view}`),
      })
      .click();

    const measured =
      await page.evaluate(() => ({
        height:
          document.documentElement
            .scrollHeight,
        nodes:
          document.querySelectorAll("*")
            .length,
      }));

    expect(
      `${view} height ${measured.height < 12000}`,
    ).toBe(`${view} height true`);

    expect(
      `${view} nodes ${measured.nodes < 12000}`,
    ).toBe(`${view} nodes true`);
  }
});
