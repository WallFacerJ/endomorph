import {
  expect,
  test,
} from "@playwright/test";

/**
 * Point-in-time replay is the capability the event-sourced architecture was
 * chosen for. Because history is append-only and every console is a pure
 * projection, "what did this look like at 14:32" is a prefix replay rather
 * than stored snapshots.
 */

const GENERATED =
  "/?scenario=/scenarios/generated-enterprise.json";

/*
  Stepping between incident steps is ground truth, so the transport only
  offers it to an instructor; everyone else gets a neutral rewind. Tests
  about replay itself use the default mode, and the one test that is
  specifically about incident-step navigation asks for the mode that has it.
*/
const GENERATED_INSTRUCTOR = `${GENERATED}&mode=instructor`;

test("starts live at the end of history", async ({
  page,
}) => {
  await page.goto(GENERATED);

  // Wait for the scenario to finish compiling before asserting. The
  // generated scenario carries ~17.9k events, and under parallel load the
  // default assertion timeout can expire while it is still inflating --
  // which made this test flaky rather than failing, the worse outcome.
  await page
    .getByRole("button", {
      name: "Endpoint",
    })
    .waitFor({ timeout: 30_000 });

  const replay = page.getByRole(
    "region",
    { name: "Replay" },
  );

  await expect(replay).toContainText(
    "Live",
  );

  await expect(
    replay.getByRole("button", {
      name: "Return to now",
    }),
  ).toBeDisabled();
});

test("rewinding changes what every console shows", async ({
  page,
}) => {
  await page.goto(GENERATED);

  await page
    .getByRole("button", {
      name: "SIEM Search",
    })
    .click();

  const matching = async () => {
    const body = await page
      .locator("body")
      .innerText();

    const found = body.match(
      /([\d,]+)\s*\n?\s*matching events/i,
    );

    return Number(
      (found?.[1] ?? "0").replace(
        /,/g,
        "",
      ),
    );
  };

  const live = await matching();

  expect(live).toBeGreaterThan(1000);

  const replay = page.getByRole(
    "region",
    { name: "Replay" },
  );

  await replay
    .getByRole("button", {
      name: "Rewind",
    })
    .click();

  await expect(replay).toContainText(
    "Viewing history",
  );

  // The SIEM is a projection of the replayed prefix, not a filtered view of
  // the whole stream, so its count genuinely shrinks.
  await expect
    .poll(matching)
    .toBeLessThan(live);

  await replay
    .getByRole("button", {
      name: "Return to now",
    })
    .click();

  await expect
    .poll(matching)
    .toBe(live);
});

test("walks backward through the incident step by step", async ({
  page,
}) => {
  await page.goto(GENERATED_INSTRUCTOR);

  const replay = page.getByRole(
    "region",
    { name: "Replay" },
  );

  const back = replay.getByRole(
    "button",
    { name: "Previous incident step" },
  );

  const positions: string[] = [];

  for (
    let step = 0;
    step < 4;
    step += 1
  ) {
    await back.click();

    const text =
      await replay.innerText();

    positions.push(
      text.match(/([\d,]+) \//)?.[1] ??
        "",
    );
  }

  // Each press moves strictly further back.
  const numeric = positions.map((value) =>
    Number(value.replace(/,/g, "")),
  );

  for (
    let index = 1;
    index < numeric.length;
    index += 1
  ) {
    expect(
      numeric[index],
    ).toBeLessThan(numeric[index - 1]);
  }
});

test("refuses response actions while rewound", async ({
  page,
}) => {
  // A small scenario is enough here; this asserts refusal, not scale.
  await page.goto(
    "/?scenario=/scenarios/account-compromise.json",
  );
  await page
    .getByRole("button", {
      name: "Open investigation",
    })
    .click();

  await page
    .getByRole("navigation")
    .getByRole("button", {
      name: "Identity",
    })
    .click();

  const operations = page.locator(
    ".identity-action",
  );

  const before = await operations.count();

  expect(before).toBeGreaterThan(0);

  const replay = page.getByRole(
    "region",
    { name: "Replay" },
  );

  await replay
    .getByRole("button", {
      name: "Rewind",
    })
    .click();

  await expect(replay).toContainText(
    "Response actions are disabled",
  );

  // Acting on a past state would either rewrite history or silently apply
  // to the present. Both are worse than refusing.
  const performed = page.locator(
    ".identity-action:not([disabled])",
  );

  if ((await performed.count()) > 0) {
    await performed.first().click();
  }

  await expect(replay).toContainText(
    "Viewing history",
  );
});
