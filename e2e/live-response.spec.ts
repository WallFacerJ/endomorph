import {
  expect,
  test,
} from "@playwright/test";

/**
 * The macro scenario, because it is the one with persistence to find and a
 * beacon still attributed to a live process. The other plans exercise the
 * same console with less in it.
 */
const SCENARIO =
  "/?scenario=/scenarios/generated-macro.json";

async function openLiveResponse(page) {
  await page.goto(SCENARIO);

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

  await page
    .getByRole("button", {
      name: /^Live Response/,
    })
    .click();

  await expect(
    page.getByRole("region", {
      name: "Live response workspace",
    }),
  ).toBeVisible();
}

test("the compromised host reports a process still running, and says why", async ({
  page,
}) => {
  await openLiveResponse(page);

  /*
    The console opens on the host the alert names, so no selection is needed.
    A running state here is the whole point of the view: the beacon is still
    attributed to that PowerShell, which is a fact the endpoint console cannot
    express because it only lists what started.
  */
  const running = page
    .locator(".live-state-running")
    .first();

  await expect(running).toBeVisible();

  await expect(running).toHaveText(
    /running/i,
  );

  // Expanding a row must give the reasoning, not just the verdict. A state
  // with no basis attached teaches an analyst to accept verdicts.
  await page
    .locator(".live-row-head")
    .first()
    .click();

  await expect(
    page
      .locator(".live-row-basis")
      .first(),
  ).toContainText(/attributed/i);
});

test("every listing states what it cannot tell you", async ({
  page,
}) => {
  await openLiveResponse(page);

  for (const command of [
    "Processes",
    "Connections",
    "Persistence",
    "Logons",
    "File changes",
  ]) {
    await page
      .getByRole("button", {
        name: command,
        exact: true,
      })
      .click();

    // Carried with the result rather than in documentation nobody opens: the
    // moment somebody needs the limits of a view is while they are reading it.
    await expect(
      page.locator(".live-limitation"),
    ).not.toBeEmpty();
  }
});

test("an ordinary host answers the same questions, and the answers are boring", async ({
  page,
}) => {
  await openLiveResponse(page);

  await page
    .getByRole("button", {
      name: "Persistence",
      exact: true,
    })
    .click();

  const onVictim = await page
    .locator(".live-row")
    .count();

  expect(onVictim).toBeGreaterThan(0);

  /*
    The comparison this console exists to make possible.

    An analyst who has only ever run a command on a compromised machine has no
    idea which part of the output was the finding. Every host in the estate is
    selectable for that reason, and the check that matters is that an ordinary
    one produces a visibly different answer rather than the same one.
  */
  const hosts = page.locator(".live-host");

  const total = await hosts.count();

  expect(total).toBeGreaterThan(10);

  let sawQuieterHost = false;

  for (
    let index = 0;
    index < Math.min(total, 12);
    index += 1
  ) {
    await hosts.nth(index).click();

    const rows = await page
      .locator(".live-row")
      .count();

    if (rows < onVictim) {
      sawQuieterHost = true;
      break;
    }
  }

  expect(sawQuieterHost).toBe(true);
});

test("the host the alert names is visible in the inventory, not just selected", async ({
  page,
}) => {
  await openLiveResponse(page);

  /*
    The console opens on the alerted host, which in a 154-machine estate sits
    far below the fold. It selected that host and left the list showing the
    first five, so the header named one machine, nothing on screen appeared
    selected, and the inventory read as broken.
  */
  const selected = page.locator(
    ".live-host.selected",
  );

  await expect(selected).toHaveCount(1);

  /*
    Measured against the scrolling container rather than the browser viewport.
    The inventory sits below the page fold at ordinary window heights, so
    toBeInViewport fails for a reason that has nothing to do with the bug --
    what was broken was the selection being scrolled out of its own list.
  */
  const visibleInList = await page.evaluate(
    () => {
      const container =
        document.querySelector(
          ".live-host-scroll",
        );

      const chosen =
        document.querySelector(
          ".live-host.selected",
        );

      if (!container || !chosen) {
        return false;
      }

      const outer =
        container.getBoundingClientRect();

      const inner =
        chosen.getBoundingClientRect();

      return (
        inner.top >= outer.top - 1 &&
        inner.bottom <= outer.bottom + 1
      );
    },
  );

  expect(visibleInList).toBe(true);
});
