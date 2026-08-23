import {
  describe,
  expect,
  it,
} from "vitest";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

import {
  generateIncident,
} from "./generateIncident.js";

import {
  generateBackgroundActivity,
} from "./backgroundActivity.js";

import {
  generateEnterprise,
} from "./generateEnterprise.js";

/**
 * The beacon must not be the loudest thing on its own host.
 *
 * Repetition to one address is the shape everybody teaches for command and
 * control, which makes it the first thing an analyst reaches for and the
 * first thing a corpus can accidentally give away. If the compromised host's
 * busiest destination were always the attacker's, the exercise would reduce
 * to sorting by count, and every rule keyed on repetition would score a
 * flawless number that meant nothing outside this repository.
 *
 * Corporate laptops hold polling connections open to mail and chat all day,
 * to a fixed address, at an interval. That is the same shape as a beacon and
 * the reason beacon detection is genuinely hard. The background generator
 * models it; this asserts the modelling actually achieves the property,
 * because the rationale living in a comment is not evidence that it works.
 *
 * Measured the way the live-response view groups traffic -- destination, port
 * and process -- since that is the grouping an analyst is looking at when the
 * temptation to sort by count arises.
 */

const enterprise = generateEnterprise();

const background =
  generateBackgroundActivity(enterprise, {
    days: 2,
  });

interface HostTraffic {
  readonly deviceId: string;
  readonly largestGroup: number;
}

function groupTraffic(
  events: readonly {
    type: string;
    payload: Record<string, unknown>;
  }[],
): readonly HostTraffic[] {
  const byHost = new Map<
    string,
    Map<string, number>
  >();

  for (const event of events) {
    if (
      event.type !== "NETWORK_CONNECTION"
    ) {
      continue;
    }

    const deviceId = String(
      event.payload.deviceId,
    );

    const groups =
      byHost.get(deviceId) ??
      new Map<string, number>();

    const key = [
      event.payload.destinationIp,
      event.payload.destinationPort ?? "",
      event.payload.processId ?? "",
    ].join("|");

    groups.set(
      key,
      (groups.get(key) ?? 0) + 1,
    );

    byHost.set(deviceId, groups);
  }

  return [...byHost.entries()].map(
    ([deviceId, groups]) => ({
      deviceId,
      largestGroup: Math.max(
        ...groups.values(),
      ),
    }),
  );
}

describe("beacon indistinguishability", () => {
  for (const plan of ATTACK_PLANS) {
    it(`${plan.id}: the compromised host is not an outlier for repeated traffic`, () => {
      const incident = generateIncident(
        enterprise,
        { planId: plan.id },
      );

      const detection =
        incident.events[
          incident.events.length - 1
        ].timestamp;

      const events = [
        ...background.filter(
          (event) =>
            event.timestamp <= detection,
        ),
        ...incident.events,
      ];

      const beaconing =
        incident.events.filter(
          (event) =>
            event.type ===
            "NETWORK_CONNECTION",
        );

      if (beaconing.length === 0) {
        /*
          Two plans never touch the network -- a directory role grant and a
          dormant account revival. There is nothing to hide on a host that
          has no attacker traffic, and asserting otherwise would be a test
          that passes for the wrong reason.
        */
        expect(beaconing).toHaveLength(0);

        return;
      }

      const victimId = String(
        beaconing[0].payload.deviceId,
      );

      const traffic = groupTraffic(
        events as never,
      );

      const victim = traffic.find(
        (host) =>
          host.deviceId === victimId,
      );

      expect(victim).toBeDefined();

      const atLeastAsBusy = traffic.filter(
        (host) =>
          host.deviceId !== victimId &&
          host.largestGroup >=
            (victim?.largestGroup ?? 0),
      );

      /*
        Not "some benign host is busier" but "a great many are". One busier
        machine would still leave the victim near the top of a sorted column,
        which is where an analyst's eye goes. A quarter of the estate is the
        floor for the attacker's traffic being genuinely unremarkable.
      */
      expect(
        atLeastAsBusy.length,
      ).toBeGreaterThan(
        traffic.length / 4,
      );
    });
  }
});
