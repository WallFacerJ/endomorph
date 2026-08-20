import {
  describe,
  expect,
  it,
} from "vitest";

import {
  accountCompromiseScenario,
  accountCompromiseScenarioIds,
} from "./accountCompromiseScenario";

import {
  edrProjection,
} from "./edrProjection";

import {
  identityProjection,
} from "./identityProjection";

import {
  rebuildProjection,
} from "./projection";

import {
  getScenarioState,
  validateScenarioDefinition,
} from "./scenario";

import {
  siemProjection,
} from "./siemProjection";

const ids = accountCompromiseScenarioIds;

describe("account compromise scenario", () => {
  it("validates and replays the opening incident deterministically", () => {
    expect(() =>
      validateScenarioDefinition(
        accountCompromiseScenario,
      ),
    ).not.toThrow();

    const first =
      getScenarioState(
        accountCompromiseScenario,
      );
    const second =
      getScenarioState(
        accountCompromiseScenario,
      );

    expect(second)
      .toEqual(first);

    expect(
      first.world.sessions[
        ids.sessionId
      ]?.status,
    ).toBe("active");

    expect(
      first.world.accounts[
        ids.accountId
      ]?.status,
    ).toBe("active");
  });

  it("contains the incident through deterministic response events", () => {
    const state =
      getScenarioState(
        accountCompromiseScenario,
        [ids.containmentActionId],
      );

    expect(
      state.world.sessions[
        ids.sessionId
      ]?.status,
    ).toBe("revoked");

    expect(
      state.world.accounts[
        ids.accountId
      ]?.status,
    ).toBe("disabled");

    expect(
      state.performedActionIds,
    ).toEqual([
      ids.containmentActionId,
    ]);
  });

  it("keeps identity, EDR, and SIEM views coherent", () => {
    const state =
      getScenarioState(
        accountCompromiseScenario,
      );

    const identity =
      rebuildProjection(
        identityProjection,
        state.events,
      );
    const edr =
      rebuildProjection(
        edrProjection,
        state.events,
      );
    const siem =
      rebuildProjection(
        siemProjection,
        state.events,
      );

    expect(
      identity.activity.some(
        (activity) =>
          activity.eventId ===
          ids.loginEventId,
      ),
    ).toBe(true);

    expect(
      edr.processes.some(
        (process) =>
          process.eventId ===
          ids.processEventId,
      ),
    ).toBe(true);

    expect(
      edr.alerts[0]
        ?.relatedEventIds,
    ).toEqual([
      ids.loginEventId,
      ids.processEventId,
      ids.networkEventId,
    ]);

    expect(
      siem.events.map(
        (event) => event.eventId,
      ),
    ).toEqual(
      state.events.map(
        (event) => event.id,
      ),
    );
  });

  it("rejects unknown and duplicate response actions", () => {
    expect(() =>
      getScenarioState(
        accountCompromiseScenario,
        ["missing-action"],
      ),
    ).toThrow(
      "Unknown scenario action: missing-action",
    );

    expect(() =>
      getScenarioState(
        accountCompromiseScenario,
        [
          ids.containmentActionId,
          ids.containmentActionId,
        ],
      ),
    ).toThrow(
      `Scenario action already performed: ${ids.containmentActionId}`,
    );
  });
});
