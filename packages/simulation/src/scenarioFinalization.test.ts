import {
  readFileSync,
} from "node:fs";

import {
  describe,
  expect,
  it,
} from "vitest";

import {
  parseScenarioJson,
} from "../../schema/src/scenario";

import {
  compileScenarioDefinition,
} from "./scenarioCompiler";

import {
  finalizeScenarioState,
  getScenarioState,
} from "./scenario";

const scenarioUrl = new URL(
  "../../../apps/web/public/scenarios/account-compromise.json",
  import.meta.url,
);

function loadScenario() {
  const file = parseScenarioJson(
    readFileSync(
      scenarioUrl,
      "utf8",
    ),
  );

  return compileScenarioDefinition(
    file.scenario,
  );
}

describe("scenario finalization", () => {
  it("fails a zero-progress response only when explicitly finalized", () => {
    const scenario = loadScenario();

    const active =
      getScenarioState(scenario);
    const finalized =
      finalizeScenarioState(scenario);

    expect(active.finalized)
      .toBe(false);
    expect(active.outcome.status)
      .toBe("in_progress");
    expect(active.score.percentage)
      .toBe(0);

    expect(finalized.finalized)
      .toBe(true);
    expect(finalized.outcome.status)
      .toBe("failed");
    expect(finalized.score.percentage)
      .toBe(0);
    expect(finalized.world)
      .toEqual(active.world);
    expect(finalized.events)
      .toEqual(active.events);
  });

  it("finalizes partial remediation as failed without changing its 50% score", () => {
    const scenario = loadScenario();
    const [firstActionId] =
      scenario.investigation
        .responseActionIds;

    expect(firstActionId)
      .toBeDefined();

    const active = getScenarioState(
      scenario,
      [firstActionId!],
    );
    const finalized =
      finalizeScenarioState(
        scenario,
        [firstActionId!],
      );

    expect(active.outcome.status)
      .toBe("in_progress");
    expect(active.score.percentage)
      .toBe(50);
    expect(finalized.outcome.status)
      .toBe("failed");
    expect(finalized.score.percentage)
      .toBe(50);
    expect(finalized.world)
      .toEqual(active.world);
    expect(finalized.events)
      .toEqual(active.events);
  });

  it("finalizes a complete response as succeeded", () => {
    const scenario = loadScenario();
    const actionIds =
      scenario.investigation
        .responseActionIds;

    const active = getScenarioState(
      scenario,
      actionIds,
    );
    const finalized =
      finalizeScenarioState(
        scenario,
        actionIds,
      );

    expect(active.outcome.status)
      .toBe("succeeded");
    expect(active.finalized)
      .toBe(false);
    expect(finalized.outcome.status)
      .toBe("succeeded");
    expect(finalized.finalized)
      .toBe(true);
    expect(finalized.score.percentage)
      .toBe(100);
  });

  it("repeats finalization deterministically", () => {
    const scenario = loadScenario();
    const [firstActionId] =
      scenario.investigation
        .responseActionIds;

    const first =
      finalizeScenarioState(
        scenario,
        [firstActionId!],
      );
    const second =
      finalizeScenarioState(
        scenario,
        [firstActionId!],
      );

    expect(second)
      .toEqual(first);
  });

  it("starts a fresh active state after reset-style reconstruction", () => {
    const scenario = loadScenario();

    const finalized =
      finalizeScenarioState(
        scenario,
        scenario.investigation
          .responseActionIds,
      );
    const reset =
      getScenarioState(scenario);

    expect(finalized.finalized)
      .toBe(true);
    expect(reset.finalized)
      .toBe(false);
    expect(reset.outcome.status)
      .toBe("in_progress");
    expect(reset.score.percentage)
      .toBe(0);
    expect(reset.performedActionIds)
      .toEqual([]);
  });
});
