import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  ScenarioOutcome,
} from "./scenarioOutcome";

import {
  evaluateScenarioScore,
} from "./scenarioScore";

function createOutcome(
  met: readonly boolean[],
): ScenarioOutcome {
  return {
    status:
      met.every(Boolean)
        ? "succeeded"
        : "in_progress",
    objectives: met.map(
      (objectiveMet, index) => ({
        id: `objective-${index + 1}`,
        label: `Objective ${index + 1}`,
        description:
          `Objective ${index + 1} description`,
        met: objectiveMet,
      }),
    ),
  };
}

describe("scenario scoring", () => {
  it("returns zero for no completed objectives", () => {
    expect(
      evaluateScenarioScore(
        createOutcome([
          false,
          false,
        ]),
      ),
    ).toEqual({
      completedObjectives: 0,
      totalObjectives: 2,
      percentage: 0,
    });
  });

  it("scores partial objective completion deterministically", () => {
    const outcome =
      createOutcome([
        true,
        false,
        true,
      ]);

    const first =
      evaluateScenarioScore(outcome);
    const second =
      evaluateScenarioScore(outcome);

    expect(second).toEqual(first);
    expect(first).toEqual({
      completedObjectives: 2,
      totalObjectives: 3,
      percentage: 67,
    });
  });

  it("returns one hundred for full completion", () => {
    expect(
      evaluateScenarioScore(
        createOutcome([
          true,
          true,
        ]),
      ),
    ).toEqual({
      completedObjectives: 2,
      totalObjectives: 2,
      percentage: 100,
    });
  });

  it("handles an empty objective result defensively", () => {
    expect(
      evaluateScenarioScore({
        status: "succeeded",
        objectives: [],
      }),
    ).toEqual({
      completedObjectives: 0,
      totalObjectives: 0,
      percentage: 0,
    });
  });
});
