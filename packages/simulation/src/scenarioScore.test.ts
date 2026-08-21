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
      objectivePercentage: 0,
      responsePenalty: 0,
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
      objectivePercentage: 67,
      responsePenalty: 0,
      percentage: 67,
    });
  });

  it("subtracts deterministic response penalties from objective completion", () => {
    expect(
      evaluateScenarioScore(
        createOutcome([
          true,
          true,
        ]),
        [10, 15],
      ),
    ).toEqual({
      completedObjectives: 2,
      totalObjectives: 2,
      objectivePercentage: 100,
      responsePenalty: 25,
      percentage: 75,
    });
  });

  it("clamps the final percentage at zero", () => {
    expect(
      evaluateScenarioScore(
        createOutcome([
          true,
          false,
        ]),
        [75],
      ),
    ).toMatchObject({
      objectivePercentage: 50,
      responsePenalty: 75,
      percentage: 0,
    });
  });

  it("rejects invalid response penalties", () => {
    expect(() =>
      evaluateScenarioScore(
        createOutcome([true]),
        [-1],
      ),
    ).toThrow(
      "Scenario response penalty must be a finite non-negative number",
    );
  });

  it("returns one hundred for full completion without penalties", () => {
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
      objectivePercentage: 100,
      responsePenalty: 0,
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
      objectivePercentage: 0,
      responsePenalty: 0,
      percentage: 0,
    });
  });
});
