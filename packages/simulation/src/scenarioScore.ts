import type {
  ScenarioOutcome,
} from "./scenarioOutcome";

export interface ScenarioScore {
  completedObjectives: number;

  totalObjectives: number;

  percentage: number;
}

export function evaluateScenarioScore(
  outcome: ScenarioOutcome,
): ScenarioScore {
  const completedObjectives =
    outcome.objectives.filter(
      (objective) => objective.met,
    ).length;
  const totalObjectives =
    outcome.objectives.length;

  return {
    completedObjectives,
    totalObjectives,
    percentage:
      totalObjectives === 0
        ? 0
        : Math.round(
            (completedObjectives * 100) /
              totalObjectives,
          ),
  };
}
