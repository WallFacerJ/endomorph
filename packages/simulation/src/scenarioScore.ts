import type {
  ScenarioOutcome,
} from "./scenarioOutcome";

export interface ScenarioScore {
  completedObjectives: number;

  totalObjectives: number;

  objectivePercentage: number;

  responsePenalty: number;

  percentage: number;
}

function requireValidPenalty(
  penalty: number,
): number {
  if (
    !Number.isFinite(penalty) ||
    penalty < 0
  ) {
    throw new Error(
      `Scenario response penalty must be a finite non-negative number: ${penalty}`,
    );
  }

  return penalty;
}

export function evaluateScenarioScore(
  outcome: ScenarioOutcome,
  responsePenalties:
    readonly number[] = [],
): ScenarioScore {
  const completedObjectives =
    outcome.objectives.filter(
      (objective) => objective.met,
    ).length;
  const totalObjectives =
    outcome.objectives.length;
  const objectivePercentage =
    totalObjectives === 0
      ? 0
      : Math.round(
          (completedObjectives * 100) /
            totalObjectives,
        );
  const responsePenalty =
    responsePenalties.reduce(
      (total, penalty) =>
        total +
        requireValidPenalty(penalty),
      0,
    );

  return {
    completedObjectives,
    totalObjectives,
    objectivePercentage,
    responsePenalty,
    percentage:
      Math.max(
        0,
        Math.min(
          100,
          objectivePercentage -
            responsePenalty,
        ),
      ),
  };
}
