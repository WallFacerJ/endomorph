import type {
  ScenarioDefinition,
} from "./scenario";

import {
  finalizeScenarioState,
} from "./scenario";

import type {
  ScenarioOutcomeStatus,
} from "./scenarioOutcome";

import type {
  ScenarioScore,
} from "./scenarioScore";

/**
 * Counterfactual response analysis.
 *
 * This is the half of the replay promise that rewinding alone does not
 * deliver: not just "what did this look like earlier" but "what would have
 * happened if I had done something else".
 *
 * It is computable rather than simulated because the runtime is
 * deterministic and response actions are declarative. Scoring an alternative
 * path is running the same pure function over a different action set, so
 * every counterfactual here is exact -- not an estimate, and not a second
 * playthrough the analyst has to sit through.
 *
 * That also makes the score explainable, which ENTERPRISE_VISION requires of
 * every metric: instead of a number, an analyst gets what each decision was
 * individually worth.
 *
 * Response order matters, and materially: re-enabling an account after
 * disabling it undoes the containment, and the same three actions score 25
 * or 75 depending on sequence. So the search considers orderings rather than
 * only sets, and a single action's influence is measured by appending it --
 * which is what "and then I also did this" means for an analyst who has
 * already acted.
 */

export interface ResponsePathOutcome {
  readonly actionIds: readonly string[];
  readonly score: ScenarioScore;
  readonly status: ScenarioOutcomeStatus;
}

export interface ActionInfluence {
  readonly actionId: string;
  readonly label: string;
  readonly performed: boolean;

  /**
   * Change in final score from toggling this one action, holding every
   * other decision constant.
   */
  readonly delta: number;

  readonly explanation: string;
}

export interface ResponseComparison {
  readonly taken: ResponsePathOutcome;
  readonly best: ResponsePathOutcome;
  readonly influences: readonly ActionInfluence[];
  readonly optimal: boolean;

  /**
   * True when every ordering was searched, so the best path is proven
   * optimal. False when a set-only or greedy search was used and the caller
   * must not claim optimality it did not establish.
   */
  readonly exhaustive: boolean;
}

/**
 * Ordered search is factorial, so it is only viable for a handful of
 * actions. Beyond this the search falls back to sets, and beyond
 * MAX_SUBSET_ACTIONS to a greedy walk.
 */
const MAX_ORDERED_ACTIONS = 6;

const MAX_SUBSET_ACTIONS = 12;

function evaluatePath(
  scenario: ScenarioDefinition,
  actionIds: readonly string[],
): ResponsePathOutcome {
  const state = finalizeScenarioState(
    scenario,
    actionIds,
  );

  return {
    actionIds: [...actionIds],
    score: state.score,
    status: state.outcome.status,
  };
}

/**
 * Some action combinations are invalid -- an action whose events cannot be
 * appended to the resulting history, for instance -- and the runtime throws
 * rather than scoring them. A path that cannot be taken is not a
 * counterfactual worth reporting, so it is skipped.
 */
function tryEvaluate(
  scenario: ScenarioDefinition,
  actionIds: readonly string[],
): ResponsePathOutcome | undefined {
  try {
    return evaluatePath(
      scenario,
      actionIds,
    );
  } catch {
    return undefined;
  }
}

/**
 * Every ordered sequence of distinct actions, including the empty one.
 *
 * Sets are not sufficient because order changes the outcome; a search over
 * subsets alone would report a "best" path that a different ordering of the
 * same actions beats.
 */
function* orderedSequences(
  candidates: readonly string[],
  prefix: readonly string[] = [],
): Generator<readonly string[]> {
  yield prefix;

  for (const candidate of candidates) {
    if (prefix.includes(candidate)) {
      continue;
    }

    yield* orderedSequences(candidates, [
      ...prefix,
      candidate,
    ]);
  }
}

function findBestOrdered(
  scenario: ScenarioDefinition,
  candidates: readonly string[],
): ResponsePathOutcome | undefined {
  let best: ResponsePathOutcome | undefined;

  for (const sequence of orderedSequences(
    candidates,
  )) {
    const outcome = tryEvaluate(
      scenario,
      sequence,
    );

    if (!outcome) {
      continue;
    }

    if (
      !best ||
      outcome.score.percentage >
        best.score.percentage ||
      (outcome.score.percentage ===
        best.score.percentage &&
        outcome.actionIds.length <
          best.actionIds.length)
    ) {
      best = outcome;
    }
  }

  return best;
}

function findBestSubsets(
  scenario: ScenarioDefinition,
  candidates: readonly string[],
): ResponsePathOutcome | undefined {
  let best: ResponsePathOutcome | undefined;

  const total = 1 << candidates.length;

  for (
    let mask = 0;
    mask < total;
    mask += 1
  ) {
    const actionIds = candidates.filter(
      (_unused, index) =>
        (mask & (1 << index)) !== 0,
    );

    const outcome = tryEvaluate(
      scenario,
      actionIds,
    );

    if (!outcome) {
      continue;
    }

    if (
      !best ||
      outcome.score.percentage >
        best.score.percentage ||
      (outcome.score.percentage ===
        best.score.percentage &&
        outcome.actionIds.length <
          best.actionIds.length)
    ) {
      best = outcome;
    }
  }

  return best;
}

function findBestGreedy(
  scenario: ScenarioDefinition,
  candidates: readonly string[],
): ResponsePathOutcome | undefined {
  let current = tryEvaluate(scenario, []);

  if (!current) {
    return undefined;
  }

  let improved = true;

  while (improved) {
    improved = false;

    for (const candidate of candidates) {
      if (
        current.actionIds.includes(
          candidate,
        )
      ) {
        continue;
      }

      const next = tryEvaluate(scenario, [
        ...current.actionIds,
        candidate,
      ]);

      if (
        next &&
        next.score.percentage >
          current.score.percentage
      ) {
        current = next;
        improved = true;
      }
    }
  }

  return current;
}

function explain(
  performed: boolean,
  delta: number,
): string {
  if (delta === 0) {
    return performed
      ? "Removing this would not have changed the score. It was neither required nor harmful."
      : "Taking this would not have changed the score.";
  }

  if (performed) {
    return delta > 0
      ? `Worth ${delta} points. Omitting it would have cost you that.`
      : `Cost ${Math.abs(delta)} points. The run scores higher without it.`;
  }

  return delta > 0
    ? `Taking this would have gained ${delta} points.`
    : `Taking this would have cost ${Math.abs(delta)} points.`;
}

export function compareResponsePaths(
  scenario: ScenarioDefinition,
  performedActionIds: readonly string[],
): ResponseComparison {
  const candidates =
    scenario.investigation
      .responseActionIds.length > 0
      ? [
          ...scenario.investigation
            .responseActionIds,
        ]
      : scenario.actions.map(
          (action) => action.id,
        );

  const taken = evaluatePath(
    scenario,
    performedActionIds,
  );

  const exhaustive =
    candidates.length <=
    MAX_ORDERED_ACTIONS;

  const best =
    (exhaustive
      ? findBestOrdered(
          scenario,
          candidates,
        )
      : candidates.length <=
          MAX_SUBSET_ACTIONS
        ? findBestSubsets(
            scenario,
            candidates,
          )
        : findBestGreedy(
            scenario,
            candidates,
          )) ?? taken;

  const influences: ActionInfluence[] =
    candidates.flatMap((actionId) => {
      const action = scenario.actions.find(
        (candidate) =>
          candidate.id === actionId,
      );

      if (!action) {
        return [];
      }

      const performed =
        performedActionIds.includes(
          actionId,
        );

      // Toggle exactly this decision and hold the rest constant, which is
      // what makes the delta attributable to it.
      const toggled = performed
        ? performedActionIds.filter(
            (candidate) =>
              candidate !== actionId,
          )
        : [
            ...performedActionIds,
            actionId,
          ];

      const alternative = tryEvaluate(
        scenario,
        toggled,
      );

      if (!alternative) {
        return [];
      }

      const delta = performed
        ? taken.score.percentage -
          alternative.score.percentage
        : alternative.score.percentage -
          taken.score.percentage;

      return [
        {
          actionId,
          label: action.label,
          performed,
          delta,
          explanation: explain(
            performed,
            delta,
          ),
        },
      ];
    });

  return {
    taken,
    best,
    influences,
    optimal:
      taken.score.percentage >=
      best.score.percentage,
    exhaustive,
  };
}
