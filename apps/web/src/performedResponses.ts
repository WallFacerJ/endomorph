import type {
  ScenarioAction,
} from "./simulationAdapter";

/**
 * A response the analyst performed, annotated with its authored quality.
 *
 * Both the machine-readable assessment record and the human-readable case
 * report have to say which responses were taken and whether any were
 * harmful. Deriving that in each of them separately is how the two come to
 * disagree about the same run, so it is derived once here and read by both
 * -- the same rule the coverage and incident-report code already follow.
 */
export interface PerformedResponse {
  readonly id: string;

  readonly label: string;

  /** True when the action carries an authored response-quality penalty. */
  readonly penalized: boolean;

  /** 0 when the action has no authored assessment, which is the usual case. */
  readonly penalty: number;

  readonly rationale?: string;
}

export function summarizePerformedResponses(
  actions: readonly ScenarioAction[],
  performedActionIds: readonly string[],
): readonly PerformedResponse[] {
  const actionsById = new Map(
    actions.map((action) => [
      action.id,
      action,
    ]),
  );

  return performedActionIds.map((id) => {
    const action = actionsById.get(id);
    const penalty =
      action?.assessment?.penalty ?? 0;

    // An id with no matching action is a runtime inconsistency, not a reason
    // to lose the fact that the run took an action. It is kept as a
    // zero-penalty entry labelled by its id rather than dropped.
    return {
      id,
      label: action?.label ?? id,
      penalized: penalty > 0,
      penalty,
      ...(action?.assessment?.rationale
        ? {
            rationale:
              action.assessment.rationale,
          }
        : {}),
    };
  });
}
