import {
  gradeQuestions,
} from "./questionGrading";

import type {
  AnalystCaseState,
  InvestigationCoverage,
  ScenarioDefinition,
  ScenarioState,
} from "./simulationAdapter";

import type {
  SessionMode,
} from "./assistanceMode";

/**
 * The machine-readable result of one run.
 *
 * The Markdown report is for a person to read. This is for an instructor
 * collecting thirty of them, or a hiring process comparing candidates, and
 * the requirements are different: it has to be structured, complete, and
 * comparable between two people who sat the same exercise.
 *
 * Comparability is the part that needs care, and it is the part a seeded
 * generator can actually deliver. Two candidates given the same scenario id
 * and seed worked byte-identical telemetry, so a score difference is a
 * difference in them. Both are recorded here for exactly that reason: a
 * result without its seed is not evidence of anything.
 *
 * The assistance level is recorded with equal prominence, because a guided
 * run and a professional run are not the same exercise and a scorecard that
 * omits which one was taken invites two incomparable numbers to be put in
 * the same column.
 */

export interface AssessmentQuestionResult {
  readonly id: string;
  readonly prompt: string;
  readonly answered: boolean;
  readonly correct: boolean;
  readonly points: number;
  readonly earned: number;
}

export interface AssessmentRecord {
  readonly format: "endomorph-assessment";
  readonly version: 1;

  /**
   * Optional label for whose result this is.
   *
   * Typed by the analyst at export time rather than collected by the
   * product, which has no accounts and should not pretend to. It exists so
   * an instructor holding thirty records can tell them apart; it is not an
   * identity and nothing is verified about it.
   */
  readonly label?: string;

  readonly scenario: {
    readonly id: string;
    readonly name: string;
  };

  /** Everything needed to reproduce the exercise this result came from. */
  readonly reproducibility: {
    readonly seed?: number;
    readonly scenarioId: string;
    readonly note: string;
  };

  readonly assistance: SessionMode;

  readonly completed: boolean;

  readonly outcome: {
    readonly status: string;
    readonly objectivePercentage: number;
    readonly objectives: readonly {
      readonly id: string;
      readonly label: string;
      readonly met: boolean;
    }[];
  };

  readonly questions: {
    readonly earned: number;
    readonly available: number;
    readonly results: readonly AssessmentQuestionResult[];
  };

  readonly work: {
    readonly evidenceCollected: number;
    readonly findingsRecorded: number;

    /**
     * The response actions the analyst performed, annotated with quality.
     *
     * A bare list of ids records that buttons were pressed, not whether
     * pressing them was sound. A run can complete every objective and still
     * have taken a harmful action along the way -- isolating the wrong host,
     * disabling a valid account -- and the final score already docks the
     * authored penalty for it. The record has to name which action carried
     * that penalty and why, or a reviewer sees a dented score with nothing
     * explaining the dent. Actions with no authored assessment are penalty
     * zero, which is the ordinary case.
     */
    readonly responsesPerformed: readonly {
      readonly id: string;
      readonly label: string;
      readonly penalized: boolean;
      readonly penalty: number;
      readonly rationale?: string;
    }[];

    /** How many performed actions carried a response-quality penalty. */
    readonly harmfulActions: number;

    /** Sum of authored penalties over the performed actions. */
    readonly responsePenalty: number;
  };

  /**
   * How much of the incident the analyst actually reached.
   *
   * The objective and question scores answer whether the world ended in the
   * right state and whether the recall questions were answered. Neither can
   * separate an analyst who scoped the intrusion from one who read the alert,
   * guessed the containment, and stopped -- both can land the same numbers.
   * Coverage is the one figure here that does, so the record carries it
   * beside the others rather than leaving it in the on-screen result the
   * instructor never receives. It is absent only when the scenario declares
   * no ground truth to measure against.
   *
   * The missed entities are kept, not only the percentage: "reached 6 of 9"
   * is a different result depending on which three were never opened, and a
   * reviewer comparing thirty records needs the which, not only the count.
   */
  readonly coverage?: {
    readonly percentage: number;
    readonly reached: number;
    readonly total: number;
    readonly missed: readonly {
      readonly id: string;
      readonly kind: string;
      readonly label: string;
    }[];
  };
}

export interface AssessmentInput {
  readonly scenario: ScenarioDefinition;
  readonly state: ScenarioState;
  readonly analystCase: AnalystCaseState;
  readonly questionAnswers: Readonly<
    Record<string, string>
  >;
  readonly assistance: SessionMode;

  /**
   * The coverage assessment for this run, when the scenario has ground truth
   * to measure against. Passed in rather than recomputed here so the record
   * cannot disagree with the coverage the result panel and case already show
   * from the same call.
   */
  readonly coverage?: InvestigationCoverage;

  /** Seed the scenario was generated from, when the file records one. */
  readonly seed?: number;

  /** Whose result this is, if the analyst chose to say. */
  readonly label?: string;
}

export function buildAssessmentRecord(
  input: AssessmentInput,
): AssessmentRecord {
  const {
    scenario,
    state,
    analystCase,
    questionAnswers,
    assistance,
    coverage,
    seed,
    label,
  } = input;

  const questions = scenario.questions ?? [];

  const score = gradeQuestions(
    questions,
    questionAnswers,
  );

  // Joined against the scenario's actions so each performed response carries
  // the authored quality judgement that decided its penalty, rather than an
  // id a reviewer would have to cross-reference by hand. An id with no
  // matching action would be a runtime inconsistency; it is recorded as a
  // zero-penalty entry rather than dropped, so the record never silently
  // loses an action the run says was taken.
  const actionsById = new Map(
    (scenario.actions ?? []).map((action) => [
      action.id,
      action,
    ]),
  );

  const performedResponses =
    state.performedActionIds.map(
      (id) => {
        const action =
          actionsById.get(id);
        const penalty =
          action?.assessment?.penalty ??
          0;

        return {
          id,
          label: action?.label ?? id,
          penalized: penalty > 0,
          penalty,
          ...(action?.assessment
            ?.rationale
            ? {
                rationale:
                  action.assessment
                    .rationale,
              }
            : {}),
        };
      },
    );

  return {
    format: "endomorph-assessment",
    version: 1,

    ...(label && label.trim().length > 0
      ? { label: label.trim() }
      : {}),

    scenario: {
      id: scenario.id,
      name: scenario.name,
    },

    reproducibility: {
      seed,
      scenarioId: scenario.id,
      // The comparability claim is only true when a seed is recorded. The
      // hand-authored scenarios carry none, and asserting byte-identical
      // telemetry for them would be a claim a reviewer might act on and be
      // wrong to. The note states what is actually reproducible.
      note:
        seed === undefined
          ? "This scenario records no generation seed, so identical telemetry between two runs is not guaranteed and scores are not strictly comparable."
          : "Two runs of this scenario id and seed present byte-identical telemetry, so a difference in score is a difference in the analyst.",
    },

    assistance,

    completed: state.finalized,

    outcome: {
      status: state.outcome.status,
      objectivePercentage:
        state.score.percentage,
      objectives:
        state.outcome.objectives.map(
          (objective) => ({
            id: objective.id,
            label: objective.label,
            met: objective.met,
          }),
        ),
    },

    questions: {
      earned: score.earned,
      available: score.available,
      results: score.grades.map(
        (grade) => ({
          id: grade.question.id,
          prompt: grade.question.prompt,
          answered: grade.answered,
          correct: grade.correct,
          points: grade.question.points,

          // Recorded per question rather than only in the total, so a
          // reviewer can see which parts of the investigation held up
          // instead of one number that hides an even spread of near misses.
          earned: grade.correct
            ? grade.question.points
            : 0,
        }),
      ),
    },

    work: {
      evidenceCollected:
        analystCase.collectedEventIds
          .length,
      findingsRecorded:
        analystCase.findings.length,
      responsesPerformed:
        performedResponses,
      harmfulActions:
        performedResponses.filter(
          (response) =>
            response.penalized,
        ).length,
      responsePenalty:
        performedResponses.reduce(
          (total, response) =>
            total + response.penalty,
          0,
        ),
    },

    ...(coverage &&
    coverage.entities.length > 0
      ? {
          coverage: {
            percentage: coverage.percentage,
            reached: coverage.reached.length,
            total: coverage.entities.length,
            missed: coverage.missed.map(
              (entity) => ({
                id: entity.id,
                kind: entity.kind,
                label: entity.label,
              }),
            ),
          },
        }
      : {}),
  };
}
