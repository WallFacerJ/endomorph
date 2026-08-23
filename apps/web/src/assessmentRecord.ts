import {
  gradeQuestions,
} from "./questionGrading";

import type {
  AnalystCaseState,
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
    readonly responsesPerformed: readonly string[];
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
    seed,
    label,
  } = input;

  const questions = scenario.questions ?? [];

  const score = gradeQuestions(
    questions,
    questionAnswers,
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
      note: "Two runs of this scenario id and seed present byte-identical telemetry, so a difference in score is a difference in the analyst.",
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
      responsesPerformed: [
        ...state.performedActionIds,
      ],
    },
  };
}
