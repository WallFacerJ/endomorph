import {
  describe,
  expect,
  it,
} from "vitest";

import {
  buildAssessmentRecord,
} from "./assessmentRecord";

import type {
  AssessmentInput,
} from "./assessmentRecord";

function createInput(
  overrides: Partial<AssessmentInput> = {},
): AssessmentInput {
  return {
    scenario: {
      id: "scenario-test-001",
      name: "Test incident",
      questions: [
        {
          id: "q-right",
          prompt: "Which host?",
          accepted: ["FIN-LT-004"],
          surface: "endpoint",
          points: 60,
        },
        {
          id: "q-wrong",
          prompt: "Which account?",
          accepted: ["simone"],
          surface: "identity",
          points: 40,
        },
      ],
    } as unknown as AssessmentInput["scenario"],

    state: {
      finalized: true,
      score: { percentage: 50 },
      outcome: {
        status: "failed",
        objectives: [
          {
            id: "objective-one",
            label: "Account disabled",
            description: "",
            met: false,
          },
        ],
      },
      performedActionIds: [
        "action-isolate-device",
      ],
    } as unknown as AssessmentInput["state"],

    analystCase: {
      collectedEventIds: ["a", "b", "c"],
      findings: [{ id: "f" }],
    } as unknown as AssessmentInput["analystCase"],

    questionAnswers: {
      "q-right": "FIN-LT-004",
      "q-wrong": "someone-else",
    },

    assistance: "professional",

    ...overrides,
  };
}

describe("buildAssessmentRecord", () => {
  it("records which questions held up, not only the total", () => {
    /*
      A single number hides an even spread of near misses. A reviewer needs
      to see which parts of the investigation were sound, because "60 of 100"
      is a very different result depending on which 60.
    */
    const record = buildAssessmentRecord(
      createInput(),
    );

    expect(
      record.questions.earned,
    ).toBe(60);

    expect(
      record.questions.available,
    ).toBe(100);

    expect(
      record.questions.results.map(
        (result) => [
          result.id,
          result.correct,
          result.earned,
        ],
      ),
    ).toEqual([
      ["q-right", true, 60],
      ["q-wrong", false, 0],
    ]);
  });

  it("records the assistance level as prominently as the score", () => {
    // A guided run and a professional run are not the same exercise. A
    // scorecard that omits which was taken invites two incomparable numbers
    // into the same column.
    expect(
      buildAssessmentRecord(
        createInput({
          assistance: "instructor",
        }),
      ).assistance,
    ).toBe("instructor");
  });

  it("carries what is needed to reproduce the exercise", () => {
    // A result without its seed is not evidence of anything: it cannot be
    // shown that two candidates worked the same telemetry.
    const record = buildAssessmentRecord(
      createInput({ seed: 20260820 }),
    );

    expect(
      record.reproducibility.seed,
    ).toBe(20260820);

    expect(
      record.reproducibility.scenarioId,
    ).toBe("scenario-test-001");
  });

  it("does not claim the run was completed when it was not", () => {
    const record = buildAssessmentRecord(
      createInput({
        state: {
          finalized: false,
          score: { percentage: 0 },
          outcome: {
            status: "in_progress",
            objectives: [],
          },
          performedActionIds: [],
        } as unknown as AssessmentInput["state"],
      }),
    );

    expect(record.completed).toBe(false);

    expect(record.outcome.status).toBe(
      "in_progress",
    );
  });

  it("records the work done, not only the answers given", () => {
    // Two analysts can reach the same answers having done very different
    // amounts of work, and for onboarding that difference is the point.
    const record = buildAssessmentRecord(
      createInput(),
    );

    expect(record.work).toEqual({
      evidenceCollected: 3,
      findingsRecorded: 1,
      responsesPerformed: [
        "action-isolate-device",
      ],
    });
  });

  it("survives a scenario with no questions", () => {
    // The hand-authored scenarios carry none, and an assessment of one
    // should be an empty question set rather than a crash.
    const record = buildAssessmentRecord(
      createInput({
        scenario: {
          id: "scenario-plain",
          name: "Plain",
        } as unknown as AssessmentInput["scenario"],
      }),
    );

    expect(
      record.questions.results,
    ).toEqual([]);

    expect(
      record.questions.available,
    ).toBe(0);
  });
});
