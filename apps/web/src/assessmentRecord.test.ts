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
        {
          id: "action-isolate-device",
          label: "action-isolate-device",
          penalized: false,
          penalty: 0,
        },
      ],
      harmfulActions: 0,
      responsePenalty: 0,
    });
  });

  it("names the harmful action that dented the score, and why", () => {
    // A run can complete every objective and still take a harmful action
    // along the way. The final score docks the authored penalty for it; the
    // record has to say which action carried that penalty and its rationale,
    // or the reviewer sees an unexplained dent.
    const record = buildAssessmentRecord(
      createInput({
        scenario: {
          id: "scenario-harm-001",
          name: "Harm",
          actions: [
            {
              id: "action-isolate-device",
              label: "Isolate the wrong host",
              description: "",
              events: [],
              assessment: {
                penalty: 25,
                rationale:
                  "This host was not involved; isolating it disrupts a bystander.",
              },
            },
          ],
        } as unknown as AssessmentInput["scenario"],
        state: {
          finalized: true,
          score: { percentage: 75 },
          outcome: {
            status: "succeeded",
            objectives: [],
          },
          performedActionIds: [
            "action-isolate-device",
          ],
        } as unknown as AssessmentInput["state"],
      }),
    );

    expect(
      record.work.responsesPerformed,
    ).toEqual([
      {
        id: "action-isolate-device",
        label: "Isolate the wrong host",
        penalized: true,
        penalty: 25,
        rationale:
          "This host was not involved; isolating it disrupts a bystander.",
      },
    ]);

    expect(
      record.work.harmfulActions,
    ).toBe(1);

    expect(
      record.work.responsePenalty,
    ).toBe(25);
  });

  it("carries incident coverage and names what was missed", () => {
    // The objective and question numbers cannot separate an analyst who
    // scoped the intrusion from one who guessed the containment and stopped.
    // Coverage can, so the record has to carry it -- and the missed entities
    // with it, because "reached 2 of 3" means nothing without the which.
    const record = buildAssessmentRecord(
      createInput({
        coverage: {
          percentage: 67,
          entities: [
            {
              id: "FIN-LT-004",
              kind: "device",
              label: "FIN-LT-004",
              reached: true,
            },
            {
              id: "simone",
              kind: "account",
              label: "simone",
              reached: true,
            },
            {
              id: "203.0.113.10",
              kind: "address",
              label: "203.0.113.10",
              reached: false,
            },
          ],
          reached: [
            {
              id: "FIN-LT-004",
              kind: "device",
              label: "FIN-LT-004",
              reached: true,
            },
            {
              id: "simone",
              kind: "account",
              label: "simone",
              reached: true,
            },
          ],
          missed: [
            {
              id: "203.0.113.10",
              kind: "address",
              label: "203.0.113.10",
              reached: false,
            },
          ],
        } as unknown as AssessmentInput["coverage"],
      }),
    );

    expect(record.coverage).toEqual({
      percentage: 67,
      reached: 2,
      total: 3,
      missed: [
        {
          id: "203.0.113.10",
          kind: "address",
          label: "203.0.113.10",
        },
      ],
    });
  });

  it("omits coverage when the scenario has no ground truth", () => {
    // The hand-authored scenarios measure against nothing. A coverage block
    // of 100% over zero entities would read as a perfect score for reaching
    // nothing, so the field is absent rather than misleadingly full.
    const record = buildAssessmentRecord(
      createInput({
        coverage: {
          percentage: 100,
          entities: [],
          reached: [],
          missed: [],
        } as unknown as AssessmentInput["coverage"],
      }),
    );

    expect(record.coverage).toBeUndefined();
  });

  it("records which key incident events were captured and names the misses", () => {
    // The record has to carry whether the smoking guns were collected, not
    // only which entities were reached. A run that banked one of two key
    // events reports one captured and names the other.
    const record = buildAssessmentRecord(
      createInput({
        scenario: {
          id: "scenario-ke-001",
          name: "KE",
          groundTruth: {
            summary: "s",
            timeline: [
              {
                eventId: "evt-a",
                title: "Encoded PowerShell",
                significance: "x",
                techniqueId: "T1059.001",
              },
              {
                eventId: "evt-b",
                title: "C2 beacon",
                significance: "y",
                techniqueId: "T1071.001",
              },
            ],
          },
        } as unknown as AssessmentInput["scenario"],
        analystCase: {
          collectedEventIds: ["evt-a"],
          findings: [],
        } as unknown as AssessmentInput["analystCase"],
      }),
    );

    expect(record.keyEvidence).toEqual({
      captured: 1,
      total: 2,
      missed: [
        {
          eventId: "evt-b",
          title: "C2 beacon",
          techniqueId: "T1071.001",
          significance: "y",
        },
      ],
    });
  });

  it("omits key evidence when the scenario has no ground truth", () => {
    // The default fixture scenario declares none; the field is absent rather
    // than a captured-zero-of-zero that would read as a perfect miss.
    expect(
      buildAssessmentRecord(createInput())
        .keyEvidence,
    ).toBeUndefined();
  });

  it("omits coverage when none was supplied", () => {
    expect(
      buildAssessmentRecord(createInput())
        .coverage,
    ).toBeUndefined();
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
