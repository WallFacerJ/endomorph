import {
  describe,
  expect,
  it,
} from "vitest";

import {
  buildCaseReport,
} from "./caseReport";

import type {
  CaseReportInput,
} from "./caseReport";

/**
 * The report is a pure function of case state, which is the point: it must
 * not be able to assert anything the console did not already show.
 */
function createInput(
  overrides: Partial<CaseReportInput> = {},
): CaseReportInput {
  return {
    scenario: {
      id: "scenario-test-001",
      name: "Test incident",
      description:
        "A scenario used to exercise the report.",
      questions: [
        {
          id: "q-one",
          prompt: "Which host?",
          accepted: ["FIN-LT-004"],
          surface: "endpoint",
          points: 100,
        },
      ],
    } as unknown as CaseReportInput["scenario"],

    state: {
      finalized: false,
      score: { percentage: 0 },
      outcome: {
        status: "in_progress",
        objectives: [
          {
            id: "objective-one",
            label: "Account disabled",
            description:
              "The credential cannot be reused.",
            met: false,
          },
        ],
      },
    } as unknown as CaseReportInput["state"],

    report: {
      phase: "triage",
      evidenceCount: 2,
      entityCount: 3,
      externalIndicators: [
        {
          kind: "address",
          value: "203.0.113.77",
        },
      ],
      openTasks: [
        {
          id: "task-one",
          title: "Isolate the host",
          owner: "Tier 2",
        },
      ],
      supportedHypotheses: [
        {
          id: "hypothesis-one",
          statement:
            "The account was phished.",
        },
      ],
      timeline: [
        {
          eventId: "event-one",
          timestamp:
            "2026-08-20T10:15:00Z",
          eventType: "PROCESS_STARTED",
          message: "powershell.exe ran",
        },
      ],
      decisions: [
        {
          id: "decision-one",
          summary: "Contain first",
          rationale:
            "The host is still beaconing.",
        },
      ],
    } as unknown as CaseReportInput["report"],

    questionAnswers: {
      "q-one": "FIN-LT-004",
    },

    questionScore: {
      earned: 0,
      available: 100,
    },

    formatTimestamp: (value) =>
      value ?? "—",

    ...overrides,
  };
}

describe("buildCaseReport", () => {
  it("writes the case out without inventing anything", () => {
    const report = buildCaseReport(
      createInput(),
    );

    expect(report).toContain(
      "# Test incident",
    );

    expect(report).toContain(
      "The account was phished.",
    );

    expect(report).toContain(
      "203.0.113.77",
    );

    expect(report).toContain(
      "powershell.exe ran",
    );

    expect(report).toContain(
      "Isolate the host",
    );

    expect(report).toContain(
      "Contain first",
    );
  });

  it("withholds the score until the run is finalized", () => {
    /*
      Before finalizing the score is not settled. Writing a number into a
      document people paste into tickets would give it a permanence it has
      not earned.
    */
    expect(
      buildCaseReport(createInput()),
    ).not.toContain(
      "Objective score",
    );

    const finalized = buildCaseReport(
      createInput({
        state: {
          finalized: true,
          score: { percentage: 75 },
          outcome: {
            status: "failed",
            objectives: [],
          },
        } as unknown as CaseReportInput["state"],
      }),
    );

    expect(finalized).toContain(
      "Objective score:** 75%",
    );

    expect(finalized).toContain(
      "0/100 points",
    );
  });

  it("omits sections the case has nothing for", () => {
    // An empty run should read as an empty case, not as a form with every
    // heading present and nothing under any of them.
    const empty = buildCaseReport(
      createInput({
        report: {
          phase: "triage",
          evidenceCount: 0,
          entityCount: 0,
          externalIndicators: [],
          openTasks: [],
          supportedHypotheses: [],
          timeline: [],
          decisions: [],
        } as unknown as CaseReportInput["report"],
        questionAnswers: {},
      }),
    );

    expect(empty).not.toContain(
      "## Evidence",
    );

    expect(empty).not.toContain(
      "## Hypotheses",
    );

    expect(empty).not.toContain(
      "## Investigation answers",
    );

    // The identity of the run survives either way.
    expect(empty).toContain(
      "# Test incident",
    );
  });

  it("names a harmful response and its penalty once finalized", () => {
    // A finalized run that isolated the wrong host should say so in the
    // document a reviewer reads, not only in the score. Mirrors the record.
    const report = buildCaseReport(
      createInput({
        scenario: {
          id: "scenario-test-001",
          name: "Test incident",
          description: "x",
          actions: [
            {
              id: "action-bad",
              label: "Isolate the wrong host",
              description: "",
              events: [],
              assessment: {
                penalty: 25,
                rationale:
                  "This host was a bystander.",
              },
            },
          ],
        } as unknown as CaseReportInput["scenario"],
        state: {
          finalized: true,
          score: { percentage: 75 },
          performedActionIds: [
            "action-bad",
          ],
          outcome: {
            status: "succeeded",
            objectives: [],
          },
        } as unknown as CaseReportInput["state"],
      }),
    );

    expect(report).toContain(
      "## Response quality",
    );

    expect(report).toContain(
      "Isolate the wrong host",
    );

    expect(report).toContain(
      "This host was a bystander.",
    );
  });

  it("reports coverage and lists the entities never reached", () => {
    const report = buildCaseReport(
      createInput({
        state: {
          finalized: true,
          score: { percentage: 100 },
          performedActionIds: [],
          outcome: {
            status: "succeeded",
            objectives: [],
          },
        } as unknown as CaseReportInput["state"],
        coverage: {
          percentage: 67,
          entities: [
            {},
            {},
            {},
          ],
          reached: [{}, {}],
          missed: [
            {
              id: "203.0.113.10",
              kind: "address",
              label: "203.0.113.10",
              reached: false,
            },
          ],
        } as unknown as CaseReportInput["coverage"],
      }),
    );

    expect(report).toContain(
      "Incident coverage:** reached 2 of 3 entities (67%)",
    );

    expect(report).toContain(
      "## Entities not reached",
    );

    expect(report).toContain(
      "203.0.113.10 (address)",
    );
  });

  it("tells the truth about reproducibility for a seeded scenario and an unseeded one", () => {
    // The footer used to promise identical replay for every scenario. The
    // hand-authored set records no seed and cannot make that promise, so the
    // document has to say which case it is rather than overclaim.
    const seeded = buildCaseReport(
      createInput({
        scenario: {
          id: "scenario-generated-x",
          name: "Gen",
          description: "x",
          provenance: {
            generator: "endomorph-fabric",
            seed: 4242,
          },
        } as unknown as CaseReportInput["scenario"],
      }),
    );

    expect(seeded).toContain(
      "(seed 4242). The same scenario and seed replay identically.",
    );

    const unseeded = buildCaseReport(
      createInput(),
    );

    expect(unseeded).toContain(
      "hand-authored and records no generation seed",
    );
  });

  it("records only questions that were actually answered", () => {
    const blank = buildCaseReport(
      createInput({
        questionAnswers: {
          "q-one": "   ",
        },
      }),
    );

    expect(blank).not.toContain(
      "## Investigation answers",
    );
  });
});
