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
