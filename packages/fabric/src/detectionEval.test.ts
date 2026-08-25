import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  DetectionReport,
  PlanReport,
} from "./detectionReport.js";

import type { CorpusRecord } from "./corpus.js";

import {
  buildTaskPrompt,
  gradeReport,
  stripLabels,
} from "./detectionEval.js";

function report(
  plans: readonly PlanReport[],
): DetectionReport {
  return {
    generator: "test",
    seed: 1,
    ruleCount: 1,
    plans: [...plans],
    totals: {
      coveredTechniques: 0,
      totalTechniques: 0,
      truePositives: 0,
      falsePositives: 0,
    },
  };
}

function plan(
  over: Partial<PlanReport>,
): PlanReport {
  return {
    planId: "p1",
    planName: "Plan One",
    recordCount: 100,
    maliciousCount: 2,
    coveredTechniques: [],
    uncoveredTechniques: [],
    rules: [],
    ...over,
  };
}

describe("gradeReport", () => {
  it("passes a covered technique that clears both bars and fails an uncovered one", () => {
    const scorecard = gradeReport(
      report([
        plan({
          coveredTechniques: ["T1059.001"],
          uncoveredTechniques: ["T1005"],
          rules: [
            {
              ruleId: "r1",
              technique: "T1059.001",
              truePositives: 1,
              falsePositives: 0,
              falseNegatives: 0,
              precision: 1,
              recall: 1,
            },
          ],
        }),
      ]),
    );

    expect(scorecard.total).toBe(2);
    expect(scorecard.passed).toBe(1);
    expect(scorecard.passRate).toBe(0.5);

    const uncovered =
      scorecard.techniques.find(
        (grade) =>
          grade.technique === "T1005",
      );
    expect(uncovered?.pass).toBe(false);
    expect(uncovered?.reason).toMatch(
      /no rule detected/i,
    );
  });

  it("fails a noisy rule on the precision bar", () => {
    const scorecard = gradeReport(
      report([
        plan({
          coveredTechniques: ["T1071.001"],
          rules: [
            {
              ruleId: "noisy",
              technique: "T1071.001",
              truePositives: 2,
              falsePositives: 1000,
              falseNegatives: 0,
              precision: 0.002,
              recall: 1,
            },
          ],
        }),
      ]),
      { minRecall: 0.5, minPrecision: 0.1 },
    );

    const grade =
      scorecard.techniques[0];
    expect(grade.pass).toBe(false);
    expect(grade.reason).toMatch(
      /precision/i,
    );
  });

  it("fails a rule that misses too much on the recall bar", () => {
    const scorecard = gradeReport(
      report([
        plan({
          coveredTechniques: ["T1110.003"],
          rules: [
            {
              ruleId: "thin",
              technique: "T1110.003",
              truePositives: 1,
              falsePositives: 0,
              falseNegatives: 4,
              precision: 1,
              recall: 0.2,
            },
          ],
        }),
      ]),
    );

    expect(
      scorecard.techniques[0].pass,
    ).toBe(false);
    expect(
      scorecard.techniques[0].reason,
    ).toMatch(/recall/i);
  });

  it("grades on the best of several rules tagged for one technique", () => {
    const scorecard = gradeReport(
      report([
        plan({
          coveredTechniques: ["T1059.001"],
          rules: [
            {
              ruleId: "weak",
              technique: "T1059.001",
              truePositives: 0,
              falsePositives: 0,
              falseNegatives: 1,
              precision: 0,
              recall: 0,
            },
            {
              ruleId: "strong",
              technique: "T1059.001",
              truePositives: 1,
              falsePositives: 0,
              falseNegatives: 0,
              precision: 1,
              recall: 1,
            },
          ],
        }),
      ]),
    );

    expect(
      scorecard.techniques[0].pass,
    ).toBe(true);
  });
});

describe("stripLabels", () => {
  it("removes every label.* field and keeps the rest", () => {
    const record = {
      "event.id": "e1",
      "event.type": "PROCESS_STARTED",
      "process.command_line": "powershell -enc AAA",
      "label.malicious": true,
      "label.technique": "T1059.001",
      "label.plan": "p1",
    } as unknown as CorpusRecord;

    const stripped = stripLabels(record);

    expect(stripped["event.type"]).toBe(
      "PROCESS_STARTED",
    );
    expect(
      "label.malicious" in stripped,
    ).toBe(false);
    expect(
      "label.technique" in stripped,
    ).toBe(false);
  });
});

describe("buildTaskPrompt", () => {
  it("names the file and lists each technique", () => {
    const prompt = buildTaskPrompt(
      "Encoded PowerShell run",
      "p1.telemetry.ndjson",
      4738,
      [
        {
          id: "T1059.001",
          name: "PowerShell",
          tactic: "execution",
        },
      ],
    );

    expect(prompt).toContain(
      "p1.telemetry.ndjson",
    );
    expect(prompt).toContain("4738");
    expect(prompt).toContain("T1059.001");
    expect(prompt).toContain("Sigma");
  });
});
