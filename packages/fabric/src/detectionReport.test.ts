import {
  describe,
  expect,
  it,
} from "vitest";

import {
  compareToBaseline,
  summarise,
  type DetectionReport,
  type PlanReport,
} from "./detectionReport.js";

function plan(
  overrides: Partial<PlanReport> = {},
): PlanReport {
  return {
    planId: "p1",
    planName: "Plan one",
    recordCount: 100,
    maliciousCount: 5,
    coveredTechniques: ["T1059.001"],
    uncoveredTechniques: ["T1005"],
    rules: [
      {
        ruleId: "r1",
        technique: "T1059.001",
        truePositives: 2,
        falsePositives: 1,
        falseNegatives: 0,
        precision: 0.667,
        recall: 1,
      },
    ],
    ...overrides,
  };
}

const baseline: DetectionReport =
  summarise(1, 1, [plan()]);

describe("detection report", () => {
  it("totals coverage across plans", () => {
    const report = summarise(1, 2, [
      plan(),
      plan({
        planId: "p2",
        coveredTechniques: [
          "T1098",
          "T1087.002",
        ],
        uncoveredTechniques: [],
      }),
    ]);

    expect(
      report.totals.coveredTechniques,
    ).toBe(3);

    expect(
      report.totals.totalTechniques,
    ).toBe(4);
  });

  describe("baseline comparison", () => {
    it("reports a plan the baseline has never seen", () => {
      // Comparing only the plans the baseline knows about means a new
      // intrusion can be added with no coverage at all and the gate stays
      // silent -- the one moment someone most needs to be told.
      const result = compareToBaseline(
        baseline,
        summarise(1, 1, [
          plan(),
          plan({
            planId: "brand-new",
            coveredTechniques: [],
            uncoveredTechniques: [
              "T1566.001",
              "T1003.001",
            ],
            rules: [],
          }),
        ]),
      );

      expect(result.regressed).toBe(
        false,
      );

      expect(
        result.findings.filter(
          (finding) =>
            finding.planId ===
            "brand-new",
        ),
      ).toEqual([
        {
          severity: "notice",
          planId: "brand-new",
          message:
            "New plan, and no rule covers any of its 2 technique(s).",
        },
      ]);
    });

    it("reports no findings for an identical report", () => {
      const result = compareToBaseline(
        baseline,
        summarise(1, 1, [plan()]),
      );

      expect(result.findings).toEqual(
        [],
      );

      expect(result.regressed).toBe(
        false,
      );
    });

    it("fails when a technique loses coverage", () => {
      const result = compareToBaseline(
        baseline,
        summarise(1, 1, [
          plan({
            coveredTechniques: [],
            uncoveredTechniques: [
              "T1059.001",
              "T1005",
            ],
            rules: [],
          }),
        ]),
      );

      expect(result.regressed).toBe(
        true,
      );

      expect(
        result.findings.some(
          (finding) =>
            finding.message.includes(
              "T1059.001",
            ),
        ),
      ).toBe(true);
    });

    it("fails when a rule stops firing even if coverage holds", () => {
      // The failure a coverage count alone hides: another rule can cover
      // the same technique while a specific rule quietly dies.
      const result = compareToBaseline(
        baseline,
        summarise(1, 2, [
          plan({
            rules: [
              {
                ruleId: "r1",
                technique: "T1059.001",
                truePositives: 0,
                falsePositives: 0,
                falseNegatives: 2,
                precision: 0,
                recall: 0,
              },
              {
                ruleId: "r2",
                technique: "T1059.001",
                truePositives: 2,
                falsePositives: 0,
                falseNegatives: 0,
                precision: 1,
                recall: 1,
              },
            ],
          }),
        ]),
      );

      expect(result.regressed).toBe(
        true,
      );

      expect(
        result.findings.some(
          (finding) =>
            finding.message.includes(
              "r1",
            ),
        ),
      ).toBe(true);
    });

    it("fails when a plan disappears entirely", () => {
      const result = compareToBaseline(
        baseline,
        summarise(1, 1, []),
      );

      expect(result.regressed).toBe(
        true,
      );
    });

    it("reports new coverage as an improvement, not a failure", () => {
      const result = compareToBaseline(
        baseline,
        summarise(1, 1, [
          plan({
            coveredTechniques: [
              "T1059.001",
              "T1005",
            ],
            uncoveredTechniques: [],
          }),
        ]),
      );

      expect(result.regressed).toBe(
        false,
      );

      expect(
        result.findings.every(
          (finding) =>
            finding.severity ===
            "improvement",
        ),
      ).toBe(true);
    });

    it("does not fail on added false positives alone", () => {
      // Tightening recall at the cost of some noise is a trade an author
      // may be making deliberately; it is reported, not blocked.
      const result = compareToBaseline(
        baseline,
        summarise(1, 1, [
          plan({
            rules: [
              {
                ruleId: "r1",
                technique: "T1059.001",
                truePositives: 2,
                falsePositives: 40,
                falseNegatives: 0,
                precision: 0.048,
                recall: 1,
              },
            ],
          }),
        ]),
      );

      expect(result.regressed).toBe(
        false,
      );

      const noisier =
        result.findings.filter(
          (finding) =>
            finding.message.includes(
              "false positive",
            ),
        );

      expect(noisier.length).toBe(1);

      // Not blocked, and not called an improvement either. A rule that got
      // noisier reported as good news is worse than not reporting it: the
      // operator reads the word and stops looking.
      expect(noisier[0]?.severity).toBe(
        "notice",
      );
    });
  });
});
