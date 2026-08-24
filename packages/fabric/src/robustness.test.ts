import {
  describe,
  expect,
  it,
} from "vitest";

import {
  summariseRobustness,
} from "./robustness.js";

import type {
  DetectionReport,
} from "./detectionReport.js";

/**
 * One seed's report with a single plan carrying one rule at a chosen recall
 * and true/false positive count. Enough to drive the aggregation without
 * running the generator.
 */
function seedReport(
  seed: number,
  rule: {
    ruleId: string;
    technique: string;
    recall: number;
    truePositives: number;
    falsePositives?: number;
  },
): DetectionReport {
  return {
    generator: "endomorph-fabric",
    seed,
    ruleCount: 1,
    plans: [
      {
        planId: "plan-a",
        planName: "Plan A",
        recordCount: 100,
        maliciousCount: 5,
        coveredTechniques:
          rule.truePositives > 0
            ? [rule.technique]
            : [],
        uncoveredTechniques:
          rule.truePositives > 0
            ? []
            : [rule.technique],
        rules: [
          {
            ruleId: rule.ruleId,
            technique: rule.technique,
            truePositives:
              rule.truePositives,
            falsePositives:
              rule.falsePositives ?? 0,
            falseNegatives: 0,
            precision: 1,
            recall: rule.recall,
          },
        ],
      },
    ],
    totals: {
      coveredTechniques: 1,
      totalTechniques: 1,
      truePositives: rule.truePositives,
      falsePositives:
        rule.falsePositives ?? 0,
    },
  };
}

describe("summariseRobustness", () => {
  it("calls a rule that always catches its technique stable", () => {
    const summary = summariseRobustness([
      seedReport(1, {
        ruleId: "auth-spray",
        technique: "T1110.003",
        recall: 1,
        truePositives: 4,
      }),
      seedReport(2, {
        ruleId: "auth-spray",
        technique: "T1110.003",
        recall: 1,
        truePositives: 4,
      }),
      seedReport(3, {
        ruleId: "auth-spray",
        technique: "T1110.003",
        recall: 1,
        truePositives: 5,
      }),
    ]);

    const rule = summary.rules[0];

    expect(rule.verdict).toBe("stable");
    expect(rule.detectedOn).toBe(3);
    expect(rule.recall.min).toBe(1);
  });

  it("calls a rule that misses on some seeds fragile", () => {
    // The signature of overfitting: full recall where the world happens to
    // suit it, nothing where it does not.
    const summary = summariseRobustness([
      seedReport(1, {
        ruleId: "c2-exact-ip",
        technique: "T1071.001",
        recall: 1,
        truePositives: 3,
      }),
      seedReport(2, {
        ruleId: "c2-exact-ip",
        technique: "T1071.001",
        recall: 0,
        truePositives: 0,
      }),
      seedReport(3, {
        ruleId: "c2-exact-ip",
        technique: "T1071.001",
        recall: 1,
        truePositives: 3,
      }),
    ]);

    const rule = summary.rules[0];

    expect(rule.verdict).toBe("fragile");
    expect(rule.detectedOn).toBe(2);
    expect(rule.recall.min).toBe(0);
  });

  it("calls a rule that always fires but at swinging recall variable", () => {
    const summary = summariseRobustness([
      seedReport(1, {
        ruleId: "partial",
        technique: "T1059.001",
        recall: 1,
        truePositives: 3,
      }),
      seedReport(2, {
        ruleId: "partial",
        technique: "T1059.001",
        recall: 0.5,
        truePositives: 1,
      }),
    ]);

    const rule = summary.rules[0];

    expect(rule.verdict).toBe(
      "variable",
    );
    expect(rule.detectedOn).toBe(2);
  });

  it("reports which techniques are covered on every seed", () => {
    const summary = summariseRobustness([
      seedReport(1, {
        ruleId: "r",
        technique: "T1110.003",
        recall: 1,
        truePositives: 4,
      }),
      seedReport(2, {
        ruleId: "r",
        technique: "T1110.003",
        recall: 0,
        truePositives: 0,
      }),
    ]);

    const technique =
      summary.techniques.find(
        (entry) =>
          entry.technique ===
          "T1110.003",
      );

    expect(
      technique?.coveredSeeds,
    ).toBe(1);
    expect(
      technique?.coveredOnEverySeed,
    ).toBe(false);
  });

  it("averages false positives across seeds", () => {
    const summary = summariseRobustness([
      seedReport(1, {
        ruleId: "noisy",
        technique: "T1005",
        recall: 1,
        truePositives: 2,
        falsePositives: 10,
      }),
      seedReport(2, {
        ruleId: "noisy",
        technique: "T1005",
        recall: 1,
        truePositives: 2,
        falsePositives: 20,
      }),
    ]);

    const rule = summary.rules[0];

    expect(
      rule.falsePositives.mean,
    ).toBe(15);
    expect(
      rule.falsePositives.max,
    ).toBe(20);
  });
});
