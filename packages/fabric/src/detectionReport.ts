import type {
  CoverageReport,
} from "./detection.js";

/**
 * Machine-readable evaluation output, and regression comparison against a
 * committed baseline.
 *
 * A printed table tells you how a ruleset performs today. A baseline tells
 * you whether today is worse than yesterday, which is the question that
 * matters once rules are under version control: editing a rule to catch one
 * technique routinely stops it catching another, and nothing surfaces that
 * until an incident is missed.
 *
 * Because the corpus is generated from a seed, the comparison is exact. Two
 * runs of the same seed produce identical numbers, so any difference is
 * attributable to a rule change rather than to sampling.
 */

export interface PlanReport {
  readonly planId: string;
  readonly planName: string;
  readonly recordCount: number;
  readonly maliciousCount: number;
  readonly coveredTechniques: readonly string[];
  readonly uncoveredTechniques: readonly string[];
  readonly rules: readonly {
    readonly ruleId: string;
    readonly technique?: string;
    readonly truePositives: number;
    readonly falsePositives: number;
    readonly falseNegatives: number;
    readonly precision: number;
    readonly recall: number;
  }[];
}

export interface DetectionReport {
  readonly generator: string;
  readonly seed: number;
  readonly ruleCount: number;
  readonly plans: readonly PlanReport[];
  readonly totals: {
    readonly coveredTechniques: number;
    readonly totalTechniques: number;
    readonly truePositives: number;
    readonly falsePositives: number;
  };
}

export function buildPlanReport(
  planId: string,
  planName: string,
  recordCount: number,
  maliciousCount: number,
  coverage: CoverageReport,
): PlanReport {
  return {
    planId,
    planName,
    recordCount,
    maliciousCount,
    coveredTechniques: [
      ...coverage.coveredTechniques,
    ],
    uncoveredTechniques: [
      ...coverage.uncoveredTechniques,
    ],
    rules: coverage.evaluations
      .filter(
        (evaluation) =>
          evaluation.matched > 0 ||
          evaluation.falseNegatives > 0,
      )
      .map((evaluation) => ({
        ruleId: evaluation.ruleId,
        technique: evaluation.technique,
        truePositives:
          evaluation.truePositives,
        falsePositives:
          evaluation.falsePositives,
        falseNegatives:
          evaluation.falseNegatives,
        precision: evaluation.precision,
        recall: evaluation.recall,
      })),
  };
}

export function summarise(
  seed: number,
  ruleCount: number,
  plans: readonly PlanReport[],
): DetectionReport {
  return {
    generator: "endomorph-fabric",
    seed,
    ruleCount,
    plans: [...plans],
    totals: {
      coveredTechniques: plans.reduce(
        (total, plan) =>
          total +
          plan.coveredTechniques.length,
        0,
      ),
      totalTechniques: plans.reduce(
        (total, plan) =>
          total +
          plan.coveredTechniques.length +
          plan.uncoveredTechniques
            .length,
        0,
      ),
      truePositives: plans.reduce(
        (total, plan) =>
          total +
          plan.rules.reduce(
            (sum, rule) =>
              sum + rule.truePositives,
            0,
          ),
        0,
      ),
      falsePositives: plans.reduce(
        (total, plan) =>
          total +
          plan.rules.reduce(
            (sum, rule) =>
              sum + rule.falsePositives,
            0,
          ),
        0,
      ),
    },
  };
}

export type RegressionSeverity =
  | "regression"
  | "improvement";

export interface RegressionFinding {
  readonly severity: RegressionSeverity;
  readonly planId: string;
  readonly message: string;
}

export interface RegressionResult {
  readonly findings: readonly RegressionFinding[];
  readonly regressed: boolean;
}

/**
 * Compares a report against a baseline.
 *
 * Losing coverage of a technique is a regression. So is a rule that used to
 * fire and no longer does, which is the failure mode a coverage count alone
 * hides: overall coverage can hold steady while a specific rule quietly
 * dies, because another rule happens to cover the same technique.
 *
 * A rise in false positives is reported but does not fail, because tightening
 * recall at the cost of some noise is a legitimate trade an author may be
 * making deliberately.
 */
export function compareToBaseline(
  baseline: DetectionReport,
  current: DetectionReport,
): RegressionResult {
  const findings: RegressionFinding[] =
    [];

  const currentPlans = new Map(
    current.plans.map((plan) => [
      plan.planId,
      plan,
    ]),
  );

  for (const basePlan of baseline.plans) {
    const plan = currentPlans.get(
      basePlan.planId,
    );

    if (!plan) {
      findings.push({
        severity: "regression",
        planId: basePlan.planId,
        message:
          "Plan is missing from the current report.",
      });

      continue;
    }

    const covered = new Set(
      plan.coveredTechniques,
    );

    for (const technique of basePlan.coveredTechniques) {
      if (!covered.has(technique)) {
        findings.push({
          severity: "regression",
          planId: plan.planId,
          message: `Lost coverage of ${technique}.`,
        });
      }
    }

    const baseCovered = new Set(
      basePlan.coveredTechniques,
    );

    for (const technique of plan.coveredTechniques) {
      if (!baseCovered.has(technique)) {
        findings.push({
          severity: "improvement",
          planId: plan.planId,
          message: `Gained coverage of ${technique}.`,
        });
      }
    }

    const currentRules = new Map(
      plan.rules.map((rule) => [
        rule.ruleId,
        rule,
      ]),
    );

    for (const baseRule of basePlan.rules) {
      if (
        baseRule.truePositives === 0
      ) {
        continue;
      }

      const rule = currentRules.get(
        baseRule.ruleId,
      );

      if (
        !rule ||
        rule.truePositives === 0
      ) {
        findings.push({
          severity: "regression",
          planId: plan.planId,
          message: `Rule ${baseRule.ruleId} no longer fires here; it previously had ${baseRule.truePositives} true positive(s).`,
        });

        continue;
      }

      if (
        rule.falsePositives >
        baseRule.falsePositives
      ) {
        findings.push({
          severity: "improvement",
          planId: plan.planId,
          message: `Rule ${baseRule.ruleId} gained ${rule.falsePositives - baseRule.falsePositives} false positive(s); precision ${baseRule.precision} to ${rule.precision}.`,
        });
      }
    }
  }

  // A plan the baseline has never seen is reported rather than passed over.
  // Comparing only the plans the baseline knows about means a new intrusion
  // can be added with no coverage at all and the gate stays silent, which is
  // the one moment someone most needs to be told.
  const baselinePlans = new Set(
    baseline.plans.map(
      (plan) => plan.planId,
    ),
  );

  for (const plan of current.plans) {
    if (baselinePlans.has(plan.planId)) {
      continue;
    }

    findings.push({
      severity: "improvement",
      planId: plan.planId,
      message:
        plan.coveredTechniques.length === 0
          ? `New plan, and no rule covers any of its ${plan.uncoveredTechniques.length} technique(s).`
          : `New plan, covering ${plan.coveredTechniques.length} of ${
              plan.coveredTechniques.length +
              plan.uncoveredTechniques.length
            } technique(s).`,
    });
  }

  return {
    findings,
    regressed: findings.some(
      (finding) =>
        finding.severity ===
        "regression",
    ),
  };
}
