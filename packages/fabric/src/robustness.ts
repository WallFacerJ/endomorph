import type {
  DetectionReport,
} from "./detectionReport.js";

/**
 * Does a detection rule generalise, or did it memorise one enterprise?
 *
 * A single evaluation scores a rule against one generated world. That number
 * is worth much less than it looks, because a rule keyed on the exact address
 * an intrusion happened to sign in from will score a flawless recall on that
 * world and catch nothing on the next one -- and a captured corpus, having
 * exactly one world, can never tell the two apart. This is the measurement no
 * fixed dataset can make: run the same rule against many seeded enterprises,
 * where the staff, hosts, and addresses all change while the technique stays
 * the same, and watch whether the score holds.
 *
 * A rule that catches its technique on every seed is detecting behaviour. One
 * whose recall collapses to zero on some seeds is detecting a coincidence of
 * this repository. The verdict names which.
 */

export type RobustnessVerdict =
  | "stable"
  | "variable"
  | "fragile";

export interface RuleRobustness {
  readonly ruleId: string;

  readonly technique?: string;

  /** Seeds the rule was evaluated against. */
  readonly seeds: number;

  /** Seeds on which it caught any real malicious activity (a true positive). */
  readonly detectedOn: number;

  /** The rule's best per-seed recall, summarised across seeds. */
  readonly recall: {
    readonly min: number;
    readonly mean: number;
    readonly max: number;
  };

  /** Total false positives per seed, summarised across seeds. */
  readonly falsePositives: {
    readonly mean: number;
    readonly max: number;
  };

  readonly verdict: RobustnessVerdict;
}

export interface TechniqueRobustness {
  readonly technique: string;

  readonly coveredSeeds: number;

  readonly seeds: number;

  readonly coveredOnEverySeed: boolean;
}

export interface RobustnessSummary {
  readonly generator: string;

  readonly seeds: readonly number[];

  readonly rules: readonly RuleRobustness[];

  readonly techniques: readonly TechniqueRobustness[];
}

/** Recall spread above which a rule that always fires is still called variable. */
const VARIABLE_RECALL_SPREAD = 0.34;

function mean(values: readonly number[]): number {
  return values.length === 0
    ? 0
    : values.reduce(
        (sum, value) => sum + value,
        0,
      ) / values.length;
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

interface PerSeedRuleFacts {
  bestRecall: number;
  totalTruePositives: number;
  totalFalsePositives: number;
  technique?: string;
}

/**
 * Collapses one seed's per-plan rows for a rule into the facts robustness
 * cares about: the best recall it reached on any plan that carried its
 * technique, and the malicious/false traffic it matched across all plans.
 */
function factsForRule(
  report: DetectionReport,
  ruleId: string,
): PerSeedRuleFacts | undefined {
  let seen = false;
  const facts: PerSeedRuleFacts = {
    bestRecall: 0,
    totalTruePositives: 0,
    totalFalsePositives: 0,
  };

  for (const plan of report.plans) {
    for (const rule of plan.rules) {
      if (rule.ruleId !== ruleId) {
        continue;
      }

      seen = true;
      facts.technique = rule.technique;
      facts.bestRecall = Math.max(
        facts.bestRecall,
        rule.recall,
      );
      facts.totalTruePositives +=
        rule.truePositives;
      facts.totalFalsePositives +=
        rule.falsePositives;
    }
  }

  return seen ? facts : undefined;
}

function classify(
  detectedOn: number,
  seeds: number,
  recallMin: number,
  recallMax: number,
): RobustnessVerdict {
  // Missing the technique on even one enterprise is the fragility that
  // matters: the rule is leaning on something this world happened to have.
  if (detectedOn < seeds) {
    return "fragile";
  }

  if (
    recallMax - recallMin >
    VARIABLE_RECALL_SPREAD
  ) {
    return "variable";
  }

  return "stable";
}

export function summariseRobustness(
  reports: readonly DetectionReport[],
): RobustnessSummary {
  const seeds = reports.map(
    (report) => report.seed,
  );

  // Every rule id that appears in any seed, in first-seen order for a stable
  // table.
  const ruleIds: string[] = [];
  const ruleSeen = new Set<string>();

  for (const report of reports) {
    for (const plan of report.plans) {
      for (const rule of plan.rules) {
        if (!ruleSeen.has(rule.ruleId)) {
          ruleSeen.add(rule.ruleId);
          ruleIds.push(rule.ruleId);
        }
      }
    }
  }

  const rules: RuleRobustness[] =
    ruleIds.map((ruleId) => {
      const recalls: number[] = [];
      const falsePositives: number[] =
        [];
      let detectedOn = 0;
      let technique: string | undefined;

      for (const report of reports) {
        const facts = factsForRule(
          report,
          ruleId,
        );

        if (!facts) {
          // The rule was not evaluated this seed at all: count it as a miss
          // rather than skipping, since inconsistent presence is itself
          // fragility.
          recalls.push(0);
          falsePositives.push(0);
          continue;
        }

        technique =
          technique ?? facts.technique;
        recalls.push(facts.bestRecall);
        falsePositives.push(
          facts.totalFalsePositives,
        );

        if (
          facts.totalTruePositives > 0
        ) {
          detectedOn += 1;
        }
      }

      const recallMin = Math.min(
        ...recalls,
      );
      const recallMax = Math.max(
        ...recalls,
      );

      return {
        ruleId,
        ...(technique
          ? { technique }
          : {}),
        seeds: reports.length,
        detectedOn,
        recall: {
          min: round(recallMin),
          mean: round(mean(recalls)),
          max: round(recallMax),
        },
        falsePositives: {
          mean: round(
            mean(falsePositives),
          ),
          max: Math.max(
            ...falsePositives,
          ),
        },
        verdict: classify(
          detectedOn,
          reports.length,
          recallMin,
          recallMax,
        ),
      };
    });

  // Technique coverage across seeds: a technique covered on every seed is one
  // the ruleset can be trusted to catch whatever the enterprise looks like.
  const techniqueSeedCounts = new Map<
    string,
    number
  >();

  for (const report of reports) {
    const covered = new Set<string>();

    for (const plan of report.plans) {
      for (const technique of plan.coveredTechniques) {
        covered.add(technique);
      }
    }

    for (const technique of covered) {
      techniqueSeedCounts.set(
        technique,
        (techniqueSeedCounts.get(
          technique,
        ) ?? 0) + 1,
      );
    }
  }

  const techniques: TechniqueRobustness[] =
    [...techniqueSeedCounts.entries()]
      .sort(([left], [right]) =>
        left.localeCompare(right),
      )
      .map(([technique, count]) => ({
        technique,
        coveredSeeds: count,
        seeds: reports.length,
        coveredOnEverySeed:
          count === reports.length,
      }));

  return {
    generator: "endomorph-fabric",
    seeds,
    rules,
    techniques,
  };
}
