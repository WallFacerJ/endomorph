import type { CorpusRecord } from "./corpus.js";
import type { DetectionReport } from "./detectionReport.js";

/**
 * The labelled corpus as a graded eval set for generated detections.
 *
 * Ground truth known by construction is exactly what an eval needs: a candidate
 * detection -- written by a person, or by an LLM or an AI SOC agent -- can be
 * scored against the planted labels and graded pass/fail against a stated bar,
 * rather than judged by eye. This module is that grading layer.
 *
 * Two halves:
 *   - the *rubric* (`gradeReport`) turns a scored ruleset into a per-technique
 *     pass/fail scorecard against a recall/precision bar, so "did these
 *     detections work" has a single headline number;
 *   - the *task* (`stripLabels`, `buildTaskPrompt`) is what a detection agent is
 *     handed -- the telemetry with the answer removed, and the instruction --
 *     so its output can then be run back through the rubric.
 */

/** The bar a detection must clear on a technique to count as a pass. */
export interface EvalCriteria {
  /** Fraction of the technique's malicious events the rule must catch. */
  readonly minRecall: number;
  /** Fraction of the rule's hits that must be true, to reject noise. */
  readonly minPrecision: number;
}

export const DEFAULT_CRITERIA: EvalCriteria =
  {
    minRecall: 0.5,
    minPrecision: 0.1,
  };

export interface TechniqueGrade {
  readonly technique: string;
  readonly planId: string;
  readonly recall: number;
  readonly precision: number;
  readonly pass: boolean;
  readonly reason: string;
}

export interface EvalScorecard {
  readonly criteria: EvalCriteria;
  readonly techniques: readonly TechniqueGrade[];
  readonly passed: number;
  readonly total: number;
  readonly passRate: number;
}

/**
 * Grade a scored report against the criteria, one row per technique instance
 * (a technique appearing in two plans is two rows, as each plan is its own
 * detection problem). A covered technique passes when its best rule clears both
 * bars; an uncovered one fails outright.
 */
export function gradeReport(
  report: DetectionReport,
  criteria: EvalCriteria = DEFAULT_CRITERIA,
): EvalScorecard {
  const techniques: TechniqueGrade[] = [];

  for (const plan of report.plans) {
    for (const technique of plan.coveredTechniques) {
      // The rules the candidate tagged for this technique; grade on the best.
      const candidates = plan.rules.filter(
        (rule) =>
          rule.technique === technique,
      );

      const best = candidates.reduce<
        (typeof candidates)[number] | null
      >((chosen, rule) => {
        if (chosen === null) {
          return rule;
        }
        if (rule.recall !== chosen.recall) {
          return rule.recall > chosen.recall
            ? rule
            : chosen;
        }
        return rule.precision >
          chosen.precision
          ? rule
          : chosen;
      }, null);

      if (best === null) {
        // Covered by the corpus but no rule carries the tag: score it 0.
        techniques.push({
          technique,
          planId: plan.planId,
          recall: 0,
          precision: 0,
          pass: false,
          reason:
            "no rule is tagged for this technique",
        });
        continue;
      }

      const pass =
        best.recall >= criteria.minRecall &&
        best.precision >=
          criteria.minPrecision;

      techniques.push({
        technique,
        planId: plan.planId,
        recall: best.recall,
        precision: best.precision,
        pass,
        reason: pass
          ? "meets the bar"
          : best.recall < criteria.minRecall
            ? `recall ${best.recall.toFixed(2)} below ${criteria.minRecall}`
            : `precision ${best.precision.toFixed(2)} below ${criteria.minPrecision}`,
      });
    }

    for (const technique of plan.uncoveredTechniques) {
      techniques.push({
        technique,
        planId: plan.planId,
        recall: 0,
        precision: 0,
        pass: false,
        reason:
          "no rule detected this technique",
      });
    }
  }

  const passed = techniques.filter(
    (grade) => grade.pass,
  ).length;

  const total = techniques.length;

  return {
    criteria,
    techniques,
    passed,
    total,
    passRate:
      total > 0 ? passed / total : 0,
  };
}

/**
 * The telemetry as an agent should see it: every ground-truth `label.*` field
 * removed, so the answer is not sitting in the data the model is asked to
 * detect on.
 */
export function stripLabels(
  record: CorpusRecord,
): Record<string, unknown> {
  const stripped: Record<
    string,
    unknown
  > = {};

  for (const [key, value] of Object.entries(
    record,
  )) {
    if (!key.startsWith("label.")) {
      stripped[key] = value;
    }
  }

  return stripped;
}

export interface EvalTaskTechnique {
  readonly id: string;
  readonly name: string;
  readonly tactic: string;
}

/**
 * The instruction handed to a detection agent for one plan's telemetry: what
 * the data is, which techniques to write for, and how the output is scored.
 */
export function buildTaskPrompt(
  planName: string,
  telemetryFile: string,
  recordCount: number,
  techniques: readonly EvalTaskTechnique[],
): string {
  const list = techniques
    .map(
      (technique) =>
        `- ${technique.id} — ${technique.name} (${technique.tactic})`,
    )
    .join("\n");

  return `# Detection task: ${planName}

You are given ${recordCount} telemetry events (ECS-shaped NDJSON) in
\`${telemetryFile}\`, from an enterprise over several days. Most are benign
background activity; some belong to a single intrusion.

Write detection rules (Sigma) that identify the malicious activity for each of
these ATT&CK techniques:

${list}

Output one Sigma rule per technique, each tagged with its technique id (for
example \`tags: [attack.t1059.001]\`). Each rule is scored on precision and
recall against the known-malicious events: catch the technique without firing
on the benign look-alikes that share its shape.
`;
}
