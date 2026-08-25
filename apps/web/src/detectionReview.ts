import {
  DETECTION_RULES,
  buildCorpusRecords,
  evaluateRuleset,
  importSigmaRules,
  importKqlRules,
  importSplRules,
  importEqlRules,
} from "@endomorph/fabric";

import type {
  CorpusRecord,
  CoverageReport,
} from "@endomorph/fabric";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

/**
 * Scoring the shipped detection rules against the incident just worked.
 *
 * This is the one thing a generated corpus can do that a captured one
 * cannot. Because the generator planted every malicious event, a rule's true
 * positives, false positives and false negatives are computable rather than
 * estimated -- so "how good is this detection" has an exact answer here and
 * only an argument anywhere else.
 *
 * It is deliberately not available during the investigation. The labels are
 * the answer: a panel showing which events are malicious would end the
 * exercise the moment it was opened. It runs after finalizing, against the
 * same telemetry the analyst just worked by hand, which is what makes the
 * comparison worth anything -- the interesting column is the one where the
 * rules missed something the analyst found.
 */
export interface DetectionReview {
  readonly report: CoverageReport;
  readonly recordCount: number;
  readonly maliciousCount: number;
  readonly ruleCount: number;
}

/**
 * The labelled corpus for a scenario, built in the browser from the same
 * events the analyst worked. Extracted so both the shipped-ruleset review and
 * the bring-your-own-rule tester score against exactly the same records.
 */
export function buildScenarioCorpus(
  scenario: ScenarioDefinition,
): readonly CorpusRecord[] {
  const timeline =
    scenario.groundTruth?.timeline ?? [];

  const techniqueByEvent = new Map(
    timeline
      .filter((step) => step.techniqueId)
      .map((step) => [
        step.eventId,
        step.techniqueId as string,
      ]),
  );

  // Ground truth is the timeline, not a name prefix. The alert the detection
  // raised is part of the incident and carries no "incident-" id, so keying
  // on the prefix would label it benign and quietly change every number
  // below.
  const maliciousIds = new Set(
    timeline.map((step) => step.eventId),
  );

  const world = scenario.initialWorld;

  return buildCorpusRecords(
    {
      users: Object.values(world.users),
      accounts: Object.values(
        world.accounts,
      ),
      devices: Object.values(
        world.devices,
      ),
      files: Object.values(world.files),
    },
    scenario.openingEvents,
    (event) => ({
      malicious: maliciousIds.has(
        event.id,
      ),
      technique: techniqueByEvent.get(
        event.id,
      ),
    }),
  );
}

function maliciousCountOf(
  records: readonly CorpusRecord[],
): number {
  return records.filter(
    (record) =>
      record["label.malicious"],
  ).length;
}

export function reviewDetections(
  scenario: ScenarioDefinition,
): DetectionReview {
  const records =
    buildScenarioCorpus(scenario);

  return {
    report: evaluateRuleset(
      DETECTION_RULES,
      records,
    ),
    recordCount: records.length,
    maliciousCount:
      maliciousCountOf(records),
    ruleCount: DETECTION_RULES.length,
  };
}

/**
 * The result of scoring a pasted Sigma rule against this scenario's corpus.
 *
 * This is the detection-data pitch made interactive: the ground truth is
 * known, so a rule the user brings gets a precision and recall that are
 * counted, not estimated -- the thing a captured corpus cannot give them.
 * Rules the supported Sigma subset cannot express are reported with a reason
 * rather than dropped, because a rule that silently matches nothing looks
 * exactly like a rule that works.
 */
export interface CustomRuleReview {
  readonly report: CoverageReport;
  readonly recordCount: number;
  readonly maliciousCount: number;
  readonly imported: number;
  readonly skipped: readonly {
    readonly source: string;
    readonly reason: string;
  }[];
}

export function scoreSigmaAgainstCorpus(
  records: readonly CorpusRecord[],
  yaml: string,
): CustomRuleReview {
  const { rules, skipped } =
    importSigmaRules([
      { source: "pasted rule", yaml },
    ]);

  return {
    report: evaluateRuleset(
      rules,
      records,
    ),
    recordCount: records.length,
    maliciousCount:
      maliciousCountOf(records),
    imported: rules.length,
    skipped,
  };
}

export function scoreSigmaRule(
  scenario: ScenarioDefinition,
  yaml: string,
): CustomRuleReview {
  return scoreSigmaAgainstCorpus(
    buildScenarioCorpus(scenario),
    yaml,
  );
}

export function scoreKqlAgainstCorpus(
  records: readonly CorpusRecord[],
  query: string,
): CustomRuleReview {
  const { rules, skipped } =
    importKqlRules([
      { source: "pasted rule", query },
    ]);

  return {
    report: evaluateRuleset(
      rules,
      records,
    ),
    recordCount: records.length,
    maliciousCount:
      maliciousCountOf(records),
    imported: rules.length,
    skipped,
  };
}

export function scoreSplAgainstCorpus(
  records: readonly CorpusRecord[],
  query: string,
): CustomRuleReview {
  const { rules, skipped } =
    importSplRules([
      { source: "pasted rule", query },
    ]);

  return {
    report: evaluateRuleset(
      rules,
      records,
    ),
    recordCount: records.length,
    maliciousCount:
      maliciousCountOf(records),
    imported: rules.length,
    skipped,
  };
}

export function scoreEqlAgainstCorpus(
  records: readonly CorpusRecord[],
  query: string,
): CustomRuleReview {
  const { rules, skipped } =
    importEqlRules([
      { source: "pasted rule", query },
    ]);

  return {
    report: evaluateRuleset(
      rules,
      records,
    ),
    recordCount: records.length,
    maliciousCount:
      maliciousCountOf(records),
    imported: rules.length,
    skipped,
  };
}
