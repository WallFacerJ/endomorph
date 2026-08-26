import {
  DETECTION_RULES,
  buildCorpusRecords,
  importSigmaRules,
  importKqlRules,
  importSplRules,
  importEqlRules,
  importEsqlRules,
  generateEnterprise,
  generateBackgroundActivity,
  generateIncident,
  buildCorpus,
  evaluateRuleset,
  ATTACK_PLANS,
} from "@endomorph/fabric";

import type {
  EvasionLevel,
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

export function scoreEsqlAgainstCorpus(
  records: readonly CorpusRecord[],
  query: string,
): CustomRuleReview {
  const { rules, skipped } =
    importEsqlRules([
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


/**
 * A corpus generated in the browser from a client-shaped profile -- the
 * digital-twin path. It runs the same deterministic pipeline the CLI's
 * single-plan mode does (`generateEnterprise` -> background -> incident ->
 * `buildCorpus`), so a detection engineer scores their rules against telemetry
 * shaped like their own estate, not the shipped Acme world. Fast enough to run
 * on the main thread (a full enterprise is tens of milliseconds).
 */
export interface ProfileCorpusOptions {
  readonly seed: number;
  readonly organizationName: string;
  readonly headcount: number;
  readonly domain: string;
  readonly planId: string;
  /** How hard the attacker is trying to evade. Defaults to "standard". */
  readonly evasion?: EvasionLevel;
}

export interface ProfileCorpusResult {
  readonly records: readonly CorpusRecord[];
  readonly maliciousCount: number;
  readonly organizationName: string;
  readonly sampleHost?: string;
  readonly sampleUser?: string;
}

export function generateProfileCorpus(
  options: ProfileCorpusOptions,
): ProfileCorpusResult {
  const enterprise = generateEnterprise({
    seed: options.seed,
    organizationName:
      options.organizationName,
    headcount: options.headcount,
    domain: options.domain,
  });

  const background =
    generateBackgroundActivity(
      enterprise,
      { days: 3 },
    );

  const incident = generateIncident(
    enterprise,
    {
      planId: options.planId,
      // generateIncident defaults evasion to "standard"; pass it through.
      evasion: options.evasion,
    },
  );

  const detection =
    incident.events[
      incident.events.length - 1
    ].timestamp;

  const events = [
    ...background.filter(
      (event) =>
        event.timestamp <= detection,
    ),
    ...incident.events,
  ].sort((left, right) =>
    left.timestamp.localeCompare(
      right.timestamp,
    ),
  );

  const corpus = buildCorpus(
    enterprise,
    events,
    incident,
  );

  const records = [...corpus.records];

  return {
    records,
    maliciousCount:
      corpus.manifest.maliciousCount,
    organizationName:
      enterprise.profile.organizationName,
    sampleHost: records.find(
      (record) => record["host.name"],
    )?.["host.name"],
    sampleUser: records.find(
      (record) => record["user.name"],
    )?.["user.name"],
  };
}

/**
 * ATT&CK coverage of the shipped ruleset across every intrusion.
 *
 * Runs the deterministic generator once, plays each attack plan against it, and
 * asks which techniques the shipped detections actually catch (recall > 0 on any
 * plan). This is the detection-posture-at-a-glance the coverage dashboard renders
 * -- computed from ground truth in the browser, not asserted.
 */
export interface TechniqueCoverage {
  readonly id: string;
  readonly name: string;
  readonly tactic: string;
  readonly covered: boolean;
  readonly detectingRules: readonly string[];
}

export interface TacticCoverage {
  readonly tactic: string;
  readonly covered: number;
  readonly total: number;
}

export interface AttackCoverage {
  readonly techniques: readonly TechniqueCoverage[];
  readonly tactics: readonly TacticCoverage[];
  readonly covered: number;
  readonly total: number;
}

const TACTIC_ORDER: readonly string[] = [
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
];

export function computeAttackCoverage(
  seed = 20260820,
): AttackCoverage {
  const enterprise = generateEnterprise({
    seed,
  });

  const background =
    generateBackgroundActivity(
      enterprise,
      { days: 3 },
    );

  const catalog = new Map<
    string,
    { name: string; tactic: string }
  >();

  const detecting = new Map<
    string,
    Set<string>
  >();

  for (const plan of ATTACK_PLANS) {
    for (const technique of plan.techniques) {
      if (!catalog.has(technique.id)) {
        catalog.set(technique.id, {
          name: technique.name,
          tactic: technique.tactic,
        });
      }
    }

    const incident = generateIncident(
      enterprise,
      { planId: plan.id },
    );

    const detection =
      incident.events[
        incident.events.length - 1
      ].timestamp;

    const events = [
      ...background.filter(
        (event) =>
          event.timestamp <= detection,
      ),
      ...incident.events,
    ].sort((left, right) =>
      left.timestamp.localeCompare(
        right.timestamp,
      ),
    );

    const corpus = buildCorpus(
      enterprise,
      events,
      incident,
    );

    for (const evaluation of evaluateRuleset(
      DETECTION_RULES,
      corpus.records,
    ).evaluations) {
      if (
        evaluation.recall > 0 &&
        evaluation.technique
      ) {
        const set =
          detecting.get(
            evaluation.technique,
          ) ?? new Set<string>();
        set.add(evaluation.ruleId);
        detecting.set(
          evaluation.technique,
          set,
        );
      }
    }
  }

  const techniques: TechniqueCoverage[] =
    [...catalog.entries()]
      .map(([id, meta]) => ({
        id,
        name: meta.name,
        tactic: meta.tactic,
        covered: detecting.has(id),
        detectingRules: [
          ...(detecting.get(id) ??
            new Set<string>()),
        ],
      }))
      .sort((left, right) => {
        const order =
          TACTIC_ORDER.indexOf(
            left.tactic,
          ) -
          TACTIC_ORDER.indexOf(
            right.tactic,
          );
        return order !== 0
          ? order
          : left.id.localeCompare(
              right.id,
            );
      });

  const tacticsPresent = [
    ...new Set(
      techniques.map((t) => t.tactic),
    ),
  ].sort(
    (a, b) =>
      TACTIC_ORDER.indexOf(a) -
      TACTIC_ORDER.indexOf(b),
  );

  const tactics: TacticCoverage[] =
    tacticsPresent.map((tactic) => {
      const inTactic = techniques.filter(
        (t) => t.tactic === tactic,
      );
      return {
        tactic,
        covered: inTactic.filter(
          (t) => t.covered,
        ).length,
        total: inTactic.length,
      };
    });

  return {
    techniques,
    tactics,
    covered: techniques.filter(
      (t) => t.covered,
    ).length,
    total: techniques.length,
  };
}