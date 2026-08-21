import {
  describe,
  expect,
  it,
} from "vitest";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

import {
  buildCorpus,
  toNdjson,
} from "./corpus.js";

import {
  DETECTION_RULES,
  NAIVE_POWERSHELL_RULE,
  EXTERNAL_AUTH_SUCCESS_RULE,
  PASSWORD_SPRAY_RULE,
} from "./detectionLibrary.js";

import {
  evaluateRule,
  evaluateRuleset,
} from "./detection.js";

import {
  generateBackgroundActivity,
} from "./backgroundActivity.js";

import {
  generateEnterprise,
} from "./generateEnterprise.js";

import {
  generateIncident,
} from "./generateIncident.js";

const enterprise = generateEnterprise();

const background =
  generateBackgroundActivity(enterprise, {
    days: 2,
  });

function corpusFor(planId: string) {
  const incident = generateIncident(
    enterprise,
    { planId },
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

  return buildCorpus(
    enterprise,
    events,
    incident,
  );
}

const corpora = ATTACK_PLANS.map((plan) =>
  corpusFor(plan.id),
);

describe("corpus", () => {
  const corpus = corpora[0];

  it("labels ground truth by construction", () => {
    // The whole point: labels are known, not inferred. Every malicious
    // record traces to an event the generator planted.
    expect(
      corpus.manifest.maliciousCount,
    ).toBeGreaterThan(0);

    expect(
      corpus.manifest.benignCount,
    ).toBeGreaterThan(1000);

    for (const record of corpus.records) {
      expect(
        typeof record[
          "label.malicious"
        ],
      ).toBe("boolean");
    }
  });

  it("keeps malicious activity a tiny fraction of the corpus", () => {
    // A corpus where the attack is 20% of records teaches nothing about
    // finding it. Real ratios are fractions of a percent.
    expect(
      corpus.manifest.maliciousRatio,
    ).toBeLessThan(0.01);
  });

  it("maps every malicious record to a technique", () => {
    const malicious = corpus.records.filter(
      (record) =>
        record["label.malicious"],
    );

    const withTechnique =
      malicious.filter(
        (record) =>
          record["label.technique"],
      );

    // The closing alert carries no technique; every other step does.
    expect(
      withTechnique.length,
    ).toBeGreaterThanOrEqual(
      malicious.length - 1,
    );
  });

  it("enriches records with names, not just ids", () => {
    // A corpus of opaque ids cannot have readable detections written
    // against it.
    const withHost = corpus.records.filter(
      (record) => record["host.name"],
    );

    expect(
      withHost.length,
    ).toBeGreaterThan(0);

    for (const record of withHost.slice(
      0,
      50,
    )) {
      expect(
        record["host.name"],
      ).not.toMatch(/^device-/);
    }
  });

  it("uses ECS-shaped field names", () => {
    for (const record of corpus.records.slice(
      0,
      20,
    )) {
      expect(
        record["@timestamp"],
      ).toBeDefined();

      expect(
        record["event.type"],
      ).toBeDefined();
    }
  });

  it("serialises to valid newline-delimited JSON", () => {
    const lines = toNdjson(
      corpus.records.slice(0, 200),
    )
      .trim()
      .split("\n");

    expect(lines).toHaveLength(200);

    for (const line of lines) {
      expect(() =>
        JSON.parse(line),
      ).not.toThrow();
    }
  });

  it("is deterministic", () => {
    expect(
      corpusFor(ATTACK_PLANS[0].id)
        .manifest,
    ).toEqual(corpus.manifest);
  });
});

describe("detection evaluation", () => {
  it("fires every shipped rule on at least one plan", () => {
    // Regression. The encoded-PowerShell rule carried "\b" -- a backspace
    // character, not a word boundary -- so its regex could never match and
    // it silently detected nothing. A rule that never fires is the worst
    // failure mode in a detection pipeline because nothing errors.
    const firedSomewhere = new Set<string>();

    for (const corpus of corpora) {
      for (const evaluation of evaluateRuleset(
        DETECTION_RULES,
        corpus.records,
      ).evaluations) {
        if (evaluation.truePositives > 0) {
          firedSomewhere.add(
            evaluation.ruleId,
          );
        }
      }
    }

    const neverFired =
      DETECTION_RULES.filter(
        (rule) =>
          !firedSomewhere.has(rule.id),
      ).map((rule) => rule.id);

    expect(neverFired).toEqual([]);
  });

  it("quantifies a naive rule as low precision", () => {
    // "Alert on any PowerShell" is the canonical bad detection. The point
    // of a labelled corpus is that this is a number, not an opinion.
    const evaluation = evaluateRule(
      NAIVE_POWERSHELL_RULE,
      corpora[0].records,
    );

    expect(
      evaluation.falsePositives,
    ).toBeGreaterThan(20);

    expect(
      evaluation.precision,
    ).toBeLessThan(0.1);
  });

  it("shows the perimeter heuristic failing on an internal intrusion", () => {
    // external-auth-success catches the credential-compromise plan and is
    // blind to the service-account plan, which is the pedagogical claim of
    // the plan library expressed as a measurement.
    const external = corpora.find(
      (corpus) =>
        corpus.manifest.plan ===
        "credential-compromise",
    );

    const internal = corpora.find(
      (corpus) =>
        corpus.manifest.plan ===
        "service-account-abuse",
    );

    expect(
      evaluateRule(
        EXTERNAL_AUTH_SUCCESS_RULE,
        external!.records,
      ).truePositives,
    ).toBeGreaterThan(0);

    expect(
      evaluateRule(
        EXTERNAL_AUTH_SUCCESS_RULE,
        internal!.records,
      ).truePositives,
    ).toBe(0);
  });

  it("applies thresholds rather than firing per record", () => {
    const evaluation = evaluateRule(
      PASSWORD_SPRAY_RULE,
      corpora[0].records,
    );

    // Benign single failures are everywhere; only the burst fires.
    expect(
      evaluation.truePositives,
    ).toBeGreaterThan(0);

    expect(
      evaluation.precision,
    ).toBeGreaterThan(0.5);
  });

  it("does not blame a rule for techniques it never claimed", () => {
    const evaluation = evaluateRule(
      PASSWORD_SPRAY_RULE,
      corpora[1].records,
    );

    // The insider plan contains no password spraying, so recall against
    // nothing is vacuously perfect rather than zero.
    expect(evaluation.recall).toBe(1);
  });

  it("reports uncovered techniques", () => {
    const report = evaluateRuleset(
      DETECTION_RULES,
      corpora[0].records,
    );

    expect(
      report.coveredTechniques.length,
    ).toBeGreaterThan(0);

    // The starter ruleset is deliberately incomplete; gaps are the output.
    expect(
      report.uncoveredTechniques.length,
    ).toBeGreaterThan(0);

    for (const technique of report.uncoveredTechniques) {
      expect(
        report.coveredTechniques,
      ).not.toContain(technique);
    }
  });

  it("scores an empty ruleset as no coverage", () => {
    const report = evaluateRuleset(
      [],
      corpora[0].records,
    );

    expect(
      report.coveredTechniques,
    ).toEqual([]);

    expect(
      report.totalTruePositives,
    ).toBe(0);
  });
});
