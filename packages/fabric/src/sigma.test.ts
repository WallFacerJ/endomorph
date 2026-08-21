import {
  readdirSync,
  readFileSync,
} from "node:fs";

import {
  join,
} from "node:path";

import {
  describe,
  expect,
  it,
} from "vitest";

import {
  convertSigmaRule,
  importSigmaRules,
  SigmaUnsupportedError,
} from "./sigma.js";

import {
  evaluateRule,
} from "./detection.js";

import {
  buildCorpus,
} from "./corpus.js";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

import {
  generateBackgroundActivity,
} from "./backgroundActivity.js";

import {
  generateEnterprise,
} from "./generateEnterprise.js";

import {
  generateIncident,
} from "./generateIncident.js";

const RULES_DIR = join(
  __dirname,
  "..",
  "..",
  "..",
  "rules",
  "sigma",
);

const documents = readdirSync(RULES_DIR)
  .filter((name) =>
    name.endsWith(".yml"),
  )
  .map((name) => ({
    source: name,
    yaml: readFileSync(
      join(RULES_DIR, name),
      "utf8",
    ),
  }));

const enterprise = generateEnterprise();

const background =
  generateBackgroundActivity(enterprise, {
    days: 2,
  });

const corpora = ATTACK_PLANS.map((plan) => {
  const incident = generateIncident(
    enterprise,
    { planId: plan.id },
  );

  const detection =
    incident.events[
      incident.events.length - 1
    ].timestamp;

  return buildCorpus(
    enterprise,
    [
      ...background.filter(
        (event) =>
          event.timestamp <= detection,
      ),
      ...incident.events,
    ].sort((left, right) =>
      left.timestamp.localeCompare(
        right.timestamp,
      ),
    ),
    incident,
  );
});

describe("sigma import", () => {
  it("finds the shipped rule files", () => {
    expect(
      documents.length,
    ).toBeGreaterThan(3);
  });

  it("imports real Sigma YAML", () => {
    const result =
      importSigmaRules(documents);

    expect(
      result.rules.length,
    ).toBeGreaterThan(2);

    for (const rule of result.rules) {
      expect(rule.name.length).toBeGreaterThan(0);
      expect(
        rule.selections.length,
      ).toBeGreaterThan(0);
    }
  });

  it("collects failures rather than aborting the batch", () => {
    // A large public ruleset always contains constructs this subset does
    // not cover; one of them must not take the run down with it.
    const result =
      importSigmaRules(documents);

    expect(
      result.skipped.length,
    ).toBeGreaterThan(0);

    for (const skip of result.skipped) {
      expect(
        skip.reason.length,
      ).toBeGreaterThan(10);
    }
  });

  it("extracts the ATT&CK technique from tags", () => {
    const rule = convertSigmaRule({
      title: "t",
      detection: {
        selection: {
          CommandLine: "x",
        },
        condition: "selection",
      },
      tags: [
        "attack.execution",
        "attack.t1059.001",
      ],
    });

    expect(rule.technique).toBe(
      "T1059.001",
    );
  });

  it("translates Sigma field names to corpus fields", () => {
    const rule = convertSigmaRule({
      title: "t",
      detection: {
        selection: {
          "Image|endswith":
            "\\powershell.exe",
          "CommandLine|contains": "-enc",
        },
        condition: "selection",
      },
    });

    const fields = Object.keys(
      rule.selections[0],
    );

    expect(fields).toContain(
      "process.executable",
    );

    expect(fields).toContain(
      "process.command_line",
    );
  });

  it("turns a negated selection into an exclusion", () => {
    const rule = convertSigmaRule({
      title: "t",
      detection: {
        selection: {
          CommandLine: "a",
        },
        filter: { CommandLine: "b" },
        condition: "selection and not filter",
      },
    });

    expect(
      rule.exclusions,
    ).toHaveLength(1);
  });

  describe("refuses what it cannot express", () => {
    // Every one of these would otherwise produce a rule that matches
    // nothing while looking like coverage.
    it("rejects aggregations", () => {
      expect(() =>
        convertSigmaRule({
          title: "t",
          detection: {
            selection: {
              CommandLine: "a",
            },
            condition:
              "selection | count() by User > 5",
          },
        }),
      ).toThrow(
        SigmaUnsupportedError,
      );
    });

    it("rejects disjunctions across selections", () => {
      expect(() =>
        convertSigmaRule({
          title: "t",
          detection: {
            a: { CommandLine: "x" },
            b: { CommandLine: "y" },
            condition: "a or b",
          },
        }),
      ).toThrow(
        SigmaUnsupportedError,
      );
    });

    it("rejects an unmapped field", () => {
      expect(() =>
        convertSigmaRule({
          title: "t",
          detection: {
            selection: {
              SomeVendorField: "x",
            },
            condition: "selection",
          },
        }),
      ).toThrow(/Unmapped Sigma field/);
    });

    it("rejects an unsupported modifier", () => {
      expect(() =>
        convertSigmaRule({
          title: "t",
          detection: {
            selection: {
              "CommandLine|base64offset":
                "x",
            },
            condition: "selection",
          },
        }),
      ).toThrow(
        SigmaUnsupportedError,
      );
    });

    it("rejects a condition naming an unknown selection", () => {
      expect(() =>
        convertSigmaRule({
          title: "t",
          detection: {
            selection: {
              CommandLine: "x",
            },
            condition: "nonexistent",
          },
        }),
      ).toThrow(
        SigmaUnsupportedError,
      );
    });
  });

  it("fires every imported rule against at least one corpus", () => {
    // The guarantee that matters: an imported rule that silently matches
    // nothing is indistinguishable from coverage until an incident is
    // missed.
    const { rules } =
      importSigmaRules(documents);

    const fired = new Set<string>();

    for (const corpus of corpora) {
      for (const rule of rules) {
        if (
          evaluateRule(
            rule,
            corpus.records,
          ).truePositives > 0
        ) {
          fired.add(rule.id);
        }
      }
    }

    expect(
      rules
        .filter(
          (rule) => !fired.has(rule.id),
        )
        .map((rule) => rule.id),
    ).toEqual([]);
  });

  it("scores imported rules against known ground truth", () => {
    const { rules } =
      importSigmaRules(documents);

    const powershell = rules.find(
      (rule) =>
        rule.technique === "T1059.001",
    );

    expect(powershell).toBeDefined();

    const evaluation = evaluateRule(
      powershell!,
      corpora[0].records,
    );

    // Precision is computable here rather than estimated, which is the
    // entire argument for generating the corpus.
    expect(
      evaluation.truePositives,
    ).toBeGreaterThan(0);

    expect(
      evaluation.precision,
    ).toBe(1);
  });
});
