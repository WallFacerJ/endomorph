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

describe("SigmaHQ idiom compatibility", () => {
  // Rules written in genuine SigmaHQ style rather than tailored to this
  // importer, so the supported-construct claim is measured rather than
  // asserted. Two are deliberately beyond the data model.
  const compatDir = join(
    __dirname,
    "..",
    "..",
    "..",
    "rules",
    "sigma-compat",
  );

  const compatDocs = readdirSync(
    compatDir,
  )
    .filter((name) =>
      name.endsWith(".yml"),
    )
    .map((name) => ({
      source: name,
      yaml: readFileSync(
        join(compatDir, name),
        "utf8",
      ),
    }));

  it("imports every idiomatic rule the data model can express", () => {
    const result =
      importSigmaRules(compatDocs);

    // Pin the refused set, not merely its size. A count alone lets the set
    // drift: one rule could start importing while another stopped, the total
    // would hold, and the documented claim would quietly be false.
    expect(result.skipped).toEqual([]);

    expect(result.rules).toHaveLength(
      compatDocs.length,
    );
  });

  it("supports a value list combined with a modifier", () => {
    // A YAML sequence under a modifier is one of the most common constructs
    // in published rules, and an OR over the same field.
    const rule = convertSigmaRule({
      title: "t",
      detection: {
        selection: {
          "Image|endswith": [
            "net.exe",
            "whoami.exe",
          ],
        },
        condition: "selection",
      },
    });

    const matcher =
      rule.selections[0][
        "process.executable"
      ];

    expect(
      JSON.stringify(matcher),
    ).toContain("anyOf");
  });

  it("supports 1 of selection_*", () => {
    const rule = convertSigmaRule({
      title: "t",
      detection: {
        selection_a: {
          CommandLine: "a",
        },
        selection_b: {
          CommandLine: "b",
        },
        condition: "1 of selection_*",
      },
    });

    expect(
      rule.anySelections,
    ).toHaveLength(2);

    expect(rule.selections).toHaveLength(
      0,
    );
  });

  it("refuses a condition that constrains nothing", () => {
    // "1 of them" with no search identifiers left selections empty and
    // alternatives empty, and an empty every() is true -- so the rule
    // matched every record in the corpus. A rule matching everything is
    // worse than one matching nothing: it looks like total coverage.
    expect(() =>
      convertSigmaRule({
        title: "t",
        detection: {
          timeframe: "5m",
          condition: "1 of them",
        },
      }),
    ).toThrow(/selects nothing/);
  });

  it("refuses an empty value list", () => {
    // Same class: {anyOf: []} imports cleanly and never fires.
    expect(() =>
      convertSigmaRule({
        title: "t",
        detection: {
          selection: {
            "Image|endswith": [],
          },
          condition: "selection",
        },
      }),
    ).toThrow(/matches nothing/);
  });

  it("supports 1 of combined with a filter", () => {
    // The common published form. Anchoring the pattern to the whole
    // condition made this fall through and be refused for a reason that was
    // not true.
    const rule = convertSigmaRule({
      title: "t",
      detection: {
        selection_a: {
          CommandLine: "a",
        },
        selection_b: {
          CommandLine: "b",
        },
        filter_main: {
          CommandLine: "safe",
        },
        condition:
          "1 of selection_* and not filter_main",
      },
    });

    expect(
      rule.anySelections,
    ).toHaveLength(2);

    expect(
      rule.exclusions,
    ).toHaveLength(1);
  });

  it("refuses N of for counts of ten and above", () => {
    // The guard was anchored [2-9] and went inert at ten, so "10 of them"
    // was misdiagnosed as an unknown selection instead.
    expect(() =>
      convertSigmaRule({
        title: "t",
        detection: {
          selection_a: {
            CommandLine: "a",
          },
          condition: "10 of them",
        },
      }),
    ).toThrow(/N other than one/);
  });

  it("names an unknown selection in a 1 of condition", () => {
    expect(() =>
      convertSigmaRule({
        title: "t",
        detection: {
          selection: {
            CommandLine: "a",
          },
          condition: "1 of nope",
        },
      }),
    ).toThrow(
      /unknown selection "nope"/,
    );
  });

  it("still refuses N of when N exceeds one", () => {
    expect(() =>
      convertSigmaRule({
        title: "t",
        detection: {
          selection_a: {
            CommandLine: "a",
          },
          selection_b: {
            CommandLine: "b",
          },
          condition: "2 of selection_*",
        },
      }),
    ).toThrow(
      SigmaUnsupportedError,
    );
  });

  it("maps ParentImage to the parent path, never the parent pid", () => {
    // Regression, and the exact failure this importer exists to prevent.
    // ParentImage is an executable path. It was once mapped onto
    // process.parent.pid, which imported cleanly and then compared a path
    // against a number -- a rule that could never match, reported as
    // coverage. The generator now emits the path, so the mapping is real;
    // this pins it to the right field.
    const rule = convertSigmaRule({
      title: "t",
      detection: {
        selection: {
          "ParentImage|endswith":
            "winword.exe",
        },
        condition: "selection",
      },
    });

    expect(
      Object.keys(rule.selections[0]),
    ).toEqual([
      "process.parent.executable",
    ]);
  });

  it("still refuses ParentCommandLine, which the corpus does not model", () => {
    // The neighbouring field remains unmapped on purpose. Importing it
    // against the parent's path would compare an argument string to a bare
    // executable, which is the same silent-failure shape in a new costume.
    expect(() =>
      convertSigmaRule({
        title: "t",
        detection: {
          selection: {
            "ParentCommandLine|contains":
              "-enc",
          },
          condition: "selection",
        },
      }),
    ).toThrow(/ParentCommandLine/);
  });
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
