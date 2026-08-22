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

  it("records who performed an action, not only who it was done to", () => {
    // Identity lifecycle events name the account being changed. Without the
    // actor, "who re-enabled that account" is unanswerable from the corpus
    // even though the runtime knows -- and it is exactly the question that
    // separates an administrative action from self-service.
    const dormant = corpora.find(
      (candidate) =>
        candidate.manifest.plan ===
        "dormant-account-revival",
    );

    const reactivation =
      dormant?.records.find(
        (record) =>
          record["event.type"] ===
          "ACCOUNT_ENABLED",
      );

    expect(
      reactivation,
    ).toBeDefined();

    expect(
      reactivation?.["actor.account.name"],
    ).toBeDefined();

    // The actor is a different account from the one acted upon.
    expect(
      reactivation?.["actor.account.id"],
    ).not.toBe(
      reactivation?.["account.id"],
    );
  });

  it("omits the actor when it is the account acted upon", () => {
    // Adding it unconditionally would restate the account on every login
    // and make the field meaningless.
    const login = corpora[0].records.find(
      (record) =>
        record["event.type"] ===
          "AUTH_LOGIN_SUCCEEDED" &&
        record["account.id"] !==
          undefined,
    );

    expect(login).toBeDefined();

    expect(
      login?.["actor.account.id"],
    ).toBeUndefined();
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

describe("process lineage", () => {
  const processesIn = (
    corpus: (typeof corpora)[number],
  ) =>
    corpus.records.filter(
      (record) =>
        record["event.type"] ===
        "PROCESS_STARTED",
    );

  it("gives every process a parent path", () => {
    // The credential-compromise walkthrough instructs the analyst to "read
    // the parent process next". For a long time that could not be done: the
    // corpus carried a parent pid pointing at a process with no start event
    // and no image anywhere, so the instruction named a field the data did
    // not contain.
    const processes = corpora.flatMap(
      (corpus) => processesIn(corpus),
    );

    expect(
      processes.length,
    ).toBeGreaterThan(0);

    for (const record of processes) {
      expect(
        record[
          "process.parent.executable"
        ],
      ).toBeTruthy();
    }
  });

  it("splits a parent image across pids only for the intruder's session", () => {
    // A pid identifies a running process, so drawing a fresh one per child
    // would put nine explorer.exe pids on one workstation and make the
    // lineage unpivotable -- the one thing the field is for.
    //
    // One split is legitimate and deliberate: a remote interactive logon
    // starts a second session with its own explorer.exe, which is why the
    // incident's processes hang off a different pid than the real user's.
    // That is a signal an analyst should be able to see, so the assertion is
    // not "one pid per image" but "any second pid is wholly the attacker's"
    // -- which catches the regression and pins the model at the same time.
    //
    // Per corpus, because each plan is a separate universe: merging them
    // puts two unrelated incidents' processes on the same host.
    for (const corpus of corpora) {
      const byImage = new Map<
        string,
        Map<
          string,
          {
            malicious: number;
            benign: number;
          }
        >
      >();

      for (const record of processesIn(
        corpus,
      )) {
        const parent =
          record[
            "process.parent.executable"
          ];

        const pid =
          record["process.parent.pid"];

        if (
          !parent ||
          !pid ||
          !record["host.id"]
        ) {
          continue;
        }

        const key = `${record["host.id"]}|${parent}`;

        let pids = byImage.get(key);

        if (!pids) {
          pids = new Map();
          byImage.set(key, pids);
        }

        const tally = pids.get(pid) ?? {
          malicious: 0,
          benign: 0,
        };

        if (record["label.malicious"]) {
          tally.malicious += 1;
        } else {
          tally.benign += 1;
        }

        pids.set(pid, tally);
      }

      expect(
        byImage.size,
      ).toBeGreaterThan(0);

      for (const pids of byImage.values()) {
        if (pids.size === 1) {
          continue;
        }

        // At most two sessions, and the extra one is entirely the incident.
        expect(pids.size).toBe(2);

        const sessions = [
          ...pids.values(),
        ].sort(
          (left, right) =>
            left.malicious -
            right.malicious,
        );

        expect(
          sessions[0].malicious,
        ).toBe(0);

        expect(sessions[1].benign).toBe(
          0,
        );
      }
    }
  });

  it("resolves in-corpus parent pids to the image the child names", () => {
    // Where the parent's own start event is present, the two records must
    // agree. A child naming a parent image that contradicts the parent's own
    // event would be worse than carrying no lineage at all.
    let resolved = 0;

    for (const corpus of corpora) {
      const processes =
        processesIn(corpus);

      const byHostPid = new Map<
        string,
        string
      >();

      for (const record of processes) {
        if (
          record["host.id"] &&
          record["process.pid"] &&
          record["process.executable"]
        ) {
          byHostPid.set(
            `${record["host.id"]}|${record["process.pid"]}`,
            record[
              "process.executable"
            ],
          );
        }
      }

      for (const record of processes) {
        const actual = byHostPid.get(
          `${record["host.id"]}|${record["process.parent.pid"]}`,
        );

        if (actual === undefined) {
          continue;
        }

        resolved += 1;

        expect(
          record[
            "process.parent.executable"
          ],
        ).toBe(actual);
      }
    }

    // The attack chains parent their later steps on their own earlier ones,
    // so this must actually have checked something.
    expect(resolved).toBeGreaterThan(0);
  });
});

describe("windows event codes", () => {
  const records = corpora.flatMap(
    (corpus) => corpus.records,
  );

  it("assigns codes only to windows hosts", () => {
    // A macOS laptop reporting 4688 would be a fabrication, and a rule
    // author keying on EventID would reasonably trust it.
    const coded = records.filter(
      (record) =>
        record["event.code"] !==
        undefined,
    );

    expect(coded.length).toBeGreaterThan(
      0,
    );

    for (const record of coded) {
      expect(
        record["host.os.full"],
      ).toMatch(/windows/i);
    }
  });

  it("leaves session starts uncoded", () => {
    // SESSION_STARTED has no honest Windows equivalent -- 4624 already
    // records the logon it abstracts over. Giving it a code of its own would
    // let a rule count one sign-in twice.
    const sessions = records.filter(
      (record) =>
        record["event.type"] ===
        "SESSION_STARTED",
    );

    expect(
      sessions.length,
    ).toBeGreaterThan(0);

    for (const record of sessions) {
      expect(
        record["event.code"],
      ).toBeUndefined();
    }
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

  it("matches through an anyOf value list", () => {
    // A shape assertion in the importer does not prove the evaluator honours
    // the branch. A matcher branch that silently returned false would look
    // exactly like "no records matched".
    const evaluation = evaluateRule(
      {
        id: "any-of",
        name: "Recon utility execution",
        technique: "T1059.001",
        severity: "low",
        selections: [
          {
            "process.executable": {
              anyOf: [
                {
                  contains:
                    "does-not-exist.exe",
                },
                {
                  contains:
                    "powershell.exe",
                },
              ],
            },
          },
        ],
      },
      corpora[0].records,
    );

    expect(
      evaluation.matched,
    ).toBeGreaterThan(0);

    expect(
      evaluation.truePositives,
    ).toBeGreaterThan(0);
  });

  it("matches through anySelections as a disjunction", () => {
    const base = {
      id: "any-sel",
      name: "Either indicator",
      technique: "T1059.001",
      severity: "low" as const,
      selections: [],
    };

    const matching = evaluateRule(
      {
        ...base,
        anySelections: [
          {
            "process.command_line": {
              contains:
                "definitely-not-present",
            },
          },
          {
            "process.command_line": {
              contains: "powershell",
            },
          },
        ],
      },
      corpora[0].records,
    );

    expect(
      matching.matched,
    ).toBeGreaterThan(0);

    // And that it is genuinely a disjunction: neither alternative matching
    // must yield nothing rather than everything.
    const nonMatching = evaluateRule(
      {
        ...base,
        anySelections: [
          {
            "process.command_line": {
              contains: "no-such-thing",
            },
          },
        ],
      },
      corpora[0].records,
    );

    expect(nonMatching.matched).toBe(0);
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
