import {
  Fragment,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  buildScenarioCorpus,
  scoreSigmaAgainstCorpus,
  scoreKqlAgainstCorpus,
  scoreSplAgainstCorpus,
  scoreEqlAgainstCorpus,
  scoreEsqlAgainstCorpus,
} from "./detectionReview";

import type {
  CustomRuleReview,
} from "./detectionReview";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

import type {
  CorpusRecord,
} from "@endomorph/fabric";

import "./CustomRuleTester.css";

/**
 * Score a Sigma rule you bring against this scenario's labelled corpus.
 *
 * This is the detection-data pitch made interactive, and the one thing a
 * captured corpus cannot offer: because the generator planted every malicious
 * event, a rule the analyst brings gets a precision and recall that are
 * counted, not estimated. And because every record is labelled, a false
 * positive is not a mystery to argue about, the exact benign events the rule
 * caught can be shown, which is the question a detection engineer actually has.
 */

const STARTER_RULE = [
  "title: Encoded PowerShell Command Line",
  "logsource:",
  "  category: process_creation",
  "detection:",
  "  selection:",
  "    Image|endswith: 'powershell.exe'",
  "    CommandLine|contains: '-enc'",
  "  condition: selection",
  "tags:",
  "  - attack.t1059.001",
].join("\n");

interface RuleExample {
  readonly id: string;
  readonly label: string;
  readonly yaml: string;
}

/**
 * A few rules that show the range of what scoring against ground truth
 * reveals, a clean hit, a precise-but-noisy rule, a plausible rule that
 * misses, and a rule noisy on a different domain. Verified to produce exactly
 * these outcomes against the default scenario's corpus, so a visitor who does
 * not want to hand-write Sigma can click through and see the point.
 */
const EXAMPLES: readonly RuleExample[] = [
  {
    id: "encoded-ps",
    label:
      "Encoded PowerShell, a clean hit",
    yaml: STARTER_RULE,
  },
  {
    id: "any-ps",
    label:
      "Any PowerShell, right technique, noisy rule",
    yaml: [
      "title: Any PowerShell launch",
      "logsource:",
      "  category: process_creation",
      "detection:",
      "  selection:",
      "    Image|endswith: 'powershell.exe'",
      "  condition: selection",
      "tags:",
      "  - attack.t1059.001",
    ].join("\n"),
  },
  {
    id: "wrong-flag",
    label:
      "Encoded, wrong flag, a rule that misses",
    yaml: [
      "title: Encoded command, long form",
      "logsource:",
      "  category: process_creation",
      "detection:",
      "  selection:",
      "    CommandLine|contains: '-EncodedCommand'",
      "  condition: selection",
      "tags:",
      "  - attack.t1059.001",
    ].join("\n"),
  },
  {
    id: "failed-auth",
    label:
      "Any failed sign-in, noisy on identity",
    yaml: [
      "title: Any failed sign-in",
      "logsource:",
      "  category: authentication",
      "detection:",
      "  selection:",
      "    event.type: 'AUTH_LOGIN_FAILED'",
      "  condition: selection",
      "tags:",
      "  - attack.t1110.003",
    ].join("\n"),
  },
];

type RuleLanguage =
  | "sigma"
  | "kql"
  | "spl"
  | "eql"
  | "esql";

/** The same lessons again, written as Elastic ES|QL (the piped query language). */
const ESQL_EXAMPLES: readonly RuleExample[] = [
  {
    id: "esql-encoded",
    label:
      "Encoded PowerShell, a clean hit",
    yaml: `// title: Encoded PowerShell
// technique: T1059.001
FROM logs-endpoint
| WHERE process.name LIKE "*powershell.exe"
    AND process.command_line LIKE "*-enc*"`,
  },
  {
    id: "esql-any",
    label:
      "Any PowerShell, right technique, noisy rule",
    yaml: `// title: Any PowerShell launch
// technique: T1059.001
FROM logs-endpoint
| WHERE process.name LIKE "*powershell.exe"`,
  },
  {
    id: "esql-wrong",
    label:
      "Encoded, wrong flag, a rule that misses",
    yaml: `// title: Encoded command, long form
// technique: T1059.001
FROM logs-endpoint
| WHERE process.command_line LIKE "*-EncodedCommand*"`,
  },
];

/** The same lessons again, written as Elastic EQL for the Elastic Stack's authors. */
const EQL_EXAMPLES: readonly RuleExample[] = [
  {
    id: "eql-encoded",
    label:
      "Encoded PowerShell, a clean hit",
    yaml: `// title: Encoded PowerShell
// technique: T1059.001
process where process.name : "*powershell.exe"
    and process.command_line : "*-enc*"`,
  },
  {
    id: "eql-any",
    label:
      "Any PowerShell, right technique, noisy rule",
    yaml: `// title: Any PowerShell launch
// technique: T1059.001
process where process.name : "*powershell.exe"`,
  },
  {
    id: "eql-wrong",
    label:
      "Encoded, wrong flag, a rule that misses",
    yaml: `// title: Encoded command, long form
// technique: T1059.001
process where process.command_line : "*-EncodedCommand*"`,
  },
];

/** The same lessons again, written as Splunk searches for the largest SIEM's authors. */
const SPL_EXAMPLES: readonly RuleExample[] = [
  {
    id: "spl-encoded",
    label:
      "Encoded PowerShell, a clean hit",
    yaml: `// title: Encoded PowerShell
// technique: T1059.001
index=edr sourcetype=sysmon Image="*powershell.exe" CommandLine="*-enc*"`,
  },
  {
    id: "spl-any",
    label:
      "Any PowerShell, right technique, noisy rule",
    yaml: `// title: Any PowerShell launch
// technique: T1059.001
index=edr sourcetype=sysmon Image="*powershell.exe"`,
  },
  {
    id: "spl-wrong",
    label:
      "Encoded, wrong flag, a rule that misses",
    yaml: `// title: Encoded command, long form
// technique: T1059.001
index=edr CommandLine="*-EncodedCommand*"`,
  },
];

/** The same lessons as the Sigma examples, written in Kusto for Sentinel/Defender authors. */
const KQL_EXAMPLES: readonly RuleExample[] = [
  {
    id: "kql-encoded",
    label:
      "Encoded PowerShell, a clean hit",
    yaml: `// title: Encoded PowerShell
// technique: T1059.001
DeviceProcessEvents
| where FileName endswith "powershell.exe"
    and ProcessCommandLine contains "-enc"`,
  },
  {
    id: "kql-any",
    label:
      "Any PowerShell, right technique, noisy rule",
    yaml: `// title: Any PowerShell launch
// technique: T1059.001
DeviceProcessEvents
| where FileName endswith "powershell.exe"`,
  },
  {
    id: "kql-wrong",
    label:
      "Encoded, wrong flag, a rule that misses",
    yaml: `// title: Encoded command, long form
// technique: T1059.001
DeviceProcessEvents
| where ProcessCommandLine contains "-EncodedCommand"`,
  },
];

/** How many matched records to list under a rule before trailing off. */
const MATCH_LIMIT = 12;

/**
 * A pasted rule is shareable: the language and the rule text encode into the
 * URL so "here is my rule scored against Endomorph" is a link, not a
 * screenshot. The rule is base64url-encoded UTF-8 so a YAML/KQL/SPL body with
 * newlines and quotes survives the query string intact.
 */
function encodeRule(text: string): string {
  const bytes = new TextEncoder().encode(
    text,
  );
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeRule(
  encoded: string,
): string | null {
  try {
    const base64 = encoded
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const binary = atob(base64);
    const bytes = Uint8Array.from(
      binary,
      (character) =>
        character.charCodeAt(0),
    );
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

interface SharedRule {
  readonly language: RuleLanguage;
  readonly text: string;
}

/** Reads a shared rule out of the URL, if this page was opened from a share link. */
function readSharedRule(): SharedRule | null {
  const params = new URLSearchParams(
    window.location.search,
  );

  const encoded = params.get("rule");

  if (!encoded) {
    return null;
  }

  const text = decodeRule(encoded);

  if (text === null) {
    return null;
  }

  const lang = params.get("lang");

  return {
    language:
      lang === "kql" ||
      lang === "spl" ||
      lang === "eql" ||
      lang === "esql"
        ? lang
        : "sigma",
    text,
  };
}

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

/**
 * A one-line description of a matched record, reaching for whichever field
 * actually says what happened, the command line for a process, the flow for
 * a connection, the role for a grant, so a matched event reads as an event
 * rather than an id.
 */
function summarise(
  record: CorpusRecord,
): string {
  const command =
    record["process.command_line"];
  if (command) {
    return command;
  }

  const destination =
    record["destination.ip"];
  if (destination) {
    const port =
      record["destination.port"];
    return `${record["source.ip"] ?? "?"} → ${destination}${
      port ? `:${port}` : ""
    }`;
  }

  const role = record["iam.role"];
  if (role) {
    return `role ${role} → ${
      record["account.name"] ??
      record["account.id"] ??
      "?"
    }`;
  }

  return (
    record["account.name"] ??
    record["user.name"] ??
    record["event.reason"] ??
    record["event.id"]
  );
}

function MatchRows({
  label,
  kind,
  records,
  total,
}: {
  readonly label: string;
  readonly kind: "fp" | "fn";
  readonly records: readonly CorpusRecord[];
  readonly total: number;
}) {
  // The evaluator returns a sample of up to 25 ids per outcome, so the header
  // shows the true count and says plainly when what follows is only a sample.
  const sampled = total > records.length;

  return (
    <div className="rule-tester-matchgroup">
      <p className="rule-tester-matchgroup-head">
        {label}{" "}
        <strong>({total})</strong>
        {sampled && (
          <span className="rule-tester-sample">
            {" "}
            &middot; a sample
          </span>
        )}
      </p>
      <ul className="rule-tester-matches">
        {records
          .slice(0, MATCH_LIMIT)
          .map((record) => (
            <li
              key={record["event.id"]}
            >
              <span
                className={`rule-tester-chip ${kind}`}
              >
                {kind === "fp"
                  ? "FP"
                  : "FN"}
              </span>
              <code className="rule-tester-match-type">
                {record["event.type"]}
              </code>
              <span className="rule-tester-match-detail">
                {summarise(record)}
              </span>
            </li>
          ))}
        {records.length >
          MATCH_LIMIT && (
          <li className="rule-tester-match-more">
            &hellip; and more
          </li>
        )}
      </ul>
    </div>
  );
}

interface CustomRuleTesterProps {
  /** A compiled scenario whose corpus to score against. */
  readonly scenario?: ScenarioDefinition;
  /**
   * Pre-built corpus records to score against, instead of a scenario. The
   * digital-twin panel generates these in the browser from a client profile.
   */
  readonly records?: readonly CorpusRecord[];
  /**
   * The scenario's corpus path, used to build a shareable result link. The
   * detection lab passes it; the in-investigation tester and the digital-twin
   * panel do not, so the share affordance is simply absent there.
   */
  readonly scenarioPath?: string;
}

export function CustomRuleTester({
  scenario,
  records: recordsProp,
  scenarioPath,
}: CustomRuleTesterProps) {
  const [shared] = useState(
    readSharedRule,
  );
  const records = useMemo(
    () =>
      recordsProp ??
      (scenario
        ? buildScenarioCorpus(scenario)
        : []),
    [recordsProp, scenario],
  );

  const recordById = useMemo(
    () =>
      new Map(
        records.map((record) => [
          record["event.id"],
          record,
        ]),
      ),
    [records],
  );

  const [yaml, setYaml] = useState(
    shared?.text ?? STARTER_RULE,
  );

  const [review, setReview] =
    useState<CustomRuleReview | null>(
      null,
    );

  const [error, setError] = useState<
    string | null
  >(null);

  const [expanded, setExpanded] =
    useState<string | null>(null);

  const [language, setLanguage] =
    useState<RuleLanguage>(
      shared?.language ?? "sigma",
    );

  const [copied, setCopied] =
    useState(false);

  const examplesFor = (
    lang: RuleLanguage,
  ): readonly RuleExample[] =>
    lang === "kql"
      ? KQL_EXAMPLES
      : lang === "spl"
        ? SPL_EXAMPLES
        : lang === "eql"
          ? EQL_EXAMPLES
          : lang === "esql"
            ? ESQL_EXAMPLES
            : EXAMPLES;

  const activeExamples =
    examplesFor(language);

  const switchLanguage = (
    next: RuleLanguage,
  ) => {
    setLanguage(next);
    setYaml(examplesFor(next)[0].yaml);
    setReview(null);
    setError(null);
    setExpanded(null);
  };

  const score = () => {
    setError(null);
    setExpanded(null);

    try {
      setReview(
        language === "kql"
          ? scoreKqlAgainstCorpus(
              records,
              yaml,
            )
          : language === "spl"
            ? scoreSplAgainstCorpus(
                records,
                yaml,
              )
            : language === "eql"
              ? scoreEqlAgainstCorpus(
                  records,
                  yaml,
                )
              : language === "esql"
                ? scoreEsqlAgainstCorpus(
                    records,
                    yaml,
                  )
                : scoreSigmaAgainstCorpus(
                    records,
                    yaml,
                  ),
      );
    } catch (caught) {
      setReview(null);
      setError(
        caught instanceof Error
          ? caught.message
          : "The rule could not be parsed.",
      );
    }
  };

  // If this page was opened from a share link, score the shared rule once the
  // corpus is ready, so the recipient lands on the result, not an empty form.
  // Guarded to fire a single time: switching scenario afterwards must not
  // silently overwrite a rule the visitor has since edited.
  const autoScored = useRef(false);

  useEffect(() => {
    if (!shared || autoScored.current) {
      return;
    }

    autoScored.current = true;

    try {
      setReview(
        shared.language === "kql"
          ? scoreKqlAgainstCorpus(
              records,
              shared.text,
            )
          : shared.language === "spl"
            ? scoreSplAgainstCorpus(
                records,
                shared.text,
              )
            : shared.language === "eql"
              ? scoreEqlAgainstCorpus(
                  records,
                  shared.text,
                )
              : shared.language === "esql"
                ? scoreEsqlAgainstCorpus(
                    records,
                    shared.text,
                  )
                : scoreSigmaAgainstCorpus(
                    records,
                    shared.text,
                  ),
      );
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "The rule could not be parsed.",
      );
    }
  }, [records, shared]);

  const shareLink = () => {
    if (!scenarioPath) {
      return;
    }

    const base = `${window.location.origin}${window.location.pathname}`;
    const url = `${base}?lab&scenario=${encodeURIComponent(
      scenarioPath,
    )}&lang=${language}&rule=${encodeRule(
      yaml,
    )}`;

    void navigator.clipboard
      .writeText(url)
      .then(() => {
        setCopied(true);
        window.setTimeout(
          () => setCopied(false),
          2000,
        );
      })
      .catch(() => {
        setCopied(false);
      });
  };

  const scored =
    review?.report.evaluations ?? [];

  return (
    <section
      className="rule-tester"
      aria-label="Test your own detection rule"
    >
      <div className="rule-tester-head">
        <p className="eyebrow">
          Bring your own rule
        </p>
        <div
          className="rule-tester-langs"
          role="group"
          aria-label="Rule language"
        >
          <button
            type="button"
            className={
              language === "sigma"
                ? "rule-tester-lang active"
                : "rule-tester-lang"
            }
            aria-pressed={
              language === "sigma"
            }
            onClick={() =>
              switchLanguage("sigma")
            }
          >
            Sigma
          </button>
          <button
            type="button"
            className={
              language === "kql"
                ? "rule-tester-lang active"
                : "rule-tester-lang"
            }
            aria-pressed={
              language === "kql"
            }
            onClick={() =>
              switchLanguage("kql")
            }
          >
            KQL
          </button>
          <button
            type="button"
            className={
              language === "spl"
                ? "rule-tester-lang active"
                : "rule-tester-lang"
            }
            aria-pressed={
              language === "spl"
            }
            onClick={() =>
              switchLanguage("spl")
            }
          >
            SPL
          </button>
          <button
            type="button"
            className={
              language === "eql"
                ? "rule-tester-lang active"
                : "rule-tester-lang"
            }
            aria-pressed={
              language === "eql"
            }
            onClick={() =>
              switchLanguage("eql")
            }
          >
            EQL
          </button>
          <button
            type="button"
            className={
              language === "esql"
                ? "rule-tester-lang active"
                : "rule-tester-lang"
            }
            aria-pressed={
              language === "esql"
            }
            onClick={() =>
              switchLanguage("esql")
            }
          >
            ES|QL
          </button>
        </div>
        <h3>
          Score a rule against this
          corpus
        </h3>
        <p className="rule-tester-lede">
          The ground truth is known by
          construction, so a rule you
          bring gets a precision and
          recall that are{" "}
          <strong>counted</strong>, not
          estimated, the thing a
          captured dataset cannot give
          you. Paste a{" "}
          {language === "kql"
            ? "KQL"
            : language === "spl"
              ? "Splunk"
              : language === "eql"
                ? "Elastic EQL"
                : language === "esql"
                  ? "Elastic ES|QL"
                  : "Sigma"}{" "}
          rule, score it against the{" "}
          {records.length.toLocaleString()}{" "}
          labelled records, and open a rule
          to see the exact benign events it
          fired on or the malicious ones it
          missed.
        </p>
      </div>

      <div className="rule-tester-input-head">
        <label
          className="rule-tester-label"
          htmlFor="rule-tester-input"
        >
          {language === "kql"
            ? "KQL query"
            : language === "spl"
              ? "SPL search"
              : language === "eql"
                ? "EQL query"
                : language === "esql"
                  ? "ES|QL query"
                  : "Sigma rule"}
        </label>

        <select
          className="rule-tester-example"
          aria-label="Load an example rule"
          value=""
          onChange={(event) => {
            const example =
              activeExamples.find(
                (candidate) =>
                  candidate.id ===
                  event.target.value,
              );

            if (example) {
              setYaml(example.yaml);
              setReview(null);
              setError(null);
              setExpanded(null);
            }
          }}
        >
          <option value="">
            Load an example…
          </option>
          {activeExamples.map((example) => (
            <option
              key={example.id}
              value={example.id}
            >
              {example.label}
            </option>
          ))}
        </select>
      </div>

      <textarea
        id="rule-tester-input"
        className="rule-tester-input"
        spellCheck={false}
        value={yaml}
        onChange={(event) =>
          setYaml(event.target.value)
        }
        rows={12}
      />

      <div className="rule-tester-actions">
        <button
          type="button"
          className="rule-tester-score"
          onClick={score}
        >
          Score rule
        </button>

        <button
          type="button"
          className="rule-tester-reset"
          onClick={() => {
            setYaml(
              activeExamples[0].yaml,
            );
            setReview(null);
            setError(null);
            setExpanded(null);
          }}
        >
          Reset to example
        </button>

        {scenarioPath && (
          <button
            type="button"
            className="rule-tester-share"
            onClick={shareLink}
          >
            {copied
              ? "Link copied ✓"
              : "Copy share link"}
          </button>
        )}
      </div>

      {error && (
        <p className="rule-tester-error">
          {error}
        </p>
      )}

      {review &&
        review.imported === 0 && (
          <div className="rule-tester-skipped">
            <p>
              <strong>Not scored.</strong>{" "}
              The supported{" "}
              {language === "kql"
                ? "KQL"
                : language === "spl"
                  ? "SPL"
                  : language === "eql"
                    ? "EQL"
                    : language === "esql"
                      ? "ES|QL"
                      : "Sigma"}{" "}
              subset
              could not express this rule
             , reported rather than
              matched silently, because a
              rule that quietly matches
              nothing looks exactly like
              one that works:
            </p>
            <ul>
              {review.skipped.map(
                (skip, index) => (
                  <li key={index}>
                    {skip.reason}
                  </li>
                ),
              )}
            </ul>
          </div>
        )}

      {review &&
        review.imported > 0 && (
          <div className="rule-tester-result">
            <p className="rule-tester-corpus">
              Scored against{" "}
              <strong>
                {review.recordCount.toLocaleString()}
              </strong>{" "}
              records,{" "}
              <strong>
                {review.maliciousCount}
              </strong>{" "}
              malicious.
            </p>

            <div className="rule-tester-table-wrap">
              <table className="rule-tester-table">
                <thead>
                  <tr>
                    <th scope="col">
                      Rule
                    </th>
                    <th scope="col">
                      Technique
                    </th>
                    <th scope="col">TP</th>
                    <th scope="col">FP</th>
                    <th scope="col">FN</th>
                    <th scope="col">
                      Precision
                    </th>
                    <th scope="col">
                      Recall
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {scored.map(
                    (evaluation) => {
                      const isOpen =
                        expanded ===
                        evaluation.ruleId;

                      const resolve = (
                        ids: readonly string[],
                      ): CorpusRecord[] =>
                        ids
                          .map((id) =>
                            recordById.get(
                              id,
                            ),
                          )
                          .filter(
                            (
                              record,
                            ): record is CorpusRecord =>
                              record !==
                              undefined,
                          );

                      const falsePositives =
                        resolve(
                          evaluation.falsePositiveEventIds,
                        );

                      const missed = resolve(
                        evaluation.missedEventIds,
                      );

                      // Only worth opening when there is a failure to
                      // explain. A rule that caught everything cleanly has
                      // nothing to debug.
                      const canOpen =
                        evaluation.falsePositives >
                          0 ||
                        evaluation.falseNegatives >
                          0;

                      return (
                        <Fragment
                          key={
                            evaluation.ruleId
                          }
                        >
                          <tr
                            className={
                              canOpen
                                ? "rule-tester-row-clickable"
                                : undefined
                            }
                            onClick={() =>
                              canOpen
                                ? setExpanded(
                                    isOpen
                                      ? null
                                      : evaluation.ruleId,
                                  )
                                : undefined
                            }
                          >
                            <th scope="row">
                              {canOpen && (
                                <span className="rule-tester-caret">
                                  {isOpen
                                    ? "▾"
                                    : "▸"}
                                </span>
                              )}
                              {
                                evaluation.ruleName
                              }
                            </th>
                            <td>
                              <code>
                                {evaluation.technique ??
                                  ", "}
                              </code>
                            </td>
                            <td className="rule-tester-num">
                              {
                                evaluation.truePositives
                              }
                            </td>
                            <td className="rule-tester-num">
                              {
                                evaluation.falsePositives
                              }
                            </td>
                            <td className="rule-tester-num">
                              {
                                evaluation.falseNegatives
                              }
                            </td>
                            <td className="rule-tester-num">
                              {percent(
                                evaluation.precision,
                              )}
                            </td>
                            <td className="rule-tester-num">
                              {evaluation.truePositives ===
                                0 &&
                              evaluation.falseNegatives ===
                                0
                                ? "n/a"
                                : percent(
                                    evaluation.recall,
                                  )}
                            </td>
                          </tr>

                          {isOpen && (
                            <tr
                              key={`${evaluation.ruleId}-matches`}
                              className="rule-tester-matches-row"
                            >
                              <td colSpan={7}>
                                {evaluation.falsePositives >
                                  0 && (
                                  <MatchRows
                                    label="False positives, benign events this rule caught"
                                    kind="fp"
                                    records={
                                      falsePositives
                                    }
                                    total={
                                      evaluation.falsePositives
                                    }
                                  />
                                )}
                                {evaluation.falseNegatives >
                                  0 && (
                                  <MatchRows
                                    label="Missed, malicious events it did not catch"
                                    kind="fn"
                                    records={
                                      missed
                                    }
                                    total={
                                      evaluation.falseNegatives
                                    }
                                  />
                                )}
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    },
                  )}
                </tbody>
              </table>
            </div>

            {review.skipped.length > 0 && (
              <p className="rule-tester-partial">
                {review.skipped.length}{" "}
                part(s) of the rule were
                skipped:{" "}
                {review.skipped
                  .map(
                    (skip) => skip.reason,
                  )
                  .join("; ")}
                .
              </p>
            )}
          </div>
        )}
    </section>
  );
}
