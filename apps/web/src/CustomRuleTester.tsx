import {
  Fragment,
  useMemo,
  useState,
} from "react";

import {
  buildScenarioCorpus,
  scoreSigmaAgainstCorpus,
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
 * positive is not a mystery to argue about -- the exact benign events the rule
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
 * reveals -- a clean hit, a precise-but-noisy rule, a plausible rule that
 * misses, and a rule noisy on a different domain. Verified to produce exactly
 * these outcomes against the default scenario's corpus, so a visitor who does
 * not want to hand-write Sigma can click through and see the point.
 */
const EXAMPLES: readonly RuleExample[] = [
  {
    id: "encoded-ps",
    label:
      "Encoded PowerShell — a clean hit",
    yaml: STARTER_RULE,
  },
  {
    id: "any-ps",
    label:
      "Any PowerShell — right technique, noisy rule",
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
      "Encoded, wrong flag — a rule that misses",
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
      "Any failed sign-in — noisy on identity",
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

/** How many matched records to list under a rule before trailing off. */
const MATCH_LIMIT = 12;

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

/**
 * A one-line description of a matched record, reaching for whichever field
 * actually says what happened -- the command line for a process, the flow for
 * a connection, the role for a grant -- so a matched event reads as an event
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
  readonly scenario: ScenarioDefinition;
}

export function CustomRuleTester({
  scenario,
}: CustomRuleTesterProps) {
  const records = useMemo(
    () => buildScenarioCorpus(scenario),
    [scenario],
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
    STARTER_RULE,
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

  const score = () => {
    setError(null);
    setExpanded(null);

    try {
      setReview(
        scoreSigmaAgainstCorpus(
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
        <h3>
          Score a Sigma rule against this
          corpus
        </h3>
        <p className="rule-tester-lede">
          The ground truth is known by
          construction, so a rule you
          bring gets a precision and
          recall that are{" "}
          <strong>counted</strong>, not
          estimated &mdash; the thing a
          captured dataset cannot give
          you. Paste a Sigma rule, score
          it against the{" "}
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
          Sigma rule
        </label>

        <select
          className="rule-tester-example"
          aria-label="Load an example rule"
          value=""
          onChange={(event) => {
            const example =
              EXAMPLES.find(
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
          {EXAMPLES.map((example) => (
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
            setYaml(STARTER_RULE);
            setReview(null);
            setError(null);
            setExpanded(null);
          }}
        >
          Reset to example
        </button>
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
              The supported Sigma subset
              could not express this rule
              &mdash; reported rather than
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
                                  "—"}
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
                                    label="False positives — benign events this rule caught"
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
                                    label="Missed — malicious events it did not catch"
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
