import {
  useState,
} from "react";

import {
  scoreSigmaRule,
} from "./detectionReview";

import type {
  CustomRuleReview,
} from "./detectionReview";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

import "./CustomRuleTester.css";

/**
 * Score a Sigma rule you bring against this scenario's labelled corpus.
 *
 * This is the detection-data pitch made interactive, and the one thing a
 * captured corpus cannot offer: because the generator planted every malicious
 * event, a rule the analyst brings gets a precision and recall that are
 * counted, not estimated. It sits under the shipped-ruleset review, after
 * finalizing, so the labels it needs are no longer a spoiler.
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

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

interface CustomRuleTesterProps {
  readonly scenario: ScenarioDefinition;
}

export function CustomRuleTester({
  scenario,
}: CustomRuleTesterProps) {
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

  const score = () => {
    setError(null);

    try {
      setReview(
        scoreSigmaRule(scenario, yaml),
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
          you. Paste a Sigma rule and
          score it against the same
          labelled records the review
          above used.
        </p>
      </div>

      <label
        className="rule-tester-label"
        htmlFor="rule-tester-input"
      >
        Sigma rule
      </label>

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
                    (evaluation) => (
                      <tr
                        key={
                          evaluation.ruleId
                        }
                      >
                        <th scope="row">
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
                    ),
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
