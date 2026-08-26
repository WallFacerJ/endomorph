import type {
  DetectionReview,
} from "./detectionReview";

import {
  SegmentMeter,
} from "./Charts";

import "./DetectionReviewPanel.css";

interface DetectionReviewPanelProps {
  review: DetectionReview;
}

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

/**
 * How the shipped detection ruleset performed on the incident just worked.
 *
 * Shown after finalizing, for the same reason instructor ground truth is:
 * the labels these numbers are computed from are the answer to the exercise.
 */
export function DetectionReviewPanel({
  review,
}: DetectionReviewPanelProps) {
  const { report } = review;

  const techniqueTotal =
    report.coveredTechniques.length +
    report.uncoveredTechniques.length;

  const scored = report.evaluations
    .filter(
      (evaluation) =>
        evaluation.matched > 0 ||
        evaluation.falseNegatives > 0,
    )
    .sort(
      (left, right) =>
        right.truePositives -
          left.truePositives ||
        left.falsePositives -
          right.falsePositives,
    );

  const missed = scored.filter(
    (evaluation) =>
      evaluation.truePositives === 0 &&
      evaluation.falseNegatives > 0,
  );

  /*
    A rule whose technique this incident never demonstrates had nothing to
    find, so it is not a miss, but it still charged for whatever it raised.
    Recall is vacuously perfect in that case, by the evaluator's deliberate
    choice, and printing "100%" next to zero true positives reads as a
    success. Those rows say so instead.
  */
  const inapplicable = (
    evaluation: (typeof scored)[number],
  ): boolean =>
    evaluation.truePositives === 0 &&
    evaluation.falseNegatives === 0;

  const noisiest = [...scored].sort(
    (left, right) =>
      right.falsePositives -
      left.falsePositives,
  )[0];

  return (
    <section
      className="detection-review"
      aria-label="Detection review"
    >
      <header className="detection-review-head">
        <div>
          <p className="eyebrow">
            Detection review
          </p>

          <h3>
            How the shipped rules did on
            this incident
          </h3>

          <p className="detection-review-lede">
            Every event in this scenario
            was planted by the generator,
            so which are malicious is
            known rather than inferred.
            That makes these numbers
            exact: they are counted, not
            sampled or estimated. You
            worked this incident by hand
           , this is what the
            automated detections would
            have given you.
          </p>
        </div>

        <dl className="detection-review-totals">
          <div>
            <dt>Techniques covered</dt>
            <dd>
              {
                report.coveredTechniques
                  .length
              }
              <span>
                {" / "}
                {techniqueTotal}
              </span>

              <SegmentMeter
                covered={
                  report.coveredTechniques
                    .length
                }
                total={techniqueTotal}
                label="Techniques covered"
              />
            </dd>
          </div>

          <div>
            <dt>True positives</dt>
            <dd>
              {report.totalTruePositives}
            </dd>
          </div>

          <div>
            <dt>False positives</dt>
            <dd>
              {report.totalFalsePositives}
            </dd>
          </div>

          <div>
            <dt>Records scored</dt>
            <dd>
              {review.recordCount.toLocaleString()}
              <span>
                {" "}
                {review.maliciousCount}{" "}
                malicious
              </span>
            </dd>
          </div>
        </dl>
      </header>

      <div className="detection-review-table-wrap">
        <table className="detection-review-table">
          <caption className="sr-only">
            Per-rule detection performance
            against this incident
          </caption>

          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">
                Technique
              </th>
              <th scope="col">TP</th>
              <th scope="col">FP</th>
              <th scope="col">FN</th>
              <th scope="col">
                Precision
              </th>
              <th scope="col">Recall</th>
            </tr>
          </thead>

          <tbody>
            {scored.map((evaluation) => (
              <tr
                key={evaluation.ruleId}
                className={
                  evaluation.truePositives >
                  0
                    ? "detection-hit"
                    : inapplicable(
                          evaluation,
                        )
                      ? "detection-na"
                      : "detection-miss"
                }
              >
                <th scope="row">
                  {evaluation.ruleName}
                  <small>
                    {evaluation.ruleId}
                  </small>
                </th>

                <td>
                  <code>
                    {evaluation.technique ??
                      ", "}
                  </code>
                </td>

                <td className="detection-num">
                  {
                    evaluation.truePositives
                  }
                </td>

                <td className="detection-num">
                  {
                    evaluation.falsePositives
                  }
                </td>

                <td className="detection-num">
                  {
                    evaluation.falseNegatives
                  }
                </td>

                <td className="detection-num">
                  {percent(
                    evaluation.precision,
                  )}
                </td>

                <td
                  className="detection-num"
                  title={
                    inapplicable(
                      evaluation,
                    )
                      ? "This incident contains no instance of the rule's technique, so there was nothing to recall."
                      : undefined
                  }
                >
                  {inapplicable(evaluation)
                    ? "n/a"
                    : percent(
                        evaluation.recall,
                      )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="detection-review-notes">
        {report.uncoveredTechniques
          .length > 0 && (
          <p>
            <strong>
              No rule detected
            </strong>{" "}
            {/*
              A real separator rather than a CSS margin: a margin is invisible
              to a screen reader and to anything that copies the text, which
              read the list as one run-on identifier.
            */}
            {report.uncoveredTechniques.map(
              (technique, index) => (
                <span key={technique}>
                  {index > 0 && ", "}
                  <code>{technique}</code>
                </span>
              ),
            )}
            {". "}
            Techniques the incident
            demonstrated and the ruleset
            has nothing for. If you found
            these by hand, you found
            something the tooling would
            not have raised.
          </p>
        )}

        {missed.length > 0 && (
          <p>
            <strong>
              Claimed but did not fire:
            </strong>{" "}
            {missed
              .map(
                (evaluation) =>
                  evaluation.ruleName,
              )
              .join(", ")}
            . A rule that targets a
            technique present here and
            matched none of it , 
            which reads as coverage on a
            dashboard and is not.
          </p>
        )}

        {noisiest &&
          noisiest.falsePositives > 0 && (
            <p>
              <strong>Noisiest:</strong>{" "}
              {noisiest.ruleName} raised{" "}
              {noisiest.falsePositives}{" "}
              false positives at{" "}
              {percent(
                noisiest.precision,
              )}{" "}
              precision. Recall is cheap
              to buy and this is what it
              costs; every one of those is
              an analyst reading a benign
              event.
            </p>
          )}
      </div>
    </section>
  );
}
