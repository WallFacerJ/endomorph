import type {
  ResponseComparison,
} from "./simulationAdapter";

import "./ResponseComparisonPanel.css";

/**
 * What the other response paths would have scored.
 *
 * Rewinding shows what the incident looked like earlier. This answers the
 * question that actually changes behaviour: what would have happened if I
 * had decided differently. Because the runtime is deterministic and actions
 * are declarative, every figure here is exact rather than estimated -- the
 * same scoring function run over a different sequence.
 */

export interface ResponseComparisonPanelProps {
  comparison: ResponseComparison;
}

export function ResponseComparisonPanel({
  comparison,
}: ResponseComparisonPanelProps) {
  const {
    taken,
    best,
    influences,
    optimal,
    exhaustive,
  } = comparison;

  const missed =
    best.score.percentage -
    taken.score.percentage;

  return (
    <section
      className="comparison-panel"
      aria-label="Response path comparison"
    >
      <header className="comparison-head">
        <div>
          <p className="comparison-eyebrow">
            Counterfactual
          </p>
          <h4>
            What the other paths would
            have scored
          </h4>
          <p className="comparison-copy">
            {optimal
              ? exhaustive
                ? "No sequence of the available operations scores higher than the one you took."
                : "No better sequence was found among those searched."
              : `A different sequence would have scored ${best.score.percentage}%, ${missed} points above your run.`}
          </p>
        </div>

        <div className="comparison-scores">
          <div>
            <span>Your path</span>
            <strong>
              {taken.score.percentage}%
            </strong>
          </div>
          <div
            className={
              optimal
                ? "comparison-best matched"
                : "comparison-best"
            }
          >
            <span>Best available</span>
            <strong>
              {best.score.percentage}%
            </strong>
          </div>
        </div>
      </header>

      <ul className="comparison-influences">
        {influences.map((influence) => (
          <li
            key={influence.actionId}
            className={
              influence.delta > 0
                ? "comparison-influence positive"
                : influence.delta < 0
                  ? "comparison-influence negative"
                  : "comparison-influence neutral"
            }
          >
            <span className="comparison-state">
              {influence.performed
                ? "Performed"
                : "Not taken"}
            </span>

            <span className="comparison-label">
              {influence.label}
            </span>

            <span className="comparison-delta">
              {influence.delta > 0
                ? `+${influence.delta}`
                : influence.delta}
            </span>

            <span className="comparison-explanation">
              {influence.explanation}
            </span>
          </li>
        ))}
      </ul>

      {!optimal && (
        <p className="comparison-note">
          Order matters. Re-enabling an
          account after disabling it
          undoes the containment, so the
          same operations can score
          differently depending on
          sequence.
        </p>
      )}
    </section>
  );
}
