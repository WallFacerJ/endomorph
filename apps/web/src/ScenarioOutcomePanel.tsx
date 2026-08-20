import type {
  ScenarioOutcome,
} from "@polymorph/simulation";

import "./ScenarioOutcomePanel.css";

interface ScenarioOutcomePanelProps {
  outcome: ScenarioOutcome;
}

export function ScenarioOutcomePanel({
  outcome,
}: ScenarioOutcomePanelProps) {
  const metCount =
    outcome.objectives.filter(
      (objective) => objective.met,
    ).length;

  return (
    <section
      className={`outcome-panel ${outcome.status}`}
      aria-label="Response objectives"
    >
      <div className="outcome-panel-header">
        <div>
          <p className="outcome-eyebrow">
            Response objectives
          </p>
          <h4>
            {outcome.status === "succeeded"
              ? "Scenario succeeded"
              : "Scenario in progress"}
          </h4>
        </div>
        <span className="outcome-count">
          {metCount}/{outcome.objectives.length} met
        </span>
      </div>

      <div className="outcome-objectives">
        {outcome.objectives.map(
          (objective) => (
            <article
              key={objective.id}
              className={
                objective.met
                  ? "outcome-objective met"
                  : "outcome-objective pending"
              }
            >
              <span
                className="outcome-objective-indicator"
                aria-hidden="true"
              >
                {objective.met ? "✓" : "○"}
              </span>
              <div>
                <strong>
                  {objective.label}
                </strong>
                <p>
                  {objective.description}
                </p>
              </div>
              <span className="outcome-objective-state">
                {objective.met
                  ? "Met"
                  : "Pending"}
              </span>
            </article>
          ),
        )}
      </div>
    </section>
  );
}
