import type {
  ScenarioAction,
  ScenarioScore,
} from "./simulationAdapter";

import "./ResponseActionPanel.css";

interface ResponseActionPanelProps {
  actions: readonly ScenarioAction[];
  performedActionIds:
    readonly string[];
  score: ScenarioScore;
  onPerform: (actionId: string) => void;
}

export function ResponseActionPanel({
  actions,
  performedActionIds,
  score,
  onPerform,
}: ResponseActionPanelProps) {
  return (
    <section
      className="response-panel"
      aria-label="Response actions"
    >
      <div className="response-panel-header">
        <div>
          <p className="response-eyebrow">
            Response actions
          </p>
          <h4>Choose remediation</h4>
          <p>
            Each action changes canonical simulation state. Objective progress and score update from the resulting world.
          </p>
        </div>

        <div className="response-score">
          <strong>
            {score.percentage}%
          </strong>
          <span>
            {score.completedObjectives}/{score.totalObjectives} objectives
          </span>
        </div>
      </div>

      <div className="response-action-grid">
        {actions.map((action) => {
          const performed =
            performedActionIds.includes(
              action.id,
            );

          return (
            <article
              key={action.id}
              className={
                performed
                  ? "response-action performed"
                  : "response-action"
              }
            >
              <div>
                <strong>{action.label}</strong>
                <p>{action.description}</p>
              </div>

              <button
                type="button"
                className={
                  performed
                    ? "response-action-button performed"
                    : "response-action-button"
                }
                disabled={performed}
                onClick={() =>
                  onPerform(action.id)
                }
              >
                {performed
                  ? "Action performed"
                  : "Perform action"}
              </button>
            </article>
          );
        })}
      </div>
    </section>
  );
}
