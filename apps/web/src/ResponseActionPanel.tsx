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
  /**
   * Professional runs hide the running score. A live percentage above the
   * action cards turns remediation into a guessing game against a number
   * rather than a judgement about the incident.
   */
  showScore: boolean;
  finalized: boolean;
  onPerform: (actionId: string) => void;
}

export function ResponseActionPanel({
  actions,
  performedActionIds,
  score,
  showScore,
  finalized,
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
            {finalized
              ? "This investigation is finalized. Reset the scenario to try a different response path."
              : showScore
                ? "Each action changes canonical simulation state. Objective progress and score update from the resulting world."
                : "Each action changes canonical simulation state. Decide from the evidence; the outcome is assessed when you finalize."}
          </p>
        </div>

        {showScore && (
          <div className="response-score">
            <strong>
              {score.percentage}%
            </strong>
            <span>
              {score.completedObjectives}/{score.totalObjectives} objectives
            </span>
          </div>
        )}
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
                disabled={
                  performed || finalized
                }
                onClick={() =>
                  onPerform(action.id)
                }
              >
                {performed
                  ? "Action performed"
                  : finalized
                    ? "Run finalized"
                    : "Perform action"}
              </button>
            </article>
          );
        })}
      </div>
    </section>
  );
}
