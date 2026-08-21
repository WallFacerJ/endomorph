import type {
  ScenarioDefinition,
  ScenarioState,
} from "./simulationAdapter";

import "./InstructorReviewPanel.css";

interface InstructorReviewPanelProps {
  scenario: ScenarioDefinition;
  state: ScenarioState;
}

export function InstructorReviewPanel({
  scenario,
  state,
}: InstructorReviewPanelProps) {
  const performedActions =
    state.performedActionIds.flatMap(
      (actionId) => {
        const action =
          scenario.actions.find(
            (candidate) =>
              candidate.id === actionId,
          );

        return action ? [action] : [];
      },
    );
  const groundTruth =
    scenario.groundTruth;

  if (!state.finalized || !groundTruth) {
    return null;
  }

  return (
    <section
      className="instructor-review"
      aria-label="Instructor review"
    >
      <div className="instructor-review-heading">
        <div>
          <p className="instructor-eyebrow">
            Instructor review
          </p>
          <h4>Ground truth and response assessment</h4>
          <p>{groundTruth.summary}</p>
        </div>

        <div className="instructor-score">
          <strong>{state.score.percentage}%</strong>
          <span>Final score</span>
        </div>
      </div>

      <div className="instructor-score-grid">
        <div>
          <span>Objective completion</span>
          <strong>
            {state.score.objectivePercentage}%
          </strong>
        </div>
        <div>
          <span>Response penalty</span>
          <strong>
            {state.score.responsePenalty > 0
              ? `−${state.score.responsePenalty}`
              : "0"}
          </strong>
        </div>
        <div>
          <span>Outcome</span>
          <strong>{state.outcome.status}</strong>
        </div>
      </div>

      <div className="instructor-section">
        <h5>Ground-truth timeline</h5>
        <div className="instructor-timeline">
          {groundTruth.timeline.map(
            (entry) => {
              const event =
                scenario.openingEvents.find(
                  (candidate) =>
                    candidate.id ===
                    entry.eventId,
                );

              return (
                <article key={entry.eventId}>
                  <div>
                    <strong>
                      {event?.type ?? entry.eventId}
                    </strong>
                    <small>{entry.eventId}</small>
                  </div>
                  <p>{entry.significance}</p>
                </article>
              );
            },
          )}
        </div>
      </div>

      <div className="instructor-section">
        <h5>Performed response actions</h5>
        {performedActions.length === 0 ? (
          <p className="instructor-empty">
            No response actions were performed before submission.
          </p>
        ) : (
          <div className="instructor-action-list">
            {performedActions.map((action) => (
              <article key={action.id}>
                <div>
                  <strong>{action.label}</strong>
                  <small>{action.id}</small>
                </div>
                <p>
                  {action.assessment
                    ? action.assessment.rationale
                    : "No response-quality penalty was authored for this action."}
                </p>
                <span>
                  {action.assessment?.penalty
                    ? `−${action.assessment.penalty} points`
                    : "No penalty"}
                </span>
              </article>
            ))}
          </div>
        )}
      </div>

      <p className="instructor-boundary-note">
        Local instructor mode is a presentation boundary for training and review, not an authentication or authorization boundary. Server-enforced roles belong to a later multi-user runtime.
      </p>
    </section>
  );
}
