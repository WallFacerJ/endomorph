import type {
  ScenarioOutcomeStatus,
  ScenarioScore,
} from "./simulationAdapter";

import "./ScenarioResultPanel.css";

interface ScenarioResultPanelProps {
  status: ScenarioOutcomeStatus;
  score: ScenarioScore;
  actionCount: number;
  evidenceCount: number;
  findingCount: number;
}

export function ScenarioResultPanel({
  status,
  score,
  actionCount,
  evidenceCount,
  findingCount,
}: ScenarioResultPanelProps) {
  const succeeded =
    status === "succeeded";
  const penalized =
    score.responsePenalty > 0;

  return (
    <section
      className={
        succeeded
          ? "result-panel succeeded"
          : "result-panel failed"
      }
      aria-label="Post-incident result"
    >
      <div className="result-panel-heading">
        <div>
          <p className="result-eyebrow">
            Post-incident result
          </p>
          <h4>
            {succeeded
              ? "Investigation succeeded"
              : "Investigation failed"}
          </h4>
          <p>
            {succeeded
              ? "The deterministic runtime confirms that every exposed response objective was satisfied when the investigation was finalized."
              : "The investigation was finalized before every exposed response objective was satisfied. The partial score is preserved for review."}
          </p>
        </div>

        <div className="result-score">
          <strong>{score.percentage}%</strong>
          <span>Final score</span>
        </div>
      </div>

      <div className="result-metrics">
        <div>
          <span>Objectives</span>
          <strong>
            {score.completedObjectives}/{score.totalObjectives}
          </strong>
        </div>
        <div>
          <span>Objective score</span>
          <strong>
            {score.objectivePercentage}%
          </strong>
        </div>
        <div>
          <span>Response penalty</span>
          <strong>
            {score.responsePenalty > 0
              ? `−${score.responsePenalty}`
              : "0"}
          </strong>
        </div>
        <div>
          <span>Response actions</span>
          <strong>{actionCount}</strong>
        </div>
        <div>
          <span>Evidence collected</span>
          <strong>{evidenceCount}</strong>
        </div>
        <div>
          <span>Findings</span>
          <strong>{findingCount}</strong>
        </div>
      </div>

      {penalized && (
        <p className="result-note">
          One or more submitted response actions carried a deterministic response-quality penalty. Objective completion and response quality are shown separately so the final score remains explainable.
        </p>
      )}

      <p className="result-note">
        Final score equals objective completion minus authored response-quality penalties, clamped to 0–100. Evidence and finding counts are report context and do not affect the score.
      </p>
    </section>
  );
}
