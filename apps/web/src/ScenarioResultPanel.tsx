import type {
  ScenarioScore,
} from "@polymorph/simulation";

import "./ScenarioResultPanel.css";

interface ScenarioResultPanelProps {
  score: ScenarioScore;
  actionCount: number;
  evidenceCount: number;
  findingCount: number;
}

export function ScenarioResultPanel({
  score,
  actionCount,
  evidenceCount,
  findingCount,
}: ScenarioResultPanelProps) {
  return (
    <section
      className="result-panel"
      aria-label="Post-incident result"
    >
      <div className="result-panel-heading">
        <div>
          <p className="result-eyebrow">
            Post-incident result
          </p>
          <h4>Response objectives completed</h4>
          <p>
            The deterministic runtime confirms that every exposed response objective is satisfied.
          </p>
        </div>

        <div className="result-score">
          <strong>{score.percentage}%</strong>
          <span>Objective score</span>
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

      <p className="result-note">
        Score is based only on scenario response objectives. Evidence and finding counts are report context and do not affect the score in this milestone.
      </p>
    </section>
  );
}
