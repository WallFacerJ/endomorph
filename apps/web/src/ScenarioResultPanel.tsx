import type {
  InvestigationCoverage,
  ScenarioOutcomeStatus,
  ScenarioScore,
} from "./simulationAdapter";

import type {
  KeyEvidenceSummary,
} from "./keyEvidence";

import "./ScenarioResultPanel.css";

interface ScenarioResultPanelProps {
  status: ScenarioOutcomeStatus;
  score: ScenarioScore;
  actionCount: number;
  evidenceCount: number;
  findingCount: number;

  /**
   * How much of the incident the analyst actually reached.
   *
   * Objective scoring answers whether the world ended in the right state.
   * It cannot separate an analyst who scoped the intrusion from one who read
   * the alert, guessed correctly, and stopped -- both land the same score.
   * Coverage answers that, and names what was missed so the number is
   * explainable rather than opaque.
   */
  coverage?: InvestigationCoverage;

  /**
   * Which of the incident's key events the analyst actually collected.
   *
   * Coverage says which entities were reached; this says whether the smoking
   * guns themselves were banked. Shown side by side because a high coverage
   * with low key-evidence capture is a real and instructive result: the
   * analyst walked the right hosts without collecting the proof.
   */
  keyEvidence?: KeyEvidenceSummary;

  /** Points earned on the investigation questions, when a scenario has any. */
  questionScore?: {
    earned: number;
    available: number;
  };
}

export function ScenarioResultPanel({
  status,
  score,
  actionCount,
  evidenceCount,
  findingCount,
  coverage,
  keyEvidence,
  questionScore,
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
        {coverage &&
          coverage.entities.length >
            0 && (
            <div>
              <span>
                Incident coverage
              </span>
              <strong>
                {coverage.percentage}%
              </strong>
            </div>
          )}
        {keyEvidence &&
          keyEvidence.total > 0 && (
            <div>
              <span>
                Key evidence
              </span>
              <strong>
                {keyEvidence.captured}/
                {keyEvidence.total}
              </strong>
            </div>
          )}
        {questionScore &&
          questionScore.available >
            0 && (
            <div>
              <span>Questions</span>
              <strong>
                {questionScore.earned}/
                {
                  questionScore.available
                }
              </strong>
            </div>
          )}
        <div>
          <span>Evidence collected</span>
          <strong>{evidenceCount}</strong>
        </div>
        <div>
          <span>Findings</span>
          <strong>{findingCount}</strong>
        </div>
      </div>

      {coverage &&
        coverage.missed.length > 0 && (
          <div className="result-coverage">
            <p className="result-coverage-head">
              Reached{" "}
              <strong>
                {coverage.reached.length}
              </strong>{" "}
              of{" "}
              <strong>
                {coverage.entities.length}
              </strong>{" "}
              entities involved in this
              incident. Never opened:
            </p>
            <ul className="result-coverage-missed">
              {coverage.missed.map(
                (entity) => (
                  <li key={entity.id}>
                    <span className="result-coverage-kind">
                      {entity.kind}
                    </span>
                    <span>
                      {entity.label}
                    </span>
                  </li>
                ),
              )}
            </ul>
            <p className="result-note">
              Coverage is measured by
              comparing the entities
              your collected evidence
              touched against the
              entities the incident
              actually involved. A
              correct containment
              decision reached without
              scoping the intrusion
              still leaves gaps.
            </p>
          </div>
        )}

      {keyEvidence &&
        keyEvidence.missed.length > 0 && (
          <div className="result-coverage">
            <p className="result-coverage-head">
              Collected{" "}
              <strong>
                {keyEvidence.captured}
              </strong>{" "}
              of{" "}
              <strong>
                {keyEvidence.total}
              </strong>{" "}
              key incident events. Never
              collected:
            </p>
            <ul className="result-coverage-missed">
              {keyEvidence.missed.map(
                (step) => (
                  <li
                    key={step.eventId}
                  >
                    {step.techniqueId && (
                      <span className="result-coverage-kind">
                        {step.techniqueId}
                      </span>
                    )}
                    <span>
                      {step.title ??
                        step.significance}
                    </span>
                  </li>
                ),
              )}
            </ul>
            <p className="result-note">
              These are the events the
              incident turned on. Reaching
              the host is not the same as
              banking the proof of what
              happened on it.
            </p>
          </div>
        )}

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
