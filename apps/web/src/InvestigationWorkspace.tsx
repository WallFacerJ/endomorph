import {
  useMemo,
} from "react";

import {
  ScenarioOutcomePanel,
} from "./ScenarioOutcomePanel";

import {
  ScenarioResultPanel,
} from "./ScenarioResultPanel";

import {
  ResponseActionPanel,
} from "./ResponseActionPanel";

import {
  InstructorReviewPanel,
} from "./InstructorReviewPanel";

import {
  DetectionReviewPanel,
} from "./DetectionReviewPanel";

import {
  reviewDetections,
} from "./detectionReview";

import {
  InvestigationBrief,
} from "./InvestigationBrief";

import {
  ResponseComparisonPanel,
} from "./ResponseComparisonPanel";

import type {
  AnalystCaseState,
  InvestigationCoverage,
  ResponseComparison,
  ScenarioAction,
  ScenarioDefinition,
  ScenarioState,
  SiemEventRecord,
} from "./simulationAdapter";

/**
 * The Investigation workspace.
 *
 * Second extraction from App, after the case view. This one owns the brief,
 * the correlated timeline, the response surface, and everything the run
 * reports at finalization -- coverage, question score, counterfactuals, and
 * instructor review.
 *
 * Presentation only, like CaseWorkspace: all state stays in App, so evidence
 * collected from the timeline is the same state the case graph and coverage
 * read.
 */

export interface InvestigationWorkspaceProps {
  scenario: ScenarioDefinition;
  scenarioState: ScenarioState;
  questionAnswers: Readonly<
    Record<string, string>
  >;
  onQuestionAnswerChange: (
    questionId: string,
    answer: string,
  ) => void;
  observedTechniqueIds: readonly string[];
  instructorMode: boolean;
  scaffolding: boolean;

  /** Which half of the brief this view shows. */
  briefSection: "brief" | "questions";
  responseActions: readonly ScenarioAction[];
  onPerformAction: (
    actionId: string,
  ) => void;
  analystCase: AnalystCaseState;
  /** The SIEM projection of the events currently in view. */
  siemRecords: readonly SiemEventRecord[];
  coverage?: InvestigationCoverage;
  questionScore: {
    earned: number;
    available: number;
  };
  responseComparison?: ResponseComparison;
  isEvidenceCollected: (
    eventId: string | undefined,
  ) => boolean;
  onCollectEvidence: (
    eventId: string | undefined,
  ) => void;
  formatTimestamp: (
    timestamp: string | undefined,
  ) => string;
}

export function InvestigationWorkspace({
  scenario,
  scenarioState,
  questionAnswers,
  onQuestionAnswerChange,
  observedTechniqueIds,
  instructorMode,
  scaffolding,
  briefSection,
  responseActions,
  onPerformAction,
  analystCase,
  siemRecords,
  coverage,
  questionScore,
  responseComparison,
  isEvidenceCollected,
  onCollectEvidence,
  formatTimestamp,
}: InvestigationWorkspaceProps) {
  const context = scenario.investigation;

  // Only computed once the run is over, so the cost never lands during the
  // investigation and the labels are never in memory while they would spoil
  // it. Roughly 20,000 records against the shipped ruleset.
  const detectionReview = useMemo(
    () =>
      scenarioState.finalized
        ? reviewDetections(scenario)
        : undefined,
    [scenario, scenarioState.finalized],
  );

  const account =
    scenarioState.world.accounts[
      context.accountId
    ];

  const device =
    scenarioState.world.devices[
      context.deviceId
    ];

  const session =
    scenarioState.world.sessions[
      context.sessionId
    ];

  return (
          <section className="workspace-section">
            <InvestigationBrief
              questions={
                scenario.questions ?? []
              }
              techniques={
                scenario.groundTruth
                  ?.techniques ?? []
              }
              answers={questionAnswers}
              onAnswerChange={
                onQuestionAnswerChange
              }
              observedTechniqueIds={
                observedTechniqueIds
              }
              finalized={
                scenarioState.finalized
              }
              revealAnswers={
                instructorMode &&
                scenarioState.finalized
              }
              revealTechniques={
                scaffolding ||
                scenarioState.finalized
              }
              section={briefSection}
            />

            {/*
              Finalize used to sit here. The brief now renders above it --
              an ATT&CK matrix and six questions tall -- which pushed the
              action that completes the run below the fold. It lives in the
              header instead, where it is always reachable and sits beside
              the other run-level control.
            */}
            <div className="section-heading">
              <div>
                <p className="eyebrow">
                  Investigation
                </p>
                <h3>Correlated incident timeline</h3>
              </div>
            </div>

            {(scaffolding ||
              scenarioState.finalized) && (
              <ScenarioOutcomePanel
                outcome={
                  scenarioState.outcome
                }
              />
            )}

            {scaffolding ||
            scenarioState.finalized ? (
              <ResponseActionPanel
                actions={responseActions}
                performedActionIds={scenarioState.performedActionIds}
                score={scenarioState.score}
                showScore={
                  scaffolding ||
                  scenarioState.finalized
                }
                finalized={scenarioState.finalized}
                onPerform={onPerformAction}
              />
            ) : (
              <p className="response-relocated">
                Response operations are
                performed from the
                console that owns them
                &mdash; endpoint actions
                in <strong>Endpoint</strong>,
                account and session
                actions in{" "}
                <strong>Identity</strong>.
              </p>
            )}

            {/*
              Gated on finalization for the same reason the instructor's
              ground truth is: these numbers are computed from the malicious
              labels, and a panel showing which events are malicious would
              end the exercise the moment it was opened.
            */}
            {scenarioState.finalized &&
              detectionReview && (
                <DetectionReviewPanel
                  review={detectionReview}
                />
              )}

            {scenarioState.finalized && (
              <ScenarioResultPanel
                status={scenarioState.outcome.status}
                score={scenarioState.score}
                actionCount={scenarioState.performedActionIds.length}
                evidenceCount={analystCase.collectedEventIds.length}
                findingCount={analystCase.findings.length}
                coverage={coverage}
                questionScore={{
                  earned: questionScore.earned,
                  available:
                    questionScore.available,
                }}
              />
            )}

            {scenarioState.finalized &&
              responseComparison && (
                <ResponseComparisonPanel
                  comparison={
                    responseComparison
                  }
                />
              )}

            {scenarioState.finalized &&
              instructorMode && (
                <InstructorReviewPanel
                  scenario={scenario}
                  state={scenarioState}
                />
              )}

            <div className="summary-grid">
              <article className="summary-card">
                <span>Account</span>
                <strong>
                  {account?.username ?? "—"}
                </strong>
                <small>
                  Status: {account?.status ?? "—"}
                </small>
              </article>
              <article className="summary-card">
                <span>Endpoint</span>
                <strong>
                  {device?.hostname ?? "—"}
                </strong>
                <small>
                  {device?.operatingSystem ?? "—"}
                </small>
              </article>
              <article className="summary-card">
                <span>Session</span>
                <strong>
                  {session?.status ?? "—"}
                </strong>
                <small>
                  {session?.id ?? "No session"}
                </small>
              </article>
              <article className="summary-card">
                <span>Case evidence</span>
                <strong>
                  {analystCase.collectedEventIds.length}
                </strong>
                <small>
                  {analystCase.findings.length} findings
                </small>
              </article>
            </div>

            <div className="timeline-list">
              {siemRecords.map(
                (event) => {
                  const collected =
                    isEvidenceCollected(
                      event.eventId,
                    );

                  return (
                    <article
                      key={event.eventId}
                      className="timeline-item"
                    >
                      <div
                        className={`timeline-marker ${event.family}`}
                      />
                      <div className="timeline-content">
                        <div className="timeline-meta">
                          <span>
                            {event.family}
                          </span>
                          <time>
                            {formatTimestamp(
                              event.timestamp,
                            )}
                          </time>
                        </div>
                        <strong>
                          {event.message}
                        </strong>
                        <div className="timeline-actions">
                          <small>
                            {event.eventType} · {event.source}
                          </small>
                          <button
                            type="button"
                            className="evidence-button"
                            onClick={() =>
                              onCollectEvidence(
                                event.eventId,
                              )
                            }
                            disabled={scenarioState.finalized || collected}
                          >
                            {collected
                              ? "Evidence collected"
                              : "Collect evidence"}
                          </button>
                        </div>
                      </div>
                    </article>
                  );
                },
              )}
            </div>
          </section>
  );
}
