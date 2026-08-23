import {
  type FormEvent,
} from "react";

import {
  IncidentCommand,
} from "./IncidentCommand";

import {
  CaseReportPanel,
} from "./CaseReportPanel";

import {
  buildCaseReport,
} from "./caseReport";

import {
  buildIncidentReport,
} from "./simulationAdapter";

import type {
  AnalystCaseState,
  IncidentCaseState,
  ScenarioDefinition,
  ScenarioState,
  SiemEventRecord,
  SimulationEvent,
} from "./simulationAdapter";

/**
 * The Case workspace.
 *
 * Split out of App, which had grown past 1,600 lines and owned replay, the
 * walkthrough, first-run orientation, coverage, and every view body. The
 * case view was the largest single block and the most self-contained, so it
 * moves first.
 *
 * This is presentation only: every piece of state still lives in App, so
 * evidence collected here is the same state the incident graph, the
 * coverage score, and run persistence all read.
 */

export interface CaseWorkspaceProps {
  scenario: ScenarioDefinition;
  scenarioState: ScenarioState;
  questionAnswers: Readonly<
    Record<string, string>
  >;
  questionScore: {
    earned: number;
    available: number;
  };
  siemRecords: readonly SiemEventRecord[];
  analystCase: AnalystCaseState;
  incidentCase: IncidentCaseState;
  onIncidentCaseChange: (
    next: IncidentCaseState,
  ) => void;
  collectedEvidence: readonly SimulationEvent[];
  siemByEventId: ReadonlyMap<
    string,
    SiemEventRecord
  >;
  selectedEvidenceIds: readonly string[];
  onToggleFindingEvidence: (
    eventId: string,
  ) => void;
  findingTitle: string;
  onFindingTitleChange: (
    value: string,
  ) => void;
  findingSummary: string;
  onFindingSummaryChange: (
    value: string,
  ) => void;
  onSubmitFinding: (
    event: FormEvent<HTMLFormElement>,
  ) => void;
  caseError: string | null;
  finalized: boolean;
  onPivotToSiem: (query: string) => void;
  formatTimestamp: (
    timestamp: string | undefined,
  ) => string;
}

export function CaseWorkspace({
  scenario,
  questionAnswers,
  questionScore,
  scenarioState,
  siemRecords,
  analystCase,
  incidentCase,
  onIncidentCaseChange,
  collectedEvidence,
  siemByEventId,
  selectedEvidenceIds,
  onToggleFindingEvidence,
  findingTitle,
  onFindingTitleChange,
  findingSummary,
  onFindingSummaryChange,
  onSubmitFinding,
  caseError,
  finalized,
  onPivotToSiem,
  formatTimestamp,
}: CaseWorkspaceProps) {
  return (
          <section className="workspace-section">
            <IncidentCommand
              world={scenarioState.world}
              records={
                siemRecords
              }
              collectedEventIds={
                analystCase.collectedEventIds
              }
              caseState={incidentCase}
              onCaseChange={
                onIncidentCaseChange
              }
              onPivotToSiem={onPivotToSiem}
              readOnly={finalized}
            />

            {/*
              The case view already called its timeline "the report". It was
              not one until it could leave the page.
            */}
            <CaseReportPanel
              markdown={buildCaseReport({
                scenario,
                state: scenarioState,
                report: buildIncidentReport(
                  scenarioState.world,
                  siemRecords,
                  analystCase.collectedEventIds,
                  incidentCase,
                ),
                questionAnswers,
                questionScore,
                formatTimestamp,
              })}
            />

            <div className="section-heading">
              <div>
                <p className="eyebrow">
                  Analyst case
                </p>
                <h3>Build your evidence-backed finding</h3>
              </div>
              <div className="case-stats">
                <span>
                  {analystCase.collectedEventIds.length} evidence
                </span>
                <span>
                  {analystCase.findings.length} findings
                </span>
              </div>
            </div>

            <div className="case-grid">
              <article className="case-panel">
                <p className="eyebrow">
                  Collected evidence
                </p>
                <h4>Evidence notebook</h4>
                <p className="case-copy">
                  Select collected telemetry to support the finding you are writing.
                </p>

                {collectedEvidence.length === 0 ? (
                  <div className="case-empty">
                    Collect events from Investigation, Endpoint, or Identity first.
                  </div>
                ) : (
                  <div className="case-evidence-list">
                    {collectedEvidence.map(
                      (event) => {
                        const record =
                          siemByEventId.get(
                            event.id,
                          );
                        const selected =
                          selectedEvidenceIds.includes(
                            event.id,
                          );

                        return (
                          <label
                            key={event.id}
                            className={
                              selected
                                ? "case-evidence-item selected"
                                : "case-evidence-item"
                            }
                          >
                            <input
                              type="checkbox"
                              checked={selected}
                              disabled={scenarioState.finalized}
                              onChange={() =>
                                onToggleFindingEvidence(
                                  event.id,
                                )
                              }
                            />
                            <span>
                              <strong>
                                {record?.message ??
                                  event.type}
                              </strong>
                              <small>
                                {event.id} · {formatTimestamp(event.timestamp)}
                              </small>
                            </span>
                          </label>
                        );
                      },
                    )}
                  </div>
                )}
              </article>

              <article className="case-panel">
                <p className="eyebrow">
                  Analyst finding
                </p>
                <h4>Document your conclusion</h4>
                <p className="case-copy">
                  Findings are your interpretation of the evidence, not ground truth.
                </p>

                <form
                  className="finding-form"
                  onSubmit={onSubmitFinding}
                >
                  <label>
                    Finding title
                    <input
                      type="text"
                      value={findingTitle}
                      disabled={scenarioState.finalized}
                      onChange={(event) =>
                        onFindingTitleChange(
                          event.target.value,
                        )
                      }
                      placeholder="Example: Account compromise led to suspicious PowerShell"
                    />
                  </label>

                  <label>
                    Analyst summary
                    <textarea
                      value={findingSummary}
                      disabled={scenarioState.finalized}
                      onChange={(event) =>
                        onFindingSummaryChange(
                          event.target.value,
                        )
                      }
                      rows={6}
                      placeholder="Explain what happened and why the selected evidence supports your conclusion."
                    />
                  </label>

                  <div className="finding-form-footer">
                    <small>
                      {selectedEvidenceIds.length} evidence linked
                    </small>
                    <button
                      type="submit"
                      className="primary-button"
                      disabled={
                        scenarioState.finalized ||
                        findingTitle.trim().length === 0 ||
                        findingSummary.trim().length === 0 ||
                        selectedEvidenceIds.length === 0
                      }
                    >
                      Save finding
                    </button>
                  </div>
                </form>

                {caseError && (
                  <div className="case-error">
                    {caseError}
                  </div>
                )}
              </article>
            </div>

            <div className="finding-list-section">
              <div className="section-heading compact-heading">
                <div>
                  <p className="eyebrow">
                    Saved findings
                  </p>
                  <h3>Case conclusions</h3>
                </div>
              </div>

              {analystCase.findings.length === 0 ? (
                <div className="case-empty">
                  No findings yet. Collect evidence, select it above, and document your conclusion.
                </div>
              ) : (
                <div className="finding-list">
                  {analystCase.findings.map(
                    (finding) => (
                      <article
                        key={finding.id}
                        className="finding-card"
                      >
                        <div className="finding-card-header">
                          <div>
                            <p className="eyebrow">
                              {finding.id}
                            </p>
                            <h4>
                              {finding.title}
                            </h4>
                          </div>
                          <span className="evidence-count-badge">
                            {finding.evidenceEventIds.length} evidence
                          </span>
                        </div>
                        <p>
                          {finding.summary}
                        </p>
                        <div className="finding-evidence-links">
                          {finding.evidenceEventIds.map(
                            (eventId) => (
                              <span
                                key={eventId}
                                className="evidence-pill"
                              >
                                {siemByEventId.get(eventId)?.eventType ?? eventId}
                              </span>
                            ),
                          )}
                        </div>
                      </article>
                    ),
                  )}
                </div>
              )}
            </div>
          </section>
  );
}
