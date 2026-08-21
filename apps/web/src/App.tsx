import {
  type FormEvent,
  useEffect,
  useMemo,
  useState,
} from "react";

import "./App.css";

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
  addAnalystFinding,
  collectAnalystEvidence,
  createAnalystCaseState,
  edrProjection,
  finalizeScenarioState,
  getScenarioState,
  identityProjection,
  rebuildProjection,
  resolveCollectedEvidence,
  siemProjection,
} from "./simulationAdapter";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

import {
  loadScenario,
  resolveScenarioPath,
} from "./scenarioLoader";

type WorkspaceView =
  | "alerts"
  | "timeline"
  | "endpoint"
  | "identity"
  | "case";

const navItems: ReadonlyArray<{
  id: WorkspaceView;
  label: string;
}> = [
  { id: "alerts", label: "Alerts" },
  { id: "timeline", label: "Investigation" },
  { id: "endpoint", label: "Endpoint" },
  { id: "identity", label: "Identity" },
  { id: "case", label: "Case" },
];

function formatTimestamp(
  timestamp: string | undefined,
): string {
  if (!timestamp) {
    return "—";
  }

  return new Intl.DateTimeFormat(
    "en-US",
    {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    },
  ).format(new Date(timestamp));
}

interface ScenarioWorkspaceProps {
  scenario: ScenarioDefinition;
  scenarioPath: string;
  instructorMode: boolean;
}

function ScenarioWorkspace({
  scenario,
  scenarioPath,
  instructorMode,
}: ScenarioWorkspaceProps) {
  const context =
    scenario.investigation;

  const [activeView, setActiveView] =
    useState<WorkspaceView>(
      "alerts",
    );
  const [performedActionIds, setPerformedActionIds] =
    useState<string[]>([]);
  const [finalized, setFinalized] =
    useState(false);
  const [analystCase, setAnalystCase] =
    useState(() =>
      createAnalystCaseState(),
    );
  const [findingTitle, setFindingTitle] =
    useState("");
  const [findingSummary, setFindingSummary] =
    useState("");
  const [selectedEvidenceIds, setSelectedEvidenceIds] =
    useState<string[]>([]);
  const [caseError, setCaseError] =
    useState<string | null>(null);

  const scenarioState = useMemo(
    () =>
      finalized
        ? finalizeScenarioState(
            scenario,
            performedActionIds,
          )
        : getScenarioState(
            scenario,
            performedActionIds,
          ),
    [
      scenario,
      performedActionIds,
      finalized,
    ],
  );

  const projections = useMemo(
    () => ({
      identity: rebuildProjection(
        identityProjection,
        scenarioState.events,
      ),
      edr: rebuildProjection(
        edrProjection,
        scenarioState.events,
      ),
      siem: rebuildProjection(
        siemProjection,
        scenarioState.events,
      ),
    }),
    [scenarioState.events],
  );

  const siemByEventId = useMemo(
    () =>
      new Map(
        projections.siem.events.map(
          (event) => [
            event.eventId,
            event,
          ],
        ),
      ),
    [projections.siem.events],
  );

  const collectedEvidence = useMemo(
    () =>
      resolveCollectedEvidence(
        analystCase,
        scenarioState.events,
      ),
    [
      analystCase,
      scenarioState.events,
    ],
  );

  const user =
    scenarioState.world.users[
      context.userId
    ];
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

  const alert =
    projections.edr.alerts.find(
      (candidate) =>
        candidate.alertId ===
        context.alertId,
    );

  const process =
    projections.edr.processes.find(
      (candidate) =>
        alert?.relatedEventIds.includes(
          candidate.eventId,
        ),
    ) ?? projections.edr.processes[0];

  const connection =
    projections.edr.networkConnections.find(
      (candidate) =>
        alert?.relatedEventIds.includes(
          candidate.eventId,
        ),
    ) ??
    projections.edr.networkConnections[0];

  const loginActivity =
    projections.identity.activity.find(
      (activity) =>
        activity.kind ===
          "login_succeeded" &&
        alert?.relatedEventIds.includes(
          activity.eventId,
        ),
    ) ??
    projections.identity.activity.find(
      (activity) =>
        activity.kind ===
        "login_succeeded",
    );

  const responseActions =
    context.responseActionIds.flatMap(
      (actionId) => {
        const action =
          scenario.actions.find(
            (candidate) =>
              candidate.id === actionId,
          );

        return action ? [action] : [];
      },
    );

  const responseSucceeded =
    scenarioState.outcome.status ===
    "succeeded";

  const runStatusLabel =
    scenarioState.finalized
      ? responseSucceeded
        ? "Succeeded"
        : "Failed"
      : responseSucceeded
        ? "Objectives met"
        : performedActionIds.length > 0
          ? "Response in progress"
          : "Needs action";

  const isEvidenceCollected = (
    eventId: string | undefined,
  ): boolean =>
    eventId !== undefined &&
    analystCase.collectedEventIds.includes(
      eventId,
    );

  const collectEvidence = (
    eventId: string | undefined,
  ) => {
    if (!eventId || scenarioState.finalized) {
      return;
    }

    setCaseError(null);
    setAnalystCase((current) =>
      collectAnalystEvidence(
        current,
        eventId,
        scenarioState.events,
      ),
    );
  };

  const toggleFindingEvidence = (
    eventId: string,
  ) => {
    if (scenarioState.finalized) {
      return;
    }

    setSelectedEvidenceIds((current) =>
      current.includes(eventId)
        ? current.filter(
            (candidate) =>
              candidate !== eventId,
          )
        : [
            ...current,
            eventId,
          ],
    );
  };

  const submitFinding = (
    event: FormEvent<HTMLFormElement>,
  ) => {
    event.preventDefault();

    if (scenarioState.finalized) {
      return;
    }

    try {
      const next = addAnalystFinding(
        analystCase,
        {
          id:
            `finding-${analystCase.findings.length + 1}`,
          title: findingTitle,
          summary: findingSummary,
          evidenceEventIds:
            selectedEvidenceIds,
        },
        scenarioState.events,
      );

      setAnalystCase(next);
      setFindingTitle("");
      setFindingSummary("");
      setSelectedEvidenceIds([]);
      setCaseError(null);
    } catch (caught: unknown) {
      setCaseError(
        caught instanceof Error
          ? caught.message
          : String(caught),
      );
    }
  };

  const performResponseAction = (
    actionId: string,
  ) => {
    if (
      scenarioState.finalized ||
      performedActionIds.includes(
        actionId,
      ) ||
      !responseActions.some(
        (action) =>
          action.id === actionId,
      )
    ) {
      return;
    }

    setPerformedActionIds((current) =>
      current.includes(actionId)
        ? current
        : [
            ...current,
            actionId,
          ],
    );
    setActiveView("timeline");
  };

  const finalizeInvestigation = () => {
    if (scenarioState.finalized) {
      return;
    }

    setFinalized(true);
    setActiveView("timeline");
  };

  const resetScenario = () => {
    setPerformedActionIds([]);
    setFinalized(false);
    setAnalystCase(
      createAnalystCaseState(),
    );
    setFindingTitle("");
    setFindingSummary("");
    setSelectedEvidenceIds([]);
    setCaseError(null);
    setActiveView("alerts");
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <p className="eyebrow">
            Polymorph
          </p>
          <h1>Security Console</h1>
          <p className="sidebar-copy">
            Synthetic analyst workspace
          </p>

          <nav className="workspace-nav">
            {navItems.map((item) => (
              <button
                key={item.id}
                type="button"
                className={
                  activeView === item.id
                    ? "nav-item active"
                    : "nav-item"
                }
                onClick={() =>
                  setActiveView(item.id)
                }
              >
                {item.label}
                {item.id === "case" &&
                  analystCase.collectedEventIds.length > 0 && (
                    <span className="nav-count">
                      {analystCase.collectedEventIds.length}
                    </span>
                  )}
              </button>
            ))}
          </nav>
        </div>

        <div className="sidebar-footer">
          <span className="status-dot" />
          <span>
            Deterministic run
            <small>
              {scenarioPath}
            </small>
          </span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">
              Training scenario
            </p>
            <h2>
              {scenario.name}
            </h2>
            <p className="scenario-description">
              {scenario.description}
            </p>
          </div>

          <div className="topbar-actions">
            <span
              className={
                scenarioState.finalized &&
                responseSucceeded
                  ? "incident-state contained"
                  : "incident-state active"
              }
            >
              {runStatusLabel}
            </span>
            <button
              type="button"
              className="secondary-button"
              onClick={resetScenario}
            >
              Reset scenario
            </button>
          </div>
        </header>

        {activeView === "alerts" && (
          <section className="workspace-section">
            <div className="section-heading">
              <div>
                <p className="eyebrow">
                  Alert queue
                </p>
                <h3>1 alert requires investigation</h3>
              </div>
            </div>

            <article className="alert-card">
              <div className="alert-card-header">
                <span className="severity-badge">
                  {alert?.severity ?? "high"}
                </span>
                <span className="timestamp">
                  {formatTimestamp(
                    alert?.timestamp,
                  )}
                </span>
              </div>

              <h3>
                {alert?.title ??
                  "Security alert"}
              </h3>
              <p>
                Correlated identity and endpoint telemetry indicates activity that requires analyst review.
              </p>

              <div className="detail-grid compact">
                <div>
                  <span>User</span>
                  <strong>
                    {user?.displayName ?? "—"}
                  </strong>
                </div>
                <div>
                  <span>Endpoint</span>
                  <strong>
                    {device?.hostname ?? "—"}
                  </strong>
                </div>
                <div>
                  <span>Account</span>
                  <strong>
                    {account?.username ?? "—"}
                  </strong>
                </div>
                <div>
                  <span>Case evidence</span>
                  <strong>
                    {analystCase.collectedEventIds.length}
                  </strong>
                </div>
              </div>

              <button
                type="button"
                className="primary-button"
                onClick={() =>
                  setActiveView("timeline")
                }
              >
                Open investigation
              </button>
            </article>
          </section>
        )}

        {activeView === "timeline" && (
          <section className="workspace-section">
            <div className="section-heading">
              <div>
                <p className="eyebrow">
                  Investigation
                </p>
                <h3>Correlated incident timeline</h3>
              </div>

              <button
                type="button"
                className="primary-button"
                onClick={finalizeInvestigation}
                disabled={scenarioState.finalized}
              >
                {scenarioState.finalized
                  ? "Investigation finalized"
                  : "Finalize investigation"}
              </button>
            </div>

            <ScenarioOutcomePanel
              outcome={scenarioState.outcome}
            />

            <ResponseActionPanel
              actions={responseActions}
              performedActionIds={scenarioState.performedActionIds}
              score={scenarioState.score}
              finalized={scenarioState.finalized}
              onPerform={performResponseAction}
            />

            {scenarioState.finalized && (
              <ScenarioResultPanel
                status={scenarioState.outcome.status}
                score={scenarioState.score}
                actionCount={scenarioState.performedActionIds.length}
                evidenceCount={analystCase.collectedEventIds.length}
                findingCount={analystCase.findings.length}
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
              {projections.siem.events.map(
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
                              collectEvidence(
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
        )}

        {activeView === "endpoint" && (
          <section className="workspace-section">
            <div className="section-heading">
              <div>
                <p className="eyebrow">
                  EDR projection
                </p>
                <h3>
                  {device?.hostname ?? "Endpoint"}
                </h3>
              </div>
            </div>

            <div className="detail-grid">
              <div>
                <span>Operating system</span>
                <strong>
                  {device?.operatingSystem ?? "—"}
                </strong>
              </div>
              <div>
                <span>IP address</span>
                <strong>
                  {device?.ipAddresses[0] ?? "—"}
                </strong>
              </div>
              <div>
                <span>Owner</span>
                <strong>
                  {user?.displayName ?? "—"}
                </strong>
              </div>
              <div>
                <span>Alert count</span>
                <strong>
                  {projections.edr.alerts.length}
                </strong>
              </div>
            </div>

            <div className="evidence-grid">
              <article className="evidence-card">
                <p className="eyebrow">
                  Process execution
                </p>
                <h4>
                  {process?.image ??
                    "No process telemetry"}
                </h4>
                <code>
                  {process?.commandLine ?? "—"}
                </code>
                <small>
                  PID {process?.processId ?? "—"} · {formatTimestamp(process?.timestamp)}
                </small>
                <button
                  type="button"
                  className="evidence-button"
                  onClick={() =>
                    collectEvidence(
                      process?.eventId,
                    )
                  }
                  disabled={
                    scenarioState.finalized ||
                    !process ||
                    isEvidenceCollected(
                      process.eventId,
                    )
                  }
                >
                  {isEvidenceCollected(
                    process?.eventId,
                  )
                    ? "Evidence collected"
                    : "Collect process evidence"}
                </button>
              </article>

              <article className="evidence-card">
                <p className="eyebrow">
                  Network connection
                </p>
                <h4>
                  {connection
                    ? `${connection.sourceIp} → ${connection.destinationIp}`
                    : "No connection telemetry"}
                </h4>
                <code>
                  {connection
                    ? `${connection.protocol.toUpperCase()} ${connection.destinationPort ?? "—"}`
                    : "—"}
                </code>
                <small>
                  {formatTimestamp(
                    connection?.timestamp,
                  )}
                </small>
                <button
                  type="button"
                  className="evidence-button"
                  onClick={() =>
                    collectEvidence(
                      connection?.eventId,
                    )
                  }
                  disabled={
                    scenarioState.finalized ||
                    !connection ||
                    isEvidenceCollected(
                      connection.eventId,
                    )
                  }
                >
                  {isEvidenceCollected(
                    connection?.eventId,
                  )
                    ? "Evidence collected"
                    : "Collect network evidence"}
                </button>
              </article>
            </div>
          </section>
        )}

        {activeView === "identity" && (
          <section className="workspace-section">
            <div className="section-heading">
              <div>
                <p className="eyebrow">
                  Identity projection
                </p>
                <h3>
                  {user?.displayName ?? "User"}
                </h3>
              </div>
            </div>

            <div className="detail-grid">
              <div>
                <span>Email</span>
                <strong>
                  {user?.email ?? "—"}
                </strong>
              </div>
              <div>
                <span>Department</span>
                <strong>
                  {user?.department ?? "—"}
                </strong>
              </div>
              <div>
                <span>Account status</span>
                <strong>
                  {account?.status ?? "—"}
                </strong>
              </div>
              <div>
                <span>Session status</span>
                <strong>
                  {session?.status ?? "—"}
                </strong>
              </div>
            </div>

            <article className="identity-event-card">
              <div>
                <p className="eyebrow">
                  Suspicious successful login
                </p>
                <h4>
                  Source IP {loginActivity?.kind === "login_succeeded"
                    ? loginActivity.sourceIp ?? "—"
                    : "—"}
                </h4>
              </div>
              <div className="identity-stats">
                <span>
                  Successful logins
                  <strong>
                    {projections.identity.successfulLogins}
                  </strong>
                </span>
                <span>
                  Identity events
                  <strong>
                    {projections.identity.activity.length}
                  </strong>
                </span>
              </div>
              <button
                type="button"
                className="evidence-button"
                onClick={() =>
                  collectEvidence(
                    loginActivity?.eventId,
                  )
                }
                disabled={
                  scenarioState.finalized ||
                  !loginActivity ||
                  isEvidenceCollected(
                    loginActivity.eventId,
                  )
                }
              >
                {isEvidenceCollected(
                  loginActivity?.eventId,
                )
                  ? "Evidence collected"
                  : "Collect login evidence"}
              </button>
            </article>
          </section>
        )}

        {activeView === "case" && (
          <section className="workspace-section">
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
                                toggleFindingEvidence(
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
                  onSubmit={submitFinding}
                >
                  <label>
                    Finding title
                    <input
                      type="text"
                      value={findingTitle}
                      disabled={scenarioState.finalized}
                      onChange={(event) =>
                        setFindingTitle(
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
                        setFindingSummary(
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
        )}
      </main>
    </div>
  );
}

function App() {
  const instructorMode = useMemo(
    () =>
      new URLSearchParams(
        window.location.search,
      ).get("mode") === "instructor",
    [],
  );

  const scenarioPath = useMemo(
    () =>
      resolveScenarioPath(
        window.location.search,
      ),
    [],
  );

  const [scenario, setScenario] =
    useState<ScenarioDefinition | null>(
      null,
    );
  const [error, setError] =
    useState<string | null>(null);
  const [reloadToken, setReloadToken] =
    useState(0);

  useEffect(() => {
    let cancelled = false;

    setScenario(null);
    setError(null);

    loadScenario(scenarioPath)
      .then((loaded) => {
        if (!cancelled) {
          setScenario(loaded);
        }
      })
      .catch((caught: unknown) => {
        if (cancelled) {
          return;
        }

        setError(
          caught instanceof Error
            ? caught.message
            : String(caught),
        );
      });

    return () => {
      cancelled = true;
    };
  }, [scenarioPath, reloadToken]);

  if (error) {
    return (
      <main className="scenario-load-state">
        <p className="eyebrow">
          Scenario validation failed
        </p>
        <h1>Polymorph could not load this scenario.</h1>
        <p>
          Fix the JSON or semantic error, then retry.
        </p>
        <code className="scenario-path">
          {scenarioPath}
        </code>
        <pre className="scenario-error">
          {error}
        </pre>
        <button
          type="button"
          className="primary-button"
          onClick={() =>
            setReloadToken((current) =>
              current + 1,
            )
          }
        >
          Retry scenario
        </button>
      </main>
    );
  }

  if (!scenario) {
    return (
      <main className="scenario-load-state">
        <p className="eyebrow">
          Loading scenario
        </p>
        <h1>Preparing deterministic training run…</h1>
        <code className="scenario-path">
          {scenarioPath}
        </code>
      </main>
    );
  }

  return (
    <ScenarioWorkspace
      scenario={scenario}
      scenarioPath={scenarioPath}
      instructorMode={instructorMode}
    />
  );
}

export default App;
