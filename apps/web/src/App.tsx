import {
  type FormEvent,
  useDeferredValue,
  useEffect,
  useMemo,
  useState,
} from "react";

import "./App.css";

import {
  CaseWorkspace,
} from "./CaseWorkspace";

import {
  InvestigationBrief,
} from "./InvestigationBrief";

import {
  Walkthrough,
} from "./Walkthrough";

import {
  gradeQuestions,
} from "./questionGrading";

import {
  PopOutWindow,
} from "./PopOutWindow";

import {
  ReplayScrubber,
} from "./ReplayScrubber";

import {
  FirstRun,
} from "./FirstRun";

import {
  ResponseComparisonPanel,
} from "./ResponseComparisonPanel";

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
  ScenarioControls,
} from "./ScenarioControls";

import {
  readInitialSessionMode,
  showsAnswers,
  showsScaffolding,
} from "./assistanceMode";

import type {
  SessionMode,
} from "./assistanceMode";

import {
  SiemWorkspace,
} from "./SiemWorkspace";

import {
  EdrWorkspace,
} from "./EdrWorkspace";

import {
  IdentityWorkspace,
} from "./IdentityWorkspace";

import {
  addAnalystFinding,
  collectAnalystEvidence,
  createAnalystCaseState,
  assessInvestigationCoverage,
  compareResponsePaths,
  createIncidentCaseState,
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

import {
  clearRun,
  isRunMeaningful,
  loadRun,
  saveRun,
} from "./runPersistence";

type WorkspaceView =
  | "alerts"
  | "timeline"
  | "siem"
  | "endpoint"
  | "identity"
  | "case";

/**
 * Navigation grouped by the phase of work it belongs to.
 *
 * A flat list of six tool names answers "what exists" but not "what is this
 * and when would I go there", which is the question a newcomer actually
 * has. Grouping by incident phase and giving each entry a purpose line
 * makes the sidebar readable without instruction.
 */
const navGroups: ReadonlyArray<{
  phase: string;
  hint: string;
  items: ReadonlyArray<{
    id: WorkspaceView;
    label: string;
    purpose: string;
  }>;
}> = [
  {
    phase: "Triage",
    hint: "Start here",
    items: [
      {
        id: "alerts",
        label: "Alerts",
        purpose:
          "What fired, and on which host",
      },
      {
        id: "timeline",
        label: "Investigation",
        purpose:
          "The brief, questions, and correlated timeline",
      },
    ],
  },
  {
    phase: "Investigate",
    hint: "Find the evidence",
    items: [
      {
        id: "siem",
        label: "SIEM Search",
        purpose:
          "Query all telemetry; start when you have a value to pivot on",
      },
      {
        id: "endpoint",
        label: "Endpoint",
        purpose:
          "Process trees, network and file activity for one host",
      },
      {
        id: "identity",
        label: "Identity",
        purpose:
          "Sign-in history, sessions, and privilege for one account",
      },
    ],
  },
  {
    phase: "Coordinate",
    hint: "Build the case",
    items: [
      {
        id: "case",
        label: "Case",
        purpose:
          "Evidence graph, indicators, hypotheses, and response decisions",
      },
    ],
  },
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
}

function ScenarioWorkspace({
  scenario,
  scenarioPath,
}: ScenarioWorkspaceProps) {
  const context =
    scenario.investigation;

  // Resume a run for this scenario if one was left behind.
  const restored = useMemo(
    () => loadRun(scenarioPath),
    [scenarioPath],
  );

  const [activeView, setActiveView] =
    useState<WorkspaceView>(
      "alerts",
    );
  const [performedActionIds, setPerformedActionIds] =
    useState<string[]>(
      () =>
        restored?.performedActionIds ??
        [],
    );
  const [finalized, setFinalized] =
    useState(
      () => restored?.finalized ?? false,
    );
  const [analystCase, setAnalystCase] =
    useState(
      () =>
        restored?.analystCase ??
        createAnalystCaseState(),
    );
  const [incidentCase, setIncidentCase] =
    useState(
      () =>
        restored?.incidentCase ??
        createIncidentCaseState(),
    );
  const [resumed, setResumed] = useState(
    () =>
      restored !== undefined &&
      isRunMeaningful(restored),
  );
  const [sessionMode, setSessionMode] =
    useState<SessionMode>(
      readInitialSessionMode,
    );

  const scaffolding =
    showsScaffolding(sessionMode);

  const instructorMode =
    showsAnswers(sessionMode);
  const [firstRunDismissed, setFirstRunDismissed] =
    useState(() => {
      try {
        return (
          window.localStorage.getItem(
            "endomorph-first-run",
          ) === "dismissed"
        );
      } catch {
        return false;
      }
    });
  const [replayPosition, setReplayPosition] =
    useState<number | null>(null);
  const [walkthroughOpen, setWalkthroughOpen] =
    useState(false);
  const [walkthroughDetached, setWalkthroughDetached] =
    useState(false);
  const [popOutBlocked, setPopOutBlocked] =
    useState(false);
  const [questionAnswers, setQuestionAnswers] =
    useState<Record<string, string>>(
      () =>
        restored?.questionAnswers ?? {},
    );
  const [findingTitle, setFindingTitle] =
    useState("");
  const [findingSummary, setFindingSummary] =
    useState("");
  const [selectedEvidenceIds, setSelectedEvidenceIds] =
    useState<string[]>([]);
  const [caseError, setCaseError] =
    useState<string | null>(null);
  const [siemPivot, setSiemPivot] =
    useState({
      query: "",
      nonce: 0,
    });

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

  // The slider stays responsive while the projection rebuild -- roughly
  // 55ms at 4k events, more at 18k -- lags a frame behind.
  const deferredReplayPosition =
    useDeferredValue(replayPosition);

  const viewedEvents = useMemo(() => {
    if (
      deferredReplayPosition === null
    ) {
      return scenarioState.events;
    }

    return scenarioState.events.slice(
      0,
      deferredReplayPosition,
    );
  }, [
    scenarioState.events,
    deferredReplayPosition,
  ]);

  const rewound =
    replayPosition !== null;

  const replayMarkers = useMemo(() => {
    const truthIds = new Set(
      (
        scenario.groundTruth?.timeline ??
        []
      ).map((step) => step.eventId),
    );

    return scenarioState.events
      .map((event, index) => ({
        event,
        index,
      }))
      .filter(({ event }) =>
        truthIds.has(event.id),
      )
      .map(({ event, index }) => ({
        index: index + 1,
        eventId: event.id,
        label: event.type,
      }));
  }, [
    scenarioState.events,
    scenario.groundTruth,
  ]);

  const projections = useMemo(
    () => ({
      identity: rebuildProjection(
        identityProjection,
        viewedEvents,
      ),
      edr: rebuildProjection(
        edrProjection,
        viewedEvents,
      ),
      siem: rebuildProjection(
        siemProjection,
        viewedEvents,
      ),
    }),
    [viewedEvents],
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

  const observedTechniqueIds = useMemo(
    () => {
      const collected = new Set(
        analystCase.collectedEventIds,
      );

      return (
        scenario.groundTruth
          ?.techniques ?? []
      )
        .filter((technique) =>
          technique.eventIds.some(
            (eventId) =>
              collected.has(eventId),
          ),
        )
        .map(
          (technique) => technique.id,
        );
    },
    [
      scenario.groundTruth,
      analystCase.collectedEventIds,
    ],
  );

  useEffect(() => {
    saveRun({
      scenarioPath,
      performedActionIds,
      finalized,
      analystCase,
      incidentCase,
      questionAnswers,
    });
  }, [
    scenarioPath,
    performedActionIds,
    finalized,
    analystCase,
    incidentCase,
    questionAnswers,
  ]);

  const coverage = useMemo(() => {
    const groundTruthIds = (
      scenario.groundTruth?.timeline ??
      []
    ).map((step) => step.eventId);

    if (groundTruthIds.length === 0) {
      return undefined;
    }

    return assessInvestigationCoverage(
      scenarioState.world,
      projections.siem.events,
      analystCase.collectedEventIds,
      groundTruthIds,
    );
  }, [
    scenario.groundTruth,
    scenarioState.world,
    projections.siem.events,
    analystCase.collectedEventIds,
  ]);

  // Only computed once the run is finalized: it searches every ordering of
  // the available operations, which is wasted work mid-investigation and
  // would also leak the answer.
  const responseComparison = useMemo(
    () =>
      scenarioState.finalized
        ? compareResponsePaths(
            scenario,
            scenarioState.performedActionIds,
          )
        : undefined,
    [
      scenario,
      scenarioState.finalized,
      scenarioState.performedActionIds,
    ],
  );

  const questionScore = useMemo(
    () =>
      gradeQuestions(
        scenario.questions ?? [],
        questionAnswers,
      ),
    [
      scenario.questions,
      questionAnswers,
    ],
  );

  const walkthroughAvailable =
    instructorMode ||
    scenarioState.finalized;

  const walkthroughNode = (
    <Walkthrough
      scenario={scenario}
      records={projections.siem.events}
      detached={walkthroughDetached}
      popOutBlocked={popOutBlocked}
      onPopOut={() => {
        setPopOutBlocked(false);
        setWalkthroughDetached(true);
      }}
      onClose={() => {
        if (walkthroughDetached) {
          setWalkthroughDetached(false);
        } else {
          setWalkthroughOpen(false);
        }
      }}
    />
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
    if (
      !eventId ||
      rewound ||
      scenarioState.finalized
    ) {
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
      rewound ||
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

    // Deliberately no navigation. Response operations are now performed
    // from the console that owns them, so jumping back to the timeline
    // would eject the analyst from the tool they are working in. When the
    // guided response cards are used they already live on that view.
  };

  const finalizeInvestigation = () => {
    if (scenarioState.finalized) {
      return;
    }

    setFinalized(true);
    setActiveView("timeline");
  };

  const openSiem = (
    query: string,
  ) => {
    setSiemPivot((current) => ({
      query,
      nonce: current.nonce + 1,
    }));
    setActiveView("siem");
  };

  const resetScenario = () => {
    setPerformedActionIds([]);
    setFinalized(false);
    setAnalystCase(
      createAnalystCaseState(),
    );
    setIncidentCase(
      createIncidentCaseState(),
    );
    setQuestionAnswers({});
    setReplayPosition(null);
    setResumed(false);
    clearRun(scenarioPath);
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
            Endomorph
          </p>
          <h1>Security Console</h1>
          <p className="sidebar-copy">
            Synthetic analyst workspace
          </p>

          <nav className="workspace-nav">
            {navGroups.map((group) => (
              <div
                key={group.phase}
                className="nav-group"
              >
                <p className="nav-group-head">
                  <span className="nav-group-phase">
                    {group.phase}
                  </span>
                  <span className="nav-group-hint">
                    {group.hint}
                  </span>
                </p>

                {group.items.map(
                  (item) => (
                    <button
                      key={item.id}
                      type="button"
                      /*
                        The purpose line is supplementary guidance for
                        scanning, not part of the control's identity.
                        Folding it into the accessible name would make
                        every nav item announce a sentence.
                      */
                      aria-label={item.label}
                      className={
                        activeView ===
                        item.id
                          ? "nav-item active"
                          : "nav-item"
                      }
                      onClick={() =>
                        setActiveView(
                          item.id,
                        )
                      }
                    >
                      <span className="nav-item-label">
                        {item.label}
                        {item.id ===
                          "case" &&
                          analystCase
                            .collectedEventIds
                            .length >
                            0 && (
                            <span className="nav-count">
                              {
                                analystCase
                                  .collectedEventIds
                                  .length
                              }
                            </span>
                          )}
                      </span>
                      <span
                        className="nav-item-purpose"
                        aria-hidden="true"
                      >
                        {item.purpose}
                      </span>
                    </button>
                  ),
                )}
              </div>
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
            <ScenarioControls
              scenarioPath={scenarioPath}
              sessionMode={sessionMode}
              onSessionModeChange={
                setSessionMode
              }
            />
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
            {walkthroughAvailable && (
              <button
                type="button"
                className={
                  walkthroughOpen ||
                  walkthroughDetached
                    ? "secondary-button walkthrough-toggle active"
                    : "secondary-button walkthrough-toggle"
                }
                onClick={() => {
                  if (
                    walkthroughDetached
                  ) {
                    setWalkthroughDetached(
                      false,
                    );
                    setWalkthroughOpen(
                      true,
                    );
                    return;
                  }

                  setWalkthroughOpen(
                    (current) => !current,
                  );
                }}
              >
                {walkthroughOpen ||
                walkthroughDetached
                  ? "Hide walkthrough"
                  : "Walkthrough"}
              </button>
            )}
            {resumed &&
              !scenarioState.finalized && (
                <span
                  className="incident-state resumed"
                  title="Your previous work on this scenario was restored."
                >
                  Run resumed
                </span>
              )}
            <button
              type="button"
              className="secondary-button"
              onClick={resetScenario}
            >
              Reset scenario
            </button>
          </div>
        </header>

        <ReplayScrubber
          totalEvents={
            scenarioState.events.length
          }
          position={replayPosition}
          renderedPosition={
            viewedEvents.length
          }
          timestamp={
            viewedEvents[
              viewedEvents.length - 1
            ]?.timestamp
          }
          markers={replayMarkers}
          onScrub={setReplayPosition}
        />

        {walkthroughDetached &&
          walkthroughAvailable && (
            <PopOutWindow
              title="Endomorph walkthrough"
              onClose={() =>
                setWalkthroughDetached(
                  false,
                )
              }
              onBlocked={() => {
                setPopOutBlocked(true);
                setWalkthroughDetached(
                  false,
                );
                setWalkthroughOpen(true);
              }}
            >
              {walkthroughNode}
            </PopOutWindow>
          )}

        {walkthroughOpen &&
          !walkthroughDetached &&
          walkthroughAvailable && (
            <div className="walkthrough-dock">
              {walkthroughNode}
            </div>
          )}

        {activeView === "alerts" &&
          !firstRunDismissed && (
            <FirstRun
              onDismiss={() => {
                setFirstRunDismissed(
                  true,
                );

                try {
                  window.localStorage.setItem(
                    "endomorph-first-run",
                    "dismissed",
                  );
                } catch {
                  // Storage can be blocked; the dismissal still applies
                  // for this session.
                }
              }}
            />
          )}

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

        {activeView === "siem" && (
          <section className="workspace-section siem-section">
            <SiemWorkspace
              key={`siem-${siemPivot.nonce}`}
              records={projections.siem.events}
              initialQuery={siemPivot.query}
              finalized={scenarioState.finalized}
              isCollected={isEvidenceCollected}
              onCollect={collectEvidence}
              onOpenCase={() => setActiveView("case")}
            />
          </section>
        )}

        {activeView === "timeline" && (
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
              onAnswerChange={(
                questionId,
                answer,
              ) =>
                setQuestionAnswers(
                  (current) => ({
                    ...current,
                    [questionId]: answer,
                  }),
                )
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
            />

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
                onPerform={performResponseAction}
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
          <section className="workspace-section edr-section">
            <EdrWorkspace
              state={projections.edr}
              devices={Object.values(scenarioState.world.devices)}
              initialDeviceId={context.deviceId}
              actions={responseActions}
              performedActionIds={
                scenarioState.performedActionIds
              }
              onPerformAction={
                performResponseAction
              }
              finalized={scenarioState.finalized}
              isCollected={isEvidenceCollected}
              onCollect={collectEvidence}
              onSearchSiem={openSiem}
              onOpenCase={() => setActiveView("case")}
            />
          </section>
        )}

        {activeView === "identity" && (
          <section className="workspace-section identity-section">
            <IdentityWorkspace
              world={scenarioState.world}
              state={projections.identity}
              initialAccountId={context.accountId}
              actions={responseActions}
              performedActionIds={scenarioState.performedActionIds}
              finalized={scenarioState.finalized}
              isCollected={isEvidenceCollected}
              onCollect={collectEvidence}
              onPerformAction={performResponseAction}
              onSearchSiem={openSiem}
              onOpenCase={() => setActiveView("case")}
            />
          </section>
        )}

        {activeView === "case" && (
          <CaseWorkspace
            scenarioState={scenarioState}
            siemRecords={
              projections.siem.events
            }
            analystCase={analystCase}
            incidentCase={incidentCase}
            onIncidentCaseChange={
              setIncidentCase
            }
            collectedEvidence={
              collectedEvidence
            }
            siemByEventId={siemByEventId}
            selectedEvidenceIds={
              selectedEvidenceIds
            }
            onToggleFindingEvidence={
              toggleFindingEvidence
            }
            findingTitle={findingTitle}
            onFindingTitleChange={
              setFindingTitle
            }
            findingSummary={
              findingSummary
            }
            onFindingSummaryChange={
              setFindingSummary
            }
            onSubmitFinding={
              submitFinding
            }
            caseError={caseError}
            finalized={finalized}
            onPivotToSiem={openSiem}
            formatTimestamp={
              formatTimestamp
            }
          />
        )}
      </main>
    </div>
  );
}

function App() {
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
        <h1>Endomorph could not load this scenario.</h1>
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
    />
  );
}

export default App;
