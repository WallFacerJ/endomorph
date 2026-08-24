import {
  type FormEvent,
  useDeferredValue,
  useEffect,
  useMemo,
  useState,
} from "react";

import "./App.css";

import {
  Icon,
} from "./Icon";

import {
  MissionPanel,
} from "./MissionPanel";

import {
  buildMissionObjectives,
} from "./missionObjectives";

import {
  EventVolume,
} from "./Charts";

import {
  bucketByTime,
} from "./chartData";

import type {
  IconName,
} from "./Icon";

import {
  CaseWorkspace,
} from "./CaseWorkspace";

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
  InvestigationWorkspace,
} from "./InvestigationWorkspace";

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
  LiveResponseWorkspace,
} from "./LiveResponseWorkspace";

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
  buildEvidenceGraph,
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

import {
  summarizeKeyEvidence,
} from "./keyEvidence";

type WorkspaceView =
  | "alerts"
  | "timeline"
  | "siem"
  | "endpoint"
  | "live"
  | "identity"
  | "questions"
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
    icon: IconName;
    purpose: string;
  }>;
}> = [
  {
    phase: "Triage",
    hint: "Start here",
    items: [
      {
        id: "alerts",
        icon: "alert",
        label: "Alerts",
        purpose:
          "What fired, and on which host",
      },
      {
        id: "timeline",
        icon: "book",
        label: "Brief",
        purpose:
          "What you are asked to establish, and the correlated timeline",
      },
    ],
  },
  {
    phase: "Investigate",
    hint: "Find the evidence",
    items: [
      {
        id: "siem",
        icon: "search",
        label: "SIEM Search",
        purpose:
          "Query all telemetry; start when you have a value to pivot on",
      },
      {
        id: "endpoint",
        icon: "endpoint",
        label: "Endpoint",
        purpose:
          "Process trees, network and file activity for one host",
      },
      {
        id: "live",
        icon: "server",
        label: "Live Response",
        purpose:
          "Ask a host what is true on it now, rather than what it did",
      },
      {
        id: "identity",
        icon: "identity",
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
        id: "questions",
        icon: "target",
        label: "Answers",
        purpose:
          "Record what you established, once the evidence supports it",
      },
      {
        id: "case",
        icon: "case",
        label: "Case",
        purpose:
          "Evidence graph, indicators, hypotheses, and response decisions",
      },
    ],
  },
];

/*
  Constructed once. Building an Intl.DateTimeFormat is expensive, and this was
  building a fresh one for every timestamp rendered -- which, on a scenario
  with twenty thousand events, was three seconds of the finalize interaction
  by itself, more than any other single thing the app did.
*/
const CLOCK_FORMAT =
  new Intl.DateTimeFormat(
    "en-US",
    {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    },
  );

function formatTimestamp(
  timestamp: string | undefined,
): string {
  if (!timestamp) {
    return "—";
  }

  return CLOCK_FORMAT.format(
    new Date(timestamp),
  );
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
  // Worth reading once, noise on every subsequent visit to a console.
  const [
    descriptionExpanded,
    setDescriptionExpanded,
  ] = useState(false);

  /*
    The objectives panel docks beside whatever console is open and can be
    torn off into its own window, exactly as the walkthrough does. A tab was
    the obvious answer and the wrong one: a checklist you have to navigate
    away from to read is a checklist you stop reading, which is how the
    objectives ended up scattered across six views in the first place.
  */
  const [missionOpen, setMissionOpen] =
    useState(false);

  const [
    missionDetached,
    setMissionDetached,
  ] = useState(false);

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

  /*
    Volume, bucketed once and shared by the alert queue and the search view.
    Derived from what the analyst can currently see rather than from the
    scenario, so rewinding the clock changes the chart with everything else.
  */
  const telemetryVolume = useMemo(() => {
    const timestamps =
      projections.siem.events.map(
        (event) => event.timestamp,
      );

    const notable =
      projections.siem.events
        .filter(
          (event) =>
            event.eventType ===
            "ALERT_CREATED",
        )
        .map((event) => event.timestamp);

    const parsed = timestamps
      .map((value) => Date.parse(value))
      .filter((value) =>
        Number.isFinite(value),
      );

    const spanMs =
      parsed.length > 0
        ? Math.max(...parsed) -
          Math.min(...parsed)
        : 0;

    return {
      total: timestamps.length,
      days: Math.max(
        1,
        Math.round(
          spanMs / 86400000,
        ),
      ),
      buckets: bucketByTime(
        timestamps,
        notable,
      ),
    };
  }, [projections.siem.events]);

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

  // Switching views used to keep the previous scroll position, dropping the
  // analyst into the middle of a workspace they had not seen and leaving the
  // run status and controls above the fold. Each view starts at its top.
  useEffect(() => {
    window.scrollTo({
      top: 0,
      behavior: "instant",
    });
  }, [activeView]);

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

  const keyEvidence = useMemo(
    () =>
      summarizeKeyEvidence(
        scenario.groundTruth?.timeline ??
          [],
        analystCase.collectedEventIds,
      ),
    [
      scenario.groundTruth,
      analystCase.collectedEventIds,
    ],
  );

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

  /*
    The same pure function the case view uses, over the same inputs. It walks
    only the collected evidence, which is small, and being pure of identical
    inputs it cannot disagree with the copy the case draws -- which is why
    this is a second call rather than a prop threaded through two components
    that do not otherwise need it.
  */
  const evidenceGraph = useMemo(
    () =>
      buildEvidenceGraph(
        scenarioState.world,
        projections.siem.events,
        analystCase.collectedEventIds,
      ),
    [
      scenarioState.world,
      projections.siem.events,
      analystCase.collectedEventIds,
    ],
  );

  const missionObjectives = useMemo(
    () =>
      buildMissionObjectives({
        analystCase,
        incidentCase,
        outcome: scenarioState.outcome,
        finalized: scenarioState.finalized,
        questionsAnswered: Object.values(
          questionAnswers,
        ).filter(
          (answer) =>
            answer.trim().length > 0,
        ).length,
        questionsTotal: (
          scenario.questions ?? []
        ).length,
        techniquesEvidenced:
          observedTechniqueIds.length,
        techniquesTotal: (
          scenario.groundTruth
            ?.techniques ?? []
        ).length,
        entitiesInScope:
          evidenceGraph.nodes.length,
      }),
    [
      analystCase,
      incidentCase,
      scenarioState.outcome,
      scenarioState.finalized,
      questionAnswers,
      scenario.questions,
      scenario.groundTruth,
      observedTechniqueIds,
      evidenceGraph.nodes.length,
    ],
  );

  const missionNode = (
    <MissionPanel
      objectives={missionObjectives}
      outcome={scenarioState.outcome}
      finalized={
        scenarioState.finalized
      }
      score={{
        earned: questionScore.earned,
        available:
          questionScore.available,
      }}
      onNavigate={(view) => {
        setActiveView(
          view as WorkspaceView,
        );
      }}
    />
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

                {group.items
                  .filter(
                    (item) =>
                      /*
                        A scenario without questions has nothing to record,
                        and the view falls back to the same content as the
                        brief. Offering a nav entry that leads somewhere
                        identical is worse than not offering it -- the v1
                        scenarios carry no questions, so this is a real case
                        rather than a defensive one.
                      */
                      item.id !==
                        "questions" ||
                      (scenario.questions ??
                        []).length > 0,
                  )
                  .map(
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
                        <Icon
                          name={item.icon}
                          size={15}
                        />
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

      <main
        className={
          missionOpen && !missionDetached
            ? "main-content mission-open"
            : "main-content"
        }
      >
        <header className="topbar">
          <div>
            <p className="eyebrow">
              Training scenario
            </p>
            <h2>
              {scenario.name}
            </h2>
            <p
              className={
                descriptionExpanded
                  ? "scenario-description"
                  : "scenario-description clamped"
              }
            >
              {scenario.description}
            </p>

            <button
              type="button"
              className="scenario-description-toggle"
              aria-expanded={
                descriptionExpanded
              }
              onClick={() =>
                setDescriptionExpanded(
                  (current) => !current,
                )
              }
            >
              {descriptionExpanded
                ? "Show less"
                : "About this scenario"}
            </button>
          </div>

          {/*
            Run actions and setup controls are separate rows. Interleaved in
            one wrapping flex row, three control groups plus four actions
            pushed Finalize below the fold at 1280x720 -- the action that
            completes the run, off-screen on an ordinary laptop.
          */}
          <div className="topbar-actions">
            <div className="topbar-run">
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
            {/*
              Always available, in every mode. The checklist is how an
              analyst knows what the run is asking of them, which is not a
              form of assistance -- Professional withholds the answers, not
              the assignment.
            */}
            <button
              type="button"
              className={
                missionOpen ||
                missionDetached
                  ? "secondary-button mission-toggle active"
                  : "secondary-button mission-toggle"
              }
              aria-pressed={
                missionOpen ||
                missionDetached
              }
              onClick={() => {
                if (missionDetached) {
                  setMissionDetached(
                    false,
                  );
                  setMissionOpen(true);
                  return;
                }

                setMissionOpen(
                  (current) => !current,
                );
              }}
            >
              <Icon
                name="target"
                size={14}
              />
              Objectives
              <span className="mission-toggle-count">
                {
                  missionObjectives.filter(
                    (objective) =>
                      objective.done,
                  ).length
                }
                /
                {missionObjectives.length}
              </span>
            </button>

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
              className="primary-button"
              onClick={finalizeInvestigation}
              disabled={
                scenarioState.finalized
              }
            >
              {scenarioState.finalized
                ? "Investigation finalized"
                : "Finalize investigation"}
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={resetScenario}
            >
              Reset scenario
            </button>
            </div>

            <ScenarioControls
              scenarioPath={scenarioPath}
              sessionMode={sessionMode}
              onSessionModeChange={
                setSessionMode
              }
            />
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
          density={
            telemetryVolume.buckets.map(
              (bucket) => bucket.total,
            )
          }
          markers={
            /*
              Ground truth, so instructor only. Handed to anyone else, the
              transport walks them through every attacker action in order --
              the whole answer, offered by a control labelled as navigation.
            */
            instructorMode
              ? replayMarkers
              : []
          }
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

        {missionDetached && (
          <PopOutWindow
            title="Endomorph objectives"
            onClose={() =>
              setMissionDetached(false)
            }
            onBlocked={() => {
              setPopOutBlocked(true);
              setMissionDetached(false);
              setMissionOpen(true);
            }}
          >
            {missionNode}
          </PopOutWindow>
        )}

        {missionOpen &&
          !missionDetached && (
            <div className="mission-dock">
              <div className="mission-dock-bar">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => {
                    setMissionDetached(
                      true,
                    );
                    setMissionOpen(false);
                  }}
                >
                  Pop out
                </button>

                <button
                  type="button"
                  className="secondary-button"
                  onClick={() =>
                    setMissionOpen(false)
                  }
                >
                  Hide
                </button>
              </div>

              {missionNode}
            </div>
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
            <div className="console-head">
              <div className="console-head-text">
                <p className="t-eyebrow">
                  Triage / Alert queue
                </p>

                <h3 className="t-title">
                  <Icon
                    name="alert"
                    size={17}
                  />
                  1 alert requires
                  investigation
                </h3>

                <p className="t-note">
                  One detection fired
                  against{" "}
                  {telemetryVolume.total.toLocaleString()}{" "}
                  events. Everything
                  before it is what the
                  investigation has to
                  reconstruct.
                </p>
              </div>

              <div className="metric-row">
                <div className="metric">
                  <span className="t-label">
                    Telemetry
                  </span>

                  <span className="metric-figure">
                    <span className="t-metric">
                      {telemetryVolume.total.toLocaleString()}
                    </span>
                  </span>
                </div>

                <div className="metric">
                  <span className="t-label">
                    Window
                  </span>

                  <span className="metric-figure">
                    <span className="t-metric">
                      {
                        telemetryVolume.days
                      }
                    </span>

                    <span className="metric-sub">
                      days
                    </span>
                  </span>
                </div>

                <div className="metric">
                  <span className="t-label">
                    Evidence held
                  </span>

                  <span className="metric-figure">
                    <span className="t-metric">
                      {
                        analystCase
                          .collectedEventIds
                          .length
                      }
                    </span>
                  </span>
                </div>
              </div>
            </div>

            {/*
              The alert on its own says nothing about how unusual it is. The
              volume chart puts it in proportion: one marked bucket against
              three days of ordinary traffic is the actual shape of the
              problem, and it is the reason an analyst cannot simply read the
              logs.
            */}
            <div className="volume-panel">
              <div className="volume-panel-head">
                <span className="t-label">
                  Telemetry volume over the
                  retained window
                </span>

                <span className="volume-legend">
                  <span className="volume-key volume-key-bulk" />
                  routine
                  <span className="volume-key volume-key-alert" />
                  detection
                </span>
              </div>

              <EventVolume
                buckets={
                  telemetryVolume.buckets
                }
                label="Telemetry volume over the retained window, with the detection marked"
              />
            </div>

            <article className="alert-card">
              <div className="alert-card-header">
                {/*
                  The shared chip, so a critical alert here reads the same as
                  a critical anything anywhere else in the console. Severity
                  takes semantic colour and never the theme accent -- an
                  alert must not look like a selected tab.
                */}
                <span
                  className={`chip chip-${
                    alert?.severity ??
                    "high"
                  }`}
                >
                  <Icon
                    name={
                      (alert?.severity ??
                        "high") ===
                      "critical"
                        ? "alert"
                        : "warning"
                    }
                    size={12}
                  />
                  {alert?.severity ??
                    "high"}
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
                  <span>
                    <Icon
                      name="user"
                      size={12}
                    />
                    User
                  </span>
                  <strong>
                    {user?.displayName ?? "—"}
                  </strong>
                </div>
                <div>
                  <span>
                    <Icon
                      name="endpoint"
                      size={12}
                    />
                    Endpoint
                  </span>
                  <strong>
                    {device?.hostname ?? "—"}
                  </strong>
                </div>
                <div>
                  <span>
                    <Icon
                      name="identity"
                      size={12}
                    />
                    Account
                  </span>
                  <strong>
                    {account?.username ?? "—"}
                  </strong>
                </div>
                <div>
                  <span>
                    <Icon
                      name="case"
                      size={12}
                    />
                    Case evidence
                  </span>
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
              world={scenarioState.world}
              key={`siem-${siemPivot.nonce}`}
              records={projections.siem.events}
              assets={scenario.assets}
              threatIntel={
                scenario.threatIntel
              }
              initialQuery={siemPivot.query}
              finalized={scenarioState.finalized}
              isCollected={isEvidenceCollected}
              onCollect={collectEvidence}
              onOpenCase={() => setActiveView("case")}
            />
          </section>
        )}

        {(activeView === "timeline" ||
          activeView === "questions") && (
          <InvestigationWorkspace
            briefSection={
              activeView === "questions"
                ? "questions"
                : "brief"
            }
            scenario={scenario}
            scenarioState={scenarioState}
            questionAnswers={
              questionAnswers
            }
            onQuestionAnswerChange={(
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
            instructorMode={
              instructorMode
            }
            scaffolding={scaffolding}
            responseActions={
              responseActions
            }
            onPerformAction={
              performResponseAction
            }
            analystCase={analystCase}
            siemRecords={
              projections.siem.events
            }
            coverage={coverage}
            keyEvidence={keyEvidence}
            questionScore={{
              earned:
                questionScore.earned,
              available:
                questionScore.available,
            }}
            responseComparison={
              responseComparison
            }
            isEvidenceCollected={
              isEvidenceCollected
            }
            onCollectEvidence={
              collectEvidence
            }
            formatTimestamp={
              formatTimestamp
            }
          />
        )}

        {activeView === "endpoint" && (
          <section className="workspace-section edr-section">
            <EdrWorkspace
              world={scenarioState.world}
              state={projections.edr}
              assets={scenario.assets}
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

        {activeView === "live" && (
          <section className="workspace-section live-section">
            <LiveResponseWorkspace
              devices={Object.values(
                scenarioState.world.devices,
              )}
              events={viewedEvents}
              initialDeviceId={context.deviceId}
              finalized={scenarioState.finalized}
              isCollected={isEvidenceCollected}
              onCollect={collectEvidence}
              onSearchSiem={openSiem}
              actions={responseActions}
              performedActionIds={
                scenarioState.performedActionIds
              }
              onPerformAction={
                performResponseAction
              }
            />
          </section>
        )}

        {activeView === "identity" && (
          <section className="workspace-section identity-section">
            <IdentityWorkspace
              world={scenarioState.world}
              state={projections.identity}
              assets={scenario.assets}
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
            scenario={scenario}
            assistance={sessionMode}
            coverage={coverage}
            questionAnswers={
              questionAnswers
            }
            questionScore={{
              earned: questionScore.earned,
              available:
                questionScore.available,
            }}
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
