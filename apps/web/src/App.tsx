import {
  useMemo,
  useState,
} from "react";

import "./App.css";

import {
  accountCompromiseScenario,
  accountCompromiseScenarioIds,
  edrProjection,
  getScenarioState,
  identityProjection,
  rebuildProjection,
  siemProjection,
} from "./simulationAdapter";

type WorkspaceView =
  | "alerts"
  | "timeline"
  | "endpoint"
  | "identity";

const navItems: ReadonlyArray<{
  id: WorkspaceView;
  label: string;
}> = [
  { id: "alerts", label: "Alerts" },
  { id: "timeline", label: "Investigation" },
  { id: "endpoint", label: "Endpoint" },
  { id: "identity", label: "Identity" },
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

function App() {
  const ids =
    accountCompromiseScenarioIds;

  const [activeView, setActiveView] =
    useState<WorkspaceView>(
      "alerts",
    );
  const [performedActionIds, setPerformedActionIds] =
    useState<string[]>([]);

  const scenarioState = useMemo(
    () =>
      getScenarioState(
        accountCompromiseScenario,
        performedActionIds,
      ),
    [performedActionIds],
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

  const user =
    scenarioState.world.users[
      ids.userId
    ];
  const account =
    scenarioState.world.accounts[
      ids.accountId
    ];
  const device =
    scenarioState.world.devices[
      ids.deviceId
    ];
  const session =
    scenarioState.world.sessions[
      ids.sessionId
    ];

  const alert =
    projections.edr.alerts[0];
  const process =
    projections.edr.processes[0];
  const connection =
    projections.edr.networkConnections[0];
  const loginActivity =
    projections.identity.activity.find(
      (activity) =>
        activity.kind ===
        "login_succeeded",
    );

  const contained =
    performedActionIds.includes(
      ids.containmentActionId,
    );

  const containIncident = () => {
    if (contained) {
      return;
    }

    setPerformedActionIds((current) => [
      ...current,
      ids.containmentActionId,
    ]);
    setActiveView("timeline");
  };

  const resetScenario = () => {
    setPerformedActionIds([]);
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
        </div>

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
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot" />
          Deterministic training run
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">
              Training scenario
            </p>
            <h2>
              {accountCompromiseScenario.name}
            </h2>
            <p className="scenario-description">
              {accountCompromiseScenario.description}
            </p>
          </div>

          <div className="topbar-actions">
            <span
              className={
                contained
                  ? "incident-state contained"
                  : "incident-state active"
              }
            >
              {contained
                ? "Contained"
                : "Needs action"}
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
                  "Suspicious PowerShell activity"}
              </h3>
              <p>
                Correlated identity and endpoint telemetry indicates a suspicious login was followed by encoded PowerShell and an outbound connection.
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
                  <span>Correlated events</span>
                  <strong>
                    {alert?.relatedEventIds.length ?? 0}
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
                onClick={containIncident}
                disabled={contained}
              >
                {contained
                  ? "Incident contained"
                  : "Contain incident"}
              </button>
            </div>

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
                <span>SIEM events</span>
                <strong>
                  {projections.siem.events.length}
                </strong>
                <small>
                  Shared immutable history
                </small>
              </article>
            </div>

            <div className="timeline-list">
              {projections.siem.events.map(
                (event) => (
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
                      <small>
                        {event.eventType} · {event.source}
                      </small>
                    </div>
                  </article>
                ),
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
                  {process?.image ?? "No process telemetry"}
                </h4>
                <code>
                  {process?.commandLine ?? "—"}
                </code>
                <small>
                  PID {process?.processId ?? "—"} · {formatTimestamp(process?.timestamp)}
                </small>
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
            </article>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
