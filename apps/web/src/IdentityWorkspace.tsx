import {
  useMemo,
  useState,
} from "react";

import {
  getIdentityAccountInvestigation,
  getIdentityInventory,
} from "./simulationAdapter";

import type {
  IdentityProjectionState,
  ScenarioAction,
  ScenarioState,
} from "./simulationAdapter";

import "./IdentityWorkspace.css";

interface IdentityWorkspaceProps {
  world: ScenarioState["world"];
  state: IdentityProjectionState;
  initialAccountId: string;
  actions: readonly ScenarioAction[];
  performedActionIds: readonly string[];
  finalized: boolean;
  isCollected: (eventId: string) => boolean;
  onCollect: (eventId: string) => void;
  onPerformAction: (actionId: string) => void;
  onSearchSiem: (query: string) => void;
  onOpenCase: () => void;
}

type IdentityTab =
  | "authentication"
  | "sessions"
  | "lifecycle";

type SelectedIdentityEvent = {
  eventId: string;
  kind: string;
  title: string;
  fields: readonly [string, string][];
};

function formatTimestamp(timestamp: string): string {
  return new Intl.DateTimeFormat(
    "en-US",
    {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    },
  ).format(new Date(timestamp));
}

function actionTargetsAccount(
  action: ScenarioAction,
  accountId: string,
  sessionIds: readonly string[],
): boolean {
  return action.events.some((event) => {
    switch (event.type) {
      case "ACCOUNT_DISABLED":
      case "ACCOUNT_ENABLED":
        return event.payload.accountId === accountId;
      case "SESSION_REVOKED":
        return sessionIds.includes(
          event.payload.sessionId,
        );
      default:
        return false;
    }
  });
}

export function IdentityWorkspace({
  world,
  state,
  initialAccountId,
  actions,
  performedActionIds,
  finalized,
  isCollected,
  onCollect,
  onPerformAction,
  onSearchSiem,
  onOpenCase,
}: IdentityWorkspaceProps) {
  const inventory = useMemo(
    () => getIdentityInventory(world, state),
    [world, state],
  );

  const initialAccountExists = Boolean(
    world.accounts[initialAccountId],
  );
  const [selectedAccountId, setSelectedAccountId] =
    useState(
      initialAccountExists
        ? initialAccountId
        : inventory[0]?.accounts[0]?.id ?? "",
    );
  const [activeTab, setActiveTab] =
    useState<IdentityTab>("authentication");
  const [selectedEvent, setSelectedEvent] =
    useState<SelectedIdentityEvent | null>(null);

  const investigation = useMemo(
    () =>
      selectedAccountId
        ? getIdentityAccountInvestigation(
            world,
            state,
            selectedAccountId,
          )
        : undefined,
    [world, state, selectedAccountId],
  );

  if (!investigation) {
    return (
      <div className="identity-console-empty">
        No identity accounts are available in this scenario.
      </div>
    );
  }

  const sessionIds = investigation.sessions.map(
    (context) => context.session.id,
  );
  const responseActions = actions.filter(
    (action) =>
      actionTargetsAccount(
        action,
        investigation.account.id,
        sessionIds,
      ),
  );

  return (
    <div
      className="identity-console"
      role="region"
      aria-label="Identity investigation workspace"
    >
      <header className="identity-console-header">
        <div>
          <p className="eyebrow">
            Polymorph Ops / Identity
          </p>
          <h3>Identity and access investigation</h3>
          <p>
            Inspect authentication provenance, account privilege, session state, and identity response operations across the synthetic enterprise.
          </p>
        </div>
        <div className="identity-console-stats">
          <span>
            <strong>{inventory.length}</strong>
            identities
          </span>
          <span>
            <strong>{state.successfulLogins}</strong>
            successful logins
          </span>
          <span>
            <strong>{state.failedLogins}</strong>
            failed logins
          </span>
        </div>
      </header>

      <div className="identity-console-layout">
        <aside
          className="identity-inventory"
          aria-label="Identity inventory"
        >
          <div className="identity-pane-heading">
            <span>Directory</span>
            <small>{inventory.length} users</small>
          </div>
          {inventory.map((entry) => (
            <div
              className="identity-user-group"
              key={entry.user.id}
            >
              <div className="identity-user-summary">
                <strong>{entry.user.displayName}</strong>
                <small>
                  {entry.user.department} · {entry.user.title}
                </small>
              </div>
              {entry.accounts.map((account) => (
                <button
                  key={account.id}
                  type="button"
                  className={
                    account.id === selectedAccountId
                      ? "identity-account-row selected"
                      : "identity-account-row"
                  }
                  onClick={() => {
                    setSelectedAccountId(account.id);
                    setSelectedEvent(null);
                  }}
                >
                  <span>
                    <strong>{account.username}</strong>
                    <small>{account.provider}</small>
                  </span>
                  <span className={`identity-account-status ${account.status}`}>
                    {account.status}
                  </span>
                </button>
              ))}
              <div className="identity-user-metrics">
                <span>{entry.activeSessionCount} active session</span>
                <span>{entry.successfulLoginCount} success</span>
                <span>{entry.failedLoginCount} failed</span>
              </div>
            </div>
          ))}
        </aside>

        <section className="identity-activity-pane">
          <div className="identity-account-header">
            <div>
              <p className="eyebrow">Selected account</p>
              <h4>{investigation.user.displayName}</h4>
              <div className="identity-account-subtitle">
                <code>{investigation.account.username}</code>
                <span>{investigation.user.email}</span>
              </div>
            </div>
            <div className="identity-account-facts">
              <span>
                <small>Status</small>
                <strong>{investigation.account.status}</strong>
              </span>
              <span>
                <small>Provider</small>
                <strong>{investigation.account.provider}</strong>
              </span>
              <span>
                <small>Sessions</small>
                <strong>{investigation.sessions.length}</strong>
              </span>
            </div>
          </div>

          <div className="identity-role-strip">
            <span>Assigned roles</span>
            <div>
              {investigation.account.roles.map((role) => (
                <code key={role}>{role}</code>
              ))}
            </div>
          </div>

          <div
            className="identity-tabs"
            role="tablist"
            aria-label="Identity activity views"
          >
            {([
              [
                "authentication",
                `Authentication ${investigation.authentication.length}`,
              ],
              [
                "sessions",
                `Sessions ${investigation.sessions.length}`,
              ],
              [
                "lifecycle",
                `Account lifecycle ${investigation.accountStatusActivity.length}`,
              ],
            ] as const).map(([tab, label]) => (
              <button
                key={tab}
                type="button"
                role="tab"
                aria-selected={activeTab === tab}
                onClick={() => {
                  setActiveTab(tab);
                  setSelectedEvent(null);
                }}
              >
                {label}
              </button>
            ))}
          </div>

          {activeTab === "authentication" && (
            <div className="identity-event-table">
              <div className="identity-event-header auth-columns">
                <span>Result</span>
                <span>Source IP</span>
                <span>Device</span>
                <span>Application</span>
                <span>Time</span>
              </div>
              {investigation.authentication.map(
                (activity) => {
                  const succeeded =
                    activity.kind === "login_succeeded";
                  const deviceId = activity.deviceId;
                  const applicationId =
                    activity.applicationId;

                  return (
                    <button
                      key={activity.eventId}
                      type="button"
                      className={
                        selectedEvent?.eventId === activity.eventId
                          ? "identity-auth-row selected"
                          : "identity-auth-row"
                      }
                      onClick={() =>
                        setSelectedEvent({
                          eventId: activity.eventId,
                          kind: activity.kind,
                          title: succeeded
                            ? "Successful authentication"
                            : "Failed authentication",
                          fields: [
                            [
                              "Result",
                              succeeded
                                ? "success"
                                : `failure · ${activity.reason}`,
                            ],
                            ["Source IP", activity.sourceIp ?? "—"],
                            [
                              "Device",
                              deviceId
                                ? world.devices[deviceId]?.hostname ?? deviceId
                                : "—",
                            ],
                            [
                              "Application",
                              applicationId
                                ? world.applications[applicationId]?.name ?? applicationId
                                : "—",
                            ],
                            ["Timestamp", activity.timestamp],
                          ],
                        })
                      }
                    >
                      <span className={
                        succeeded
                          ? "auth-result success"
                          : "auth-result failure"
                      }>
                        {succeeded ? "SUCCESS" : "FAILED"}
                      </span>
                      <code>{activity.sourceIp ?? "—"}</code>
                      <span>
                        {deviceId
                          ? world.devices[deviceId]?.hostname ?? deviceId
                          : "—"}
                      </span>
                      <span>
                        {applicationId
                          ? world.applications[applicationId]?.name ?? applicationId
                          : "—"}
                      </span>
                      <time>{formatTimestamp(activity.timestamp)}</time>
                    </button>
                  );
                },
              )}
            </div>
          )}

          {activeTab === "sessions" && (
            <div className="identity-session-list">
              {investigation.sessions.map((context) => (
                <button
                  key={context.session.id}
                  type="button"
                  className={
                    selectedEvent?.eventId === context.startedEvent?.eventId
                      ? "identity-session-row selected"
                      : "identity-session-row"
                  }
                  onClick={() => {
                    const eventId =
                      context.revokedEvent?.eventId ??
                      context.startedEvent?.eventId;
                    if (!eventId) {
                      return;
                    }
                    setSelectedEvent({
                      eventId,
                      kind: "session",
                      title: `Session ${context.session.status}`,
                      fields: [
                        ["Session ID", context.session.id],
                        ["Status", context.session.status],
                        ["Device", context.device?.hostname ?? context.session.deviceId ?? "—"],
                        ["Application", context.application?.name ?? context.session.applicationId ?? "—"],
                        ["Started", context.session.startedAt],
                        ["Ended", context.session.endedAt ?? "—"],
                      ],
                    });
                  }}
                >
                  <span>
                    <strong>{context.session.id}</strong>
                    <small>{context.application?.name ?? "Unknown application"}</small>
                  </span>
                  <span>{context.device?.hostname ?? context.session.deviceId ?? "—"}</span>
                  <span className={`session-state ${context.session.status}`}>
                    {context.session.status}
                  </span>
                  <time>{formatTimestamp(context.session.startedAt)}</time>
                </button>
              ))}
            </div>
          )}

          {activeTab === "lifecycle" && (
            <div className="identity-session-list">
              {investigation.accountStatusActivity.length === 0 ? (
                <div className="identity-empty-state">
                  No account status changes are recorded for this account in the current run.
                </div>
              ) : investigation.accountStatusActivity.map(
                (activity) => (
                  <button
                    key={activity.eventId}
                    type="button"
                    className={
                      selectedEvent?.eventId === activity.eventId
                        ? "identity-session-row selected"
                        : "identity-session-row"
                    }
                    onClick={() =>
                      setSelectedEvent({
                        eventId: activity.eventId,
                        kind: activity.kind,
                        title:
                          activity.kind === "account_disabled"
                            ? "Account disabled"
                            : "Account enabled",
                        fields: [
                          ["Account", activity.accountId],
                          ["Reason", activity.reason ?? "—"],
                          ["Timestamp", activity.timestamp],
                        ],
                      })
                    }
                  >
                    <span>
                      <strong>{activity.kind.replaceAll("_", " ")}</strong>
                      <small>{activity.reason ?? "No reason provided"}</small>
                    </span>
                    <time>{formatTimestamp(activity.timestamp)}</time>
                  </button>
                ),
              )}
            </div>
          )}
        </section>

        <aside
          className="identity-detail-pane"
          aria-label="Identity event detail"
        >
          <section className="identity-response-operations">
            <p className="eyebrow">Identity response</p>
            <h4>Available operations</h4>
            {responseActions.length === 0 ? (
              <p className="identity-muted">
                No scenario response operations target this identity.
              </p>
            ) : (
              <div className="identity-action-list">
                {responseActions.map((action) => {
                  const performed =
                    performedActionIds.includes(action.id);
                  return (
                    <button
                      key={action.id}
                      type="button"
                      className="identity-action"
                      disabled={finalized || performed}
                      onClick={() =>
                        onPerformAction(action.id)
                      }
                    >
                      <strong>{action.label}</strong>
                      <span>{action.description}</span>
                      <small>
                        {performed
                          ? "Performed"
                          : finalized
                            ? "Run finalized"
                            : "Execute operation"}
                      </small>
                    </button>
                  );
                })}
              </div>
            )}
          </section>

          <section className="identity-selected-detail">
            {!selectedEvent ? (
              <div className="identity-detail-empty">
                <p className="eyebrow">Event detail</p>
                <strong>Select identity activity</strong>
                <p>
                  Inspect source provenance, preserve an event in Case, or pivot the exact shared event into SIEM.
                </p>
              </div>
            ) : (
              <>
                <div className="identity-detail-heading">
                  <p className="eyebrow">{selectedEvent.kind}</p>
                  <h4>{selectedEvent.title}</h4>
                  <code>{selectedEvent.eventId}</code>
                </div>
                <dl className="identity-detail-fields">
                  {selectedEvent.fields.map(
                    ([field, value]) => (
                      <div key={field}>
                        <dt>{field}</dt>
                        <dd>{value}</dd>
                      </div>
                    ),
                  )}
                </dl>
                <div className="identity-detail-actions">
                  <button
                    type="button"
                    className="evidence-button"
                    disabled={
                      finalized ||
                      isCollected(selectedEvent.eventId)
                    }
                    onClick={() =>
                      onCollect(selectedEvent.eventId)
                    }
                  >
                    {isCollected(selectedEvent.eventId)
                      ? "Evidence collected"
                      : finalized
                        ? "Run finalized"
                        : "Collect evidence"}
                  </button>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() =>
                      onSearchSiem(
                        `eventId:${selectedEvent.eventId}`,
                      )
                    }
                  >
                    Search event in SIEM
                  </button>
                  {isCollected(selectedEvent.eventId) && (
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={onOpenCase}
                    >
                      Open in Case
                    </button>
                  )}
                </div>
              </>
            )}
          </section>
        </aside>
      </div>
    </div>
  );
}
