import {
  useMemo,
  useState,
} from "react";

import {
  getIdentityAccountInvestigation,
  getIdentityInventory,
} from "./simulationAdapter";

import type {
  AssetContext,
  AssetCriticality,
  IdentityProjectionState,
  ScenarioAction,
  ScenarioState,
} from "./simulationAdapter";

import {
  actionTargetsAccount,
} from "./actionRouting";

import {
  Icon,
} from "./Icon";

import {
  Sparkline,
} from "./Charts";

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

  /**
   * Business context per entity, when the scenario carries it. On the
   * identity console it is the privileged accounts, the ones marked severe
   *, that most need to stand out from ordinary staff logins.
   */
  assets?: readonly AssetContext[];
}

const CRITICALITY_LABEL: Record<
  AssetCriticality,
  string
> = {
  severe: "Severe",
  high: "High",
  moderate: "Moderate",
  low: "Low",
};

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

/*
  Constructed once. Building an Intl.DateTimeFormat is expensive, and this was
  building a fresh one for every timestamp rendered, which, on a scenario
  with twenty thousand events, was three seconds of the finalize interaction
  by itself, more than any other single thing the app did.
*/
const CLOCK_FORMAT =
  new Intl.DateTimeFormat(
    "en-US",
    {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    },
  );

function formatTimestamp(timestamp: string): string {
  return CLOCK_FORMAT.format(
    new Date(timestamp),
  );
}

export function IdentityWorkspace({
  world,
  state,
  assets,
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
  const assetByEntityId = useMemo(
    () =>
      new Map(
        (assets ?? []).map(
          (asset) =>
            [
              asset.entityId,
              asset,
            ] as const,
        ),
      ),
    [assets],
  );

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
  // The console exists to examine one account. Finding it meant scrolling
  // past 119 others, which also stretched the page to twenty-odd screens.
  const [directoryFilter, setDirectoryFilter] =
    useState("");

  const [selectedEvent, setSelectedEvent] =
    useState<SelectedIdentityEvent | null>(null);

  /*
    Sign-in activity per account, bucketed in one pass.

    A directory row showed a name, a department and three counts, and 120 of
    them looked the same. When an account was active is the thing that lets
    an analyst spot the one that behaved unlike the rest, a service account
    that runs at 03:00 every night against a person who works office hours.
  */
  const activityByAccount = useMemo(() => {
    const buckets = 14;

    const times = state.activity
      .map((entry) =>
        Date.parse(entry.timestamp),
      )
      .filter((value) =>
        Number.isFinite(value),
      );

    if (times.length === 0) {
      return new Map<
        string,
        number[]
      >();
    }

    const start = Math.min(...times);

    const span = Math.max(
      Math.max(...times) - start,
      1,
    );

    const byAccount = new Map<
      string,
      number[]
    >();

    for (const entry of state.activity) {
      const accountId = (
        entry as {
          accountId?: string;
        }
      ).accountId;

      const at = Date.parse(
        entry.timestamp,
      );

      if (
        !accountId ||
        !Number.isFinite(at)
      ) {
        continue;
      }

      let series =
        byAccount.get(accountId);

      if (!series) {
        series = Array.from(
          { length: buckets },
          () => 0,
        );

        byAccount.set(
          accountId,
          series,
        );
      }

      series[
        Math.min(
          buckets - 1,
          Math.floor(
            ((at - start) / span) *
              buckets,
          ),
        )
      ] += 1;
    }

    return byAccount;
  }, [state.activity]);

  const filteredInventory = useMemo(() => {
    const needle = directoryFilter
      .trim()
      .toLowerCase();

    if (needle.length === 0) {
      return inventory;
    }

    // Matches on the things an analyst actually arrives holding: a name from
    // a ticket, a username from an alert, or a department when scoping.
    return inventory.filter(
      (entry) =>
        entry.user.displayName
          .toLowerCase()
          .includes(needle) ||
        entry.user.department
          .toLowerCase()
          .includes(needle) ||
        (entry.user.title ?? "")
          .toLowerCase()
          .includes(needle) ||
        entry.accounts.some((account) =>
          account.username
            .toLowerCase()
            .includes(needle),
        ),
    );
  }, [inventory, directoryFilter]);

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
        investigation.account.username,
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
            Endomorph Ops / Identity
          </p>
          <h3>
            <Icon name="identity" size={17} />
            Identity and access investigation
          </h3>
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
            <small>
              {filteredInventory.length ===
              inventory.length
                ? `${inventory.length} users`
                : `${filteredInventory.length} of ${inventory.length}`}
            </small>
          </div>

          <div className="identity-directory-filter">
            <input
              type="search"
              value={directoryFilter}
              placeholder="Filter by name, username, or department"
              aria-label="Filter the directory"
              onChange={(event) =>
                setDirectoryFilter(
                  event.target.value,
                )
              }
            />
          </div>

          <div className="identity-directory-scroll">
          {filteredInventory.length === 0 && (
            <p className="identity-directory-empty">
              No account matches
              &ldquo;{directoryFilter}&rdquo;.
            </p>
          )}
          {filteredInventory.map((entry) => (
            <div
              className="identity-user-group"
              key={entry.user.id}
            >
              <div className="identity-user-summary">
                <span className="identity-user-name">
                  <strong>{entry.user.displayName}</strong>
                  {(() => {
                    const asset =
                      assetByEntityId.get(
                        entry.user.id,
                      );

                    return asset ? (
                      <span
                        className={`identity-criticality identity-criticality-${asset.criticality}`}
                        title={
                          asset.rationale
                        }
                      >
                        {
                          CRITICALITY_LABEL[
                            asset
                              .criticality
                          ]
                        }
                      </span>
                    ) : null;
                  })()}
                </span>
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
                  {(() => {
                    const asset =
                      assetByEntityId.get(
                        account.id,
                      );

                    return asset ? (
                      <span
                        className={`identity-criticality identity-criticality-${asset.criticality}`}
                        title={
                          asset.rationale
                        }
                      >
                        {
                          CRITICALITY_LABEL[
                            asset
                              .criticality
                          ]
                        }
                      </span>
                    ) : null;
                  })()}
                </button>
              ))}
              <div className="identity-user-metrics">
                <Sparkline
                  values={
                    activityByAccount.get(
                      entry.accounts[0]
                        ?.id ?? "",
                    ) ?? []
                  }
                  label={`Sign-in activity for ${entry.user.displayName}`}
                  width={58}
                  height={15}
                />
                <span>{entry.activeSessionCount} active session</span>
                <span>{entry.successfulLoginCount} success</span>
                <span>{entry.failedLoginCount} failed</span>
              </div>
            </div>
          ))}
          </div>
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
              {(() => {
                const asset =
                  assetByEntityId.get(
                    selectedAccountId,
                  );

                return asset ? (
                  <span
                    title={asset.rationale}
                  >
                    <small>
                      Criticality
                    </small>
                    <strong
                      className={`identity-criticality identity-criticality-${asset.criticality}`}
                    >
                      {
                        CRITICALITY_LABEL[
                          asset.criticality
                        ]
                      }
                    </strong>
                  </span>
                ) : null;
              })()}
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
                            ["Source IP", activity.sourceIp ?? ", "],
                            [
                              "Device",
                              deviceId
                                ? world.devices[deviceId]?.hostname ?? deviceId
                                : ", ",
                            ],
                            [
                              "Application",
                              applicationId
                                ? world.applications[applicationId]?.name ?? applicationId
                                : ", ",
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
                      <code>{activity.sourceIp ?? ", "}</code>
                      <span>
                        {deviceId
                          ? world.devices[deviceId]?.hostname ?? deviceId
                          : ", "}
                      </span>
                      <span>
                        {applicationId
                          ? world.applications[applicationId]?.name ?? applicationId
                          : ", "}
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
                        ["Device", context.device?.hostname ?? context.session.deviceId ?? ", "],
                        ["Application", context.application?.name ?? context.session.applicationId ?? ", "],
                        ["Started", context.session.startedAt],
                        ["Ended", context.session.endedAt ?? ", "],
                      ],
                    });
                  }}
                >
                  <span>
                    <strong>{context.session.id}</strong>
                    <small>{context.application?.name ?? "Unknown application"}</small>
                  </span>
                  <span>{context.device?.hostname ?? context.session.deviceId ?? ", "}</span>
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
                  No lifecycle changes are recorded for this account in the current run, no status change, and no role granted or removed.
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
                            : activity.kind === "role_granted"
                              ? "Role granted"
                              : "Account enabled",
                        fields: [
                          ["Account", activity.accountId],
                          // The role is the whole point of a grant, so it
                          // leads rather than sitting under a reason.
                          ...(activity.kind === "role_granted"
                            ? ([["Role", activity.role]] as [string, string][])
                            : []),
                          ["Reason", activity.reason ?? ", "],
                          ["Timestamp", activity.timestamp],
                        ],
                      })
                    }
                  >
                    <span>
                      <strong>
                        {activity.kind === "role_granted"
                          ? `role granted: ${activity.role}`
                          : activity.kind.replaceAll("_", " ")}
                      </strong>
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
                <p className="identity-section-label">
                  Normalized fields
                </p>
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
                <p className="identity-section-label">
                  Actions on this event
                </p>
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
