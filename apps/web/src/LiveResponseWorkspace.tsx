import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  runLiveResponse,
} from "./simulationAdapter";

import type {
  AssetContext,
  AssetCriticality,
  LiveResponseCommandId,
  LiveResponseRow,
  ScenarioAction,
  SimulationEvent,
} from "./simulationAdapter";

import {
  actionTargetsDevice,
} from "./actionRouting";

import {
  Icon,
} from "./Icon";

import "./LiveResponseWorkspace.css";

/**
 * The console where an analyst asks a host a question instead of reading a log.
 *
 * It is deliberately its own console rather than another tab on Endpoint. The
 * endpoint view answers "what did this host do", live response answers "what
 * is true on it now", and folding the second into the first would teach that
 * they are the same question. They are not, and the gap between them is where
 * containment decisions are made.
 *
 * It runs against the replayed event window rather than the whole corpus, so
 * rewinding the scrubber and re-running a command shows what the host would
 * have said at that moment. That falls out of the projection design rather
 * than being built, and it is worth having: "was the persistence there yet
 * when the alert fired" is a real question with a real answer here.
 */

const COMMANDS: ReadonlyArray<{
  id: LiveResponseCommandId;
  label: string;
  /** What a responder is actually trying to find out. */
  question: string;
}> = [
  {
    id: "processes",
    label: "Processes",
    question:
      "What is running on this host now?",
  },
  {
    id: "connections",
    label: "Connections",
    question:
      "What is it talking to, and which program is doing the talking?",
  },
  {
    id: "persistence",
    label: "Persistence",
    question:
      "What has installed itself to start with the machine?",
  },
  {
    id: "logons",
    label: "Logons",
    question:
      "Who is signed in on it right now?",
  },
  {
    id: "files",
    label: "File changes",
    question:
      "What has been written or deleted here?",
  },
];

const CRITICALITY_LABEL: Record<
  AssetCriticality,
  string
> = {
  severe: "Severe",
  high: "High",
  moderate: "Moderate",
  low: "Low",
};

const STATE_LABEL: Record<
  string,
  string
> = {
  running: "running",
  exited: "exited",
  unknown: "unknown",
};

/**
 * Declared structurally rather than imported from the domain package, as the
 * other consoles here do: this view needs a name and an OS to render a row,
 * and taking the full entity would couple the console to fields it never
 * reads.
 */
interface HostInventoryItem {
  readonly id: string;
  readonly hostname: string;
  readonly operatingSystem: string;
  readonly autoruns?: readonly {
    readonly name: string;
    readonly location: string;
    readonly target: string;
  }[];
}

interface LiveResponseWorkspaceProps {
  readonly devices: readonly HostInventoryItem[];

  readonly events: readonly SimulationEvent[];

  readonly initialDeviceId: string | undefined;

  readonly finalized: boolean;

  readonly isCollected: (
    eventId: string,
  ) => boolean;

  readonly onCollect: (
    eventId: string,
  ) => void;

  readonly onSearchSiem: (
    query: string,
  ) => void;

  /**
   * Scenario response operations. The header calls this console the one that
   * decides whether a machine goes back to its owner, so the containment that
   * follows from looking belongs here, not on a console the analyst has to
   * leave for, the same response-in-context rule the endpoint and identity
   * consoles already follow.
   */
  readonly actions: readonly ScenarioAction[];

  readonly performedActionIds: readonly string[];

  readonly onPerformAction: (
    actionId: string,
  ) => void;

  /**
   * Business context per entity, when the scenario carries it. Shown on the
   * host status so the containment decision is made knowing what the host is
   * worth, isolating a severe-criticality Finance workstation and a
   * print-room machine are not the same call.
   */
  readonly assets?: readonly AssetContext[];
}

export function LiveResponseWorkspace({
  devices,
  events,
  initialDeviceId,
  finalized,
  isCollected,
  onCollect,
  onSearchSiem,
  actions,
  performedActionIds,
  onPerformAction,
  assets,
}: LiveResponseWorkspaceProps) {
  const [deviceId, setDeviceId] = useState(
    initialDeviceId ??
      devices[0]?.id ??
      "",
  );

  const [command, setCommand] =
    useState<LiveResponseCommandId>(
      "processes",
    );

  const [filter, setFilter] = useState("");

  const [expanded, setExpanded] = useState<
    string | null
  >(null);

  const scrollRef =
    useRef<HTMLDivElement>(null);


  /*
    The clock this console reads as "now".

    Taken from the last event in the replayed window rather than wall time,
    because the whole product runs on a virtual clock and a live-response view
    keyed to the reviewer's actual afternoon would report every process as
    long dead.
  */
  const now =
    events[events.length - 1]?.timestamp;

  const listed = useMemo(() => {
    const needle = filter
      .trim()
      .toLowerCase();

    if (!needle) {
      return devices;
    }

    return devices.filter(
      (device) =>
        device.hostname
          .toLowerCase()
          .includes(needle) ||
        device.operatingSystem
          .toLowerCase()
          .includes(needle),
    );
  }, [devices, filter]);

  /*
    Bring the selected host into view.

    The console opens on the host the alert names, which in a 154-machine
    estate is far below the fold: the list showed FIN-LT-001 onwards while the
    header said HR-LT-028, so nothing on screen appeared selected and the
    inventory read as broken. Scrolling the container rather than calling
    scrollIntoView keeps the page itself where the analyst left it.
  */
  useEffect(() => {
    const container = scrollRef.current;

    const selected =
      container?.querySelector<HTMLElement>(
        ".live-host.selected",
      );

    if (!container || !selected) {
      return;
    }

    /*
      offsetTop is already relative to the container, which is positioned for
      exactly that reason, subtracting the container's own offsetTop as well
      scrolled to a point above the target and left the selection off screen.
    */
    container.scrollTop =
      selected.offsetTop -
      container.clientHeight / 2 +
      selected.clientHeight / 2;
  }, [deviceId, listed]);

  const result = useMemo(() => {
    if (!deviceId || !now) {
      return undefined;
    }

    return runLiveResponse({
      command,
      deviceId,
      now,
      events,
      autoruns: devices.find(
        (candidate) =>
          candidate.id === deviceId,
      )?.autoruns,
    });
  }, [
    command,
    deviceId,
    now,
    events,
    devices,
  ]);

  const device = devices.find(
    (candidate) =>
      candidate.id === deviceId,
  );

  const asset = assets?.find(
    (entry) => entry.entityId === deviceId,
  );

  // The response operations that act on the host being examined. Filtered by
  // the same routing the endpoint console uses, so an operation appears on
  // exactly the consoles that can perform it and nowhere else.
  const hostActions = useMemo(
    () =>
      actions.filter((action) =>
        actionTargetsDevice(
          action,
          deviceId,
        ),
      ),
    [actions, deviceId],
  );

  const active = COMMANDS.find(
    (entry) => entry.id === command,
  );

  return (
    <div
      className="live-workspace"
      role="region"
      aria-label="Live response workspace"
    >
      <header className="live-header">
        <div>
          <p className="eyebrow">
            Endomorph Ops / Live response
          </p>
          <h3>
            <Icon name="server" size={17} />
            Live response
          </h3>
          <p>
            Query a host directly for its current state. Every other console
            here reads what was recorded; this asks what is true now, which is
            the question that decides whether a machine goes back to its owner.
          </p>
        </div>
      </header>

      <div className="live-layout">
        <aside
          className="live-host-list"
          aria-label="Estate inventory"
        >
          <div className="live-pane-heading">
            <span>Hosts</span>
            <small>
              {listed.length ===
              devices.length
                ? `${devices.length} in estate`
                : `${listed.length} of ${devices.length}`}
            </small>
          </div>

          <div className="live-host-filter">
            <input
              type="search"
              value={filter}
              onChange={(event) =>
                setFilter(
                  event.target.value,
                )
              }
              placeholder="Filter by hostname or OS"
              aria-label="Filter hosts"
            />
          </div>

          {/*
            Every host in the estate, not only the ones with an alert.

            Running the same command against a machine you suspect and one you
            do not is how an analyst learns what ordinary looks like. Limiting
            this list to hosts already implicated would remove the only
            baseline available and quietly confirm whatever they arrived
            believing.
          */}
          <p className="live-host-note">
            Any host, not only the alerted one. Comparing a suspect machine
            with an ordinary one is the fastest way to tell which is which.
          </p>

          <div
            className="live-host-scroll"
            ref={scrollRef}
          >
            {listed.map((candidate) => (
              <button
                key={candidate.id}
                type="button"
                className={`live-host${
                  candidate.id === deviceId
                    ? " selected"
                    : ""
                }`}
                onClick={() => {
                  setDeviceId(candidate.id);
                  setExpanded(null);
                }}
              >
                <strong>
                  {candidate.hostname}
                </strong>
                <small>
                  {
                    candidate.operatingSystem
                  }
                </small>
              </button>
            ))}
          </div>
        </aside>

        <section className="live-console">
          {result && device ? (
            <>
              <div
                className={`live-status live-status-${result.host.reachability}`}
              >
                <div className="live-status-head">
                  <Icon
                    name={
                      result.host
                        .reachability ===
                      "online"
                        ? "check"
                        : result.host
                              .reachability ===
                            "contained"
                          ? "shield"
                          : "warning"
                    }
                    size={15}
                  />
                  <strong>
                    {device.hostname}
                  </strong>
                  <span>
                    {result.host
                      .reachability ===
                    "not-reporting"
                      ? "not reporting"
                      : result.host
                          .reachability}
                  </span>
                  {asset && (
                    <span
                      className={`live-criticality live-criticality-${asset.criticality}`}
                      title={asset.rationale}
                    >
                      {
                        CRITICALITY_LABEL[
                          asset.criticality
                        ]
                      }
                      {" · "}
                      {asset.businessUnit}
                    </span>
                  )}
                </div>
                <p>
                  {
                    result.host
                      .reachabilityBasis
                  }
                </p>
              </div>

              <div
                className="live-commands"
                role="group"
                aria-label="Live response commands"
              >
                {COMMANDS.map((entry) => (
                  <button
                    key={entry.id}
                    type="button"
                    className={`live-command${
                      entry.id === command
                        ? " selected"
                        : ""
                    }`}
                    onClick={() => {
                      setCommand(entry.id);
                      setExpanded(null);
                    }}
                  >
                    {entry.label}
                  </button>
                ))}
              </div>

              {active && (
                <p className="live-question">
                  {active.question}
                </p>
              )}

              {result.rows.length === 0 ? (
                <p className="live-empty">
                  {result.host
                    .reachability ===
                  "not-reporting"
                    ? "Nothing gathered: the host is not answering."
                    : "Nothing to report. On most hosts in an estate that is the correct answer, and knowing what it looks like is worth the query."}
                </p>
              ) : (
                <ul className="live-rows">
                  {result.rows.map((row) => (
                    <LiveRow
                      key={`${row.eventId ?? row.primary}-${row.timestamp}`}
                      row={row}
                      expanded={
                        expanded ===
                        `${row.eventId}-${row.timestamp}`
                      }
                      onToggle={() =>
                        setExpanded(
                          expanded ===
                            `${row.eventId}-${row.timestamp}`
                            ? null
                            : `${row.eventId}-${row.timestamp}`,
                        )
                      }
                      finalized={finalized}
                      collected={
                        row.eventId
                          ? isCollected(
                              row.eventId,
                            )
                          : false
                      }
                      onCollect={onCollect}
                      onSearchSiem={
                        onSearchSiem
                      }
                    />
                  ))}
                </ul>
              )}

              {/*
                The limits of the view, next to the view.

                A responder needs to know what a listing cannot tell them at
                the moment they are reading it, not in documentation they will
                never open. This is also the honest counterweight to how
                authoritative a table looks.
              */}
              <p className="live-limitation">
                <Icon name="info" size={13} />
                {result.limitation}
              </p>

              <section
                className="live-response-operations"
                aria-label="Host containment"
              >
                <p className="eyebrow">
                  Host containment
                </p>
                <h4>
                  Act on{" "}
                  {device.hostname}
                </h4>

                {hostActions.length ===
                0 ? (
                  <p className="live-muted">
                    No scenario response
                    operation targets this
                    host.
                  </p>
                ) : (
                  <div className="live-action-list">
                    {hostActions.map(
                      (action) => {
                        const performed =
                          performedActionIds.includes(
                            action.id,
                          );

                        return (
                          <button
                            key={action.id}
                            type="button"
                            className="live-action"
                            disabled={
                              finalized ||
                              performed
                            }
                            onClick={() =>
                              onPerformAction(
                                action.id,
                              )
                            }
                          >
                            <strong>
                              {action.label}
                            </strong>
                            <span>
                              {
                                action.description
                              }
                            </span>
                            <small>
                              {performed
                                ? "Performed"
                                : finalized
                                  ? "Run finalized"
                                  : "Execute operation"}
                            </small>
                          </button>
                        );
                      },
                    )}
                  </div>
                )}
              </section>
            </>
          ) : (
            <p className="live-empty">
              Select a host to query.
            </p>
          )}
        </section>
      </div>
    </div>
  );
}

interface LiveRowProps {
  readonly row: LiveResponseRow;
  readonly expanded: boolean;
  readonly onToggle: () => void;
  readonly finalized: boolean;
  readonly collected: boolean;
  readonly onCollect: (
    eventId: string,
  ) => void;
  readonly onSearchSiem: (
    query: string,
  ) => void;
}

function LiveRow({
  row,
  expanded,
  onToggle,
  finalized,
  collected,
  onCollect,
  onSearchSiem,
}: LiveRowProps) {
  return (
    <li className="live-row">
      <button
        type="button"
        className="live-row-head"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        {row.state && (
          <span
            className={`live-state live-state-${row.state}`}
          >
            {STATE_LABEL[row.state] ??
              row.state}
          </span>
        )}
        <span className="live-row-primary">
          {row.primary}
        </span>
        {row.secondary && (
          <span className="live-row-secondary">
            {row.secondary}
          </span>
        )}
        <Icon
          name={
            expanded
              ? "chevron-down"
              : "chevron-right"
          }
          size={13}
        />
      </button>

      {expanded && (
        <div className="live-row-body">
          {row.detail && (
            <code className="live-row-detail">
              {row.detail}
            </code>
          )}

          {/*
            Why the row says what it says.

            A state with no reasoning attached is an assertion, and an analyst
            who cannot see how a verdict was reached learns to accept verdicts
           , the opposite of the habit this product exists to build.
          */}
          {row.basis && (
            <p className="live-row-basis">
              {row.basis}
            </p>
          )}

          <div className="live-row-actions">
            {row.eventId &&
              !finalized &&
              !collected && (
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() =>
                    onCollect(
                      row.eventId as string,
                    )
                  }
                >
                  Collect as evidence
                </button>
              )}

            {row.eventId && collected && (
              <span className="live-collected">
                <Icon
                  name="check"
                  size={13}
                />
                Collected
              </span>
            )}

            {row.eventId && (
              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  onSearchSiem(
                    `eventId:${row.eventId}`,
                  )
                }
              >
                Search event in SIEM
              </button>
            )}
          </div>
        </div>
      )}
    </li>
  );
}
