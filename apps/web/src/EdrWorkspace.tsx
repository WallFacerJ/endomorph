import {
  useMemo,
  useState,
} from "react";

import {
  getEdrEndpointInvestigation,
  getObservedEdrDeviceIds,
} from "./simulationAdapter";

import type {
  AssetContext,
  AssetCriticality,
  EdrProjectionState,
  ScenarioAction,
} from "./simulationAdapter";

import {
  actionTargetsDevice,
} from "./actionRouting";

import type {
  WorldState,
} from "./simulationAdapter";

import {
  Icon,
} from "./Icon";

import {
  Sparkline,
} from "./Charts";

import "./EdrWorkspace.css";

/**
 * The program name alone, for the list row.
 *
 * The row is scanned, not read: a full image path pushes the address and
 * the timestamp off the line. The path stays in the detail pane, where an
 * analyst who needs to check the directory can find it, and the
 * directory is often the whole finding.
 */
function processName(image: string): string {
  const segments = image.split(
    /[\\/]/,
  );

  return (
    segments[segments.length - 1] ??
    image
  );
}

interface EndpointInventoryItem {
  id: string;
  hostname: string;
  operatingSystem: string;
  status: string;
  ipAddresses: readonly string[];
}

interface EdrWorkspaceProps {
  /**
   * The world, for resolving identifiers to the names people use.
   *
   * The console showed raw entity ids, "file-deployment-keys-txt",
   * "account-rosa.rahman", where an analyst expects "deployment-keys.txt"
   * and "rosa.rahman@acme.test". One of the investigation questions asks
   * which document was read and accepts the file's name, so the console was
   * asking the analyst to guess a transformation rather than read a value.
   */
  world: WorldState;

  state: EdrProjectionState;
  devices: readonly EndpointInventoryItem[];
  initialDeviceId: string;
  actions: readonly ScenarioAction[];
  performedActionIds: readonly string[];
  onPerformAction: (
    actionId: string,
  ) => void;
  finalized: boolean;
  isCollected: (eventId: string) => boolean;
  onCollect: (eventId: string) => void;
  onSearchSiem: (query: string) => void;
  onOpenCase: () => void;

  /**
   * Business context per entity, when the scenario carries it. Generated
   * scenarios do; the hand-authored set predates it, so the inventory falls
   * back to no criticality rather than inventing one.
   */
  assets?: readonly AssetContext[];
}

type EdrTab =
  | "processes"
  | "network"
  | "files"
  | "alerts";

type SelectedObservation =
  | {
      kind: "process";
      eventId: string;
    }
  | {
      kind: "network";
      eventId: string;
    }
  | {
      kind: "file";
      eventId: string;
    }
  | {
      kind: "alert";
      eventId: string;
    };

function basename(path: string): string {
  return path.split(/[\\/]/).at(-1) ?? path;
}

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

function DetailActionBar({
  eventId,
  finalized,
  collected,
  onCollect,
  onSearchSiem,
  onOpenCase,
}: {
  eventId: string;
  finalized: boolean;
  collected: boolean;
  onCollect: (eventId: string) => void;
  onSearchSiem: (query: string) => void;
  onOpenCase: () => void;

  /**
   * Business context per entity, when the scenario carries it. Generated
   * scenarios do; the hand-authored set predates it, so the inventory falls
   * back to no criticality rather than inventing one.
   */
  assets?: readonly AssetContext[];
}) {
  return (
    <div className="edr-detail-actions">
      <button
        type="button"
        className="evidence-button"
        disabled={finalized || collected}
        onClick={() => onCollect(eventId)}
      >
        {collected
          ? "Evidence collected"
          : finalized
            ? "Run finalized"
            : "Collect evidence"}
      </button>
      <button
        type="button"
        className="secondary-button"
        onClick={() =>
          onSearchSiem(`eventId:${eventId}`)
        }
      >
        Search event in SIEM
      </button>
      {collected && (
        <button
          type="button"
          className="secondary-button"
          onClick={onOpenCase}
        >
          Open in Case
        </button>
      )}
    </div>
  );
}

/**
 * Triage order: the most critical asset is the one to look at first, so it
 * sorts to the top of the inventory. Assets with no context sort last rather
 * than jumping the queue on a rank of zero.
 */
const CRITICALITY_RANK: Record<
  AssetCriticality,
  number
> = {
  severe: 0,
  high: 1,
  moderate: 2,
  low: 3,
};

const CRITICALITY_LABEL: Record<
  AssetCriticality,
  string
> = {
  severe: "Severe",
  high: "High",
  moderate: "Moderate",
  low: "Low",
};

export function EdrWorkspace({
  assets,
  world,
  state,
  devices,
  initialDeviceId,
  actions,
  performedActionIds,
  onPerformAction,
  finalized,
  isCollected,
  onCollect,
  onSearchSiem,
  onOpenCase,
}: EdrWorkspaceProps) {
  const observedDeviceIds = useMemo(
    () => getObservedEdrDeviceIds(state),
    [state],
  );

  // 147 endpoints listed unbounded made this console sixteen screens tall,
  // and an analyst who arrives holding a hostname had to scroll for it.
  const [endpointFilter, setEndpointFilter] =
    useState("");

  const availableDevices = useMemo(
    () => devices.filter((device) =>
      observedDeviceIds.includes(device.id),
    ),
    [devices, observedDeviceIds],
  );

  /*
    Activity per device, bucketed once.

    Every row previously showed the same two facts, "active" and a process
    count that barely varies, so 147 endpoints looked identical and there
    was nothing to steer by. The shape says when a host was busy, which is
    the thing an analyst actually scans an inventory for.

    Built in a single pass keyed by device. A filter per row would be 147
    scans of the full process stream.
  */
  const activityByDevice = useMemo(() => {
    const buckets = 14;

    const times = state.processes
      .map((process) =>
        Date.parse(process.timestamp),
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

    const byDevice = new Map<
      string,
      number[]
    >();

    for (const process of state.processes) {
      const at = Date.parse(
        process.timestamp,
      );

      if (!Number.isFinite(at)) {
        continue;
      }

      let series = byDevice.get(
        process.deviceId,
      );

      if (!series) {
        series = Array.from(
          { length: buckets },
          () => 0,
        );

        byDevice.set(
          process.deviceId,
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

    return byDevice;
  }, [state.processes]);

  const fileNames = useMemo(
    () =>
      new Map(
        Object.values(world.files).map(
          (file) => [file.id, file.name],
        ),
      ),
    [world.files],
  );

  const accountNames = useMemo(
    () =>
      new Map(
        Object.values(
          world.accounts,
        ).map((account) => [
          account.id,
          account.username,
        ]),
      ),
    [world.accounts],
  );

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

  const filteredDevices = useMemo(() => {
    const needle = endpointFilter
      .trim()
      .toLowerCase();

    const base =
      needle.length === 0
        ? availableDevices
        : availableDevices.filter(
            (device) =>
              device.hostname
                .toLowerCase()
                .includes(needle) ||
              device.operatingSystem
                .toLowerCase()
                .includes(needle),
          );

    // Rank a device by the criticality of its asset context, most critical
    // first, with unranked assets last. Ties break on hostname so the order
    // is deterministic rather than dependent on generation order.
    const rankOf = (
      deviceId: string,
    ): number => {
      const asset =
        assetByEntityId.get(deviceId);

      return asset
        ? CRITICALITY_RANK[
            asset.criticality
          ]
        : 4;
    };

    return [...base].sort(
      (left, right) => {
        const rankDelta =
          rankOf(left.id) -
          rankOf(right.id);

        return rankDelta !== 0
          ? rankDelta
          : left.hostname.localeCompare(
              right.hostname,
            );
      },
    );
  }, [
    availableDevices,
    endpointFilter,
    assetByEntityId,
  ]);

  const [selectedDeviceId, setSelectedDeviceId] =
    useState(
      observedDeviceIds.includes(initialDeviceId)
        ? initialDeviceId
        : observedDeviceIds[0] ?? initialDeviceId,
    );
  const endpointActions = useMemo(
    () =>
      actions.filter((action) =>
        actionTargetsDevice(
          action,
          selectedDeviceId,
        ),
      ),
    [actions, selectedDeviceId],
  );

  const [activeTab, setActiveTab] =
    useState<EdrTab>("processes");
  const [selected, setSelected] =
    useState<SelectedObservation | null>(null);

  const investigation = useMemo(
    () =>
      getEdrEndpointInvestigation(
        state,
        selectedDeviceId,
      ),
    [state, selectedDeviceId],
  );

  const selectedDevice = devices.find(
    (device) => device.id === selectedDeviceId,
  );

  const selectedProcess =
    selected?.kind === "process"
      ? investigation.processes.find(
          (process) =>
            process.eventId === selected.eventId,
        )
      : undefined;

  const selectedNetwork =
    selected?.kind === "network"
      ? investigation.networkConnections.find(
          (connection) =>
            connection.eventId === selected.eventId,
        )
      : undefined;

  const selectedFile =
    selected?.kind === "file"
      ? investigation.fileActivity.find(
          (activity) =>
            activity.eventId === selected.eventId,
        )
      : undefined;

  const selectedAlert =
    selected?.kind === "alert"
      ? investigation.alerts.find(
          (alert) =>
            alert.eventId === selected.eventId,
        )
      : undefined;

  const eventId =
    selectedProcess?.eventId ??
    selectedNetwork?.eventId ??
    selectedFile?.eventId ??
    selectedAlert?.eventId;

  return (
    <div
      className="edr-workspace"
      role="region"
      aria-label="EDR endpoint workspace"
    >
      <header className="edr-header">
        <div>
          <p className="eyebrow">
            Endomorph Ops / EDR
          </p>
          <h3>
            <Icon name="endpoint" size={17} />
            Endpoint investigation
          </h3>
          <p>
            Trace process ancestry, inspect endpoint-scoped activity, and pivot shared telemetry into SIEM or Case.
          </p>
        </div>
        <div className="edr-header-stats">
          <span>
            <strong>{availableDevices.length}</strong>
            observed endpoints
          </span>
          <span>
            <strong>{state.processes.length}</strong>
            process events
          </span>
          <span>
            <strong>{state.alerts.length}</strong>
            EDR alerts
          </span>
        </div>
      </header>

      <div className="edr-layout">
        <aside
          className="edr-endpoint-list"
          aria-label="EDR endpoint inventory"
        >
          <div className="edr-pane-heading">
            <span>Endpoints</span>
            <small>
              {filteredDevices.length ===
              availableDevices.length
                ? `${availableDevices.length} observed`
                : `${filteredDevices.length} of ${availableDevices.length}`}
            </small>
          </div>

          <div className="edr-endpoint-filter">
            <input
              type="search"
              value={endpointFilter}
              placeholder="Filter by hostname or OS"
              aria-label="Filter the endpoint inventory"
              onChange={(event) =>
                setEndpointFilter(
                  event.target.value,
                )
              }
            />
          </div>

          <div className="edr-endpoint-scroll">
          {filteredDevices.length === 0 && (
            <p className="edr-endpoint-empty">
              No endpoint matches
              &ldquo;{endpointFilter}&rdquo;.
            </p>
          )}
          {filteredDevices.map((device) => {
            const observation =
              state.endpointObservations[device.id];
            const asset =
              assetByEntityId.get(device.id);
            const processCount = state.processes.filter(
              (process) => process.deviceId === device.id,
            ).length;
            const alertCount = state.alerts.filter(
              (alert) =>
                alert.relatedEntityIds.includes(device.id),
            ).length;

            return (
              <button
                key={device.id}
                type="button"
                className={
                  device.id === selectedDeviceId
                    ? "edr-endpoint-row selected"
                    : "edr-endpoint-row"
                }
                onClick={() => {
                  setSelectedDeviceId(device.id);
                  setSelected(null);
                }}
              >
                <span className="edr-endpoint-name">
                  <strong>{device.hostname}</strong>
                  <small>{device.operatingSystem}</small>
                  {asset && (
                    <small className="edr-endpoint-unit">
                      {asset.businessUnit}
                    </small>
                  )}
                </span>
                {asset && (
                  <span
                    className={`edr-criticality edr-criticality-${asset.criticality}`}
                    title={asset.rationale}
                  >
                    {
                      CRITICALITY_LABEL[
                        asset.criticality
                      ]
                    }
                  </span>
                )}
                <span className="edr-endpoint-meta">
                  <span>{observation?.status ?? device.status}</span>
                  <span>{processCount} proc</span>
                  <Sparkline
                    values={
                      activityByDevice.get(
                        device.id,
                      ) ?? []
                    }
                    label={`Process activity on ${device.hostname}`}
                    width={64}
                    height={16}
                  />
                  {alertCount > 0 && (
                    <span className="edr-alert-count">
                      {alertCount} alert
                    </span>
                  )}
                </span>
              </button>
            );
          })}
          </div>
        </aside>

        <section className="edr-activity-pane">
          <div className="edr-endpoint-summary">
            <div>
              <p className="eyebrow">Selected endpoint</p>
              <h4>{selectedDevice?.hostname ?? selectedDeviceId}</h4>
            </div>
            <div className="edr-endpoint-facts">
              <span>
                <small>OS</small>
                <strong>{selectedDevice?.operatingSystem ?? ", "}</strong>
              </span>
              <span>
                <small>IP</small>
                <strong>{selectedDevice?.ipAddresses.join(", ") || ", "}</strong>
              </span>
              <span>
                <small>Status</small>
                <strong>{investigation.endpoint?.status ?? selectedDevice?.status ?? ", "}</strong>
              </span>
              {(() => {
                const selectedAsset =
                  assetByEntityId.get(
                    selectedDeviceId,
                  );

                return selectedAsset ? (
                  <>
                    <span>
                      <small>
                        Business unit
                      </small>
                      <strong>
                        {
                          selectedAsset.businessUnit
                        }
                      </strong>
                    </span>
                    <span
                      title={
                        selectedAsset.rationale
                      }
                    >
                      <small>
                        Criticality
                      </small>
                      <strong
                        className={`edr-criticality edr-criticality-${selectedAsset.criticality}`}
                      >
                        {
                          CRITICALITY_LABEL[
                            selectedAsset
                              .criticality
                          ]
                        }
                      </strong>
                    </span>
                  </>
                ) : null;
              })()}
            </div>
          </div>

          <div
            className="edr-tabs"
            role="tablist"
            aria-label="EDR activity views"
          >
            {([
              ["processes", `Processes ${investigation.processes.length}`],
              ["network", `Network ${investigation.networkConnections.length}`],
              ["files", `Files ${investigation.fileActivity.length}`],
              ["alerts", `Alerts ${investigation.alerts.length}`],
            ] as const).map(([tab, label]) => (
              <button
                key={tab}
                type="button"
                role="tab"
                aria-selected={activeTab === tab}
                onClick={() => {
                  setActiveTab(tab);
                  setSelected(null);
                }}
              >
                {label}
              </button>
            ))}
          </div>

          {activeTab === "processes" && (
            <div className="edr-process-list">
              <div className="edr-table-header process-columns">
                <span>Process</span>
                <span>PID</span>
                <span>Parent / PID</span>
                <span>Account</span>
                <span>Time</span>
              </div>
              {investigation.processTree.map((node) => (
                <button
                  key={node.process.eventId}
                  type="button"
                  className={
                    selected?.eventId === node.process.eventId
                      ? "edr-process-row selected"
                      : "edr-process-row"
                  }
                  onClick={() =>
                    setSelected({
                      kind: "process",
                      eventId: node.process.eventId,
                    })
                  }
                >
                  <span
                    className="edr-process-name"
                    style={{
                      paddingLeft: `${node.depth * 22 + 10}px`,
                    }}
                  >
                    <span className="edr-tree-branch">
                      {node.depth > 0 ? "└" : "•"}
                    </span>
                    <strong>{basename(node.process.image)}</strong>
                    {node.orphanedParent &&
                      !node.parentImage && (
                        <small>parent not observed</small>
                      )}
                  </span>
                  <code>{node.process.processId}</code>
                  <span className="edr-process-parent">
                    <code>
                      {node.parentImage
                        ? basename(node.parentImage)
                        : ", "}
                    </code>
                    {node.process.parentProcessId && (
                      <code className="edr-process-parent-pid">
                        {node.process.parentProcessId}
                      </code>
                    )}
                  </span>
                  <span>{node.process.accountId ?? ", "}</span>
                  <time>{formatTimestamp(node.process.timestamp)}</time>
                </button>
              ))}
            </div>
          )}

          {activeTab === "network" && (
            <div className="edr-activity-list">
              {investigation.networkConnections.map((connection) => (
                <button
                  key={connection.eventId}
                  type="button"
                  className={
                    selected?.eventId === connection.eventId
                      ? "edr-activity-row selected"
                      : "edr-activity-row"
                  }
                  onClick={() =>
                    setSelected({
                      kind: "network",
                      eventId: connection.eventId,
                    })
                  }
                >
                  <span>
                    <strong>{connection.sourceIp}</strong>
                    <small>source</small>
                  </span>
                  <span className="edr-flow-arrow">→</span>
                  <span>
                    <strong>{connection.destinationIp}:{connection.destinationPort ?? ", "}</strong>
                    <small>
                      {connection.image
                        ? processName(connection.image)
                        : connection.protocol.toUpperCase()}
                    </small>
                  </span>
                  <time>{formatTimestamp(connection.timestamp)}</time>
                </button>
              ))}
            </div>
          )}

          {activeTab === "files" && (
            <div className="edr-activity-list">
              {investigation.fileActivity.map((activity) => (
                <button
                  key={activity.eventId}
                  type="button"
                  className={
                    selected?.eventId === activity.eventId
                      ? "edr-activity-row selected"
                      : "edr-activity-row"
                  }
                  onClick={() =>
                    setSelected({
                      kind: "file",
                      eventId: activity.eventId,
                    })
                  }
                >
                  <span>
                    <strong>
                      {fileNames.get(
                        activity.fileId,
                      ) ?? activity.fileId}
                    </strong>
                    <small>file</small>
                  </span>
                  <span>
                    <strong>{activity.operation}</strong>
                    <small>operation</small>
                  </span>
                  <span>
                    <strong>
                      {(activity.accountId &&
                        accountNames.get(
                          activity.accountId,
                        )) ??
                        activity.accountId ??
                        ", "}
                    </strong>
                    <small>account</small>
                  </span>
                  <time>{formatTimestamp(activity.timestamp)}</time>
                </button>
              ))}
            </div>
          )}

          {activeTab === "alerts" && (
            <div className="edr-alert-list">
              {investigation.alerts.map((alert) => (
                <button
                  key={alert.eventId}
                  type="button"
                  className={
                    selected?.eventId === alert.eventId
                      ? "edr-alert-row selected"
                      : "edr-alert-row"
                  }
                  onClick={() =>
                    setSelected({
                      kind: "alert",
                      eventId: alert.eventId,
                    })
                  }
                >
                  <span className={`severity-dot ${alert.severity}`} />
                  <span>
                    <strong>{alert.title}</strong>
                    <small>{alert.alertId} · {alert.severity}</small>
                  </span>
                  <time>{formatTimestamp(alert.timestamp)}</time>
                </button>
              ))}
            </div>
          )}
        </section>

        <aside
          className="edr-detail-pane"
          aria-label="EDR observation detail"
        >
          {!selected || !eventId ? (
            <div className="edr-detail-empty">
              <p className="eyebrow">Observation detail</p>
              <strong>Select endpoint activity</strong>
              <p>
                Inspect process ancestry or endpoint activity, then pivot the same event into SIEM or preserve it in Case.
              </p>
            </div>
          ) : selectedProcess ? (
            <>
              <div className="edr-detail-heading">
                <p className="eyebrow">Process detail</p>
                <h4>{basename(selectedProcess.image)}</h4>
                <code>{selectedProcess.eventId}</code>
              </div>
              <dl className="edr-detail-fields">
                <div><dt>Image</dt><dd>{selectedProcess.image}</dd></div>
                <div><dt>Command line</dt><dd><code>{selectedProcess.commandLine ?? ", "}</code></dd></div>
                <div><dt>PID</dt><dd>{selectedProcess.processId}</dd></div>
                <div><dt>Parent</dt><dd>{selectedProcess.parentImage ?? ", "}</dd></div>
                <div><dt>Parent PID</dt><dd>{selectedProcess.parentProcessId ?? ", "}</dd></div>
                <div><dt>Account</dt><dd>{selectedProcess.accountId ?? ", "}</dd></div>
                <div><dt>Started</dt><dd>{selectedProcess.timestamp}</dd></div>
              </dl>
              <DetailActionBar
                eventId={selectedProcess.eventId}
                finalized={finalized}
                collected={isCollected(selectedProcess.eventId)}
                onCollect={onCollect}
                onSearchSiem={onSearchSiem}
                onOpenCase={onOpenCase}
              />
            </>
          ) : selectedNetwork ? (
            <>
              <div className="edr-detail-heading">
                <p className="eyebrow">Network detail</p>
                <h4>{selectedNetwork.destinationIp}:{selectedNetwork.destinationPort ?? ", "}</h4>
                <code>{selectedNetwork.eventId}</code>
              </div>
              <dl className="edr-detail-fields">
                <div><dt>Source</dt><dd>{selectedNetwork.sourceIp}:{selectedNetwork.sourcePort ?? ", "}</dd></div>
                <div><dt>Destination</dt><dd>{selectedNetwork.destinationIp}:{selectedNetwork.destinationPort ?? ", "}</dd></div>
                <div><dt>Protocol</dt><dd>{selectedNetwork.protocol.toUpperCase()}</dd></div>
                <div>
                  <dt>Process</dt>
                  <dd>
                    {selectedNetwork.image
                      ? `${selectedNetwork.image}${
                          selectedNetwork.processId
                            ? ` (pid ${selectedNetwork.processId})`
                            : ""
                        }`
                      : "Not attributed, seen by a network sensor, off the host"}
                  </dd>
                </div>
                <div><dt>Observed</dt><dd>{selectedNetwork.timestamp}</dd></div>
              </dl>
              <DetailActionBar
                eventId={selectedNetwork.eventId}
                finalized={finalized}
                collected={isCollected(selectedNetwork.eventId)}
                onCollect={onCollect}
                onSearchSiem={onSearchSiem}
                onOpenCase={onOpenCase}
              />
            </>
          ) : selectedFile ? (
            <>
              <div className="edr-detail-heading">
                <p className="eyebrow">File activity</p>
                <h4>
                  {fileNames.get(
                    selectedFile.fileId,
                  ) ?? selectedFile.fileId}
                </h4>
                <code>{selectedFile.eventId}</code>
              </div>
              <dl className="edr-detail-fields">
                <div><dt>Operation</dt><dd>{selectedFile.operation}</dd></div>
                <div><dt>Account</dt><dd>{(selectedFile.accountId && accountNames.get(selectedFile.accountId)) ?? selectedFile.accountId ?? ", "}</dd></div>
                <div><dt>Observed</dt><dd>{selectedFile.timestamp}</dd></div>
              </dl>
              <DetailActionBar
                eventId={selectedFile.eventId}
                finalized={finalized}
                collected={isCollected(selectedFile.eventId)}
                onCollect={onCollect}
                onSearchSiem={onSearchSiem}
                onOpenCase={onOpenCase}
              />
            </>
          ) : selectedAlert ? (
            <>
              <div className="edr-detail-heading">
                <p className="eyebrow">Detection detail</p>
                <h4>{selectedAlert.title}</h4>
                <code>{selectedAlert.eventId}</code>
              </div>
              <dl className="edr-detail-fields">
                <div><dt>Severity</dt><dd>{selectedAlert.severity}</dd></div>
                <div><dt>Alert ID</dt><dd>{selectedAlert.alertId}</dd></div>
                <div><dt>Related events</dt><dd>{selectedAlert.relatedEventIds.join(", ")}</dd></div>
                <div><dt>Observed</dt><dd>{selectedAlert.timestamp}</dd></div>
              </dl>
              <DetailActionBar
                eventId={selectedAlert.eventId}
                finalized={finalized}
                collected={isCollected(selectedAlert.eventId)}
                onCollect={onCollect}
                onSearchSiem={onSearchSiem}
                onOpenCase={onOpenCase}
              />
            </>
          ) : null}

          <section className="edr-response-operations">
            <p className="eyebrow">
              Endpoint response
            </p>
            <h4>Available operations</h4>

            {endpointActions.length ===
            0 ? (
              <p className="edr-muted">
                No scenario response
                operations target this
                endpoint.
              </p>
            ) : (
              <div className="edr-action-list">
                {endpointActions.map(
                  (action) => {
                    const performed =
                      performedActionIds.includes(
                        action.id,
                      );

                    return (
                      <button
                        key={action.id}
                        type="button"
                        className="edr-action"
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
        </aside>
      </div>
    </div>
  );
}
