import {
  useMemo,
  useState,
} from "react";

import {
  getEdrEndpointInvestigation,
  getObservedEdrDeviceIds,
} from "./simulationAdapter";

import type {
  EdrProjectionState,
} from "./simulationAdapter";

import "./EdrWorkspace.css";

interface EndpointInventoryItem {
  id: string;
  hostname: string;
  operatingSystem: string;
  status: string;
  ipAddresses: readonly string[];
}

interface EdrWorkspaceProps {
  state: EdrProjectionState;
  devices: readonly EndpointInventoryItem[];
  initialDeviceId: string;
  finalized: boolean;
  isCollected: (eventId: string) => boolean;
  onCollect: (eventId: string) => void;
  onSearchSiem: (query: string) => void;
  onOpenCase: () => void;
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

export function EdrWorkspace({
  state,
  devices,
  initialDeviceId,
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

  const availableDevices = useMemo(
    () => devices.filter((device) =>
      observedDeviceIds.includes(device.id),
    ),
    [devices, observedDeviceIds],
  );

  const [selectedDeviceId, setSelectedDeviceId] =
    useState(
      observedDeviceIds.includes(initialDeviceId)
        ? initialDeviceId
        : observedDeviceIds[0] ?? initialDeviceId,
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
            Polymorph Ops / EDR
          </p>
          <h3>Endpoint investigation</h3>
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
            <small>{availableDevices.length} observed</small>
          </div>
          {availableDevices.map((device) => {
            const observation =
              state.endpointObservations[device.id];
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
                </span>
                <span className="edr-endpoint-meta">
                  <span>{observation?.status ?? device.status}</span>
                  <span>{processCount} proc</span>
                  {alertCount > 0 && (
                    <span className="edr-alert-count">
                      {alertCount} alert
                    </span>
                  )}
                </span>
              </button>
            );
          })}
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
                <strong>{selectedDevice?.operatingSystem ?? "—"}</strong>
              </span>
              <span>
                <small>IP</small>
                <strong>{selectedDevice?.ipAddresses.join(", ") || "—"}</strong>
              </span>
              <span>
                <small>Status</small>
                <strong>{investigation.endpoint?.status ?? selectedDevice?.status ?? "—"}</strong>
              </span>
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
                <span>Parent</span>
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
                    {node.orphanedParent && (
                      <small>parent not observed</small>
                    )}
                  </span>
                  <code>{node.process.processId}</code>
                  <code>{node.process.parentProcessId ?? "—"}</code>
                  <span>{node.process.accountId ?? "—"}</span>
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
                    <strong>{connection.destinationIp}:{connection.destinationPort ?? "—"}</strong>
                    <small>{connection.protocol.toUpperCase()}</small>
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
                    <strong>{activity.fileId}</strong>
                    <small>file entity</small>
                  </span>
                  <span>
                    <strong>{activity.operation}</strong>
                    <small>operation</small>
                  </span>
                  <span>
                    <strong>{activity.accountId ?? "—"}</strong>
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
                <div><dt>Command line</dt><dd><code>{selectedProcess.commandLine ?? "—"}</code></dd></div>
                <div><dt>PID</dt><dd>{selectedProcess.processId}</dd></div>
                <div><dt>Parent PID</dt><dd>{selectedProcess.parentProcessId ?? "—"}</dd></div>
                <div><dt>Account</dt><dd>{selectedProcess.accountId ?? "—"}</dd></div>
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
                <h4>{selectedNetwork.destinationIp}:{selectedNetwork.destinationPort ?? "—"}</h4>
                <code>{selectedNetwork.eventId}</code>
              </div>
              <dl className="edr-detail-fields">
                <div><dt>Source</dt><dd>{selectedNetwork.sourceIp}:{selectedNetwork.sourcePort ?? "—"}</dd></div>
                <div><dt>Destination</dt><dd>{selectedNetwork.destinationIp}:{selectedNetwork.destinationPort ?? "—"}</dd></div>
                <div><dt>Protocol</dt><dd>{selectedNetwork.protocol.toUpperCase()}</dd></div>
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
                <h4>{selectedFile.fileId}</h4>
                <code>{selectedFile.eventId}</code>
              </div>
              <dl className="edr-detail-fields">
                <div><dt>Operation</dt><dd>{selectedFile.operation}</dd></div>
                <div><dt>Account</dt><dd>{selectedFile.accountId ?? "—"}</dd></div>
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
        </aside>
      </div>
    </div>
  );
}
