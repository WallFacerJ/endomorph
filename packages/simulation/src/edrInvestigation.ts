import type {
  EntityId,
} from "@polymorph/domain";

import type {
  EdrAlertObservation,
  EdrProjectionState,
  EndpointTelemetryObservation,
  FileActivityObservation,
  NetworkConnectionObservation,
  ProcessExecutionObservation,
} from "./edrProjection";

export interface EdrProcessTreeNode {
  process: ProcessExecutionObservation;
  depth: number;
  parentProcess: ProcessExecutionObservation | undefined;
  childProcessIds: readonly string[];
  orphanedParent: boolean;
}

export interface EdrEndpointInvestigation {
  deviceId: EntityId;
  endpoint: EndpointTelemetryObservation | undefined;
  processes: readonly ProcessExecutionObservation[];
  processTree: readonly EdrProcessTreeNode[];
  fileActivity: readonly FileActivityObservation[];
  networkConnections: readonly NetworkConnectionObservation[];
  alerts: readonly EdrAlertObservation[];
}

function compareObservations(
  left: { timestamp: string; eventId: string },
  right: { timestamp: string; eventId: string },
): number {
  const time = left.timestamp.localeCompare(
    right.timestamp,
  );

  return time !== 0
    ? time
    : left.eventId.localeCompare(right.eventId);
}

function buildProcessTree(
  processes: readonly ProcessExecutionObservation[],
): readonly EdrProcessTreeNode[] {
  const byProcessId = new Map(
    processes.map((process) => [
      process.processId,
      process,
    ]),
  );

  const childIds = new Map<string, string[]>();

  for (const process of processes) {
    if (!process.parentProcessId) {
      continue;
    }

    const current =
      childIds.get(process.parentProcessId) ?? [];
    current.push(process.processId);
    childIds.set(process.parentProcessId, current);
  }

  const depthCache = new Map<string, number>();

  const getDepth = (
    process: ProcessExecutionObservation,
    seen = new Set<string>(),
  ): number => {
    const cached = depthCache.get(process.processId);

    if (cached !== undefined) {
      return cached;
    }

    if (
      !process.parentProcessId ||
      !byProcessId.has(process.parentProcessId) ||
      seen.has(process.processId)
    ) {
      depthCache.set(process.processId, 0);
      return 0;
    }

    const parent = byProcessId.get(
      process.parentProcessId,
    );

    if (!parent) {
      depthCache.set(process.processId, 0);
      return 0;
    }

    seen.add(process.processId);
    const depth = getDepth(parent, seen) + 1;
    depthCache.set(process.processId, depth);
    return depth;
  };

  return [...processes]
    .sort(compareObservations)
    .map((process) => {
      const parentProcess = process.parentProcessId
        ? byProcessId.get(process.parentProcessId)
        : undefined;

      return {
        process,
        depth: getDepth(process),
        parentProcess,
        childProcessIds: [
          ...(childIds.get(process.processId) ?? []),
        ],
        orphanedParent: Boolean(
          process.parentProcessId &&
          !parentProcess,
        ),
      };
    });
}

export function getEdrEndpointInvestigation(
  state: EdrProjectionState,
  deviceId: EntityId,
): EdrEndpointInvestigation {
  const processes = state.processes
    .filter((process) =>
      process.deviceId === deviceId,
    )
    .sort(compareObservations);

  const fileActivity = state.fileActivity
    .filter((activity) =>
      activity.deviceId === deviceId,
    )
    .sort(compareObservations);

  const networkConnections = state.networkConnections
    .filter((connection) =>
      connection.deviceId === deviceId,
    )
    .sort(compareObservations);

  const alerts = state.alerts
    .filter((alert) =>
      alert.relatedEntityIds.includes(deviceId),
    )
    .sort(compareObservations);

  return {
    deviceId,
    endpoint: state.endpointObservations[deviceId],
    processes,
    processTree: buildProcessTree(processes),
    fileActivity,
    networkConnections,
    alerts,
  };
}

export function getObservedEdrDeviceIds(
  state: EdrProjectionState,
): readonly EntityId[] {
  const deviceIds = new Set<EntityId>();

  for (const deviceId of Object.keys(
    state.endpointObservations,
  )) {
    deviceIds.add(deviceId);
  }

  for (const process of state.processes) {
    deviceIds.add(process.deviceId);
  }

  for (const activity of state.fileActivity) {
    if (activity.deviceId) {
      deviceIds.add(activity.deviceId);
    }
  }

  for (const connection of state.networkConnections) {
    deviceIds.add(connection.deviceId);
  }

  return [...deviceIds].sort();
}
