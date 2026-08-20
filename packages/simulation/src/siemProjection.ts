import type {
  EntityId,
  SimulationTimestamp,
} from "@polymorph/domain";

import type {
  AlertSeverity,
  SimulationEvent,
  SimulationEventType,
} from "./simulationEvent";

import {
  getSimulationEventFamily,
} from "./eventMetadata";

import type {
  SimulationEventFamily,
} from "./eventMetadata";

import type {
  Projection,
} from "./projection";

import {
  assertNever,
} from "./assertNever";

export interface SiemEventRecord {
  eventId: EntityId;

  timestamp: SimulationTimestamp;

  source: string;

  eventType: SimulationEventType;

  family: SimulationEventFamily;

  actorId: EntityId | undefined;

  subjectId: EntityId | undefined;

  severity: AlertSeverity | undefined;

  relatedEventIds: readonly EntityId[];

  relatedEntityIds: readonly EntityId[];

  message: string;
}

export interface SiemProjectionState {
  events: readonly SiemEventRecord[];

  familyCounts: Readonly<
    Record<SimulationEventFamily, number>
  >;

  typeCounts: Readonly<
    Partial<Record<SimulationEventType, number>>
  >;
}

function createFamilyCounts():
  Record<SimulationEventFamily, number> {
  return {
    authentication: 0,
    identity: 0,
    session: 0,
    process: 0,
    file: 0,
    network: 0,
    endpoint: 0,
    security: 0,
  };
}

function createInitialState():
  SiemProjectionState {
  return {
    events: [],
    familyCounts: createFamilyCounts(),
    typeCounts: {},
  };
}

function getMessage(
  event: SimulationEvent,
): string {
  switch (event.type) {
    case "AUTH_LOGIN_SUCCEEDED":
      return `Login succeeded for account ${event.payload.accountId}`;

    case "AUTH_LOGIN_FAILED":
      return `Login failed for ${event.payload.username}: ${event.payload.reason}`;

    case "ACCOUNT_DISABLED":
      return `Account disabled: ${event.payload.accountId}`;

    case "ACCOUNT_ENABLED":
      return `Account enabled: ${event.payload.accountId}`;

    case "SESSION_STARTED":
      return `Session started: ${event.payload.sessionId}`;

    case "SESSION_REVOKED":
      return `Session revoked: ${event.payload.sessionId}`;

    case "PROCESS_STARTED":
      return `Process started on ${event.payload.deviceId}: ${event.payload.image}`;

    case "FILE_ACCESSED":
      return `File ${event.payload.operation}: ${event.payload.fileId}`;

    case "NETWORK_CONNECTION":
      return `Network connection ${event.payload.sourceIp} -> ${event.payload.destinationIp}`;

    case "ENDPOINT_HEARTBEAT":
      return `Endpoint heartbeat from ${event.payload.deviceId}: ${event.payload.status}`;

    case "ALERT_CREATED":
      return `Alert created: ${event.payload.title}`;

    default:
      return assertNever(event);
  }
}

function normalizeEvent(
  event: SimulationEvent,
): SiemEventRecord {
  const isAlert =
    event.type === "ALERT_CREATED";

  return {
    eventId: event.id,
    timestamp: event.timestamp,
    source: event.source,
    eventType: event.type,
    family:
      getSimulationEventFamily(event),
    actorId: event.actorId,
    subjectId: event.subjectId,
    severity:
      isAlert
        ? event.payload.severity
        : undefined,
    relatedEventIds:
      isAlert
        ? [...event.payload.relatedEventIds]
        : [],
    relatedEntityIds:
      isAlert
        ? [...event.payload.relatedEntityIds]
        : [],
    message: getMessage(event),
  };
}

function reduceSiemProjection(
  state: SiemProjectionState,
  event: SimulationEvent,
): SiemProjectionState {
  const record = normalizeEvent(event);

  return {
    events: [
      ...state.events,
      record,
    ],
    familyCounts: {
      ...state.familyCounts,
      [record.family]:
        state.familyCounts[
          record.family
        ] + 1,
    },
    typeCounts: {
      ...state.typeCounts,
      [record.eventType]:
        (state.typeCounts[
          record.eventType
        ] ?? 0) + 1,
    },
  };
}

export const siemProjection:
  Projection<SiemProjectionState> = {
    createInitialState,
    reduce: reduceSiemProjection,
  };
