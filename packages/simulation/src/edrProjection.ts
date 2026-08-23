import type {
  EntityId,
  EntityStatus,
  SimulationTimestamp,
} from "@endomorph/domain";

import type {
  AlertSeverity,
  FileAccessOperation,
  NetworkProtocol,
  SimulationEvent,
} from "./simulationEvent";

import type {
  Projection,
} from "./projection";

interface EdrObservationBase {
  eventId: EntityId;

  timestamp: SimulationTimestamp;
}

export interface EndpointTelemetryObservation
  extends EdrObservationBase {
  deviceId: EntityId;

  status: EntityStatus;

  ipAddresses: readonly string[];
}

export interface ProcessExecutionObservation
  extends EdrObservationBase {
  deviceId: EntityId;

  processId: string;

  image: string;

  commandLine: string | undefined;

  parentProcessId: string | undefined;

  /**
   * The parent's image path, as reported by the sensor.
   *
   * Carried separately from the parent's own observation because the parent
   * is usually outside the collection window -- explorer.exe, services.exe
   * and the scheduler all start long before anything worth investigating --
   * and "what launched this" is the first question asked of a process.
   */
  parentImage: string | undefined;

  accountId: EntityId | undefined;
}

export interface FileActivityObservation
  extends EdrObservationBase {
  fileId: EntityId;

  operation: FileAccessOperation;

  deviceId: EntityId | undefined;

  accountId: EntityId | undefined;
}

export interface NetworkConnectionObservation
  extends EdrObservationBase {
  deviceId: EntityId;

  protocol: NetworkProtocol;

  sourceIp: string;

  destinationIp: string;

  sourcePort: number | undefined;

  destinationPort: number | undefined;

  /** The program that opened it, where the sensor saw the host side. */
  processId: string | undefined;

  image: string | undefined;
}

export interface EdrAlertObservation
  extends EdrObservationBase {
  alertId: EntityId;

  title: string;

  severity: AlertSeverity;

  applicationId: EntityId | undefined;

  relatedEventIds: readonly EntityId[];

  relatedEntityIds: readonly EntityId[];
}

export interface EdrProjectionState {
  endpointObservations: Readonly<
    Record<
      EntityId,
      EndpointTelemetryObservation
    >
  >;

  processes:
    readonly ProcessExecutionObservation[];

  fileActivity:
    readonly FileActivityObservation[];

  networkConnections:
    readonly NetworkConnectionObservation[];

  alerts:
    readonly EdrAlertObservation[];
}

function createInitialState():
  EdrProjectionState {
  return {
    endpointObservations: {},
    processes: [],
    fileActivity: [],
    networkConnections: [],
    alerts: [],
  };
}

function reduceEdrProjection(
  state: EdrProjectionState,
  event: SimulationEvent,
): EdrProjectionState {
  switch (event.type) {
    case "ENDPOINT_HEARTBEAT":
      return {
        ...state,
        endpointObservations: {
          ...state.endpointObservations,
          [event.payload.deviceId]: {
            eventId: event.id,
            timestamp: event.timestamp,
            deviceId:
              event.payload.deviceId,
            status:
              event.payload.status,
            ipAddresses: [
              ...event.payload.ipAddresses,
            ],
          },
        },
      };

    case "PROCESS_STARTED":
      return {
        ...state,
        processes: [
          ...state.processes,
          {
            eventId: event.id,
            timestamp: event.timestamp,
            deviceId:
              event.payload.deviceId,
            processId:
              event.payload.processId,
            image:
              event.payload.image,
            commandLine:
              event.payload.commandLine,
            parentProcessId:
              event.payload.parentProcessId,
            parentImage:
              event.payload.parentImage,
            accountId:
              event.payload.accountId,
          },
        ],
      };

    case "FILE_ACCESSED":
      return {
        ...state,
        fileActivity: [
          ...state.fileActivity,
          {
            eventId: event.id,
            timestamp: event.timestamp,
            fileId:
              event.payload.fileId,
            operation:
              event.payload.operation,
            deviceId:
              event.payload.deviceId,
            accountId:
              event.payload.accountId,
          },
        ],
      };

    case "NETWORK_CONNECTION":
      return {
        ...state,
        networkConnections: [
          ...state.networkConnections,
          {
            eventId: event.id,
            timestamp: event.timestamp,
            deviceId:
              event.payload.deviceId,
            protocol:
              event.payload.protocol,
            sourceIp:
              event.payload.sourceIp,
            destinationIp:
              event.payload.destinationIp,
            sourcePort:
              event.payload.sourcePort,
            destinationPort:
              event.payload.destinationPort,
            processId:
              event.payload.processId,
            image: event.payload.image,
          },
        ],
      };

    case "ALERT_CREATED":
      return {
        ...state,
        alerts: [
          ...state.alerts,
          {
            eventId: event.id,
            timestamp: event.timestamp,
            alertId:
              event.payload.alertId,
            title:
              event.payload.title,
            severity:
              event.payload.severity,
            applicationId:
              event.payload.applicationId,
            relatedEventIds: [
              ...event.payload.relatedEventIds,
            ],
            relatedEntityIds: [
              ...event.payload.relatedEntityIds,
            ],
          },
        ],
      };

    default:
      return state;
  }
}

export const edrProjection:
  Projection<EdrProjectionState> = {
    createInitialState,
    reduce: reduceEdrProjection,
  };
