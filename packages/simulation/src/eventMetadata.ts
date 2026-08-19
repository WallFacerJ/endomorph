import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  assertNever,
} from "./assertNever";

export type SimulationEventFamily =
  | "authentication"
  | "identity"
  | "session"
  | "process"
  | "file"
  | "network"
  | "endpoint"
  | "security";

export function getSimulationEventFamily(
  event: SimulationEvent,
): SimulationEventFamily {
  switch (event.type) {
    case "AUTH_LOGIN_SUCCEEDED":
    case "AUTH_LOGIN_FAILED":
      return "authentication";

    case "ACCOUNT_DISABLED":
    case "ACCOUNT_ENABLED":
      return "identity";

    case "SESSION_STARTED":
    case "SESSION_REVOKED":
      return "session";

    case "PROCESS_STARTED":
      return "process";

    case "FILE_ACCESSED":
      return "file";

    case "NETWORK_CONNECTION":
      return "network";

    case "ENDPOINT_HEARTBEAT":
      return "endpoint";

    case "ALERT_CREATED":
      return "security";

    default:
      return assertNever(event);
  }
}
