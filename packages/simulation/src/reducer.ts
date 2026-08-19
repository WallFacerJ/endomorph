import {
  assertNever,
} from "./assertNever";

import {
  validateSimulationEvent,
} from "./eventValidation";

import type {
  SimulationEvent,
} from "./simulationEvent";

import type {
  WorldState,
} from "./worldState";

export function applySimulationEvent(
  world: WorldState,
  event: SimulationEvent,
): WorldState {
  validateSimulationEvent(
    world,
    event,
  );

  switch (event.type) {
    case "ACCOUNT_DISABLED": {
      const account =
        world.accounts[
          event.payload.accountId
        ];

      return {
        ...world,

        simulationTime:
          event.timestamp,

        accounts: {
          ...world.accounts,

          [account.id]: {
            ...account,
            status: "disabled",
          },
        },
      };
    }

    case "ACCOUNT_ENABLED": {
      const account =
        world.accounts[
          event.payload.accountId
        ];

      return {
        ...world,

        simulationTime:
          event.timestamp,

        accounts: {
          ...world.accounts,

          [account.id]: {
            ...account,
            status: "active",
          },
        },
      };
    }

    case "SESSION_STARTED": {
      const {
        sessionId,
        accountId,
        deviceId,
        applicationId,
      } = event.payload;

      return {
        ...world,

        simulationTime:
          event.timestamp,

        sessions: {
          ...world.sessions,

          [sessionId]: {
            id: sessionId,
            accountId,
            deviceId,
            applicationId,
            startedAt:
              event.timestamp,
            status: "active",
          },
        },
      };
    }

    case "SESSION_REVOKED": {
      const session =
        world.sessions[
          event.payload.sessionId
        ];

      return {
        ...world,

        simulationTime:
          event.timestamp,

        sessions: {
          ...world.sessions,

          [session.id]: {
            ...session,
            status: "revoked",
            endedAt:
              event.timestamp,
          },
        },
      };
    }

    case "AUTH_LOGIN_SUCCEEDED":
    case "AUTH_LOGIN_FAILED":
    case "PROCESS_STARTED":
    case "FILE_ACCESSED":
    case "NETWORK_CONNECTION":
    case "ENDPOINT_HEARTBEAT":
    case "ALERT_CREATED":
      return {
        ...world,

        simulationTime:
          event.timestamp,
      };

    default:
      return assertNever(event);
  }
}
