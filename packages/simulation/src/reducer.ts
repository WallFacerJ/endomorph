import type {
  WorldState,
} from "./worldState";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  assertNever,
} from "./assertNever";

export function applySimulationEvent(
  world: WorldState,
  event: SimulationEvent,
): WorldState {
  switch (event.type) {
    case "ACCOUNT_DISABLED": {
      const account =
        world.accounts[
          event.payload.accountId
        ];

      if (!account) {
        throw new Error(
          `Account not found: ${event.payload.accountId}`,
        );
      }

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

      if (!account) {
        throw new Error(
          `Account not found: ${event.payload.accountId}`,
        );
      }

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

      if (
        world.sessions[sessionId]
      ) {
        throw new Error(
          `Session already exists: ${sessionId}`,
        );
      }

      if (
        !world.accounts[accountId]
      ) {
        throw new Error(
          `Account not found: ${accountId}`,
        );
      }

      if (
        deviceId &&
        !world.devices[deviceId]
      ) {
        throw new Error(
          `Device not found: ${deviceId}`,
        );
      }

      if (
        applicationId &&
        !world.applications[
          applicationId
        ]
      ) {
        throw new Error(
          `Application not found: ${applicationId}`,
        );
      }

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

      if (!session) {
        throw new Error(
          `Session not found: ${event.payload.sessionId}`,
        );
      }

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
