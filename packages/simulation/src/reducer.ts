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

    /*
      A granted role changes the account, which is the whole point: the
      Identity console reads roles off the world, so an escalation is visible
      there afterwards rather than only as a line in a log.
    */
    case "ROLE_GRANTED": {
      const account =
        world.accounts[
          event.payload.accountId
        ];

      if (
        account.roles.includes(
          event.payload.role,
        )
      ) {
        return {
          ...world,
          simulationTime:
            event.timestamp,
        };
      }

      return {
        ...world,

        simulationTime: event.timestamp,

        accounts: {
          ...world.accounts,

          [account.id]: {
            ...account,
            roles: [
              ...account.roles,
              event.payload.role,
            ],
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

    /*
      Isolating a host is a change to the world, not only a reading of it.

      This was a pass-through, so a device's status in the world never moved
      and only the EDR projection knew an endpoint had gone quiet. That made
      isolation unscoreable: for an intrusion that persists through a run key
      and beacons out, cutting the host off is the containment that matters,
      and an analyst who did exactly that was told the scenario failed.

      Only a transition to inactive is applied. A routine heartbeat reporting
      "active" must not revive a host somebody isolated.
    */
    case "ENDPOINT_HEARTBEAT": {
      const device =
        world.devices[
          event.payload.deviceId
        ];

      if (
        !device ||
        event.payload.status !==
          "inactive"
      ) {
        return {
          ...world,
          simulationTime:
            event.timestamp,
        };
      }

      return {
        ...world,

        simulationTime: event.timestamp,

        devices: {
          ...world.devices,

          [device.id]: {
            ...device,
            status: "inactive",
          },
        },
      };
    }

    case "AUTH_LOGIN_SUCCEEDED":
    case "AUTH_LOGIN_FAILED":
    case "PROCESS_STARTED":
    case "FILE_ACCESSED":
    case "NETWORK_CONNECTION":
    case "ALERT_CREATED":
      return {
        ...world,

        simulationTime:
          event.timestamp,
      };

    // A received message is a log line; it changes no world state, only the
    // clock, the same as a process start or a network connection.
    case "EMAIL_RECEIVED":
      return {
        ...world,
        simulationTime: event.timestamp,
      };

    // A control-plane audit record is likewise a log line.
    case "CLOUD_AUDIT":
      return {
        ...world,
        simulationTime: event.timestamp,
      };

    // A DNS resolution is a log line; no world state changes.
    case "DNS_QUERY":
      return {
        ...world,
        simulationTime: event.timestamp,
      };

    // A proxy request is a log line; no world state changes.
    case "WEB_REQUEST":
      return {
        ...world,
        simulationTime: event.timestamp,
      };

    default:
      return assertNever(event);
  }
}
