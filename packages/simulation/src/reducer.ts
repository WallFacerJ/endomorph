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
