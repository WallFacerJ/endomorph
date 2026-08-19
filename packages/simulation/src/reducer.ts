import type {
  WorldState,
} from "./worldState";

import type {
  SimulationEvent,
} from "./simulationEvent";

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
  }
}
