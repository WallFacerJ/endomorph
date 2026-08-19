import type {
  WorldState,
} from "./worldState";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  applySimulationEvent,
} from "./reducer";

export function replayEvents(
  initialWorld: WorldState,
  events: readonly SimulationEvent[],
): WorldState {
  return events.reduce(
    (
      world,
      event,
    ) =>
      applySimulationEvent(
        world,
        event,
      ),

    initialWorld,
  );
}