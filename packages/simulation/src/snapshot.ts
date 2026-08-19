import type {
  WorldState,
} from "./worldState";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  replayEvents,
} from "./replay";

export interface SimulationSnapshot {
  eventCount: number;
  world: WorldState;
}

export function createSnapshot(
  world: WorldState,
  eventCount: number,
): SimulationSnapshot {
  if (
    !Number.isInteger(eventCount) ||
    eventCount < 0
  ) {
    throw new Error(
      "Snapshot event count must be a non-negative integer.",
    );
  }

  return {
    eventCount,
    world: structuredClone(world),
  };
}

export function replayFromSnapshot(
  snapshot: SimulationSnapshot,
  fullEventHistory:
    readonly SimulationEvent[],
): WorldState {
  if (
    snapshot.eventCount >
    fullEventHistory.length
  ) {
    throw new Error(
      "Snapshot event count exceeds event history length.",
    );
  }

  const remainingEvents =
    fullEventHistory.slice(
      snapshot.eventCount,
    );

  return replayEvents(
    snapshot.world,
    remainingEvents,
  );
}