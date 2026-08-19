import {
  describe,
  expect,
  it,
} from "vitest";

import {
  exampleAccount,
} from "@polymorph/domain";

import {
  createWorldState,
} from "./worldState";

import type {
  AccountDisabledEvent,
} from "./simulationEvent";

import {
  replayEvents,
} from "./replay";

import {
  createSnapshot,
  replayFromSnapshot,
} from "./snapshot";

function createInitialWorld() {
  return createWorldState({
    simulationTime:
      "2026-08-18T09:00:00Z",

    accounts: [
      exampleAccount,
    ],
  });
}

function createEvent():
  AccountDisabledEvent {
  return {
    id: "event-account-disabled-001",

    type: "ACCOUNT_DISABLED",

    timestamp:
      "2026-08-18T09:30:00Z",

    source: "identity",

    subjectId:
      exampleAccount.id,

    payload: {
      accountId:
        exampleAccount.id,
    },
  };
}

describe("SimulationSnapshot", () => {
  it("captures world state after a known number of events", () => {
    const initialWorld =
      createInitialWorld();

    const event =
      createEvent();

    const worldAfterEvent =
      replayEvents(
        initialWorld,
        [event],
      );

    const snapshot =
      createSnapshot(
        worldAfterEvent,
        1,
      );

    expect(snapshot.eventCount)
      .toBe(1);

    expect(
      snapshot.world.accounts[
        exampleAccount.id
      ].status,
    ).toBe("disabled");
  });

  it("copies world state instead of retaining the original reference", () => {
    const world =
      createInitialWorld();

    const snapshot =
      createSnapshot(
        world,
        0,
      );

    expect(snapshot.world)
      .toEqual(world);

    expect(snapshot.world)
      .not.toBe(world);
  });

  it("replays only events after the snapshot position", () => {
    const event =
      createEvent();

    const fullHistory = [
      event,
    ];

    const worldAfterEvent =
      replayEvents(
        createInitialWorld(),
        fullHistory,
      );

    const snapshot =
      createSnapshot(
        worldAfterEvent,
        1,
      );

    const finalWorld =
      replayFromSnapshot(
        snapshot,
        fullHistory,
      );

    expect(finalWorld)
      .toEqual(worldAfterEvent);
  });

  it("rejects invalid snapshot positions", () => {
    expect(
      () =>
        createSnapshot(
          createInitialWorld(),
          -1,
        ),
    ).toThrow(
      "Snapshot event count must be a non-negative integer.",
    );
  });

  it("rejects snapshots beyond the supplied event history", () => {
    const snapshot =
      createSnapshot(
        createInitialWorld(),
        5,
      );

    expect(
      () =>
        replayFromSnapshot(
          snapshot,
          [],
        ),
    ).toThrow(
      "Snapshot event count exceeds event history length.",
    );
  });
});