import {
  describe,
  expect,
  it,
} from "vitest";

import {
  exampleAccount,
  exampleOrganization,
  exampleUser,
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

function createInitialWorld() {
  return createWorldState({
    simulationTime:
      "2026-08-18T09:00:00Z",

    organizations: [
      exampleOrganization,
    ],

    users: [
      exampleUser,
    ],

    accounts: [
      exampleAccount,
    ],
  });
}

function createEvents():
  AccountDisabledEvent[] {
  return [
    {
      id: "event-account-disabled-001",

      type: "ACCOUNT_DISABLED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "identity",

      actorId: exampleUser.id,

      subjectId:
        exampleAccount.id,

      payload: {
        accountId:
          exampleAccount.id,
      },
    },
  ];
}

describe("replayEvents", () => {
  it("applies an ordered event stream to the world", () => {
    const finalWorld =
      replayEvents(
        createInitialWorld(),
        createEvents(),
      );

    expect(
      finalWorld.accounts[
        exampleAccount.id
      ].status,
    ).toBe("disabled");

    expect(
      finalWorld.simulationTime,
    ).toBe(
      "2026-08-18T09:30:00Z",
    );
  });

  it("produces identical final state when replayed twice", () => {
    const events =
      createEvents();

    const first =
      replayEvents(
        createInitialWorld(),
        events,
      );

    const second =
      replayEvents(
        createInitialWorld(),
        events,
      );

    expect(first)
      .toEqual(second);
  });

  it("does not mutate the initial world", () => {
    const initialWorld =
      createInitialWorld();

    replayEvents(
      initialWorld,
      createEvents(),
    );

    expect(
      initialWorld.accounts[
        exampleAccount.id
      ].status,
    ).toBe("active");

    expect(
      initialWorld.simulationTime,
    ).toBe(
      "2026-08-18T09:00:00Z",
    );
  });

  it("returns the initial world when no events exist", () => {
    const initialWorld =
      createInitialWorld();

    const finalWorld =
      replayEvents(
        initialWorld,
        [],
      );

    expect(finalWorld)
      .toEqual(initialWorld);
  });
});