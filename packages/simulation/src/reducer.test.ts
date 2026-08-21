import {
  describe,
  expect,
  it,
} from "vitest";

import {
  exampleAccount,
  exampleOrganization,
  exampleUser,
} from "@endomorph/domain";

import {
  createWorldState,
} from "./worldState";

import {
  applySimulationEvent,
} from "./reducer";

import type {
  AccountDisabledEvent,
} from "./simulationEvent";

function createTestWorld() {
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

function createDisableEvent():
  AccountDisabledEvent {
  return {
    id: "event-account-disabled-001",

    type: "ACCOUNT_DISABLED",

    timestamp:
      "2026-08-18T09:30:00Z",

    source: "identity",

    actorId: exampleUser.id,

    subjectId: exampleAccount.id,

    payload: {
      accountId:
        exampleAccount.id,
    },
  };
}

describe("applySimulationEvent", () => {
  it("disables an account", () => {
    const world =
      createTestWorld();

    const next =
      applySimulationEvent(
        world,
        createDisableEvent(),
      );

    expect(
      next.accounts[
        exampleAccount.id
      ].status,
    ).toBe("disabled");
  });

  it("advances world simulation time to the event timestamp", () => {
    const next =
      applySimulationEvent(
        createTestWorld(),
        createDisableEvent(),
      );

    expect(next.simulationTime)
      .toBe(
        "2026-08-18T09:30:00Z",
      );
  });

  it("does not mutate the previous world state", () => {
    const world =
      createTestWorld();

    applySimulationEvent(
      world,
      createDisableEvent(),
    );

    expect(
      world.accounts[
        exampleAccount.id
      ].status,
    ).toBe("active");
  });

  it("produces identical state from identical world and event", () => {
    const event =
      createDisableEvent();

    const first =
      applySimulationEvent(
        createTestWorld(),
        event,
      );

    const second =
      applySimulationEvent(
        createTestWorld(),
        event,
      );

    expect(first)
      .toEqual(second);
  });

  it("rejects events referencing unknown accounts", () => {
    const event:
      AccountDisabledEvent = {
      ...createDisableEvent(),

      payload: {
        accountId:
          "account-does-not-exist",
      },
    };

    expect(
      () =>
        applySimulationEvent(
          createTestWorld(),
          event,
        ),
    ).toThrow(
      "Account not found: account-does-not-exist",
    );
  });
});
