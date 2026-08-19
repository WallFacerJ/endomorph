import {
  describe,
  expect,
  it,
} from "vitest";

import {
  exampleAccount,
  exampleApplication,
  exampleDevice,
  exampleFile,
  exampleOrganization,
  exampleSession,
  exampleUser,
} from "@polymorph/domain";

import {
  createEmptyWorldState,
  createWorldState,
} from "./worldState";

describe("WorldState", () => {
  it("creates an empty world at an explicit simulation time", () => {
    const world = createEmptyWorldState(
      "2026-08-18T09:00:00Z",
    );

    expect(world.simulationTime)
      .toBe("2026-08-18T09:00:00Z");

    expect(world.users)
      .toEqual({});

    expect(world.devices)
      .toEqual({});

    expect(world.sessions)
      .toEqual({});
  });

  it("normalizes domain entities by id", () => {
    const world = createWorldState({
      simulationTime:
        "2026-08-18T09:14:00Z",

      organizations: [
        exampleOrganization,
      ],

      users: [
        exampleUser,
      ],

      accounts: [
        exampleAccount,
      ],

      devices: [
        exampleDevice,
      ],

      files: [
        exampleFile,
      ],

      applications: [
        exampleApplication,
      ],

      sessions: [
        exampleSession,
      ],
    });

    expect(
      world.users[exampleUser.id],
    ).toEqual(exampleUser);

    expect(
      world.devices[exampleDevice.id],
    ).toEqual(exampleDevice);

    expect(
      world.accounts[exampleAccount.id],
    ).toEqual(exampleAccount);
  });

  it("preserves relationships between normalized entities", () => {
    const world = createWorldState({
      simulationTime:
        "2026-08-18T09:14:00Z",

      users: [
        exampleUser,
      ],

      accounts: [
        exampleAccount,
      ],

      devices: [
        exampleDevice,
      ],
    });

    const user =
      world.users[exampleUser.id];

    const account =
      world.accounts[
        user.accountIds[0]
      ];

    const device =
      world.devices[
        user.deviceIds[0]
      ];

    expect(account.userId)
      .toBe(user.id);

    expect(device.ownerUserId)
      .toBe(user.id);
  });

  it("produces identical state from identical input", () => {
    const seed = {
      simulationTime:
        "2026-08-18T09:14:00Z",

      organizations: [
        exampleOrganization,
      ],

      users: [
        exampleUser,
      ],

      devices: [
        exampleDevice,
      ],
    };

    const first =
      createWorldState(seed);

    const second =
      createWorldState(seed);

    expect(first)
      .toEqual(second);
  });
});
