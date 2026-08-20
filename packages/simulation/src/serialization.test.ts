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
  createSnapshot,
} from "./snapshot";

import {
  createWorldState,
} from "./worldState";

import type {
  WorldState,
} from "./worldState";

import {
  deserializeSimulationSnapshot,
  deserializeWorldState,
  serializeSimulationSnapshot,
  serializeWorldState,
} from "./serialization";

function createExampleWorld(): WorldState {
  return createWorldState({
    simulationTime:
      "2026-08-20T12:00:00Z",
    organizations: [
      exampleOrganization,
    ],
    users: [exampleUser],
    accounts: [exampleAccount],
    devices: [exampleDevice],
    files: [exampleFile],
    applications: [
      exampleApplication,
    ],
    sessions: [exampleSession],
  });
}

describe("world serialization", () => {
  it("roundtrips a valid world state", () => {
    const world = createExampleWorld();

    expect(
      deserializeWorldState(
        serializeWorldState(world),
      ),
    ).toEqual(world);
  });

  it("produces identical bytes for equivalent record insertion order", () => {
    const secondOrganization = {
      ...exampleOrganization,
      id: "org-zeta",
      name: "Zeta Holdings",
    };

    const first = createWorldState({
      simulationTime:
        "2026-08-20T12:00:00Z",
      organizations: [
        exampleOrganization,
        secondOrganization,
      ],
      users: [exampleUser],
      accounts: [exampleAccount],
      devices: [exampleDevice],
      files: [exampleFile],
      applications: [
        exampleApplication,
      ],
      sessions: [exampleSession],
    });

    const second = createWorldState({
      simulationTime:
        "2026-08-20T12:00:00Z",
      organizations: [
        secondOrganization,
        exampleOrganization,
      ],
      users: [exampleUser],
      accounts: [exampleAccount],
      devices: [exampleDevice],
      files: [exampleFile],
      applications: [
        exampleApplication,
      ],
      sessions: [exampleSession],
    });

    expect(serializeWorldState(first))
      .toBe(serializeWorldState(second));
  });

  it("rejects malformed and unsupported envelopes", () => {
    expect(
      () => deserializeWorldState("{"),
    ).toThrow(
      "Serialized simulation state is not valid JSON.",
    );

    const envelope = JSON.parse(
      serializeWorldState(
        createExampleWorld(),
      ),
    ) as {
      version: number;
    };

    envelope.version = 99;

    expect(
      () =>
        deserializeWorldState(
          JSON.stringify(envelope),
        ),
    ).toThrow(
      "Unsupported serialization version: 99.",
    );
  });

  it("rejects the wrong envelope kind", () => {
    const snapshot = createSnapshot(
      createExampleWorld(),
      2,
    );

    expect(
      () =>
        deserializeWorldState(
          serializeSimulationSnapshot(
            snapshot,
          ),
        ),
    ).toThrow(
      "Expected world-state envelope, received simulation-snapshot.",
    );
  });

  it("rejects structurally incomplete world payloads", () => {
    const envelope = JSON.parse(
      serializeWorldState(
        createExampleWorld(),
      ),
    ) as {
      payload: Record<
        string,
        unknown
      >;
    };

    delete envelope.payload.accounts;

    expect(
      () =>
        deserializeWorldState(
          JSON.stringify(envelope),
        ),
    ).toThrow(
      "envelope.payload.accounts must be an object.",
    );
  });

  it("rejects semantically invalid world references after structural parsing", () => {
    const envelope = JSON.parse(
      serializeWorldState(
        createExampleWorld(),
      ),
    ) as {
      payload: {
        users: Record<
          string,
          {
            organizationId: string;
          }
        >;
      };
    };

    const serializedUser =
      envelope.payload.users[
        exampleUser.id
      ];

    if (!serializedUser) {
      throw new Error(
        "Expected serialized example user.",
      );
    }

    serializedUser.organizationId =
      "org-missing";

    expect(
      () =>
        deserializeWorldState(
          JSON.stringify(envelope),
        ),
    ).toThrow(
      "Invalid world state:",
    );
  });
});

describe("snapshot serialization", () => {
  it("roundtrips a simulation snapshot", () => {
    const snapshot = createSnapshot(
      createExampleWorld(),
      4,
    );

    expect(
      deserializeSimulationSnapshot(
        serializeSimulationSnapshot(
          snapshot,
        ),
      ),
    ).toEqual(snapshot);
  });

  it("rejects invalid snapshot event counts", () => {
    const envelope = JSON.parse(
      serializeSimulationSnapshot(
        createSnapshot(
          createExampleWorld(),
          1,
        ),
      ),
    ) as {
      payload: {
        eventCount: number;
      };
    };

    envelope.payload.eventCount = -1;

    expect(
      () =>
        deserializeSimulationSnapshot(
          JSON.stringify(envelope),
        ),
    ).toThrow(
      "Snapshot event count must be a non-negative integer.",
    );
  });
});
