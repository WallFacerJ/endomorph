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
  EndpointHeartbeatEvent,
} from "./simulationEvent";

import type {
  Device,
} from "@endomorph/domain";

const exampleDevice: Device = {
  id: "device-fin-lt-004",
  organizationId:
    exampleOrganization.id,
  hostname: "FIN-LT-004",
  operatingSystem:
    "Windows 11 Enterprise",
  status: "active",
  ownerUserId: exampleUser.id,
  ipAddresses: ["10.20.30.44"],
};

function createHeartbeat(
  status: "active" | "inactive",
): EndpointHeartbeatEvent {
  return {
    id: `event-heartbeat-${status}`,
    type: "ENDPOINT_HEARTBEAT",
    timestamp: "2026-08-18T09:40:00Z",
    source: "edr",
    subjectId: exampleDevice.id,
    payload: {
      deviceId: exampleDevice.id,
      status,
      ipAddresses:
        exampleDevice.ipAddresses,
    },
  };
}

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

    devices: [exampleDevice],
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

describe("endpoint isolation", () => {
  /*
    Isolating a host used to be a pass-through here, so the world never
    recorded it and only the EDR projection knew. That made isolation
    unscoreable: for an intrusion that persists through a run key and beacons
    out, cutting the host off is the containment that matters, and an analyst
    who did exactly that was told the scenario failed.
  */
  it("marks the device inactive when the endpoint reports isolation", () => {
    const world = applySimulationEvent(
      createTestWorld(),
      createHeartbeat("inactive"),
    );

    expect(
      world.devices[exampleDevice.id]
        .status,
    ).toBe("inactive");
  });

  it("does not revive an isolated host on the next routine heartbeat", () => {
    // Isolation is a decision the analyst made. A device that keeps
    // reporting in must not undo it, or the objective would flicker back to
    // unmet on the next beat and the run would score by timing.
    const isolated = applySimulationEvent(
      createTestWorld(),
      createHeartbeat("inactive"),
    );

    const afterBeat =
      applySimulationEvent(
        isolated,
        createHeartbeat("active"),
      );

    expect(
      afterBeat.devices[
        exampleDevice.id
      ].status,
    ).toBe("inactive");
  });

  it("refuses a heartbeat about a device that does not exist", () => {
    // The reducer validates before it applies, so the missing-device branch
    // inside the case is defensive rather than reachable from here. Worth
    // pinning which of the two actually guards it: a heartbeat naming an
    // unknown host is rejected outright, not quietly ignored.
    expect(() =>
      applySimulationEvent(
        createTestWorld(),
        {
          ...createHeartbeat("inactive"),
          payload: {
            deviceId: "device-not-here",
            status: "inactive",
            ipAddresses: [],
          },
        },
      ),
    ).toThrow(/Device not found/);
  });
});
