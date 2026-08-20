import {
  describe,
  expect,
  it,
} from "vitest";

import {
  InMemoryEventBus,
} from "./eventBus";

import {
  identityProjection,
} from "./identityProjection";

import type {
  Projection,
} from "./projection";

import {
  LiveProjection,
  rebuildProjection,
} from "./projection";

import type {
  SimulationEvent,
} from "./simulationEvent";

function createEvents():
  SimulationEvent[] {
  return [
    {
      id: "event-001",
      type: "AUTH_LOGIN_SUCCEEDED",
      timestamp:
        "2026-08-20T09:00:00Z",
      source: "identity",
      payload: {
        accountId: "account-001",
        userId: "user-001",
        deviceId: "device-001",
        sourceIp: "10.0.0.10",
      },
    },
    {
      id: "event-002",
      type: "AUTH_LOGIN_FAILED",
      timestamp:
        "2026-08-20T09:01:00Z",
      source: "identity",
      payload: {
        username: "analyst",
        reason: "invalid_credentials",
        sourceIp: "10.0.0.11",
      },
    },
    {
      id: "event-003",
      type: "ACCOUNT_DISABLED",
      timestamp:
        "2026-08-20T09:02:00Z",
      source: "identity",
      payload: {
        accountId: "account-001",
        reason: "containment",
      },
    },
    {
      id: "event-004",
      type: "ACCOUNT_ENABLED",
      timestamp:
        "2026-08-20T09:03:00Z",
      source: "identity",
      payload: {
        accountId: "account-001",
        reason: "restored",
      },
    },
    {
      id: "event-005",
      type: "SESSION_STARTED",
      timestamp:
        "2026-08-20T09:04:00Z",
      source: "identity",
      payload: {
        sessionId: "session-001",
        accountId: "account-001",
        applicationId:
          "application-001",
      },
    },
    {
      id: "event-006",
      type: "SESSION_REVOKED",
      timestamp:
        "2026-08-20T09:05:00Z",
      source: "identity",
      payload: {
        sessionId: "session-001",
        reason: "containment",
      },
    },
    {
      id: "event-007",
      type: "PROCESS_STARTED",
      timestamp:
        "2026-08-20T09:06:00Z",
      source: "edr",
      payload: {
        deviceId: "device-001",
        processId: "process-001",
        image: "example.exe",
      },
    },
  ];
}

describe("projections", () => {
  it("produces identical identity state from live delivery and replay", () => {
    const bus =
      new InMemoryEventBus();

    const live =
      new LiveProjection(
        identityProjection,
      );

    bus.subscribe((event) => {
      live.apply(event);
    });

    for (const event of createEvents()) {
      bus.publish(event);
    }

    const rebuilt =
      rebuildProjection(
        identityProjection,
        bus.all(),
      );

    expect(live.state)
      .toEqual(rebuilt);

    expect(
      live.state.activity.map(
        (activity) => activity.kind,
      ),
    ).toEqual([
      "login_succeeded",
      "login_failed",
      "account_disabled",
      "account_enabled",
      "session_started",
      "session_revoked",
    ]);

    expect(live.state.successfulLogins)
      .toBe(1);

    expect(live.state.failedLogins)
      .toBe(1);
  });

  it("allows multiple independent projections to observe one event", () => {
    const bus =
      new InMemoryEventBus();

    const identity =
      new LiveProjection(
        identityProjection,
      );

    const countProjection:
      Projection<number> = {
        createInitialState: () => 0,
        reduce: (state) =>
          state + 1,
      };

    const count =
      new LiveProjection(
        countProjection,
      );

    bus.subscribe((event) => {
      identity.apply(event);
    });

    bus.subscribe((event) => {
      count.apply(event);
    });

    bus.publish(createEvents()[0]);

    expect(identity.state.activity)
      .toHaveLength(1);

    expect(count.state)
      .toBe(1);
  });

  it("keeps projection reducers immutable", () => {
    const initial =
      identityProjection
        .createInitialState();

    const next =
      identityProjection.reduce(
        initial,
        createEvents()[0],
      );

    expect(initial.activity)
      .toEqual([]);

    expect(initial.successfulLogins)
      .toBe(0);

    expect(next)
      .not.toBe(initial);

    expect(next.activity)
      .toHaveLength(1);
  });
});
