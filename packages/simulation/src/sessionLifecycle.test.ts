import {
  describe,
  expect,
  it,
} from "vitest";

import {
  exampleAccount,
  exampleApplication,
  exampleDevice,
} from "@endomorph/domain";

import {
  applySimulationEvent,
} from "./reducer";

import type {
  AccountEnabledEvent,
  SessionRevokedEvent,
  SessionStartedEvent,
} from "./simulationEvent";

import {
  createWorldState,
} from "./worldState";

function createWorld() {
  return createWorldState({
    simulationTime:
      "2026-08-18T09:00:00Z",

    accounts: [
      exampleAccount,
    ],

    devices: [
      exampleDevice,
    ],

    applications: [
      exampleApplication,
    ],
  });
}

function createSessionStartedEvent():
  SessionStartedEvent {
  return {
    id: "event-session-start-001",

    type: "SESSION_STARTED",

    timestamp:
      "2026-08-18T09:15:00Z",

    source: "identity",

    payload: {
      sessionId:
        "session-new-001",

      accountId:
        exampleAccount.id,

      deviceId:
        exampleDevice.id,

      applicationId:
        exampleApplication.id,
    },
  };
}

describe("identity and session lifecycle reducers", () => {
  it("creates a new active session", () => {
    const next =
      applySimulationEvent(
        createWorld(),
        createSessionStartedEvent(),
      );

    expect(
      next.sessions[
        "session-new-001"
      ],
    ).toEqual({
      id: "session-new-001",

      accountId:
        exampleAccount.id,

      deviceId:
        exampleDevice.id,

      applicationId:
        exampleApplication.id,

      startedAt:
        "2026-08-18T09:15:00Z",

      status: "active",
    });
  });

  it("rejects session creation for an unknown account", () => {
    const event:
      SessionStartedEvent = {
      ...createSessionStartedEvent(),

      payload: {
        ...createSessionStartedEvent()
          .payload,

        accountId:
          "account-missing",
      },
    };

    expect(
      () =>
        applySimulationEvent(
          createWorld(),
          event,
        ),
    ).toThrow(
      "Account not found: account-missing",
    );
  });

  it("rejects duplicate session ids", () => {
    const first =
      applySimulationEvent(
        createWorld(),
        createSessionStartedEvent(),
      );

    expect(
      () =>
        applySimulationEvent(
          first,
          createSessionStartedEvent(),
        ),
    ).toThrow(
      "Session already exists: session-new-001",
    );
  });

  it("revokes an existing session", () => {
    const started =
      applySimulationEvent(
        createWorld(),
        createSessionStartedEvent(),
      );

    const revokeEvent:
      SessionRevokedEvent = {
      id: "event-session-revoke-001",

      type: "SESSION_REVOKED",

      timestamp:
        "2026-08-18T09:45:00Z",

      source: "identity",

      payload: {
        sessionId:
          "session-new-001",

        reason:
          "security containment",
      },
    };

    const revoked =
      applySimulationEvent(
        started,
        revokeEvent,
      );

    expect(
      revoked.sessions[
        "session-new-001"
      ].status,
    ).toBe("revoked");

    expect(
      revoked.sessions[
        "session-new-001"
      ].endedAt,
    ).toBe(
      "2026-08-18T09:45:00Z",
    );
  });

  it("rejects revocation of an unknown session", () => {
    const event:
      SessionRevokedEvent = {
      id: "event-session-revoke-001",

      type: "SESSION_REVOKED",

      timestamp:
        "2026-08-18T09:45:00Z",

      source: "identity",

      payload: {
        sessionId:
          "session-missing",
      },
    };

    expect(
      () =>
        applySimulationEvent(
          createWorld(),
          event,
        ),
    ).toThrow(
      "Session not found: session-missing",
    );
  });

  it("re-enables a disabled account", () => {
    const disabledAccount = {
      ...exampleAccount,
      status:
        "disabled" as const,
    };

    const world =
      createWorldState({
        simulationTime:
          "2026-08-18T09:00:00Z",

        accounts: [
          disabledAccount,
        ],
      });

    const event:
      AccountEnabledEvent = {
      id: "event-account-enabled-001",

      type: "ACCOUNT_ENABLED",

      timestamp:
        "2026-08-18T10:00:00Z",

      source: "identity",

      payload: {
        accountId:
          exampleAccount.id,

        reason:
          "containment cleared",
      },
    };

    const next =
      applySimulationEvent(
        world,
        event,
      );

    expect(
      next.accounts[
        exampleAccount.id
      ].status,
    ).toBe("active");
  });
});
