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
  exampleSession,
  exampleUser,
} from "@polymorph/domain";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  validateSimulationEvent,
} from "./eventValidation";

import {
  createWorldState,
} from "./worldState";

function createWorld() {
  return createWorldState({
    simulationTime:
      "2026-08-18T09:00:00Z",

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
}

describe("validateSimulationEvent", () => {
  it("accepts valid entity references", () => {
    const event: SimulationEvent = {
      id: "event-process-001",

      type: "PROCESS_STARTED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "edr",

      payload: {
        deviceId:
          exampleDevice.id,

        processId: "4242",

        image: "cmd.exe",

        accountId:
          exampleAccount.id,
      },
    };

    expect(
      () =>
        validateSimulationEvent(
          createWorld(),
          event,
        ),
    ).not.toThrow();
  });

  it("allows failed logins without a known account", () => {
    const event: SimulationEvent = {
      id: "event-login-failed-001",

      type: "AUTH_LOGIN_FAILED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "identity",

      payload: {
        username:
          "unknown-user",

        reason:
          "unknown_account",
      },
    };

    expect(
      () =>
        validateSimulationEvent(
          createWorld(),
          event,
        ),
    ).not.toThrow();
  });

  it("rejects process events for unknown devices", () => {
    const event: SimulationEvent = {
      id: "event-process-001",

      type: "PROCESS_STARTED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "edr",

      payload: {
        deviceId:
          "device-missing",

        processId: "4242",

        image: "cmd.exe",
      },
    };

    expect(
      () =>
        validateSimulationEvent(
          createWorld(),
          event,
        ),
    ).toThrow(
      "Device not found: device-missing",
    );
  });

  it("rejects file events for unknown files", () => {
    const event: SimulationEvent = {
      id: "event-file-001",

      type: "FILE_ACCESSED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "edr",

      payload: {
        fileId:
          "file-missing",

        operation: "read",
      },
    };

    expect(
      () =>
        validateSimulationEvent(
          createWorld(),
          event,
        ),
    ).toThrow(
      "File not found: file-missing",
    );
  });

  it("rejects successful logins for unknown accounts", () => {
    const event: SimulationEvent = {
      id: "event-login-001",

      type:
        "AUTH_LOGIN_SUCCEEDED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "identity",

      payload: {
        accountId:
          "account-missing",

        userId:
          exampleUser.id,
      },
    };

    expect(
      () =>
        validateSimulationEvent(
          createWorld(),
          event,
        ),
    ).toThrow(
      "Account not found: account-missing",
    );
  });

  it("rejects duplicate session creation", () => {
    const event: SimulationEvent = {
      id: "event-session-001",

      type: "SESSION_STARTED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "identity",

      payload: {
        sessionId:
          exampleSession.id,

        accountId:
          exampleAccount.id,
      },
    };

    expect(
      () =>
        validateSimulationEvent(
          createWorld(),
          event,
        ),
    ).toThrow(
      `Session already exists: ${exampleSession.id}`,
    );
  });

  it("rejects revocation of unknown sessions", () => {
    const event: SimulationEvent = {
      id: "event-revoke-001",

      type: "SESSION_REVOKED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "identity",

      payload: {
        sessionId:
          "session-missing",
      },
    };

    expect(
      () =>
        validateSimulationEvent(
          createWorld(),
          event,
        ),
    ).toThrow(
      "Session not found: session-missing",
    );
  });

  it("rejects alerts referencing unknown applications", () => {
    const event: SimulationEvent = {
      id: "event-alert-001",

      type: "ALERT_CREATED",

      timestamp:
        "2026-08-18T09:30:00Z",

      source: "siem",

      payload: {
        alertId:
          "alert-001",

        title:
          "Test alert",

        severity: "high",

        applicationId:
          "app-missing",

        relatedEventIds: [],

        relatedEntityIds: [],
      },
    };

    expect(
      () =>
        validateSimulationEvent(
          createWorld(),
          event,
        ),
    ).toThrow(
      "Application not found: app-missing",
    );
  });
});
