import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  AccountDisabledEvent,
  AlertCreatedEvent,
  AuthLoginFailedEvent,
  AuthLoginSucceededEvent,
  EndpointHeartbeatEvent,
  FileAccessedEvent,
  NetworkConnectionEvent,
  ProcessStartedEvent,
  SimulationEvent,
  SimulationEventType,
} from "./simulationEvent";

function getEventSummary(
  event: SimulationEvent,
): string {
  switch (event.type) {
    case "AUTH_LOGIN_SUCCEEDED":
      return `Login succeeded for ${event.payload.accountId}`;

    case "AUTH_LOGIN_FAILED":
      return `Login failed for ${event.payload.username}`;

    case "ACCOUNT_DISABLED":
      return `Account disabled: ${event.payload.accountId}`;

    case "PROCESS_STARTED":
      return `Process started: ${event.payload.image}`;

    case "FILE_ACCESSED":
      return `File ${event.payload.operation}: ${event.payload.fileId}`;

    case "NETWORK_CONNECTION":
      return `Connection to ${event.payload.destinationIp}`;

    case "ENDPOINT_HEARTBEAT":
      return `Endpoint heartbeat: ${event.payload.deviceId}`;

    case "ALERT_CREATED":
      return `Alert created: ${event.payload.title}`;
  }
}

describe("SimulationEvent", () => {
  it("models successful authentication", () => {
    const event = {
      id: "event-auth-success-001",
      type: "AUTH_LOGIN_SUCCEEDED",
      timestamp:
        "2026-08-18T09:14:00Z",
      source: "identity",
      payload: {
        accountId:
          "account-smartinez",
        userId:
          "user-sarah-martinez",
        deviceId:
          "device-fin-lt-04",
        applicationId:
          "app-identity",
        sourceIp:
          "10.20.30.44",
      },
    } satisfies AuthLoginSucceededEvent;

    expect(getEventSummary(event))
      .toBe(
        "Login succeeded for account-smartinez",
      );
  });

  it("models failed authentication without requiring a known account", () => {
    const event = {
      id: "event-auth-failed-001",
      type: "AUTH_LOGIN_FAILED",
      timestamp:
        "2026-08-18T09:15:00Z",
      source: "identity",
      payload: {
        username: "smartinez",
        reason:
          "invalid_credentials",
        sourceIp:
          "10.20.30.99",
      },
    } satisfies AuthLoginFailedEvent;

    expect(getEventSummary(event))
      .toBe(
        "Login failed for smartinez",
      );
  });

  it("models identity changes", () => {
    const event = {
      id: "event-account-disabled-001",
      type: "ACCOUNT_DISABLED",
      timestamp:
        "2026-08-18T09:30:00Z",
      source: "identity",
      payload: {
        accountId:
          "account-smartinez",
        reason:
          "security containment",
      },
    } satisfies AccountDisabledEvent;

    expect(getEventSummary(event))
      .toBe(
        "Account disabled: account-smartinez",
      );
  });

  it("models process execution", () => {
    const event = {
      id: "event-process-001",
      type: "PROCESS_STARTED",
      timestamp:
        "2026-08-18T09:35:00Z",
      source: "edr",
      payload: {
        deviceId:
          "device-fin-lt-04",
        processId: "4242",
        image:
          "C:\\Windows\\System32\\cmd.exe",
        commandLine:
          "cmd.exe /c whoami",
        accountId:
          "account-smartinez",
      },
    } satisfies ProcessStartedEvent;

    expect(getEventSummary(event))
      .toBe(
        "Process started: C:\\Windows\\System32\\cmd.exe",
      );
  });

  it("models file activity", () => {
    const event = {
      id: "event-file-001",
      type: "FILE_ACCESSED",
      timestamp:
        "2026-08-18T09:36:00Z",
      source: "edr",
      payload: {
        fileId:
          "file-q4-forecast",
        operation: "read",
        deviceId:
          "device-fin-lt-04",
        accountId:
          "account-smartinez",
      },
    } satisfies FileAccessedEvent;

    expect(getEventSummary(event))
      .toBe(
        "File read: file-q4-forecast",
      );
  });

  it("models network activity", () => {
    const event = {
      id: "event-network-001",
      type: "NETWORK_CONNECTION",
      timestamp:
        "2026-08-18T09:37:00Z",
      source: "edr",
      payload: {
        deviceId:
          "device-fin-lt-04",
        protocol: "tcp",
        sourceIp:
          "10.20.30.44",
        destinationIp:
          "10.20.40.10",
        sourcePort: 52144,
        destinationPort: 443,
      },
    } satisfies NetworkConnectionEvent;

    expect(getEventSummary(event))
      .toBe(
        "Connection to 10.20.40.10",
      );
  });

  it("models endpoint telemetry", () => {
    const event = {
      id: "event-heartbeat-001",
      type: "ENDPOINT_HEARTBEAT",
      timestamp:
        "2026-08-18T09:38:00Z",
      source: "edr",
      payload: {
        deviceId:
          "device-fin-lt-04",
        status: "active",
        ipAddresses: [
          "10.20.30.44",
        ],
      },
    } satisfies EndpointHeartbeatEvent;

    expect(getEventSummary(event))
      .toBe(
        "Endpoint heartbeat: device-fin-lt-04",
      );
  });

  it("models security detections", () => {
    const event = {
      id: "event-alert-001",
      type: "ALERT_CREATED",
      timestamp:
        "2026-08-18T09:40:00Z",
      source: "siem",
      payload: {
        alertId:
          "alert-001",
        title:
          "Suspicious command execution",
        severity: "high",
        applicationId:
          "app-siem",
        relatedEventIds: [
          "event-process-001",
        ],
        relatedEntityIds: [
          "device-fin-lt-04",
          "account-smartinez",
        ],
      },
    } satisfies AlertCreatedEvent;

    expect(getEventSummary(event))
      .toBe(
        "Alert created: Suspicious command execution",
      );
  });

  it("exposes event types as a string union", () => {
    const type:
      SimulationEventType =
        "PROCESS_STARTED";

    expect(type)
      .toBe("PROCESS_STARTED");
  });
});
