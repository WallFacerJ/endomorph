import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  getSimulationEventFamily,
} from "./eventMetadata";

function createEvent(
  type: SimulationEvent["type"],
): SimulationEvent {
  switch (type) {
    case "AUTH_LOGIN_SUCCEEDED":
      return {
        id: "event-001",
        type,
        timestamp:
          "2026-08-18T09:00:00Z",
        source: "identity",
        payload: {
          accountId: "account-001",
          userId: "user-001",
        },
      };

    case "AUTH_LOGIN_FAILED":
      return {
        id: "event-002",
        type,
        timestamp:
          "2026-08-18T09:00:00Z",
        source: "identity",
        payload: {
          username: "user",
          reason:
            "invalid_credentials",
        },
      };

    case "ACCOUNT_DISABLED":
      return {
        id: "event-003",
        type,
        timestamp:
          "2026-08-18T09:00:00Z",
        source: "identity",
        payload: {
          accountId: "account-001",
        },
      };

    case "PROCESS_STARTED":
      return {
        id: "event-004",
        type,
        timestamp:
          "2026-08-18T09:00:00Z",
        source: "edr",
        payload: {
          deviceId: "device-001",
          processId: "100",
          image: "cmd.exe",
        },
      };

    case "FILE_ACCESSED":
      return {
        id: "event-005",
        type,
        timestamp:
          "2026-08-18T09:00:00Z",
        source: "edr",
        payload: {
          fileId: "file-001",
          operation: "read",
        },
      };

    case "NETWORK_CONNECTION":
      return {
        id: "event-006",
        type,
        timestamp:
          "2026-08-18T09:00:00Z",
        source: "edr",
        payload: {
          deviceId: "device-001",
          protocol: "tcp",
          sourceIp: "10.0.0.1",
          destinationIp:
            "10.0.0.2",
        },
      };

    case "ENDPOINT_HEARTBEAT":
      return {
        id: "event-007",
        type,
        timestamp:
          "2026-08-18T09:00:00Z",
        source: "edr",
        payload: {
          deviceId: "device-001",
          status: "active",
          ipAddresses: [
            "10.0.0.1",
          ],
        },
      };

    case "ALERT_CREATED":
      return {
        id: "event-008",
        type,
        timestamp:
          "2026-08-18T09:00:00Z",
        source: "siem",
        payload: {
          alertId: "alert-001",
          title: "Test alert",
          severity: "high",
          relatedEventIds: [],
          relatedEntityIds: [],
        },
      };
  }
}

describe("getSimulationEventFamily", () => {
  it("classifies authentication events", () => {
    expect(
      getSimulationEventFamily(
        createEvent(
          "AUTH_LOGIN_SUCCEEDED",
        ),
      ),
    ).toBe("authentication");

    expect(
      getSimulationEventFamily(
        createEvent(
          "AUTH_LOGIN_FAILED",
        ),
      ),
    ).toBe("authentication");
  });

  it("classifies identity events", () => {
    expect(
      getSimulationEventFamily(
        createEvent(
          "ACCOUNT_DISABLED",
        ),
      ),
    ).toBe("identity");
  });

  it("classifies telemetry event families", () => {
    expect(
      getSimulationEventFamily(
        createEvent(
          "PROCESS_STARTED",
        ),
      ),
    ).toBe("process");

    expect(
      getSimulationEventFamily(
        createEvent(
          "FILE_ACCESSED",
        ),
      ),
    ).toBe("file");

    expect(
      getSimulationEventFamily(
        createEvent(
          "NETWORK_CONNECTION",
        ),
      ),
    ).toBe("network");

    expect(
      getSimulationEventFamily(
        createEvent(
          "ENDPOINT_HEARTBEAT",
        ),
      ),
    ).toBe("endpoint");

    expect(
      getSimulationEventFamily(
        createEvent(
          "ALERT_CREATED",
        ),
      ),
    ).toBe("security");
  });
});
