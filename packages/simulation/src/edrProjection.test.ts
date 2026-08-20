import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  AccountDisabledEvent,
  AlertCreatedEvent,
  EndpointHeartbeatEvent,
  FileAccessedEvent,
  NetworkConnectionEvent,
  ProcessStartedEvent,
  SimulationEvent,
} from "./simulationEvent";

import {
  InMemoryEventBus,
} from "./eventBus";

import {
  LiveProjection,
  rebuildProjection,
} from "./projection";

import {
  edrProjection,
} from "./edrProjection";

function heartbeat(
  id: string,
  timestamp: string,
  status:
    | "active"
    | "inactive"
    | "disabled" = "active",
): EndpointHeartbeatEvent {
  return {
    id,
    type: "ENDPOINT_HEARTBEAT",
    timestamp,
    source: "endpoint-agent",
    subjectId: "device-001",
    payload: {
      deviceId: "device-001",
      status,
      ipAddresses: [
        status === "active"
          ? "10.0.0.10"
          : "10.0.0.20",
      ],
    },
  };
}

function processStarted(
  id: string,
  timestamp: string,
  processId: string,
): ProcessStartedEvent {
  return {
    id,
    type: "PROCESS_STARTED",
    timestamp,
    source: "edr-agent",
    subjectId: "device-001",
    payload: {
      deviceId: "device-001",
      processId,
      image: "powershell.exe",
      commandLine:
        "powershell.exe -NoProfile",
      parentProcessId: "proc-parent",
      accountId: "account-001",
    },
  };
}

function fileAccessed(
  id: string,
  timestamp: string,
): FileAccessedEvent {
  return {
    id,
    type: "FILE_ACCESSED",
    timestamp,
    source: "edr-agent",
    payload: {
      fileId: "file-001",
      operation: "read",
      deviceId: "device-001",
      accountId: "account-001",
    },
  };
}

function networkConnection(
  id: string,
  timestamp: string,
): NetworkConnectionEvent {
  return {
    id,
    type: "NETWORK_CONNECTION",
    timestamp,
    source: "edr-agent",
    subjectId: "device-001",
    payload: {
      deviceId: "device-001",
      protocol: "tcp",
      sourceIp: "10.0.0.10",
      destinationIp: "198.51.100.25",
      sourcePort: 51000,
      destinationPort: 443,
    },
  };
}

function alertCreated(
  id: string,
  timestamp: string,
): AlertCreatedEvent {
  return {
    id,
    type: "ALERT_CREATED",
    timestamp,
    source: "detection-engine",
    payload: {
      alertId: "alert-001",
      title: "Suspicious PowerShell",
      severity: "high",
      applicationId: "app-edr",
      relatedEventIds: [
        "event-process",
      ],
      relatedEntityIds: [
        "device-001",
        "account-001",
      ],
    },
  };
}

describe("edrProjection", () => {
  it("produces identical live and replayed state", () => {
    const events: SimulationEvent[] = [
      heartbeat(
        "event-heartbeat",
        "2026-08-20T10:00:00Z",
      ),
      processStarted(
        "event-process",
        "2026-08-20T10:01:00Z",
        "proc-001",
      ),
      fileAccessed(
        "event-file",
        "2026-08-20T10:02:00Z",
      ),
      networkConnection(
        "event-network",
        "2026-08-20T10:03:00Z",
      ),
      alertCreated(
        "event-alert",
        "2026-08-20T10:04:00Z",
      ),
    ];

    const bus =
      new InMemoryEventBus();

    const live =
      new LiveProjection(
        edrProjection,
      );

    bus.subscribe(
      (event) => live.apply(event),
    );

    for (const event of events) {
      bus.publish(event);
    }

    expect(live.state)
      .toEqual(
        rebuildProjection(
          edrProjection,
          bus.all(),
        ),
      );
  });

  it("keeps only the latest endpoint observation per device", () => {
    const first =
      edrProjection.reduce(
        edrProjection.createInitialState(),
        heartbeat(
          "event-heartbeat-1",
          "2026-08-20T10:00:00Z",
          "active",
        ),
      );

    const second =
      edrProjection.reduce(
        first,
        heartbeat(
          "event-heartbeat-2",
          "2026-08-20T10:05:00Z",
          "inactive",
        ),
      );

    expect(
      Object.keys(
        second.endpointObservations,
      ),
    ).toEqual([
      "device-001",
    ]);

    expect(
      second.endpointObservations[
        "device-001"
      ],
    ).toEqual({
      eventId: "event-heartbeat-2",
      timestamp:
        "2026-08-20T10:05:00Z",
      deviceId: "device-001",
      status: "inactive",
      ipAddresses: [
        "10.0.0.20",
      ],
    });
  });

  it("preserves source event order for process, file, and network observations", () => {
    const events: SimulationEvent[] = [
      processStarted(
        "event-process-1",
        "2026-08-20T10:00:00Z",
        "proc-001",
      ),
      fileAccessed(
        "event-file-1",
        "2026-08-20T10:01:00Z",
      ),
      processStarted(
        "event-process-2",
        "2026-08-20T10:02:00Z",
        "proc-002",
      ),
      networkConnection(
        "event-network-1",
        "2026-08-20T10:03:00Z",
      ),
    ];

    const state =
      rebuildProjection(
        edrProjection,
        events,
      );

    expect(
      state.processes.map(
        (observation) =>
          observation.eventId,
      ),
    ).toEqual([
      "event-process-1",
      "event-process-2",
    ]);

    expect(
      state.fileActivity.map(
        (observation) =>
          observation.eventId,
      ),
    ).toEqual([
      "event-file-1",
    ]);

    expect(
      state.networkConnections.map(
        (observation) =>
          observation.eventId,
      ),
    ).toEqual([
      "event-network-1",
    ]);
  });

  it("ignores unrelated identity events", () => {
    const initial =
      edrProjection.createInitialState();

    const event: AccountDisabledEvent = {
      id: "event-account-disabled",
      type: "ACCOUNT_DISABLED",
      timestamp:
        "2026-08-20T10:00:00Z",
      source: "identity",
      subjectId: "account-001",
      payload: {
        accountId: "account-001",
        reason: "containment",
      },
    };

    expect(
      edrProjection.reduce(
        initial,
        event,
      ),
    ).toBe(initial);
  });

  it("allows the same event to feed EDR and an independent subscriber", () => {
    const bus =
      new InMemoryEventBus();

    const live =
      new LiveProjection(
        edrProjection,
      );

    const seenEventIds: string[] = [];

    bus.subscribe(
      (event) => live.apply(event),
    );

    bus.subscribe((event) => {
      seenEventIds.push(event.id);
    });

    bus.publish(
      processStarted(
        "event-process",
        "2026-08-20T10:00:00Z",
        "proc-001",
      ),
    );

    expect(live.state.processes)
      .toHaveLength(1);

    expect(seenEventIds)
      .toEqual([
        "event-process",
      ]);
  });
});
