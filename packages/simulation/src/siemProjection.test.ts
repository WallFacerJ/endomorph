import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  AlertCreatedEvent,
  AuthLoginSucceededEvent,
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

import {
  identityProjection,
} from "./identityProjection";

import {
  siemProjection,
} from "./siemProjection";

function createEvents(): SimulationEvent[] {
  return [
    {
      id: "event-auth",
      type: "AUTH_LOGIN_SUCCEEDED",
      timestamp: "2026-08-20T10:00:00Z",
      source: "identity-provider",
      actorId: "user-001",
      subjectId: "account-001",
      payload: {
        accountId: "account-001",
        userId: "user-001",
        deviceId: "device-001",
        applicationId: "app-001",
        sourceIp: "10.0.0.10",
      },
    },
    {
      id: "event-identity",
      type: "ACCOUNT_DISABLED",
      timestamp: "2026-08-20T10:01:00Z",
      source: "identity-provider",
      subjectId: "account-001",
      payload: {
        accountId: "account-001",
        reason: "containment",
      },
    },
    {
      id: "event-session",
      type: "SESSION_STARTED",
      timestamp: "2026-08-20T10:02:00Z",
      source: "identity-provider",
      subjectId: "session-001",
      payload: {
        sessionId: "session-001",
        accountId: "account-001",
        deviceId: "device-001",
        applicationId: "app-001",
      },
    },
    {
      id: "event-process",
      type: "PROCESS_STARTED",
      timestamp: "2026-08-20T10:03:00Z",
      source: "edr-agent",
      subjectId: "device-001",
      payload: {
        deviceId: "device-001",
        processId: "proc-001",
        image: "powershell.exe",
        commandLine: "powershell.exe -NoProfile",
        parentProcessId: "proc-parent",
        accountId: "account-001",
      },
    },
    {
      id: "event-file",
      type: "FILE_ACCESSED",
      timestamp: "2026-08-20T10:04:00Z",
      source: "edr-agent",
      payload: {
        fileId: "file-001",
        operation: "read",
        deviceId: "device-001",
        accountId: "account-001",
      },
    },
    {
      id: "event-network",
      type: "NETWORK_CONNECTION",
      timestamp: "2026-08-20T10:05:00Z",
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
    },
    {
      id: "event-endpoint",
      type: "ENDPOINT_HEARTBEAT",
      timestamp: "2026-08-20T10:06:00Z",
      source: "edr-agent",
      subjectId: "device-001",
      payload: {
        deviceId: "device-001",
        status: "active",
        ipAddresses: ["10.0.0.10"],
      },
    },
    {
      id: "event-alert",
      type: "ALERT_CREATED",
      timestamp: "2026-08-20T10:07:00Z",
      source: "detection-engine",
      payload: {
        alertId: "alert-001",
        title: "Suspicious PowerShell",
        severity: "high",
        applicationId: "app-siem",
        relatedEventIds: ["event-process"],
        relatedEntityIds: [
          "device-001",
          "account-001",
        ],
      },
    },
  ];
}

describe("siemProjection", () => {
  it("produces identical live and replayed state", () => {
    const bus = new InMemoryEventBus();
    const live = new LiveProjection(
      siemProjection,
    );

    bus.subscribe(
      (event) => live.apply(event),
    );

    for (const event of createEvents()) {
      bus.publish(event);
    }

    expect(live.state)
      .toEqual(
        rebuildProjection(
          siemProjection,
          bus.all(),
        ),
      );
  });

  it("normalizes every current event family in source order", () => {
    const state = rebuildProjection(
      siemProjection,
      createEvents(),
    );

    expect(
      state.events.map(
        (record) => record.family,
      ),
    ).toEqual([
      "authentication",
      "identity",
      "session",
      "process",
      "file",
      "network",
      "endpoint",
      "security",
    ]);

    expect(
      state.events.map(
        (record) => record.eventId,
      ),
    ).toEqual(
      createEvents().map(
        (event) => event.id,
      ),
    );
  });

  it("tracks deterministic family and type counters", () => {
    const events = [
      ...createEvents(),
      createEvents()[0],
    ].map((event, index) => ({
      ...event,
      id: `${event.id}-${index}`,
      timestamp:
        `2026-08-20T11:${String(index).padStart(2, "0")}:00Z`,
    })) as SimulationEvent[];

    const state = rebuildProjection(
      siemProjection,
      events,
    );

    expect(
      state.familyCounts.authentication,
    ).toBe(2);

    expect(
      state.familyCounts.security,
    ).toBe(1);

    expect(
      state.typeCounts.AUTH_LOGIN_SUCCEEDED,
    ).toBe(2);

    expect(
      state.typeCounts.ALERT_CREATED,
    ).toBe(1);
  });

  it("preserves alert severity and correlation ids", () => {
    const alert =
      createEvents()[7] as AlertCreatedEvent;

    const state = rebuildProjection(
      siemProjection,
      [alert],
    );

    expect(state.events[0])
      .toMatchObject({
        eventId: "event-alert",
        eventType: "ALERT_CREATED",
        family: "security",
        severity: "high",
        relatedEventIds: [
          "event-process",
        ],
        relatedEntityIds: [
          "device-001",
          "account-001",
        ],
      });
  });

  it("feeds the same process event to SIEM and EDR", () => {
    const processEvent =
      createEvents()[3];

    const bus = new InMemoryEventBus();
    const siem = new LiveProjection(
      siemProjection,
    );
    const edr = new LiveProjection(
      edrProjection,
    );

    bus.subscribe(
      (event) => siem.apply(event),
    );
    bus.subscribe(
      (event) => edr.apply(event),
    );

    bus.publish(processEvent);

    expect(siem.state.events[0]?.eventId)
      .toBe(processEvent.id);
    expect(edr.state.processes[0]?.eventId)
      .toBe(processEvent.id);
  });

  it("feeds the same authentication event to SIEM and identity", () => {
    const authEvent =
      createEvents()[0] as AuthLoginSucceededEvent;

    const bus = new InMemoryEventBus();
    const siem = new LiveProjection(
      siemProjection,
    );
    const identity = new LiveProjection(
      identityProjection,
    );

    bus.subscribe(
      (event) => siem.apply(event),
    );
    bus.subscribe(
      (event) => identity.apply(event),
    );

    bus.publish(authEvent);

    expect(siem.state.events[0]?.eventId)
      .toBe(authEvent.id);
    expect(
      identity.state.activity[0]?.eventId,
    ).toBe(authEvent.id);
  });
});
