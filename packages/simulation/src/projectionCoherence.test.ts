import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  AlertCreatedEvent,
  AuthLoginSucceededEvent,
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
  identityProjection,
} from "./identityProjection";

import {
  edrProjection,
} from "./edrProjection";

import {
  siemProjection,
} from "./siemProjection";

function createIncidentEvents():
  SimulationEvent[] {
  const login:
    AuthLoginSucceededEvent = {
      id: "event-login",
      type: "AUTH_LOGIN_SUCCEEDED",
      timestamp:
        "2026-08-20T12:00:00Z",
      source: "identity-provider",
      actorId: "user-001",
      subjectId: "account-001",
      payload: {
        accountId: "account-001",
        userId: "user-001",
        deviceId: "device-001",
        applicationId: "app-vpn",
        sourceIp: "203.0.113.25",
      },
    };

  const process:
    ProcessStartedEvent = {
      id: "event-process",
      type: "PROCESS_STARTED",
      timestamp:
        "2026-08-20T12:02:00Z",
      source: "edr-agent",
      actorId: "account-001",
      subjectId: "device-001",
      payload: {
        deviceId: "device-001",
        processId: "proc-001",
        image: "powershell.exe",
        commandLine:
          "powershell.exe -NoProfile",
        parentProcessId: "proc-parent",
        accountId: "account-001",
      },
    };

  const alert:
    AlertCreatedEvent = {
      id: "event-alert",
      type: "ALERT_CREATED",
      timestamp:
        "2026-08-20T12:03:00Z",
      source: "detection-engine",
      subjectId: "device-001",
      payload: {
        alertId: "alert-001",
        title:
          "Suspicious PowerShell after remote login",
        severity: "high",
        applicationId: "app-edr",
        relatedEventIds: [
          login.id,
          process.id,
        ],
        relatedEntityIds: [
          "user-001",
          "account-001",
          "device-001",
        ],
      },
    };

  return [
    login,
    process,
    alert,
  ];
}

describe(
  "cross-projection incident coherence",
  () => {
    it("derives coherent identity, EDR, and SIEM views from one shared history", () => {
      const events =
        createIncidentEvents();

      const bus =
        new InMemoryEventBus();

      const identity =
        new LiveProjection(
          identityProjection,
        );

      const edr =
        new LiveProjection(
          edrProjection,
        );

      const siem =
        new LiveProjection(
          siemProjection,
        );

      bus.subscribe(
        (event) =>
          identity.apply(event),
      );
      bus.subscribe(
        (event) => edr.apply(event),
      );
      bus.subscribe(
        (event) => siem.apply(event),
      );

      for (const event of events) {
        bus.publish(event);
      }

      expect(
        identity.state.activity,
      ).toHaveLength(1);

      const loginActivity =
        identity.state.activity[0];

      expect(loginActivity?.kind)
        .toBe("login_succeeded");

      if (
        !loginActivity ||
        loginActivity.kind !==
          "login_succeeded"
      ) {
        throw new Error(
          "Expected login activity.",
        );
      }

      expect(loginActivity)
        .toMatchObject({
          eventId: "event-login",
          accountId: "account-001",
          userId: "user-001",
          deviceId: "device-001",
        });

      expect(edr.state.processes)
        .toHaveLength(1);
      expect(edr.state.alerts)
        .toHaveLength(1);

      const processObservation =
        edr.state.processes[0];

      expect(processObservation)
        .toMatchObject({
          eventId: "event-process",
          accountId: "account-001",
          deviceId: "device-001",
        });

      expect(
        loginActivity.accountId,
      ).toBe(
        processObservation?.accountId,
      );
      expect(
        loginActivity.deviceId,
      ).toBe(
        processObservation?.deviceId,
      );

      expect(edr.state.alerts[0])
        .toMatchObject({
          eventId: "event-alert",
          severity: "high",
          relatedEventIds: [
            "event-login",
            "event-process",
          ],
          relatedEntityIds: [
            "user-001",
            "account-001",
            "device-001",
          ],
        });

      expect(
        siem.state.events.map(
          (record) => record.eventId,
        ),
      ).toEqual([
        "event-login",
        "event-process",
        "event-alert",
      ]);

      expect(siem.state.events[2])
        .toMatchObject({
          eventId: "event-alert",
          family: "security",
          severity: "high",
          relatedEventIds: [
            "event-login",
            "event-process",
          ],
          relatedEntityIds: [
            "user-001",
            "account-001",
            "device-001",
          ],
        });

      expect(identity.state)
        .toEqual(
          rebuildProjection(
            identityProjection,
            bus.all(),
          ),
        );
      expect(edr.state)
        .toEqual(
          rebuildProjection(
            edrProjection,
            bus.all(),
          ),
        );
      expect(siem.state)
        .toEqual(
          rebuildProjection(
            siemProjection,
            bus.all(),
          ),
        );
    });
  },
);
