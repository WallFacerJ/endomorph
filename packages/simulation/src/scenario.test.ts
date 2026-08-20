import {
  describe,
  expect,
  it,
} from "vitest";

import {
  compileScenarioDefinition,
} from "./scenarioCompiler";

import type {
  ScenarioDefinitionInput,
} from "./scenarioCompiler";

import {
  edrProjection,
} from "./edrProjection";

import {
  identityProjection,
} from "./identityProjection";

import {
  rebuildProjection,
} from "./projection";

import {
  getScenarioState,
} from "./scenario";

import {
  siemProjection,
} from "./siemProjection";

const ids = {
  organizationId: "org-001",
  userId: "user-001",
  accountId: "account-001",
  deviceId: "device-001",
  identityApplicationId:
    "app-identity",
  edrApplicationId: "app-edr",
  sessionId: "session-001",
  loginEventId: "event-login",
  processEventId: "event-process",
  networkEventId: "event-network",
  alertEventId: "event-alert",
  alertId: "alert-001",
  containmentActionId:
    "contain-incident",
} as const;

function createScenarioInput():
  ScenarioDefinitionInput {
  return {
    id: "scenario-001",
    name: "Compiled scenario",
    description:
      "A small deterministic incident.",
    initialWorld: {
      simulationTime:
        "2026-08-20T09:00:00Z",
      organizations: [
        {
          id: ids.organizationId,
          name: "Example Org",
          status: "active",
          departments: ["Finance"],
        },
      ],
      users: [
        {
          id: ids.userId,
          organizationId:
            ids.organizationId,
          displayName: "Alex Morgan",
          email: "alex@example.test",
          department: "Finance",
          status: "active",
          accountIds: [ids.accountId],
          deviceIds: [ids.deviceId],
        },
      ],
      accounts: [
        {
          id: ids.accountId,
          organizationId:
            ids.organizationId,
          userId: ids.userId,
          username: "amorgan",
          provider: "Example Identity",
          status: "active",
          roles: ["user"],
        },
      ],
      devices: [
        {
          id: ids.deviceId,
          organizationId:
            ids.organizationId,
          hostname: "FIN-LT-01",
          operatingSystem: "Windows 11",
          status: "active",
          ownerUserId: ids.userId,
          ipAddresses: ["10.0.0.10"],
        },
      ],
      applications: [
        {
          id: ids.identityApplicationId,
          organizationId:
            ids.organizationId,
          name: "Identity",
          kind: "identity",
          status: "active",
        },
        {
          id: ids.edrApplicationId,
          organizationId:
            ids.organizationId,
          name: "EDR",
          kind: "edr",
          status: "active",
        },
      ],
    },
    openingEvents: [
      {
        id: "event-heartbeat",
        type: "ENDPOINT_HEARTBEAT",
        timestamp:
          "2026-08-20T09:00:00Z",
        source: "edr",
        payload: {
          deviceId: ids.deviceId,
          status: "active",
          ipAddresses: ["10.0.0.10"],
        },
      },
      {
        id: ids.loginEventId,
        type: "AUTH_LOGIN_SUCCEEDED",
        timestamp:
          "2026-08-20T09:01:00Z",
        source: "identity",
        payload: {
          accountId: ids.accountId,
          userId: ids.userId,
          deviceId: ids.deviceId,
          applicationId:
            ids.identityApplicationId,
          sourceIp: "198.51.100.10",
        },
      },
      {
        id: "event-session",
        type: "SESSION_STARTED",
        timestamp:
          "2026-08-20T09:01:01Z",
        source: "identity",
        payload: {
          sessionId: ids.sessionId,
          accountId: ids.accountId,
          deviceId: ids.deviceId,
          applicationId:
            ids.identityApplicationId,
        },
      },
      {
        id: ids.processEventId,
        type: "PROCESS_STARTED",
        timestamp:
          "2026-08-20T09:02:00Z",
        source: "edr",
        payload: {
          deviceId: ids.deviceId,
          processId: "100",
          image: "powershell.exe",
          commandLine:
            "powershell.exe -EncodedCommand <synthetic>",
          accountId: ids.accountId,
        },
      },
      {
        id: ids.networkEventId,
        type: "NETWORK_CONNECTION",
        timestamp:
          "2026-08-20T09:02:01Z",
        source: "edr",
        payload: {
          deviceId: ids.deviceId,
          protocol: "tcp",
          sourceIp: "10.0.0.10",
          destinationIp: "203.0.113.10",
          destinationPort: 443,
        },
      },
      {
        id: ids.alertEventId,
        type: "ALERT_CREATED",
        timestamp:
          "2026-08-20T09:02:02Z",
        source: "edr",
        payload: {
          alertId: ids.alertId,
          title: "Suspicious PowerShell",
          severity: "high",
          applicationId:
            ids.edrApplicationId,
          relatedEventIds: [
            ids.loginEventId,
            ids.processEventId,
            ids.networkEventId,
          ],
          relatedEntityIds: [
            ids.userId,
            ids.accountId,
            ids.deviceId,
          ],
        },
      },
    ],
    actions: [
      {
        id: ids.containmentActionId,
        label: "Contain incident",
        description:
          "Revoke session and disable account.",
        events: [
          {
            id: "event-revoke",
            type: "SESSION_REVOKED",
            timestamp:
              "2026-08-20T09:03:00Z",
            source: "identity",
            payload: {
              sessionId: ids.sessionId,
            },
          },
          {
            id: "event-disable",
            type: "ACCOUNT_DISABLED",
            timestamp:
              "2026-08-20T09:03:01Z",
            source: "identity",
            payload: {
              accountId: ids.accountId,
            },
          },
        ],
      },
    ],
    objectives: [
      {
        id: "objective-session",
        kind: "session_status",
        label: "Revoke compromised session",
        description:
          "The suspicious session should be revoked.",
        sessionId: ids.sessionId,
        expectedStatus: "revoked",
      },
      {
        id: "objective-account",
        kind: "account_status",
        label: "Disable compromised account",
        description:
          "The compromised account should be disabled.",
        accountId: ids.accountId,
        expectedStatus: "disabled",
      },
    ],
    investigation: {
      alertId: ids.alertId,
      userId: ids.userId,
      accountId: ids.accountId,
      deviceId: ids.deviceId,
      sessionId: ids.sessionId,
      primaryActionId:
        ids.containmentActionId,
    },
  };
}

describe("scenario compilation", () => {
  it("compiles and replays a deterministic incident", () => {
    const scenario =
      compileScenarioDefinition(
        createScenarioInput(),
      );

    const first =
      getScenarioState(scenario);
    const second =
      getScenarioState(scenario);

    expect(second)
      .toEqual(first);

    expect(
      first.world.sessions[
        ids.sessionId
      ]?.status,
    ).toBe("active");

    expect(first.outcome.status)
      .toBe("in_progress");
    expect(
      first.outcome.objectives.map(
        (objective) => objective.met,
      ),
    ).toEqual([false, false]);
  });

  it("contains the incident and satisfies all response objectives", () => {
    const scenario =
      compileScenarioDefinition(
        createScenarioInput(),
      );

    const state =
      getScenarioState(
        scenario,
        [ids.containmentActionId],
      );

    expect(
      state.world.sessions[
        ids.sessionId
      ]?.status,
    ).toBe("revoked");

    expect(
      state.world.accounts[
        ids.accountId
      ]?.status,
    ).toBe("disabled");

    expect(state.outcome.status)
      .toBe("succeeded");
    expect(
      state.outcome.objectives.every(
        (objective) => objective.met,
      ),
    ).toBe(true);
  });

  it("keeps identity, EDR, and SIEM views coherent", () => {
    const scenario =
      compileScenarioDefinition(
        createScenarioInput(),
      );
    const state =
      getScenarioState(scenario);

    const identity =
      rebuildProjection(
        identityProjection,
        state.events,
      );
    const edr =
      rebuildProjection(
        edrProjection,
        state.events,
      );
    const siem =
      rebuildProjection(
        siemProjection,
        state.events,
      );

    expect(
      identity.activity.some(
        (activity) =>
          activity.eventId ===
          ids.loginEventId,
      ),
    ).toBe(true);

    expect(
      edr.processes.some(
        (process) =>
          process.eventId ===
          ids.processEventId,
      ),
    ).toBe(true);

    expect(
      edr.alerts[0]
        ?.relatedEventIds,
    ).toEqual([
      ids.loginEventId,
      ids.processEventId,
      ids.networkEventId,
    ]);

    expect(
      siem.events.map(
        (event) => event.eventId,
      ),
    ).toEqual(
      state.events.map(
        (event) => event.id,
      ),
    );
  });

  it("rejects invalid investigation references", () => {
    const input =
      createScenarioInput();

    input.investigation.userId =
      "missing-user";

    expect(() =>
      compileScenarioDefinition(input),
    ).toThrow(
      "investigation references missing user",
    );
  });

  it("rejects invalid and duplicate objective references", () => {
    const missing =
      createScenarioInput();

    missing.objectives = [
      {
        id: "objective-missing",
        kind: "session_status",
        label: "Missing session",
        description: "Invalid target.",
        sessionId: "missing-session",
        expectedStatus: "revoked",
      },
    ];

    expect(() =>
      compileScenarioDefinition(missing),
    ).toThrow(
      "objective objective-missing references missing session",
    );

    const duplicate =
      createScenarioInput();

    duplicate.objectives = [
      duplicate.objectives[0],
      {
        ...duplicate.objectives[0],
      },
    ];

    expect(() =>
      compileScenarioDefinition(duplicate),
    ).toThrow(
      "defines duplicate objective id: objective-session",
    );
  });

  it("rejects unknown and duplicate response actions", () => {
    const scenario =
      compileScenarioDefinition(
        createScenarioInput(),
      );

    expect(() =>
      getScenarioState(
        scenario,
        ["missing-action"],
      ),
    ).toThrow(
      "Unknown scenario action: missing-action",
    );

    expect(() =>
      getScenarioState(
        scenario,
        [
          ids.containmentActionId,
          ids.containmentActionId,
        ],
      ),
    ).toThrow(
      `Scenario action already performed: ${ids.containmentActionId}`,
    );
  });
});
