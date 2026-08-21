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
  getScenarioState,
} from "./scenario";

const ids = {
  organizationId: "org-choices",
  userId: "user-choices",
  accountId: "account-choices",
  deviceId: "device-choices",
  applicationId: "app-choices",
  sessionId: "session-choices",
  alertId: "alert-choices",
  revokeActionId: "revoke-session",
  disableActionId: "disable-account",
} as const;

function createInput():
  ScenarioDefinitionInput {
  return {
    id: "scenario-remediation-choices",
    name: "Remediation choices",
    description:
      "Choose deterministic response actions.",
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
          id: ids.applicationId,
          organizationId:
            ids.organizationId,
          name: "Identity",
          kind: "identity",
          status: "active",
        },
      ],
    },
    openingEvents: [
      {
        id: "event-login",
        type: "AUTH_LOGIN_SUCCEEDED",
        timestamp:
          "2026-08-20T09:01:00Z",
        source: "identity",
        payload: {
          accountId: ids.accountId,
          userId: ids.userId,
          deviceId: ids.deviceId,
          applicationId:
            ids.applicationId,
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
            ids.applicationId,
        },
      },
      {
        id: "event-alert",
        type: "ALERT_CREATED",
        timestamp:
          "2026-08-20T09:02:00Z",
        source: "identity",
        payload: {
          alertId: ids.alertId,
          title: "Suspicious login",
          severity: "high",
          applicationId:
            ids.applicationId,
          relatedEventIds: [
            "event-login",
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
        id: ids.revokeActionId,
        label: "Revoke session",
        description:
          "Revoke the suspicious session.",
        events: [
          {
            id: "event-revoke-session",
            type: "SESSION_REVOKED",
            timestamp:
              "2026-08-20T09:03:00Z",
            source: "identity",
            payload: {
              sessionId: ids.sessionId,
            },
          },
        ],
      },
      {
        id: ids.disableActionId,
        label: "Disable account",
        description:
          "Disable the compromised account.",
        events: [
          {
            id: "event-disable-account",
            type: "ACCOUNT_DISABLED",
            timestamp:
              "2026-08-20T09:03:00Z",
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
        label: "Revoke session",
        description:
          "The suspicious session must be revoked.",
        sessionId: ids.sessionId,
        expectedStatus: "revoked",
      },
      {
        id: "objective-account",
        kind: "account_status",
        label: "Disable account",
        description:
          "The compromised account must be disabled.",
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
        ids.revokeActionId,
      responseActionIds: [
        ids.revokeActionId,
        ids.disableActionId,
      ],
    },
  };
}

describe("multiple remediation choices", () => {
  it("falls back to the primary action for older scenario inputs", () => {
    const input = createInput();
    delete input.investigation
      .responseActionIds;

    const scenario =
      compileScenarioDefinition(input);

    expect(
      scenario.investigation
        .responseActionIds,
    ).toEqual([
      ids.revokeActionId,
    ]);
  });

  it("rejects duplicate and missing response action ids", () => {
    const duplicate = createInput();
    duplicate.investigation
      .responseActionIds = [
      ids.revokeActionId,
      ids.revokeActionId,
    ];

    expect(() =>
      compileScenarioDefinition(duplicate),
    ).toThrow(
      "duplicate response action id",
    );

    const missing = createInput();
    missing.investigation
      .responseActionIds = [
      ids.revokeActionId,
      "missing-action",
    ];

    expect(() =>
      compileScenarioDefinition(missing),
    ).toThrow(
      "references missing response action",
    );
  });

  it("produces 50% partial progress from either response action", () => {
    const scenario =
      compileScenarioDefinition(
        createInput(),
      );

    const revoked = getScenarioState(
      scenario,
      [ids.revokeActionId],
    );

    expect(revoked.outcome.status)
      .toBe("in_progress");
    expect(revoked.score.percentage)
      .toBe(50);
    expect(
      revoked.world.sessions[
        ids.sessionId
      ]?.status,
    ).toBe("revoked");
    expect(
      revoked.world.accounts[
        ids.accountId
      ]?.status,
    ).toBe("active");

    const disabled = getScenarioState(
      scenario,
      [ids.disableActionId],
    );

    expect(disabled.outcome.status)
      .toBe("in_progress");
    expect(disabled.score.percentage)
      .toBe(50);
    expect(
      disabled.world.accounts[
        ids.accountId
      ]?.status,
    ).toBe("disabled");
    expect(
      disabled.world.sessions[
        ids.sessionId
      ]?.status,
    ).toBe("active");
  });

  it("succeeds after both actions in either order", () => {
    const scenario =
      compileScenarioDefinition(
        createInput(),
      );

    const revokeThenDisable =
      getScenarioState(
        scenario,
        [
          ids.revokeActionId,
          ids.disableActionId,
        ],
      );

    const disableThenRevoke =
      getScenarioState(
        scenario,
        [
          ids.disableActionId,
          ids.revokeActionId,
        ],
      );

    expect(revokeThenDisable.outcome.status)
      .toBe("succeeded");
    expect(disableThenRevoke.outcome.status)
      .toBe("succeeded");
    expect(revokeThenDisable.score.percentage)
      .toBe(100);
    expect(disableThenRevoke.score.percentage)
      .toBe(100);
    expect(revokeThenDisable.world)
      .toEqual(disableThenRevoke.world);
    expect(
      revokeThenDisable
        .performedActionIds,
    ).toEqual([
      ids.revokeActionId,
      ids.disableActionId,
    ]);
    expect(
      disableThenRevoke
        .performedActionIds,
    ).toEqual([
      ids.disableActionId,
      ids.revokeActionId,
    ]);
  });

  it("prevents duplicate actions and resets to zero progress", () => {
    const scenario =
      compileScenarioDefinition(
        createInput(),
      );

    expect(() =>
      getScenarioState(
        scenario,
        [
          ids.revokeActionId,
          ids.revokeActionId,
        ],
      ),
    ).toThrow(
      `Scenario action already performed: ${ids.revokeActionId}`,
    );

    const reset =
      getScenarioState(scenario);

    expect(reset.outcome.status)
      .toBe("in_progress");
    expect(reset.score.percentage)
      .toBe(0);
    expect(reset.performedActionIds)
      .toEqual([]);
  });
});
