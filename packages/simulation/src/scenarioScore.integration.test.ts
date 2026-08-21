import {
  describe,
  expect,
  it,
} from "vitest";

import {
  getScenarioState,
} from "./scenario";

import type {
  ScenarioDefinition,
} from "./scenario";

import {
  createWorldState,
} from "./worldState";

function createScenario():
  ScenarioDefinition {
  const accountId = "account-001";

  return {
    id: "scenario-score-001",
    name: "Scoring scenario",
    description:
      "A minimal deterministic scoring scenario.",
    initialWorld: createWorldState({
      simulationTime:
        "2026-08-20T09:00:00Z",
      organizations: [
        {
          id: "org-001",
          name: "Example Org",
          status: "active",
          departments: ["Security"],
        },
      ],
      users: [
        {
          id: "user-001",
          organizationId: "org-001",
          displayName: "Alex Morgan",
          email: "alex@example.test",
          department: "Security",
          status: "active",
          accountIds: [accountId],
          deviceIds: [],
        },
      ],
      accounts: [
        {
          id: accountId,
          organizationId: "org-001",
          userId: "user-001",
          username: "amorgan",
          provider: "Example Identity",
          status: "active",
          roles: ["user"],
        },
      ],
    }),
    openingEvents: [],
    actions: [
      {
        id: "disable-account",
        label: "Disable account",
        description:
          "Disable the affected account.",
        events: [
          {
            id: "event-disable-account",
            type: "ACCOUNT_DISABLED",
            timestamp:
              "2026-08-20T09:01:00Z",
            source: "identity",
            payload: {
              accountId,
            },
          },
        ],
      },
    ],
    objectives: [
      {
        id: "objective-disable-account",
        kind: "account_status",
        label: "Disable account",
        description:
          "The affected account must be disabled.",
        accountId,
        expectedStatus: "disabled",
      },
    ],
    investigation: {
      alertId: "unused-alert",
      userId: "user-001",
      accountId,
      deviceId: "unused-device",
      sessionId: "unused-session",
      primaryActionId: "disable-account",
      responseActionIds: [
        "disable-account",
      ],
    },
  };
}

describe("scenario-state scoring", () => {
  it("moves from zero to full score and resets deterministically", () => {
    const scenario = createScenario();

    const initial =
      getScenarioState(scenario);
    const completed =
      getScenarioState(
        scenario,
        ["disable-account"],
      );
    const reset =
      getScenarioState(scenario);

    expect(initial.score).toEqual({
      completedObjectives: 0,
      totalObjectives: 1,
      objectivePercentage: 0,
      responsePenalty: 0,
      percentage: 0,
    });
    expect(initial.outcome.status)
      .toBe("in_progress");

    expect(completed.score).toEqual({
      completedObjectives: 1,
      totalObjectives: 1,
      objectivePercentage: 100,
      responsePenalty: 0,
      percentage: 100,
    });
    expect(completed.outcome.status)
      .toBe("succeeded");

    expect(reset.score)
      .toEqual(initial.score);
    expect(reset.outcome)
      .toEqual(initial.outcome);
  });
});
