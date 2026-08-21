import {
  describe,
  expect,
  it,
} from "vitest";

import {
  parseScenarioFile,
  parseScenarioJson,
  SCENARIO_FILE_VERSION,
} from "./scenario";

function createValidFile(): unknown {
  return {
    version: SCENARIO_FILE_VERSION,
    kind: "polymorph-scenario",
    scenario: {
      id: "scenario-001",
      name: "Example scenario",
      description:
        "A structurally valid scenario.",
      initialWorld: {
        simulationTime:
          "2026-08-20T09:00:00Z",
      },
      openingEvents: [
        {
          id: "event-001",
          type: "AUTH_LOGIN_FAILED",
          timestamp:
            "2026-08-20T09:01:00Z",
          source: "identity",
          payload: {
            username: "example",
            reason:
              "invalid_credentials",
            sourceIp:
              "198.51.100.20",
          },
        },
      ],
      actions: [
        {
          id: "action-001",
          label: "Respond",
          description:
            "Perform a deterministic response.",
          events: [
            {
              id: "event-002",
              type: "ACCOUNT_DISABLED",
              timestamp:
                "2026-08-20T09:02:00Z",
              source: "identity",
              payload: {
                accountId: "account-001",
              },
            },
          ],
        },
      ],
      objectives: [
        {
          id: "objective-001",
          kind: "account_status",
          label: "Disable account",
          description:
            "The affected account should be disabled.",
          accountId: "account-001",
          expectedStatus: "disabled",
        },
      ],
      investigation: {
        alertId: "alert-001",
        userId: "user-001",
        accountId: "account-001",
        deviceId: "device-001",
        sessionId: "session-001",
        primaryActionId: "action-001",
      },
    },
  };
}

describe("scenario file schema", () => {
  it("parses a versioned scenario and fills empty world collections", () => {
    const parsed =
      parseScenarioFile(
        createValidFile(),
      );

    expect(parsed.version)
      .toBe(1);

    expect(
      parsed.scenario.initialWorld,
    ).toMatchObject({
      organizations: [],
      users: [],
      accounts: [],
      devices: [],
      files: [],
      applications: [],
      sessions: [],
    });

    expect(
      parsed.scenario.objectives[0],
    ).toMatchObject({
      kind: "account_status",
      expectedStatus: "disabled",
    });
  });

  it("accepts optional deterministic response assessment metadata", () => {
    const input =
      createValidFile() as {
        scenario: {
          actions: Array<
            Record<string, unknown>
          >;
        };
      };

    input.scenario.actions[0].assessment = {
      penalty: 25,
      rationale:
        "This response creates avoidable exposure.",
    };

    expect(
      parseScenarioFile(input)
        .scenario.actions[0]
        .assessment,
    ).toEqual({
      penalty: 25,
      rationale:
        "This response creates avoidable exposure.",
    });
  });

  it("rejects malformed response assessment metadata", () => {
    const negative =
      createValidFile() as {
        scenario: {
          actions: Array<
            Record<string, unknown>
          >;
        };
      };

    negative.scenario.actions[0].assessment = {
      penalty: -1,
      rationale: "Invalid penalty.",
    };

    expect(() =>
      parseScenarioFile(negative),
    ).toThrow();

    const blankRationale =
      createValidFile() as {
        scenario: {
          actions: Array<
            Record<string, unknown>
          >;
        };
      };

    blankRationale.scenario.actions[0].assessment = {
      penalty: 10,
      rationale: "",
    };

    expect(() =>
      parseScenarioFile(blankRationale),
    ).toThrow();
  });

  it("rejects unsupported file versions", () => {
    const input =
      createValidFile() as {
        version: number;
      };

    input.version = 2;

    expect(() =>
      parseScenarioFile(input),
    ).toThrow();
  });

  it("rejects malformed event payloads", () => {
    const input =
      createValidFile() as {
        scenario: {
          openingEvents:
            Array<{
              payload: Record<
                string,
                unknown
              >;
            }>;
        };
      };

    delete input.scenario
      .openingEvents[0]
      .payload.reason;

    expect(() =>
      parseScenarioFile(input),
    ).toThrow();
  });

  it("rejects missing or unsupported objectives", () => {
    const missing =
      createValidFile() as {
        scenario: {
          objectives?: unknown[];
        };
      };

    delete missing.scenario.objectives;

    expect(() =>
      parseScenarioFile(missing),
    ).toThrow();

    const unsupported =
      createValidFile() as {
        scenario: {
          objectives: Array<
            Record<string, unknown>
          >;
        };
      };

    unsupported.scenario
      .objectives[0].kind =
      "javascript_expression";

    expect(() =>
      parseScenarioFile(unsupported),
    ).toThrow();
  });

  it("rejects malformed JSON before structural validation", () => {
    expect(() =>
      parseScenarioJson("{not-json"),
    ).toThrow(
      "Scenario file is not valid JSON.",
    );
  });
});
