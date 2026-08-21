import {
  readFileSync,
  readdirSync,
} from "node:fs";

import {
  join,
} from "node:path";

import {
  describe,
  expect,
  it,
} from "vitest";

import {
  parseScenarioFile,
} from "@endomorph/schema";

import {
  routeAction,
} from "./actionRouting";

const SCENARIO_DIR = join(
  __dirname,
  "..",
  "public",
  "scenarios",
);

const scenarioFiles = readdirSync(
  SCENARIO_DIR,
).filter((name) =>
  name.endsWith(".json"),
);

describe("response action routing", () => {
  it("finds the shipped scenarios", () => {
    expect(
      scenarioFiles.length,
    ).toBeGreaterThan(0);
  });

  for (const fileName of scenarioFiles) {
    describe(fileName, () => {
      const parsed = parseScenarioFile(
        JSON.parse(
          readFileSync(
            join(
              SCENARIO_DIR,
              fileName,
            ),
            "utf8",
          ),
        ),
      );

      const { scenario } = parsed;

      const context = {
        deviceIds:
          scenario.initialWorld.devices.map(
            (device) => device.id,
          ),
        accounts:
          scenario.initialWorld.accounts.map(
            (account) => ({
              id: account.id,
              username: account.username,
            }),
          ),
        sessionIds: [
          ...scenario.initialWorld.sessions.map(
            (session) => session.id,
          ),
          // Sessions the opening history establishes are equally valid
          // targets; the identity console lists them for the account.
          ...scenario.openingEvents
            .filter(
              (event) =>
                event.type ===
                "SESSION_STARTED",
            )
            .map((event) =>
              event.type ===
              "SESSION_STARTED"
                ? event.payload.sessionId
                : "",
            ),
        ],
      };

      it("routes every response action to a tool console", () => {
        // Professional mode hides the response-card row. If an action has
        // no console, it becomes unreachable and the run cannot be
        // completed -- a silent, total failure.
        const unrouted =
          scenario.actions.filter(
            (action) =>
              routeAction(
                action,
                context,
              ).length === 0,
          );

        expect(
          unrouted.map(
            (action) => action.id,
          ),
        ).toEqual([]);
      });

      it("routes the scenario's primary action", () => {
        const primary =
          scenario.actions.find(
            (action) =>
              action.id ===
              scenario.investigation
                .primaryActionId,
          );

        expect(primary).toBeDefined();

        expect(
          routeAction(
            primary!,
            context,
          ).length,
        ).toBeGreaterThan(0);
      });
    });
  }
});

describe("routeAction", () => {
  const context = {
    deviceIds: ["device-1"],
    accounts: [
      {
        id: "account-1",
        username: "a@example.test",
      },
    ],
    sessionIds: ["session-1"],
  };

  it("routes endpoint operations to the endpoint console", () => {
    expect(
      routeAction(
        {
          id: "isolate",
          label: "Isolate",
          description: "",
          events: [
            {
              id: "e1",
              type: "ENDPOINT_HEARTBEAT",
              timestamp:
                "2026-08-20T09:00:00.000Z",
              source: "edr",
              payload: {
                deviceId: "device-1",
                status: "inactive",
                ipAddresses: [],
              },
            },
          ],
        } as never,
        context,
      ),
    ).toEqual(["endpoint"]);
  });

  it("routes account operations to the identity console", () => {
    expect(
      routeAction(
        {
          id: "disable",
          label: "Disable",
          description: "",
          events: [
            {
              id: "e1",
              type: "ACCOUNT_DISABLED",
              timestamp:
                "2026-08-20T09:00:00.000Z",
              source: "identity",
              payload: {
                accountId: "account-1",
              },
            },
          ],
        } as never,
        context,
      ),
    ).toEqual(["identity"]);
  });

  it("routes credential operations by username", () => {
    // Regression: a password reset emits AUTH_LOGIN_FAILED keyed by
    // username, not account id. It routed nowhere until identity targeting
    // learned to match usernames, which would have stranded it once the
    // response-card row was hidden.
    expect(
      routeAction(
        {
          id: "reset",
          label: "Reset password",
          description: "",
          events: [
            {
              id: "e1",
              type: "AUTH_LOGIN_FAILED",
              timestamp:
                "2026-08-20T09:00:00.000Z",
              source: "identity",
              payload: {
                username:
                  "a@example.test",
                reason:
                  "invalid_credentials",
              },
            },
          ],
        } as never,
        context,
      ),
    ).toEqual(["identity"]);
  });

  it("reports no surface for an action targeting nothing known", () => {
    expect(
      routeAction(
        {
          id: "orphan",
          label: "Orphan",
          description: "",
          events: [
            {
              id: "e1",
              type: "ACCOUNT_DISABLED",
              timestamp:
                "2026-08-20T09:00:00.000Z",
              source: "identity",
              payload: {
                accountId:
                  "account-unknown",
              },
            },
          ],
        } as never,
        context,
      ),
    ).toEqual([]);
  });
});
