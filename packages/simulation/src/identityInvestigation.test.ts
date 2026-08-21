import {
  describe,
  expect,
  it,
} from "vitest";

import {
  createWorldState,
} from "./worldState";

import type {
  IdentityProjectionState,
} from "./identityProjection";

import {
  getIdentityAccountInvestigation,
  getIdentityInventory,
} from "./identityInvestigation";

const world = createWorldState({
  simulationTime: "2026-08-20T10:10:00Z",
  organizations: [
    {
      id: "org-a",
      name: "Example",
      status: "active",
      departments: ["Security"],
    },
  ],
  users: [
    {
      id: "user-a",
      organizationId: "org-a",
      displayName: "Alex Analyst",
      email: "alex@example.test",
      department: "Security",
      title: "Administrator",
      status: "active",
      accountIds: ["account-a"],
      deviceIds: ["device-a"],
    },
    {
      id: "user-b",
      organizationId: "org-a",
      displayName: "Bailey User",
      email: "bailey@example.test",
      department: "Security",
      title: "Analyst",
      status: "active",
      accountIds: ["account-b"],
      deviceIds: [],
    },
  ],
  accounts: [
    {
      id: "account-a",
      organizationId: "org-a",
      userId: "user-a",
      username: "alex",
      provider: "Example Identity",
      status: "active",
      roles: ["global-admin", "security-admin"],
    },
    {
      id: "account-b",
      organizationId: "org-a",
      userId: "user-b",
      username: "bailey",
      provider: "Example Identity",
      status: "active",
      roles: ["user"],
    },
  ],
  devices: [
    {
      id: "device-a",
      organizationId: "org-a",
      hostname: "SEC-LT-01",
      operatingSystem: "Windows 11",
      status: "active",
      ownerUserId: "user-a",
      ipAddresses: ["10.0.0.10"],
    },
  ],
  applications: [
    {
      id: "app-id",
      organizationId: "org-a",
      name: "Example Identity",
      kind: "identity",
      status: "active",
    },
  ],
  sessions: [
    {
      id: "session-a",
      accountId: "account-a",
      deviceId: "device-a",
      applicationId: "app-id",
      startedAt: "2026-08-20T10:02:00Z",
      status: "active",
    },
  ],
});

const state: IdentityProjectionState = {
  successfulLogins: 2,
  failedLogins: 1,
  activity: [
    {
      kind: "login_failed",
      eventId: "failed-a",
      timestamp: "2026-08-20T10:00:00Z",
      username: "alex",
      reason: "mfa_failed",
      deviceId: undefined,
      applicationId: "app-id",
      sourceIp: "198.51.100.10",
    },
    {
      kind: "login_succeeded",
      eventId: "login-a",
      timestamp: "2026-08-20T10:01:00Z",
      accountId: "account-a",
      userId: "user-a",
      deviceId: "device-a",
      applicationId: "app-id",
      sourceIp: "198.51.100.10",
    },
    {
      kind: "session_started",
      eventId: "session-start-a",
      timestamp: "2026-08-20T10:02:00Z",
      sessionId: "session-a",
      accountId: "account-a",
      deviceId: "device-a",
      applicationId: "app-id",
    },
    {
      kind: "login_succeeded",
      eventId: "login-b",
      timestamp: "2026-08-20T10:03:00Z",
      accountId: "account-b",
      userId: "user-b",
      deviceId: undefined,
      applicationId: "app-id",
      sourceIp: "10.0.0.20",
    },
  ],
};

describe("identity investigation model", () => {
  it("builds account-scoped authentication and session context", () => {
    const investigation =
      getIdentityAccountInvestigation(
        world,
        state,
        "account-a",
      );

    expect(investigation.user.id).toBe("user-a");
    expect(investigation.account.roles).toEqual([
      "global-admin",
      "security-admin",
    ]);
    expect(
      investigation.authentication.map(
        (activity) => activity.eventId,
      ),
    ).toEqual(["failed-a", "login-a"]);
    expect(investigation.sessions).toHaveLength(1);
    expect(investigation.sessions[0])
      .toMatchObject({
        session: {
          id: "session-a",
          status: "active",
        },
        device: {
          id: "device-a",
        },
        application: {
          id: "app-id",
        },
        startedEvent: {
          eventId: "session-start-a",
        },
      });
  });

  it("matches failed authentications by account username", () => {
    const investigation =
      getIdentityAccountInvestigation(
        world,
        state,
        "account-a",
      );

    expect(
      investigation.authentication[0],
    ).toMatchObject({
      kind: "login_failed",
      username: "alex",
      sourceIp: "198.51.100.10",
    });
  });

  it("builds deterministic user inventory metrics", () => {
    const inventory = getIdentityInventory(
      world,
      state,
    );

    expect(
      inventory.map((entry) =>
        entry.user.displayName,
      ),
    ).toEqual([
      "Alex Analyst",
      "Bailey User",
    ]);

    expect(inventory[0]).toMatchObject({
      activeSessionCount: 1,
      successfulLoginCount: 1,
      failedLoginCount: 1,
      latestAuthenticationAt:
        "2026-08-20T10:01:00Z",
    });
  });

  it("rejects unknown accounts", () => {
    expect(() =>
      getIdentityAccountInvestigation(
        world,
        state,
        "missing",
      ),
    ).toThrow(
      "Unknown account for identity investigation: missing",
    );
  });
});
