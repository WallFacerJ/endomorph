import {
  describe,
  expect,
  it,
} from "vitest";

import {
  assessInvestigationCoverage,
} from "./investigationCoverage";

import {
  rebuildProjection,
} from "./projection";

import {
  siemProjection,
} from "./siemProjection";

import {
  createWorldState,
} from "./worldState";

import type {
  SimulationEvent,
} from "./simulationEvent";

const world = createWorldState({
  simulationTime: "2026-08-20T08:00:00.000Z",
  organizations: [
    { id: "org", name: "Acme", status: "active", departments: ["Finance"] },
  ],
  users: [
    {
      id: "user-a",
      organizationId: "org",
      displayName: "Ana Ruiz",
      email: "ana@acme.test",
      department: "Finance",
      status: "active",
      accountIds: ["account-a"],
      deviceIds: ["device-a"],
    },
  ],
  accounts: [
    {
      id: "account-a",
      organizationId: "org",
      userId: "user-a",
      username: "ana@acme.test",
      provider: "corporate-directory",
      status: "active",
      roles: ["domain-users"],
    },
  ],
  devices: [
    {
      id: "device-a",
      organizationId: "org",
      hostname: "FIN-01",
      operatingSystem: "Windows 11",
      status: "active",
      ownerUserId: "user-a",
      ipAddresses: ["10.20.1.5"],
    },
  ],
  applications: [],
  files: [],
});

const events: SimulationEvent[] = [
  {
    id: "truth-login",
    type: "AUTH_LOGIN_SUCCEEDED",
    timestamp: "2026-08-20T09:00:00.000Z",
    source: "identity",
    payload: {
      accountId: "account-a",
      userId: "user-a",
      deviceId: "device-a",
      sourceIp: "203.0.113.9",
    },
  },
  {
    id: "truth-lateral",
    type: "NETWORK_CONNECTION",
    timestamp: "2026-08-20T09:20:00.000Z",
    source: "network",
    payload: {
      deviceId: "device-a",
      protocol: "tcp",
      sourceIp: "10.20.1.5",
      destinationIp: "10.90.9.9",
      destinationPort: 445,
    },
  },
];

const records = rebuildProjection(
  siemProjection,
  events,
).events;

const groundTruth = [
  "truth-login",
  "truth-lateral",
];

describe("assessInvestigationCoverage", () => {
  it("reports full coverage when the analyst reached everything", () => {
    const coverage =
      assessInvestigationCoverage(
        world,
        records,
        groundTruth,
        groundTruth,
      );

    expect(coverage.percentage).toBe(100);
    expect(coverage.missed).toEqual([]);
  });

  it("reports nothing reached for an empty case", () => {
    const coverage =
      assessInvestigationCoverage(
        world,
        records,
        [],
        groundTruth,
      );

    expect(coverage.percentage).toBe(0);
    expect(coverage.reached).toEqual([]);
    expect(
      coverage.missed.length,
    ).toBeGreaterThan(0);
  });

  it("distinguishes a partial investigation from a complete one", () => {
    // The distinction objective scoring cannot make: this analyst collected
    // the alerting login and stopped, never establishing the lateral
    // movement. State outcomes could still be correct.
    const partial =
      assessInvestigationCoverage(
        world,
        records,
        ["truth-login"],
        groundTruth,
      );

    expect(
      partial.percentage,
    ).toBeGreaterThan(0);

    expect(
      partial.percentage,
    ).toBeLessThan(100);

    expect(
      partial.missed.map(
        (entity) => entity.id,
      ),
    ).toContain("10.90.9.9");
  });

  it("names what was missed so the score is explainable", () => {
    const partial =
      assessInvestigationCoverage(
        world,
        records,
        ["truth-login"],
        groundTruth,
      );

    for (const entity of partial.missed) {
      expect(entity.label.length).toBeGreaterThan(0);
      expect(entity.reached).toBe(false);
    }

    for (const entity of partial.reached) {
      expect(entity.reached).toBe(true);
    }

    expect(
      partial.reached.length +
        partial.missed.length,
    ).toBe(partial.entities.length);
  });

  it("treats a scenario without ground truth as fully covered", () => {
    expect(
      assessInvestigationCoverage(
        world,
        records,
        [],
        [],
      ).percentage,
    ).toBe(100);
  });

  it("is deterministic", () => {
    expect(
      assessInvestigationCoverage(
        world,
        records,
        ["truth-login"],
        groundTruth,
      ),
    ).toEqual(
      assessInvestigationCoverage(
        world,
        records,
        ["truth-login"],
        groundTruth,
      ),
    );
  });
});
