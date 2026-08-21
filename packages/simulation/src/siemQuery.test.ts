import {
  describe,
  expect,
  it,
} from "vitest";

import {
  searchSiem,
} from "./siemQuery";

import type {
  SiemEventRecord,
} from "./siemProjection";

const records: SiemEventRecord[] = [
  {
    eventId: "event-benign-auth",
    timestamp: "2026-08-20T09:00:00Z",
    source: "identity-provider",
    eventType: "AUTH_LOGIN_SUCCEEDED",
    family: "authentication",
    actorId: "user-benign",
    subjectId: "account-benign",
    severity: undefined,
    relatedEventIds: [],
    relatedEntityIds: [],
    message:
      "Login succeeded for account account-benign",
    fields: {
      accountId: "account-benign",
      userId: "user-benign",
      deviceId: "device-benign",
      sourceIp: "10.0.0.12",
    },
  },
  {
    eventId: "event-auth",
    timestamp: "2026-08-20T09:01:00Z",
    source: "identity-provider",
    eventType: "AUTH_LOGIN_SUCCEEDED",
    family: "authentication",
    actorId: "user-001",
    subjectId: "account-001",
    severity: undefined,
    relatedEventIds: [],
    relatedEntityIds: [],
    message:
      "Login succeeded for account account-001",
    fields: {
      accountId: "account-001",
      userId: "user-001",
      deviceId: "device-001",
      sourceIp: "198.51.100.42",
    },
  },
  {
    eventId: "event-process",
    timestamp: "2026-08-20T09:03:15Z",
    source: "edr-agent",
    eventType: "PROCESS_STARTED",
    family: "process",
    actorId: undefined,
    subjectId: "device-001",
    severity: undefined,
    relatedEventIds: [],
    relatedEntityIds: [],
    message:
      "Process started on device-001: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    fields: {
      deviceId: "device-001",
      processId: "proc-001",
      image:
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      commandLine:
        "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
      accountId: "account-001",
    },
  },
  {
    eventId: "event-network",
    timestamp: "2026-08-20T09:03:19Z",
    source: "edr-agent",
    eventType: "NETWORK_CONNECTION",
    family: "network",
    actorId: undefined,
    subjectId: "device-001",
    severity: undefined,
    relatedEventIds: [],
    relatedEntityIds: [],
    message:
      "Network connection 10.20.30.44 -> 203.0.113.77",
    fields: {
      deviceId: "device-001",
      protocol: "tcp",
      sourceIp: "10.20.30.44",
      destinationIp: "203.0.113.77",
      sourcePort: 51231,
      destinationPort: 443,
    },
  },
  {
    eventId: "event-alert",
    timestamp: "2026-08-20T09:03:25Z",
    source: "detection-engine",
    eventType: "ALERT_CREATED",
    family: "security",
    actorId: undefined,
    subjectId: undefined,
    severity: "critical",
    relatedEventIds: [
      "event-auth",
      "event-process",
      "event-network",
    ],
    relatedEntityIds: [
      "account-001",
      "device-001",
    ],
    message:
      "Alert created: Suspicious encoded PowerShell after unusual login",
    fields: {
      alertId: "alert-001",
      title:
        "Suspicious encoded PowerShell after unusual login",
      severity: "critical",
      relatedEventIds: [
        "event-auth",
        "event-process",
        "event-network",
      ],
      relatedEntityIds: [
        "account-001",
        "device-001",
      ],
    },
  },
];

describe("searchSiem", () => {
  it("performs free-text search across normalized fields", () => {
    const result = searchSiem(
      records,
      { query: "203.0.113.77" },
    );

    expect(
      result.records.map(
        (record) => record.eventId,
      ),
    ).toEqual(["event-network"]);
  });

  it("supports field aliases and case-insensitive values", () => {
    const result = searchSiem(
      records,
      {
        query:
          "type:process_started accountId:ACCOUNT-001",
      },
    );

    expect(
      result.records.map(
        (record) => record.eventId,
      ),
    ).toEqual(["event-process"]);
  });

  it("supports quoted field values", () => {
    const result = searchSiem(
      records,
      {
        query:
          'commandLine:"-NoProfile -EncodedCommand"',
      },
    );

    expect(result.records).toHaveLength(1);
    expect(result.records[0]?.eventId)
      .toBe("event-process");
  });

  it("supports negated terms", () => {
    const result = searchSiem(
      records,
      {
        query:
          "family:authentication -accountId:account-benign",
        order: "asc",
      },
    );

    expect(
      result.records.map(
        (record) => record.eventId,
      ),
    ).toEqual(["event-auth"]);
  });

  it("applies inclusive time ranges", () => {
    const result = searchSiem(
      records,
      {
        startTime:
          "2026-08-20T09:03:15Z",
        endTime:
          "2026-08-20T09:03:19Z",
        order: "asc",
      },
    );

    expect(
      result.records.map(
        (record) => record.eventId,
      ),
    ).toEqual([
      "event-process",
      "event-network",
    ]);
  });

  it("matches array-valued correlation fields", () => {
    const result = searchSiem(
      records,
      {
        query:
          "relatedEventIds:event-process",
      },
    );

    expect(
      result.records.map(
        (record) => record.eventId,
      ),
    ).toEqual(["event-alert"]);
  });

  it("returns deterministic ordering and matched-result facets", () => {
    const result = searchSiem(
      records,
      {
        query: "device-001",
        order: "asc",
      },
    );

    expect(
      result.records.map(
        (record) => record.eventId,
      ),
    ).toEqual([
      "event-auth",
      "event-process",
      "event-network",
      "event-alert",
    ]);

    expect(result.facets.families)
      .toEqual([
        {
          value: "authentication",
          count: 1,
        },
        { value: "network", count: 1 },
        { value: "process", count: 1 },
        { value: "security", count: 1 },
      ]);
  });

  it("returns every record for an empty query", () => {
    const result = searchSiem(records);

    expect(result.total).toBe(records.length);
    expect(result.records[0]?.eventId)
      .toBe("event-alert");
  });
});
