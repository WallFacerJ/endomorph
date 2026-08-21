import {
  describe,
  expect,
  it,
} from "vitest";

import type {
  EdrProjectionState,
} from "./edrProjection";

import {
  getEdrEndpointInvestigation,
  getObservedEdrDeviceIds,
} from "./edrInvestigation";

function createState(): EdrProjectionState {
  return {
    endpointObservations: {
      "device-a": {
        eventId: "heartbeat-a",
        timestamp: "2026-08-20T10:00:00Z",
        deviceId: "device-a",
        status: "active",
        ipAddresses: ["10.0.0.10"],
      },
    },
    processes: [
      {
        eventId: "process-root",
        timestamp: "2026-08-20T10:01:00Z",
        deviceId: "device-a",
        processId: "100",
        image: "explorer.exe",
        commandLine: "explorer.exe",
        parentProcessId: undefined,
        accountId: "account-a",
      },
      {
        eventId: "process-child",
        timestamp: "2026-08-20T10:02:00Z",
        deviceId: "device-a",
        processId: "200",
        image: "WINWORD.EXE",
        commandLine: "WINWORD.EXE report.docm",
        parentProcessId: "100",
        accountId: "account-a",
      },
      {
        eventId: "process-grandchild",
        timestamp: "2026-08-20T10:03:00Z",
        deviceId: "device-a",
        processId: "300",
        image: "powershell.exe",
        commandLine: "powershell.exe -EncodedCommand synthetic",
        parentProcessId: "200",
        accountId: "account-a",
      },
      {
        eventId: "process-orphan",
        timestamp: "2026-08-20T10:04:00Z",
        deviceId: "device-b",
        processId: "900",
        image: "cmd.exe",
        commandLine: "cmd.exe /c whoami",
        parentProcessId: "899",
        accountId: "account-b",
      },
    ],
    fileActivity: [
      {
        eventId: "file-a",
        timestamp: "2026-08-20T10:02:30Z",
        fileId: "file-a",
        operation: "read",
        deviceId: "device-a",
        accountId: "account-a",
      },
    ],
    networkConnections: [
      {
        eventId: "network-a",
        timestamp: "2026-08-20T10:03:30Z",
        deviceId: "device-a",
        protocol: "tcp",
        sourceIp: "10.0.0.10",
        destinationIp: "203.0.113.10",
        sourcePort: 50000,
        destinationPort: 443,
      },
    ],
    alerts: [
      {
        eventId: "alert-a",
        timestamp: "2026-08-20T10:04:30Z",
        alertId: "alert-a",
        title: "Suspicious process chain",
        severity: "high",
        applicationId: "app-edr",
        relatedEventIds: ["process-grandchild"],
        relatedEntityIds: ["device-a", "account-a"],
      },
    ],
  };
}

describe("EDR investigation model", () => {
  it("builds deterministic endpoint-scoped activity", () => {
    const investigation =
      getEdrEndpointInvestigation(
        createState(),
        "device-a",
      );

    expect(
      investigation.processes.map(
        (process) => process.processId,
      ),
    ).toEqual(["100", "200", "300"]);

    expect(
      investigation.fileActivity.map(
        (activity) => activity.eventId,
      ),
    ).toEqual(["file-a"]);

    expect(
      investigation.networkConnections.map(
        (connection) => connection.eventId,
      ),
    ).toEqual(["network-a"]);

    expect(
      investigation.alerts.map(
        (alert) => alert.eventId,
      ),
    ).toEqual(["alert-a"]);
  });

  it("derives process ancestry and child relationships", () => {
    const investigation =
      getEdrEndpointInvestigation(
        createState(),
        "device-a",
      );

    expect(
      investigation.processTree.map((node) => ({
        processId: node.process.processId,
        depth: node.depth,
        parentId: node.parentProcess?.processId,
        children: node.childProcessIds,
        orphaned: node.orphanedParent,
      })),
    ).toEqual([
      {
        processId: "100",
        depth: 0,
        parentId: undefined,
        children: ["200"],
        orphaned: false,
      },
      {
        processId: "200",
        depth: 1,
        parentId: "100",
        children: ["300"],
        orphaned: false,
      },
      {
        processId: "300",
        depth: 2,
        parentId: "200",
        children: [],
        orphaned: false,
      },
    ]);
  });

  it("marks missing authored parents without inventing them", () => {
    const investigation =
      getEdrEndpointInvestigation(
        createState(),
        "device-b",
      );

    expect(investigation.processTree[0])
      .toMatchObject({
        depth: 0,
        parentProcess: undefined,
        orphanedParent: true,
      });
  });

  it("lists every device observed through EDR telemetry", () => {
    expect(
      getObservedEdrDeviceIds(createState()),
    ).toEqual(["device-a", "device-b"]);
  });
});
