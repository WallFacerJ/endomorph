import {
  describe,
  expect,
  it,
} from "vitest";

import {
  addAnalystFinding,
  collectAnalystEvidence,
  createAnalystCaseState,
  resolveCollectedEvidence,
} from "./analystCase";

import type {
  SimulationEvent,
} from "./simulationEvent";

const availableEvents:
  readonly SimulationEvent[] = [
    {
      id: "event-login",
      type: "AUTH_LOGIN_SUCCEEDED",
      timestamp: "2026-08-20T12:00:00.000Z",
      source: "identity-provider",
      payload: {
        accountId: "account-1",
        userId: "user-1",
        deviceId: "device-1",
        sourceIp: "198.51.100.42",
      },
    },
    {
      id: "event-process",
      type: "PROCESS_STARTED",
      timestamp: "2026-08-20T12:01:00.000Z",
      source: "edr",
      payload: {
        deviceId: "device-1",
        processId: "process-1",
        image: "powershell.exe",
        commandLine: "powershell.exe -EncodedCommand <synthetic>",
        accountId: "account-1",
      },
    },
  ];

describe("analyst case", () => {
  it("collects available evidence once while preserving order", () => {
    const initial =
      createAnalystCaseState();
    const afterLogin =
      collectAnalystEvidence(
        initial,
        "event-login",
        availableEvents,
      );
    const afterProcess =
      collectAnalystEvidence(
        afterLogin,
        "event-process",
        availableEvents,
      );
    const duplicate =
      collectAnalystEvidence(
        afterProcess,
        "event-login",
        availableEvents,
      );

    expect(initial.collectedEventIds)
      .toEqual([]);
    expect(afterProcess.collectedEventIds)
      .toEqual([
        "event-login",
        "event-process",
      ]);
    expect(duplicate)
      .toBe(afterProcess);
    expect(
      resolveCollectedEvidence(
        afterProcess,
        availableEvents,
      ).map((event) => event.id),
    ).toEqual([
      "event-login",
      "event-process",
    ]);
  });

  it("rejects evidence that is not in the current scenario history", () => {
    expect(() =>
      collectAnalystEvidence(
        createAnalystCaseState(),
        "missing-event",
        availableEvents,
      ),
    ).toThrow(
      "Analyst evidence references unavailable event: missing-event",
    );
  });

  it("adds an immutable analyst finding linked to collected evidence", () => {
    const collected =
      collectAnalystEvidence(
        collectAnalystEvidence(
          createAnalystCaseState(),
          "event-login",
          availableEvents,
        ),
        "event-process",
        availableEvents,
      );

    const next = addAnalystFinding(
      collected,
      {
        id: "finding-1",
        title: " Compromised account executed PowerShell ",
        summary: " Suspicious login was followed by encoded PowerShell on the assigned endpoint. ",
        evidenceEventIds: [
          "event-login",
          "event-process",
        ],
      },
      availableEvents,
    );

    expect(collected.findings)
      .toEqual([]);
    expect(next.findings)
      .toEqual([
        {
          id: "finding-1",
          title: "Compromised account executed PowerShell",
          summary: "Suspicious login was followed by encoded PowerShell on the assigned endpoint.",
          evidenceEventIds: [
            "event-login",
            "event-process",
          ],
        },
      ]);
  });

  it("rejects invalid finding references and duplicate finding ids", () => {
    const collected =
      collectAnalystEvidence(
        createAnalystCaseState(),
        "event-login",
        availableEvents,
      );

    expect(() =>
      addAnalystFinding(
        collected,
        {
          id: "finding-uncollected",
          title: "Suspicious process",
          summary: "Process evidence was not collected yet.",
          evidenceEventIds: [
            "event-process",
          ],
        },
        availableEvents,
      ),
    ).toThrow(
      "Analyst finding references uncollected evidence event: event-process",
    );

    expect(() =>
      addAnalystFinding(
        collected,
        {
          id: "finding-empty",
          title: " ",
          summary: "Summary",
          evidenceEventIds: [
            "event-login",
          ],
        },
        availableEvents,
      ),
    ).toThrow(
      "Analyst finding title must not be empty.",
    );

    const withFinding =
      addAnalystFinding(
        collected,
        {
          id: "finding-1",
          title: "Suspicious login",
          summary: "Login source requires investigation.",
          evidenceEventIds: [
            "event-login",
          ],
        },
        availableEvents,
      );

    expect(() =>
      addAnalystFinding(
        withFinding,
        {
          id: "finding-1",
          title: "Duplicate",
          summary: "Duplicate id should fail.",
          evidenceEventIds: [
            "event-login",
          ],
        },
        availableEvents,
      ),
    ).toThrow(
      "Analyst finding id already exists: finding-1",
    );
  });
});
