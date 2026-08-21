import {
  describe,
  expect,
  it,
} from "vitest";

import {
  buildEvidenceGraph,
  buildIncidentReport,
  createIncidentCaseState,
  extractIncidentIndicators,
  INCIDENT_PHASES,
} from "./incidentCase";

import {
  siemProjection,
} from "./siemProjection";

import {
  rebuildProjection,
} from "./projection";

import {
  createWorldState,
} from "./worldState";

import type {
  SimulationEvent,
} from "./simulationEvent";

const world = createWorldState({
  simulationTime:
    "2026-08-20T08:00:00.000Z",
  organizations: [
    {
      id: "org-acme",
      name: "Acme",
      status: "active",
      departments: ["Finance"],
    },
  ],
  users: [
    {
      id: "user-sarah",
      organizationId: "org-acme",
      displayName: "Sarah Martinez",
      email: "sarah@acme.test",
      department: "Finance",
      status: "active",
      accountIds: ["account-sarah"],
      deviceIds: ["device-fin-01"],
    },
  ],
  accounts: [
    {
      id: "account-sarah",
      organizationId: "org-acme",
      userId: "user-sarah",
      username: "sarah@acme.test",
      provider: "corporate-directory",
      status: "active",
      roles: ["domain-users"],
    },
  ],
  devices: [
    {
      id: "device-fin-01",
      organizationId: "org-acme",
      hostname: "FIN-LT-01",
      operatingSystem: "Windows 11",
      status: "active",
      ownerUserId: "user-sarah",
      ipAddresses: ["10.20.5.10"],
    },
  ],
  applications: [
    {
      id: "app-identity",
      organizationId: "org-acme",
      name: "Acme Identity",
      kind: "identity",
      status: "active",
    },
  ],
  files: [
    {
      id: "file-payroll",
      organizationId: "org-acme",
      name: "payroll.csv",
      path: "\\\\FS\\payroll.csv",
      classification: "restricted",
      ownerUserId: "user-sarah",
    },
  ],
});

const events: SimulationEvent[] = [
  {
    id: "event-login",
    type: "AUTH_LOGIN_SUCCEEDED",
    timestamp:
      "2026-08-20T09:00:00.000Z",
    source: "identity",
    actorId: "account-sarah",
    subjectId: "user-sarah",
    payload: {
      accountId: "account-sarah",
      userId: "user-sarah",
      deviceId: "device-fin-01",
      applicationId: "app-identity",
      sourceIp: "203.0.113.77",
    },
  },
  {
    id: "event-powershell",
    type: "PROCESS_STARTED",
    timestamp:
      "2026-08-20T09:05:00.000Z",
    source: "edr",
    subjectId: "device-fin-01",
    payload: {
      deviceId: "device-fin-01",
      processId: "9001",
      image:
        "C:\\Windows\\System32\\powershell.exe",
      commandLine:
        "powershell.exe -enc ZQBjAGgAbwA=",
      accountId: "account-sarah",
    },
  },
  {
    id: "event-file",
    type: "FILE_ACCESSED",
    timestamp:
      "2026-08-20T09:09:00.000Z",
    source: "file_server",
    actorId: "account-sarah",
    subjectId: "file-payroll",
    payload: {
      fileId: "file-payroll",
      operation: "read",
      deviceId: "device-fin-01",
      accountId: "account-sarah",
    },
  },
  {
    id: "event-internal-net",
    type: "NETWORK_CONNECTION",
    timestamp:
      "2026-08-20T09:07:00.000Z",
    source: "network",
    subjectId: "device-fin-01",
    payload: {
      deviceId: "device-fin-01",
      protocol: "tcp",
      sourceIp: "10.20.5.10",
      destinationIp: "10.90.1.4",
      sourcePort: 51000,
      destinationPort: 445,
    },
  },
  {
    id: "event-unrelated",
    type: "ENDPOINT_HEARTBEAT",
    timestamp:
      "2026-08-20T09:10:00.000Z",
    source: "edr",
    subjectId: "device-fin-01",
    payload: {
      deviceId: "device-fin-01",
      status: "active",
      ipAddresses: ["10.20.5.10"],
    },
  },
];

const records = rebuildProjection(
  siemProjection,
  events,
).events;

const collected = [
  "event-login",
  "event-powershell",
  "event-file",
];

describe("incident case", () => {
  describe("workflow state", () => {
    it("starts in triage with nothing recorded", () => {
      const state =
        createIncidentCaseState();

      expect(state.phase).toBe("triage");
      expect(state.hypotheses).toEqual(
        [],
      );
      expect(state.tasks).toEqual([]);
      expect(state.decisions).toEqual(
        [],
      );
    });

    it("orders the incident lifecycle", () => {
      expect(INCIDENT_PHASES).toEqual([
        "triage",
        "investigation",
        "containment",
        "eradication",
        "recovery",
        "lessons_learned",
      ]);
    });
  });

  describe("evidence graph", () => {
    const graph = buildEvidenceGraph(
      world,
      records,
      collected,
    );

    it("derives entities from collected evidence without being told", () => {
      // This is the whole argument for the redesign: the analyst collected
      // three events and the case worked out who and what is involved.
      const ids = graph.nodes.map(
        (node) => node.id,
      );

      expect(ids).toContain(
        "user-sarah",
      );
      expect(ids).toContain(
        "account-sarah",
      );
      expect(ids).toContain(
        "device-fin-01",
      );
      expect(ids).toContain(
        "app-identity",
      );
      expect(ids).toContain(
        "file-payroll",
      );
      expect(ids).toContain(
        "203.0.113.77",
      );
    });

    it("ignores evidence the analyst did not collect", () => {
      // The heartbeat was never collected, so nothing it implies belongs in
      // the case. A case that absorbs the whole world explains nothing.
      const withHeartbeatOnly =
        buildEvidenceGraph(
          world,
          records,
          ["event-unrelated"],
        );

      expect(
        withHeartbeatOnly.nodes.map(
          (node) => node.id,
        ),
      ).not.toContain("account-sarah");
    });

    it("resolves human-readable labels from the world", () => {
      const user = graph.nodes.find(
        (node) =>
          node.id === "user-sarah",
      );

      expect(user?.label).toBe(
        "Sarah Martinez",
      );

      const device = graph.nodes.find(
        (node) =>
          node.id === "device-fin-01",
      );

      expect(device?.label).toBe(
        "FIN-LT-01",
      );

      const file = graph.nodes.find(
        (node) =>
          node.id === "file-payroll",
      );

      expect(file?.label).toBe(
        "payroll.csv",
      );
    });

    it("marks addresses outside the enterprise as external", () => {
      const address = graph.nodes.find(
        (node) =>
          node.id === "203.0.113.77",
      );

      expect(address?.kind).toBe(
        "address",
      );

      expect(address?.external).toBe(
        true,
      );
    });

    it("does not mark a corporate address external", () => {
      const withInternalTraffic =
        buildEvidenceGraph(
          world,
          records,
          [
            ...collected,
            "event-internal-net",
          ],
        );

      const corporate =
        withInternalTraffic.nodes.find(
          (node) =>
            node.id === "10.20.5.10",
        );

      expect(corporate).toBeDefined();

      expect(corporate?.external).toBe(
        false,
      );

      // And the same graph still flags the attacker address, so the
      // distinction is doing real work rather than defaulting one way.
      expect(
        withInternalTraffic.nodes.find(
          (node) =>
            node.id === "203.0.113.77",
        )?.external,
      ).toBe(true);
    });

    it("connects entities that appear in the same event", () => {
      const edge = graph.edges.find(
        (candidate) =>
          [
            candidate.from,
            candidate.to,
          ].includes("account-sarah") &&
          [
            candidate.from,
            candidate.to,
          ].includes("203.0.113.77"),
      );

      expect(edge).toBeDefined();

      expect(edge?.eventIds).toContain(
        "event-login",
      );
    });

    it("attributes every edge to the events that justify it", () => {
      // Bidirectional pivot: any relationship in the case can be traced
      // back to the exact evidence that established it.
      const known = new Set(collected);

      for (const edge of graph.edges) {
        expect(
          edge.eventIds.length,
        ).toBeGreaterThan(0);

        for (const eventId of edge.eventIds) {
          expect(
            known.has(eventId),
          ).toBe(true);
        }
      }
    });

    it("ranks the most-referenced entities first", () => {
      const counts = graph.nodes.map(
        (node) => node.eventIds.length,
      );

      expect(counts).toEqual(
        [...counts].sort(
          (left, right) =>
            right - left,
        ),
      );
    });

    it("returns an empty graph for an empty case", () => {
      expect(
        buildEvidenceGraph(
          world,
          records,
          [],
        ),
      ).toEqual({
        nodes: [],
        edges: [],
      });
    });
  });

  describe("indicators", () => {
    const indicators =
      extractIncidentIndicators(
        world,
        records,
        collected,
      );

    it("extracts the external address", () => {
      const address = indicators.find(
        (indicator) =>
          indicator.value ===
          "203.0.113.77",
      );

      expect(address?.kind).toBe(
        "address",
      );

      expect(address?.external).toBe(
        true,
      );
    });

    it("extracts the command line and process image", () => {
      expect(
        indicators.some(
          (indicator) =>
            indicator.kind ===
              "command_line" &&
            indicator.value.includes(
              "-enc",
            ),
        ),
      ).toBe(true);

      expect(
        indicators.some(
          (indicator) =>
            indicator.kind ===
            "process_image",
        ),
      ).toBe(true);
    });

    it("lists external indicators first", () => {
      const externals = indicators.map(
        (indicator) =>
          indicator.external,
      );

      expect(externals).toEqual(
        [...externals].sort(
          (left, right) =>
            Number(right) - Number(left),
        ),
      );
    });

    it("records a first and last sighting", () => {
      for (const indicator of indicators) {
        expect(
          indicator.firstSeen <=
            indicator.lastSeen,
        ).toBe(true);

        expect(
          indicator.eventIds.length,
        ).toBeGreaterThan(0);
      }
    });
  });

  describe("report", () => {
    const caseState = {
      ...createIncidentCaseState(),
      phase: "containment" as const,
      hypotheses: [
        {
          id: "hyp-1",
          statement:
            "The account was compromised from an external address.",
          status: "supported" as const,
          evidenceEventIds: [
            "event-login",
          ],
        },
        {
          id: "hyp-2",
          statement:
            "The user travelled and signed in legitimately.",
          status: "refuted" as const,
          evidenceEventIds: [
            "event-powershell",
          ],
        },
      ],
      tasks: [
        {
          id: "task-1",
          title: "Isolate FIN-LT-01",
          owner: "Tier 2",
          status: "open" as const,
          phase: "containment" as const,
        },
        {
          id: "task-2",
          title: "Confirm scope",
          owner: "Tier 3",
          status: "done" as const,
          phase:
            "investigation" as const,
        },
      ],
      decisions: [
        {
          id: "dec-1",
          summary:
            "Contain before eradicating.",
          rationale:
            "Beacon is still active.",
          phase: "containment" as const,
        },
      ],
    };

    const report = buildIncidentReport(
      world,
      records,
      collected,
      caseState,
    );

    it("reports counts derived from the case, not authored again", () => {
      expect(report.evidenceCount).toBe(
        collected.length,
      );

      expect(
        report.entityCount,
      ).toBeGreaterThan(0);

      expect(report.phase).toBe(
        "containment",
      );
    });

    it("orders the timeline chronologically", () => {
      const times =
        report.timeline.map(
          (record) => record.timestamp,
        );

      expect(times).toEqual(
        [...times].sort(),
      );
    });

    it("includes only collected evidence in the timeline", () => {
      expect(
        report.timeline.map(
          (record) => record.eventId,
        ),
      ).toEqual(
        [...collected].sort((a, b) => {
          const at =
            records.find(
              (r) => r.eventId === a,
            )?.timestamp ?? "";
          const bt =
            records.find(
              (r) => r.eventId === b,
            )?.timestamp ?? "";

          return at.localeCompare(bt);
        }),
      );
    });

    it("surfaces only unfinished tasks", () => {
      expect(
        report.openTasks.map(
          (task) => task.id,
        ),
      ).toEqual(["task-1"]);
    });

    it("surfaces only supported hypotheses", () => {
      expect(
        report.supportedHypotheses.map(
          (hypothesis) => hypothesis.id,
        ),
      ).toEqual(["hyp-1"]);
    });

    it("surfaces only external indicators", () => {
      for (const indicator of report.externalIndicators) {
        expect(indicator.external).toBe(
          true,
        );
      }

      expect(
        report.externalIndicators.some(
          (indicator) =>
            indicator.value ===
            "203.0.113.77",
        ),
      ).toBe(true);
    });

    it("carries the analyst's decisions through", () => {
      expect(report.decisions).toEqual(
        caseState.decisions,
      );
    });
  });
});
