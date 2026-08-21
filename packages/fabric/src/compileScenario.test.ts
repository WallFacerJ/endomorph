import {
  describe,
  expect,
  it,
} from "vitest";

import {
  parseScenarioFile,
} from "@endomorph/schema";

import {
  compileScenario,
} from "./compileScenario.js";

const compiled = compileScenario({
  id: "scenario-generated-001",
  name: "Generated account compromise",
  description:
    "A compromised Finance account inside a generated enterprise.",
});

describe("compileScenario", () => {
  describe("contract compliance", () => {
    it("emits a file the scenario schema accepts", () => {
      // If this passes, the generated world is playable by the existing
      // runtime today rather than after a parallel pipeline is built.
      expect(() =>
        parseScenarioFile(compiled.file),
      ).not.toThrow();
    });

    it("keeps opening events chronologically ordered", () => {
      const parsed = parseScenarioFile(
        compiled.file,
      );

      const events =
        parsed.scenario.openingEvents;

      for (
        let index = 1;
        index < events.length;
        index += 1
      ) {
        expect(
          events[index].timestamp >=
            events[index - 1].timestamp,
        ).toBe(true);
      }
    });

    it("points investigation metadata at real entities", () => {
      const parsed = parseScenarioFile(
        compiled.file,
      );

      const {
        investigation,
        initialWorld,
      } = parsed.scenario;

      expect(
        initialWorld.users.some(
          (user) =>
            user.id ===
            investigation.userId,
        ),
      ).toBe(true);

      expect(
        initialWorld.accounts.some(
          (account) =>
            account.id ===
            investigation.accountId,
        ),
      ).toBe(true);

      expect(
        initialWorld.devices.some(
          (device) =>
            device.id ===
            investigation.deviceId,
        ),
      ).toBe(true);
    });

    it("references only declared actions", () => {
      const parsed = parseScenarioFile(
        compiled.file,
      );

      const actionIds = new Set(
        parsed.scenario.actions.map(
          (action) => action.id,
        ),
      );

      expect(
        actionIds.has(
          parsed.scenario.investigation
            .primaryActionId,
        ),
      ).toBe(true);

      for (const actionId of parsed
        .scenario.investigation
        .responseActionIds ?? []) {
        expect(
          actionIds.has(actionId),
        ).toBe(true);
      }
    });

    it("never dates a response action before the last opening event", () => {
      // Regression. The event store appends response events onto the same
      // ordered history as the opening events and rejects anything older
      // than the newest entry. The first generated scenario stamped
      // responses at the alert time while background noise continued for
      // another four hours past it, so every response was rejected and the
      // scenario failed to load with "Events must be appended in
      // chronological order."
      const parsed = parseScenarioFile(
        compiled.file,
      );

      const events =
        parsed.scenario.openingEvents;

      const lastOpening = Date.parse(
        events[events.length - 1]
          .timestamp,
      );

      for (const action of parsed.scenario
        .actions) {
        for (const event of action.events) {
          expect(
            Date.parse(event.timestamp),
          ).toBeGreaterThanOrEqual(
            lastOpening,
          );
        }
      }
    });

    it("stops the opening history at detection", () => {
      // Detection is "now". Nothing the analyst sees may postdate the alert.
      const parsed = parseScenarioFile(
        compiled.file,
      );

      const alert =
        parsed.scenario.openingEvents.find(
          (event) =>
            event.id ===
            compiled.incident.alertId,
        );

      expect(alert).toBeDefined();

      const alertAt = Date.parse(
        alert?.timestamp ?? "",
      );

      for (const event of parsed.scenario
        .openingEvents) {
        expect(
          Date.parse(event.timestamp),
        ).toBeLessThanOrEqual(alertAt);
      }
    });

    it("anchors every ground-truth step to a real opening event", () => {
      const parsed = parseScenarioFile(
        compiled.file,
      );

      const eventIds = new Set(
        parsed.scenario.openingEvents.map(
          (event) => event.id,
        ),
      );

      for (const step of parsed.scenario
        .groundTruth?.timeline ?? []) {
        expect(
          eventIds.has(step.eventId),
        ).toBe(true);
      }
    });
  });

  describe("determinism", () => {
    it("compiles identically from the same seed", () => {
      const first = compileScenario({
        id: "s",
        name: "n",
        description: "d",
        enterprise: { seed: 31337 },
      });

      const second = compileScenario({
        id: "s",
        name: "n",
        description: "d",
        enterprise: { seed: 31337 },
      });

      expect(
        JSON.stringify(first.file),
      ).toBe(
        JSON.stringify(second.file),
      );
    });

    it("compiles differently from a different seed", () => {
      expect(
        JSON.stringify(
          compileScenario({
            id: "s",
            name: "n",
            description: "d",
            enterprise: { seed: 1 },
          }).file,
        ),
      ).not.toBe(
        JSON.stringify(
          compileScenario({
            id: "s",
            name: "n",
            description: "d",
            enterprise: { seed: 2 },
          }).file,
        ),
      );
    });
  });

  describe("investigative difficulty", () => {
    it("buries the incident inside the noise floor", () => {
      // The incident must be a small fraction of the stream. If the attack
      // were most of what the analyst sees, the scenario would be the
      // curated list Phase 1 exists to eliminate.
      const incidentShare =
        compiled.incident.events.length /
        compiled.totalEventCount;

      expect(
        incidentShare,
      ).toBeLessThan(0.01);
    });

    it("interleaves incident events with background events", () => {
      const parsed = parseScenarioFile(
        compiled.file,
      );

      const incidentIds = new Set(
        compiled.incident.events.map(
          (event) => event.id,
        ),
      );

      const positions =
        parsed.scenario.openingEvents
          .map((event, index) =>
            incidentIds.has(event.id)
              ? index
              : -1,
          )
          .filter(
            (index) => index >= 0,
          );

      expect(
        positions.length,
      ).toBe(incidentIds.size);

      // Between the first and last incident event there must be a
      // substantial run of unrelated activity to sift through.
      const span =
        positions[positions.length - 1] -
        positions[0];

      expect(span).toBeGreaterThan(
        positions.length * 5,
      );
    });

    it("gives the analyst a large evidence surface", () => {
      expect(
        compiled.totalEventCount,
      ).toBeGreaterThan(3000);

      const parsed = parseScenarioFile(
        compiled.file,
      );

      const entityCount =
        parsed.scenario.initialWorld.users
          .length +
        parsed.scenario.initialWorld
          .accounts.length +
        parsed.scenario.initialWorld
          .devices.length +
        parsed.scenario.initialWorld.files
          .length +
        parsed.scenario.initialWorld
          .applications.length;

      expect(
        entityCount,
      ).toBeGreaterThan(400);
    });

    it("offers a plausible half-measure that carries a penalty", () => {
      const parsed = parseScenarioFile(
        compiled.file,
      );

      const penalised =
        parsed.scenario.actions.filter(
          (action) =>
            action.assessment !==
            undefined,
        );

      expect(
        penalised.length,
      ).toBeGreaterThan(0);

      for (const action of penalised) {
        expect(
          action.assessment?.rationale
            .length,
        ).toBeGreaterThan(20);
      }
    });
  });

  describe("incident coherence", () => {
    it("casts the incident from real generated entities", () => {
      const {
        enterprise,
        incident,
      } = compiled;

      expect(
        enterprise.users.some(
          (user) =>
            user.id ===
            incident.victimUserId,
        ),
      ).toBe(true);

      expect(
        enterprise.devices.some(
          (device) =>
            device.id ===
            incident.lateralTargetDeviceId,
        ),
      ).toBe(true);

      expect(
        enterprise.files.some(
          (file) =>
            file.id ===
            incident.targetFileId,
        ),
      ).toBe(true);
    });

    it("originates the attack outside every corporate subnet", () => {
      const corporatePrefixes =
        compiled.enterprise.segments.map(
          (segment) =>
            segment.cidr.split("/")[0],
        );

      expect(
        corporatePrefixes.some(
          (prefix) =>
            compiled.incident.attackerIp.startsWith(
              prefix
                .split(".")
                .slice(0, 2)
                .join("."),
            ),
        ),
      ).toBe(false);
    });

    it("targets a restricted document", () => {
      const file =
        compiled.enterprise.files.find(
          (candidate) =>
            candidate.id ===
            compiled.incident
              .targetFileId,
        );

      expect(
        file?.classification,
      ).toBe("restricted");
    });
  });
});
