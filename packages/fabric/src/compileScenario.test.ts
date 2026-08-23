import {
  describe,
  expect,
  it,
} from "vitest";

import {
  parseScenarioFile,
} from "@endomorph/schema";

import {
  compileScenarioDefinition,
} from "@endomorph/simulation";

import {
  compileScenario,
} from "./compileScenario.js";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

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

describe("every shipped plan compiles to a loadable scenario", () => {
  // The schema check above proves the file's *shape*. It does not prove its
  // references resolve, and the two failed apart: a plan whose intrusion
  // never authenticates produced an investigation pointing at a session id
  // nothing had emitted. The schema accepted it, the whole suite passed, and
  // the app refused to open it -- "scenario validation failed", nothing
  // playable, found only by loading the page in a browser.
  //
  // compileScenarioDefinition is the same function the loader runs, so this
  // fails at build time for the same reasons the app would.
  for (const plan of ATTACK_PLANS) {
    it(`loads ${plan.id}`, () => {
      const scenario = compileScenario({
        id: `scenario-loadable-${plan.id}`,
        name: `Loadable ${plan.id}`,
        description:
          "Compiled to prove the runtime accepts it.",
        incident: { planId: plan.id },
      });

      const parsed = parseScenarioFile(
        scenario.file,
      );

      expect(() =>
        compileScenarioDefinition(
          parsed.scenario,
        ),
      ).not.toThrow();
    });

    it(`explains ${plan.id}'s half-measure in terms of that incident`, () => {
      /*
        The penalty rationale was one fixed sentence for every scenario:
        "The established session survives a password reset, and the host
        continues beaconing." Neither half is true everywhere -- three plans
        have no beacon at all, and the macro intrusion never opens a session,
        which is its entire premise.

        So four scenarios out of five justified a scored penalty with
        something that did not happen. That is the same failing as ground
        truth that lies, aimed at the analyst's feedback instead of the data.
      */
      const scenario = compileScenario({
        id: `scenario-rationale-${plan.id}`,
        name: `Rationale ${plan.id}`,
        description:
          "Compiled to check the penalty rationale.",
        incident: { planId: plan.id },
      });

      const parsed = parseScenarioFile(
        scenario.file,
      ).scenario;

      const halfMeasure =
        parsed.actions.find(
          (action) =>
            action.id ===
            "action-reset-password-only",
        );

      const rationale =
        halfMeasure?.assessment
          ?.rationale ?? "";

      expect(rationale).not.toBe("");

      // It may only mention a session where the incident opens one.
      expect(
        `${plan.id} mentions session: ${/session/i.test(rationale)}`,
      ).toBe(
        `${plan.id} mentions session: ${plan.containment.revokeSession}`,
      );

      // And a host where isolation is the response.
      expect(
        `${plan.id} mentions network: ${/on the network/i.test(rationale)}`,
      ).toBe(
        `${plan.id} mentions network: ${plan.containment.isolateDevice}`,
      );

      // Nothing about beaconing, which most of these incidents never do.
      expect(rationale).not.toMatch(
        /beacon/i,
      );
    });

    it(`describes ${plan.id}'s isolation by what it actually stops`, () => {
      /*
        The isolate action told every analyst it "stops the beacon and any
        further lateral movement". Privileged-insider does neither -- it is
        an administrator reading a file share from their own desk -- and each
        of the others does one or the other, not both. Overstating what a
        response achieves teaches the wrong thing about containment.
      */
      const scenario = compileScenario({
        id: `scenario-isolate-${plan.id}`,
        name: `Isolate ${plan.id}`,
        description:
          "Compiled to check the response descriptions.",
        incident: { planId: plan.id },
      });

      const parsed = parseScenarioFile(
        scenario.file,
      ).scenario;

      const isolate =
        parsed.actions.find(
          (action) =>
            action.id ===
            "action-isolate-device",
        );

      if (!isolate) {
        expect(
          plan.containment.isolateDevice,
        ).toBe(false);

        return;
      }

      const connections =
        parsed.openingEvents.filter(
          (event) =>
            event.type ===
              "NETWORK_CONNECTION" &&
            event.id.startsWith(
              "incident-",
            ),
        );

      const beacons = connections.some(
        (event) =>
          !(
            event.payload as {
              destinationIp?: string;
            }
          ).destinationIp?.startsWith(
            "10.",
          ),
      );

      const lateral = connections.some(
        (event) =>
          (
            event.payload as {
              destinationPort?: number;
            }
          ).destinationPort === 445,
      );

      expect(
        `${plan.id} claims beacon: ${/the beacon/i.test(isolate.description)}`,
      ).toBe(
        `${plan.id} claims beacon: ${beacons}`,
      );

      expect(
        `${plan.id} claims movement: ${/between hosts/i.test(isolate.description)}`,
      ).toBe(
        `${plan.id} claims movement: ${lateral}`,
      );
    });

    it(`offers ${plan.id} only the responses it declares`, () => {
      // `containment` was declared on every plan and read by nothing: the
      // compiler emitted all four actions for every incident. Dormant
      // account revival was offered device isolation it explicitly says it
      // does not support, and an intrusion with no attacker session was
      // offered "revoke the attacker's session".
      //
      // The routing test cannot catch this. It only fails when an action has
      // nothing to point at, and once the investigation falls back to the
      // subject's own session a wrongly-offered revoke routes perfectly
      // well -- it is simply describing something that did not happen.
      const scenario = compileScenario({
        id: `scenario-containment-${plan.id}`,
        name: `Containment ${plan.id}`,
        description:
          "Compiled to check the offered responses.",
        incident: { planId: plan.id },
      });

      const offered = new Set(
        parseScenarioFile(
          scenario.file,
        ).scenario.actions.map(
          (action) => action.id,
        ),
      );

      expect(
        offered.has(
          "action-isolate-device",
        ),
      ).toBe(
        plan.containment.isolateDevice,
      );

      expect(
        offered.has(
          "action-disable-account",
        ),
      ).toBe(
        plan.containment.disableAccount,
      );

      expect(
        offered.has(
          "action-revoke-session",
        ),
      ).toBe(
        plan.containment.revokeSession,
      );

      // The half-measure is always offered: its purpose is to be a plausible
      // wrong answer, and removing it where it is wrong removes the decision
      // being tested.
      expect(
        offered.has(
          "action-reset-password-only",
        ),
      ).toBe(true);
    });

    it(`gives ${plan.id} an investigation that points at real entities`, () => {
      // Every id the investigation names must appear in the world or the
      // events, not merely be a well-formed string. The account one bit
      // first: it used to be whichever account was most privileged rather
      // than the one the plan acts through, so it could name an account the
      // incident never touches -- and the primary response action disables
      // exactly that account.
      const scenario = compileScenario({
        id: `scenario-refs-${plan.id}`,
        name: `Refs ${plan.id}`,
        description:
          "Compiled to check investigation references.",
        incident: { planId: plan.id },
      });

      const parsed = parseScenarioFile(
        scenario.file,
      ).scenario;

      const investigation =
        parsed.investigation;

      const accountsInEvents = new Set(
        parsed.openingEvents.flatMap(
          (event) => {
            const payload =
              event.payload as {
                accountId?: string;
              };

            return [
              payload.accountId,
              event.actorId,
            ].filter(
              (id): id is string =>
                typeof id === "string",
            );
          },
        ),
      );

      expect(
        accountsInEvents.has(
          investigation.accountId,
        ),
      ).toBe(true);

      const sessionsInEvents = new Set(
        parsed.openingEvents
          .filter(
            (event) =>
              event.type ===
              "SESSION_STARTED",
          )
          .map(
            (event) =>
              (
                event.payload as {
                  sessionId: string;
                }
              ).sessionId,
          ),
      );

      expect(
        sessionsInEvents.has(
          investigation.sessionId,
        ),
      ).toBe(true);

      // And the primary action must be one the plan actually offers.
      expect(
        parsed.actions.map(
          (action) => action.id,
        ),
      ).toContain(
        investigation.primaryActionId,
      );
    });
  }
});
