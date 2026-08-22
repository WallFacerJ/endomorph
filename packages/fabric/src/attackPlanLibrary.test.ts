import {
  describe,
  expect,
  it,
} from "vitest";

import {
  createWorldState,
  validateSimulationEvent,
} from "@endomorph/simulation";

import {
  parseScenarioFile,
} from "@endomorph/schema";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

import {
  compileScenario,
} from "./compileScenario.js";

import {
  generateEnterprise,
} from "./generateEnterprise.js";

import {
  generateIncident,
} from "./generateIncident.js";

const enterprise = generateEnterprise();

const world = createWorldState({
  simulationTime:
    enterprise.profile.startTime,
  organizations: enterprise.organizations,
  users: enterprise.users,
  accounts: enterprise.accounts,
  devices: enterprise.devices,
  files: enterprise.files,
  applications: enterprise.applications,
});

describe("attack plan library", () => {
  it("ships more than one plan", () => {
    // The whole point of the refactor: a second run must not replay the
    // first with different names.
    expect(
      ATTACK_PLANS.length,
    ).toBeGreaterThan(2);
  });

  it("gives every plan a unique id", () => {
    const ids = ATTACK_PLANS.map(
      (plan) => plan.id,
    );

    expect(new Set(ids).size).toBe(
      ids.length,
    );
  });

  for (const plan of ATTACK_PLANS) {
    describe(plan.id, () => {
      const incident = generateIncident(
        enterprise,
        { planId: plan.id },
      );

      it("renders against the generated enterprise", () => {
        expect(
          incident.events.length,
        ).toBeGreaterThan(3);

        expect(incident.planId).toBe(
          plan.id,
        );
      });

      it("passes the runtime's own event validation", () => {
        for (const event of incident.events) {
          expect(() =>
            validateSimulationEvent(
              world,
              event,
            ),
          ).not.toThrow();
        }
      });

      it("maps every technique to at least one emitted event", () => {
        expect(
          incident.techniques.length,
        ).toBeGreaterThan(0);

        const emitted = new Set(
          incident.events.map(
            (event) => event.id,
          ),
        );

        for (const technique of incident.techniques) {
          expect(
            technique.eventIds.length,
          ).toBeGreaterThan(0);

          for (const eventId of technique.eventIds) {
            expect(
              emitted.has(eventId),
            ).toBe(true);
          }
        }
      });

      it("anchors every question's evidence to a real event", () => {
        const emitted = new Set(
          incident.events.map(
            (event) => event.id,
          ),
        );

        expect(
          incident.questions.length,
        ).toBeGreaterThan(3);

        for (const question of incident.questions) {
          expect(
            question.accepted.length,
          ).toBeGreaterThan(0);

          for (const answer of question.accepted) {
            expect(
              answer.trim().length,
            ).toBeGreaterThan(0);
          }

          if (
            question.evidenceEventId
          ) {
            expect(
              emitted.has(
                question.evidenceEventId,
              ),
            ).toBe(true);
          }
        }
      });

      it("awards exactly 100 points", () => {
        // A consistent scale across plans keeps scores comparable.
        expect(
          incident.questions.reduce(
            (total, question) =>
              total + question.points,
            0,
          ),
        ).toBe(100);
      });

      it("anchors every ground-truth step to an emitted event", () => {
        const emitted = new Set(
          incident.events.map(
            (event) => event.id,
          ),
        );

        for (const step of incident.timeline) {
          expect(
            emitted.has(step.eventId),
          ).toBe(true);
        }
      });

      it("compiles into a schema-valid scenario", () => {
        const compiled = compileScenario(
          {
            id: `scenario-${plan.id}`,
            name: plan.name,
            description: plan.lesson,
            incident: { planId: plan.id },
          },
        );

        expect(() =>
          parseScenarioFile(
            compiled.file,
          ),
        ).not.toThrow();
      });

      it("is deterministic", () => {
        expect(
          generateIncident(enterprise, {
            planId: plan.id,
          }),
        ).toEqual(incident);
      });
    });
  }

  describe("plans teach different lessons", () => {
    const incidents = ATTACK_PLANS.map(
      (plan) =>
        generateIncident(enterprise, {
          planId: plan.id,
        }),
    );

    it("uses a different technique set per plan", () => {
      const signatures = incidents.map(
        (incident) =>
          incident.techniques
            .map(
              (technique) =>
                technique.id,
            )
            .sort()
            .join(","),
      );

      expect(
        new Set(signatures).size,
      ).toBe(signatures.length);
    });

    it("asks different questions per plan", () => {
      const prompts = incidents.map(
        (incident) =>
          incident.questions
            .map(
              (question) =>
                question.prompt,
            )
            .join("|"),
      );

      expect(
        new Set(prompts).size,
      ).toBe(prompts.length);
    });

    it("does not make every incident originate externally", () => {
      // The credential-compromise plan trains "look for the foreign
      // address". If every plan did that, the heuristic would always work
      // and the library would teach one lesson three times.
      const corporate =
        enterprise.segments.map(
          (segment) =>
            segment.cidr
              .split(".")
              .slice(0, 2)
              .join("."),
        );

      const originatesInternally =
        incidents.filter((incident) =>
          incident.events.some(
            (event) =>
              event.type ===
                "AUTH_LOGIN_SUCCEEDED" &&
              corporate.some((prefix) =>
                (
                  event.payload
                    .sourceIp ?? ""
                ).startsWith(prefix),
              ),
          ),
        );

      expect(
        originatesInternally.length,
      ).toBeGreaterThan(0);
    });

    it("varies difficulty", () => {
      expect(
        new Set(
          incidents.map(
            (incident) =>
              incident.difficulty,
          ),
        ).size,
      ).toBeGreaterThan(1);
    });
  });

  describe("plan requirements are enforced", () => {
    it("rejects an unknown plan id", () => {
      expect(() =>
        generateIncident(enterprise, {
          planId: "does-not-exist",
        }),
      ).toThrow(/Unknown attack plan/);
    });

    it("stages Windows artefacts only on Windows hosts, across many seeds", () => {
      // Found by sweeping seeds, not by the suite: the renderer took the
      // subject's first listed device without checking what it was, so
      // C:\\Windows\\System32\\WindowsPowerShell was staged on macOS and
      // Ubuntu laptops in roughly four seeds out of ten. The ground truth
      // then described something that could not have happened, and a rule
      // keyed on a Windows event id would silently miss the whole incident
      // because event codes are only emitted for Windows hosts.
      //
      // Invisible under the default seed, which happens to be Windows -- so
      // this sweeps rather than sampling one.
      for (
        let seed = 1;
        seed <= 240;
        seed += 17
      ) {
        const enterprise =
          generateEnterprise({ seed });

        for (const plan of ATTACK_PLANS) {
          if (
            !plan.requires
              .windowsWorkstation
          ) {
            continue;
          }

          const incident =
            generateIncident(enterprise, {
              planId: plan.id,
            });

          const deviceIds = new Set(
            incident.events
              .map(
                (event) =>
                  (
                    event.payload as {
                      deviceId?: string;
                    }
                  ).deviceId,
              )
              .filter(
                (id): id is string =>
                  typeof id === "string",
              ),
          );

          for (const deviceId of deviceIds) {
            const device =
              enterprise.devices.find(
                (candidate) =>
                  candidate.id ===
                  deviceId,
              );

            // Servers are legitimately not workstations; the requirement is
            // about where the plan stages its process activity.
            if (
              !device ||
              !device.ownerUserId
            ) {
              continue;
            }

            expect(
              `${plan.id} seed ${seed}: ${device.hostname} ${device.operatingSystem}`,
            ).toMatch(/windows/i);
          }
        }
      }
    });

    it("refuses to render a privileged plan without a privileged account", () => {
      // Silently substituting an ordinary account would produce an incident
      // whose ground truth is false.
      const noAdmins = generateEnterprise({
        seed: 5,
        privilegedAccountRate: 0,
      });

      expect(() =>
        generateIncident(noAdmins, {
          planId: "privileged-insider",
        }),
      ).toThrow();
    });
  });
});
