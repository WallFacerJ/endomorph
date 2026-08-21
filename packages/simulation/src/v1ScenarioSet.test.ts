import {
  readFileSync,
} from "node:fs";

import {
  describe,
  expect,
  it,
} from "vitest";

import {
  parseScenarioJson,
} from "../../schema/src/scenario";

import {
  compileScenarioDefinition,
} from "./scenarioCompiler";

import {
  finalizeScenarioState,
  validateScenarioDefinition,
} from "./scenario";

const scenarioFiles = [
  "account-compromise.json",
  "hr-malware-beacon.json",
  "cloud-admin-compromise.json",
] as const;

function loadScenario(
  filename: string,
) {
  const url = new URL(
    `../../../apps/web/public/scenarios/${filename}`,
    import.meta.url,
  );
  const file = parseScenarioJson(
    readFileSync(url, "utf8"),
  );

  return compileScenarioDefinition(
    file.scenario,
  );
}

const cleanResponse = [
  "revoke_compromised_session",
  "disable_compromised_account",
] as const;

const penalizedResponse = [
  "restore_compromised_account_access",
  ...cleanResponse,
] as const;

describe("v1 scenario set", () => {
  it("ships three distinct structurally and semantically valid scenarios", () => {
    const scenarios =
      scenarioFiles.map(loadScenario);

    expect(
      new Set(
        scenarios.map(
          (scenario) => scenario.id,
        ),
      ).size,
    ).toBe(3);

    for (const scenario of scenarios) {
      expect(scenario.groundTruth)
        .toBeDefined();
      expect(
        scenario.groundTruth?.timeline.length,
      ).toBeGreaterThan(0);

      const openingIds = new Set(
        scenario.openingEvents.map(
          (event) => event.id,
        ),
      );

      for (const entry of
        scenario.groundTruth?.timeline ?? []) {
        expect(openingIds.has(entry.eventId))
          .toBe(true);
      }
    }
  });

  it("allows clean containment to succeed at full score in every v1 scenario", () => {
    for (const filename of scenarioFiles) {
      const final =
        finalizeScenarioState(
          loadScenario(filename),
          cleanResponse,
        );

      expect(final.outcome.status)
        .toBe("succeeded");
      expect(final.score)
        .toMatchObject({
          objectivePercentage: 100,
          responsePenalty: 0,
          percentage: 100,
        });
    }
  });

  it("applies the authored harmful-response penalty consistently across the v1 scenarios", () => {
    for (const filename of scenarioFiles) {
      const final =
        finalizeScenarioState(
          loadScenario(filename),
          penalizedResponse,
        );

      expect(final.outcome.status)
        .toBe("succeeded");
      expect(final.score)
        .toMatchObject({
          objectivePercentage: 100,
          responsePenalty: 25,
          percentage: 75,
        });
    }
  });

  it("rejects ground truth that references an event outside the opening history", () => {
    const scenario =
      loadScenario(
        "account-compromise.json",
      );

    const invalid = {
      ...scenario,
      groundTruth: {
        summary:
          "Invalid ground truth for validation coverage.",
        timeline: [
          {
            eventId: "missing-event",
            significance:
              "This event does not exist.",
          },
        ],
      },
    };

    expect(() =>
      validateScenarioDefinition(invalid),
    ).toThrow(
      "ground truth references missing opening event",
    );
  });
});
