import {
  describe,
  expect,
  it,
} from "vitest";

import {
  generateEnterprise,
  generateBackgroundActivity,
  generateIncident,
  buildCorpus,
  evaluateRuleset,
  ENCODED_POWERSHELL_RULE,
  OFFICE_SPAWNS_SCRIPT_RULE,
} from "./index.js";

import type {
  EvasionLevel,
} from "./attackPlan.js";

const enterprise = generateEnterprise({
  seed: 20260820,
});

function macroCorpus(
  evasion: EvasionLevel,
) {
  const background =
    generateBackgroundActivity(
      enterprise,
      { days: 3 },
    );

  const incident = generateIncident(
    enterprise,
    { planId: "macro-execution", evasion },
  );

  const detection =
    incident.events[
      incident.events.length - 1
    ].timestamp;

  const events = [
    ...background.filter(
      (event) =>
        event.timestamp <= detection,
    ),
    ...incident.events,
  ].sort((left, right) =>
    left.timestamp.localeCompare(
      right.timestamp,
    ),
  );

  return buildCorpus(
    enterprise,
    events,
    incident,
  ).records;
}

describe("seeded attack variation (evasion)", () => {
  it("renders the same technique with different tradecraft", () => {
    const commandFor = (
      evasion: EvasionLevel,
    ) => {
      const incident = generateIncident(
        enterprise,
        {
          planId: "macro-execution",
          evasion,
        },
      );

      const spawn =
        incident.events.find(
          (event) =>
            event.id ===
            "incident-macro-spawn",
        );

      if (!spawn) {
        throw new Error(
          "macro-spawn event not found",
        );
      }

      return (
        spawn.payload as {
          commandLine?: string;
        }
      ).commandLine;
    };

    expect(
      commandFor("standard"),
    ).toContain("-enc");
    expect(
      commandFor("stealth"),
    ).not.toContain("-enc");
  });

  it("evades a command-line rule at stealth but not a behavioural one", () => {
    const score = (
      evasion: EvasionLevel,
      rule: typeof ENCODED_POWERSHELL_RULE,
    ) =>
      evaluateRuleset(
        [rule],
        macroCorpus(evasion),
      ).evaluations[0].recall;

    // The command-line rule catches the loud variant and misses the stealth
    // one; the lineage rule (a word processor spawned a scripting host) holds
    // across both, because the attacker cannot evade it without abandoning the
    // technique.
    expect(
      score(
        "standard",
        ENCODED_POWERSHELL_RULE,
      ),
    ).toBe(1);
    expect(
      score(
        "stealth",
        ENCODED_POWERSHELL_RULE,
      ),
    ).toBe(0);

    expect(
      score(
        "standard",
        OFFICE_SPAWNS_SCRIPT_RULE,
      ),
    ).toBe(1);
    expect(
      score(
        "stealth",
        OFFICE_SPAWNS_SCRIPT_RULE,
      ),
    ).toBe(1);
  });
});
