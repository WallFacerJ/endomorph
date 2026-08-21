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
  getScenarioState,
} from "./scenario";

const scenarioUrl = new URL(
  "../../../apps/web/public/scenarios/account-compromise.json",
  import.meta.url,
);

function loadScenario() {
  const file = parseScenarioJson(
    readFileSync(
      scenarioUrl,
      "utf8",
    ),
  );

  return compileScenarioDefinition(
    file.scenario,
  );
}

describe("response-quality assessment", () => {
  it("does not expose hidden response penalties during an active run", () => {
    const scenario = loadScenario();
    const active = getScenarioState(
      scenario,
      [
        "restore_compromised_account_access",
        "revoke_compromised_session",
        "disable_compromised_account",
      ],
    );

    expect(active.finalized).toBe(false);
    expect(active.outcome.status)
      .toBe("succeeded");
    expect(active.score)
      .toMatchObject({
        objectivePercentage: 100,
        responsePenalty: 0,
        percentage: 100,
      });
  });

  it("keeps a clean response at full score", () => {
    const final = finalizeScenarioState(
      loadScenario(),
      [
        "revoke_compromised_session",
        "disable_compromised_account",
      ],
    );

    expect(final.outcome.status)
      .toBe("succeeded");
    expect(final.score)
      .toMatchObject({
        objectivePercentage: 100,
        responsePenalty: 0,
        percentage: 100,
      });
  });

  it("penalizes a harmful action even when later remediation restores the objectives", () => {
    const final = finalizeScenarioState(
      loadScenario(),
      [
        "restore_compromised_account_access",
        "revoke_compromised_session",
        "disable_compromised_account",
      ],
    );

    expect(final.outcome.status)
      .toBe("succeeded");
    expect(final.score)
      .toMatchObject({
        objectivePercentage: 100,
        responsePenalty: 25,
        percentage: 75,
      });
  });

  it("reflects both an undone objective and the harmful-action penalty", () => {
    const final = finalizeScenarioState(
      loadScenario(),
      [
        "revoke_compromised_session",
        "disable_compromised_account",
        "restore_compromised_account_access",
      ],
    );

    expect(final.world.accounts[
      "account-smartinez"
    ]?.status).toBe("active");
    expect(final.outcome.status)
      .toBe("failed");
    expect(final.score)
      .toMatchObject({
        objectivePercentage: 50,
        responsePenalty: 25,
        percentage: 25,
      });
  });

  it("repeats the same final assessment for the same response history", () => {
    const scenario = loadScenario();
    const actions = [
      "restore_compromised_account_access",
      "revoke_compromised_session",
      "disable_compromised_account",
    ];

    expect(
      finalizeScenarioState(
        scenario,
        actions,
      ),
    ).toEqual(
      finalizeScenarioState(
        scenario,
        actions,
      ),
    );
  });

  it("reset-style reconstruction clears the quality penalty", () => {
    const active = getScenarioState(
      loadScenario(),
    );

    expect(active.score)
      .toMatchObject({
        objectivePercentage: 0,
        responsePenalty: 0,
        percentage: 0,
      });
  });
});
