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
  getScenarioState,
} from "./scenario";

const scenarioUrl = new URL(
  "../../../apps/web/public/scenarios/account-compromise.json",
  import.meta.url,
);

function loadCompiledScenario() {
  const serialized =
    readFileSync(
      scenarioUrl,
      "utf8",
    );

  const file =
    parseScenarioJson(serialized);

  return compileScenarioDefinition(
    file.scenario,
  );
}

describe("editable scenario fixture", () => {
  it("structurally parses and semantically compiles the browser scenario", () => {
    const scenario =
      loadCompiledScenario();
    const state =
      getScenarioState(scenario);
    const context =
      scenario.investigation;

    expect(scenario.name)
      .toContain("PowerShell");

    expect(
      context.responseActionIds,
    ).toEqual([
      "revoke_compromised_session",
      "disable_compromised_account",
      "restore_compromised_account_access",
    ]);

    expect(
      state.world.accounts[
        context.accountId
      ]?.status,
    ).toBe("active");

    expect(
      state.world.sessions[
        context.sessionId
      ]?.status,
    ).toBe("active");
  });

  it("replays partial and complete JSON-defined remediation deterministically", () => {
    const scenario =
      loadCompiledScenario();
    const context =
      scenario.investigation;

    const partialFirst =
      getScenarioState(
        scenario,
        [context.primaryActionId],
      );
    const partialSecond =
      getScenarioState(
        scenario,
        [context.primaryActionId],
      );

    expect(partialSecond)
      .toEqual(partialFirst);

    expect(
      partialFirst.world.accounts[
        context.accountId
      ]?.status,
    ).toBe("active");

    expect(
      partialFirst.world.sessions[
        context.sessionId
      ]?.status,
    ).toBe("revoked");

    expect(partialFirst.score.percentage)
      .toBe(50);
    expect(partialFirst.outcome.status)
      .toBe("in_progress");

    const complete =
      getScenarioState(
        scenario,
        [
          "revoke_compromised_session",
          "disable_compromised_account",
        ],
      );

    expect(
      complete.world.accounts[
        context.accountId
      ]?.status,
    ).toBe("disabled");

    expect(
      complete.world.sessions[
        context.sessionId
      ]?.status,
    ).toBe("revoked");

    expect(complete.score.percentage)
      .toBe(100);
    expect(complete.outcome.status)
      .toBe("succeeded");
  });
});
