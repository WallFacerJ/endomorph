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

  it("replays the JSON-defined primary action deterministically", () => {
    const scenario =
      loadCompiledScenario();
    const context =
      scenario.investigation;

    const first =
      getScenarioState(
        scenario,
        [context.primaryActionId],
      );
    const second =
      getScenarioState(
        scenario,
        [context.primaryActionId],
      );

    expect(second)
      .toEqual(first);

    expect(
      first.world.accounts[
        context.accountId
      ]?.status,
    ).toBe("disabled");

    expect(
      first.world.sessions[
        context.sessionId
      ]?.status,
    ).toBe("revoked");
  });
});
