import {
  parseScenarioFile,
} from "@polymorph/schema";

import {
  compileScenarioDefinition,
} from "./simulationAdapter";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

export const DEFAULT_SCENARIO_PATH =
  "/scenarios/account-compromise.json";

export function resolveScenarioPath(
  search: string,
): string {
  const requested =
    new URLSearchParams(search)
      .get("scenario");

  if (
    requested &&
    requested.startsWith("/scenarios/") &&
    !requested.includes("..")
  ) {
    return requested;
  }

  return DEFAULT_SCENARIO_PATH;
}

export function compileScenarioPayload(
  input: unknown,
): ScenarioDefinition {
  const file =
    parseScenarioFile(input);

  return compileScenarioDefinition(
    file.scenario,
  );
}

export async function loadScenario(
  path: string,
): Promise<ScenarioDefinition> {
  const response = await fetch(path, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(
      `Unable to load scenario ${path}: HTTP ${response.status}.`,
    );
  }

  let input: unknown;

  try {
    input = await response.json();
  } catch {
    throw new Error(
      `Scenario ${path} is not valid JSON.`,
    );
  }

  return compileScenarioPayload(input);
}
