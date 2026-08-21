import {
  parseScenarioFile,
} from "@polymorph/schema";

import {
  compileScenarioDefinition,
} from "./simulationAdapter";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

export interface ShippedScenario {
  path: string;
  label: string;
}

export const SHIPPED_SCENARIOS:
  readonly ShippedScenario[] = [
    {
      path: "/scenarios/account-compromise.json",
      label: "Finance account compromise",
    },
    {
      path: "/scenarios/hr-malware-beacon.json",
      label: "HR malware beacon",
    },
    {
      path: "/scenarios/cloud-admin-compromise.json",
      label: "Cloud-admin compromise",
    },
  ];

export const DEFAULT_SCENARIO_PATH =
  SHIPPED_SCENARIOS[0].path;

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

function resolveHostedScenarioPath(
  path: string,
): string {
  const relativePath =
    path.startsWith("/")
      ? path.slice(1)
      : path;

  return `${import.meta.env.BASE_URL}${relativePath}`;
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
  const response = await fetch(
    resolveHostedScenarioPath(path),
    {
      cache: "no-store",
    },
  );

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
