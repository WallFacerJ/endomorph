import {
  parseScenarioFile,
} from "@endomorph/schema";

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
    {
      path: "/scenarios/generated-enterprise.json",
      label:
        "Generated: external credential compromise",
    },
    {
      path: "/scenarios/generated-insider.json",
      label:
        "Generated: privileged insider (advanced)",
    },
    {
      path: "/scenarios/generated-service-account.json",
      label:
        "Generated: service account abuse (advanced)",
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

/**
 * Reads a scenario embedded in the page instead of fetching it.
 *
 * The standalone single-file build inlines each scenario as a JSON script
 * tag so the whole product runs from one HTML file with no network access
 * at all. Returns undefined in the normal hosted build, which falls through
 * to fetch.
 */
function readEmbeddedScenario(
  path: string,
): unknown {
  if (
    typeof document === "undefined"
  ) {
    return undefined;
  }

  const element =
    document.getElementById(
      `endomorph-scenario:${path}`,
    );

  if (!element?.textContent) {
    return undefined;
  }

  try {
    return JSON.parse(
      element.textContent,
    );
  } catch {
    throw new Error(
      `Embedded scenario ${path} is not valid JSON.`,
    );
  }
}

export async function loadScenario(
  path: string,
): Promise<ScenarioDefinition> {
  const embedded =
    readEmbeddedScenario(path);

  if (embedded !== undefined) {
    return compileScenarioPayload(
      embedded,
    );
  }

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
