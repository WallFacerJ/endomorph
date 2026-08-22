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

  /**
   * Generated scenarios carry ATT&CK mapping, scored investigation
   * questions, and analytical reasoning on every walkthrough step. The
   * hand-authored v1 scenarios predate all three.
   *
   * Grouping them in the selector makes that a stated difference rather
   * than something a user discovers by switching and finding the brief
   * gone.
   */
  group: "generated" | "authored";
}

export const SCENARIO_GROUP_LABELS: Readonly<
  Record<ShippedScenario["group"], string>
> = {
  generated: "Generated (ATT&CK-mapped, with questions)",
  authored: "Hand-authored v1 (smaller, no questions)",
};

export const SHIPPED_SCENARIOS:
  readonly ShippedScenario[] = [
    {
      path: "/scenarios/account-compromise.json",
      label: "Finance account compromise",
      group: "authored",
    },
    {
      path: "/scenarios/hr-malware-beacon.json",
      label: "HR malware beacon",
      group: "authored",
    },
    {
      path: "/scenarios/cloud-admin-compromise.json",
      label: "Cloud-admin compromise",
      group: "authored",
    },
    {
      path: "/scenarios/generated-enterprise.json",
      label:
        "External credential compromise",
      group: "generated",
    },
    {
      path: "/scenarios/generated-insider.json",
      label:
        "Privileged insider (advanced)",
      group: "generated",
    },
    {
      path: "/scenarios/generated-service-account.json",
      label:
        "Service account abuse (advanced)",
      group: "generated",
    },
    {
      path: "/scenarios/generated-dormant.json",
      label:
        "Dormant account revived (advanced)",
      group: "generated",
    },
  ];

/**
 * A generated scenario is the default.
 *
 * The hand-authored v1 scenarios predate the generator and carry no ATT&CK
 * mapping, no investigation questions, and no analytical reasoning in their
 * ground truth. Landing a first-time visitor on one showed them the
 * thinnest version of the product.
 */
export const DEFAULT_SCENARIO_PATH =
  "/scenarios/generated-enterprise.json";

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
async function inflateBase64Gzip(
  base64: string,
): Promise<unknown> {
  if (
    typeof DecompressionStream ===
    "undefined"
  ) {
    throw new Error(
      "This browser cannot decompress the embedded scenario (no DecompressionStream).",
    );
  }

  const binary = atob(base64.trim());

  const bytes = new Uint8Array(
    binary.length,
  );

  for (
    let index = 0;
    index < binary.length;
    index += 1
  ) {
    bytes[index] =
      binary.charCodeAt(index);
  }

  const stream = new Blob([bytes])
    .stream()
    .pipeThrough(
      new DecompressionStream("gzip"),
    );

  return JSON.parse(
    await new Response(stream).text(),
  );
}

/**
 * Reads a scenario embedded in the page instead of fetching it.
 *
 * Scenario JSON is enormously repetitive -- 13.7MB across the shipped set,
 * 1.2MB gzipped -- so the standalone build embeds each one gzipped and
 * base64 encoded and inflates it here. Storing them as plain text put the
 * single-file bundle within 2MB of the size ceiling with four scenarios,
 * which would have capped the library rather than the product capping it.
 */
async function readEmbeddedScenario(
  path: string,
): Promise<unknown> {
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

  const encoding =
    element.getAttribute(
      "data-encoding",
    );

  if (encoding === "gzip+base64") {
    return inflateBase64Gzip(
      element.textContent,
    );
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
    await readEmbeddedScenario(path);

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
