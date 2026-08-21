/**
 * Fabric scenario generator CLI.
 *
 * Emits a deterministic generated scenario as a scenario file the browser
 * workspace loads directly.
 *
 *   pnpm generate:scenario -- --out apps/web/public/scenarios/generated.json
 *
 * Every flag has a default, so running it bare produces the shipped
 * generated scenario. The same flags always produce byte-identical output.
 */

import {
  existsSync,
  mkdirSync,
  writeFileSync,
} from "node:fs";

import {
  dirname,
  resolve,
} from "node:path";

import {
  fileURLToPath,
} from "node:url";

import {
  compileScenario,
} from "./compileScenario.js";

interface CliOptions {
  out: string;
  seed: number;
  headcount: number;
  id: string;
  name: string;
  description: string;
  organizationName: string;
  domain: string;
  startTime: string;
  durationHours: number;
  pretty: boolean;
}

/**
 * Resolves the workspace root by walking up from this module.
 *
 * pnpm --filter runs package scripts with the package directory as cwd, so
 * a relative --out would otherwise land inside packages/fabric.
 */
function findWorkspaceRoot(): string {
  let directory = dirname(
    fileURLToPath(import.meta.url),
  );

  for (
    let depth = 0;
    depth < 10;
    depth += 1
  ) {
    if (
      existsSync(
        resolve(
          directory,
          "pnpm-workspace.yaml",
        ),
      )
    ) {
      return directory;
    }

    const parent = dirname(directory);

    if (parent === directory) {
      break;
    }

    directory = parent;
  }

  return process.cwd();
}

const DEFAULTS: CliOptions = {
  out: "apps/web/public/scenarios/generated-enterprise.json",
  seed: 20260820,
  headcount: 120,
  id: "scenario-generated-enterprise-001",
  name: "Generated enterprise: Finance account compromise",
  description:
    "A compromised Finance account inside a generated 120-person enterprise. The chain is buried in a full working day of ordinary telemetry; nothing is pre-filtered.",
  organizationName: "Acme Financial",
  domain: "acme.test",
  startTime: "2026-08-20T08:00:00.000Z",
  durationHours: 10,
  pretty: false,
};

export function parseArgs(
  argv: readonly string[],
): CliOptions {
  const options: CliOptions = {
    ...DEFAULTS,
  };

  for (
    let index = 0;
    index < argv.length;
    index += 1
  ) {
    const argument = argv[index];

    // `pnpm run x -- --flag` forwards the bare separator through to us.
    if (
      argument === "--" ||
      !argument.startsWith("--")
    ) {
      continue;
    }

    const key = argument.slice(2);

    if (key === "pretty") {
      options.pretty = true;
      continue;
    }

    const value = argv[index + 1];

    if (
      value === undefined ||
      value.startsWith("--")
    ) {
      throw new Error(
        `Missing value for --${key}`,
      );
    }

    index += 1;

    switch (key) {
      case "out":
        options.out = value;
        break;

      case "seed":
        options.seed = Number(value);
        break;

      case "headcount":
        options.headcount =
          Number(value);
        break;

      case "id":
        options.id = value;
        break;

      case "name":
        options.name = value;
        break;

      case "description":
        options.description = value;
        break;

      case "organization":
        options.organizationName =
          value;
        break;

      case "domain":
        options.domain = value;
        break;

      case "start-time":
        options.startTime = value;
        break;

      case "duration-hours":
        options.durationHours =
          Number(value);
        break;

      default:
        throw new Error(
          `Unknown flag: --${key}`,
        );
    }
  }

  return options;
}

function main(): void {
  const options = parseArgs(
    process.argv.slice(2),
  );

  const compiled = compileScenario({
    id: options.id,
    name: options.name,
    description: options.description,
    enterprise: {
      seed: options.seed,
      headcount: options.headcount,
      organizationName:
        options.organizationName,
      domain: options.domain,
      startTime: options.startTime,
    },
    activity: {
      durationHours:
        options.durationHours,
    },
  });

  const outputPath = resolve(
    findWorkspaceRoot(),
    options.out,
  );

  mkdirSync(dirname(outputPath), {
    recursive: true,
  });

  writeFileSync(
    outputPath,
    `${JSON.stringify(compiled.file, null, options.pretty ? 2 : 0)}\n`,
    "utf8",
  );

  const { enterprise } = compiled;

  const entityCount =
    enterprise.organizations.length +
    enterprise.users.length +
    enterprise.accounts.length +
    enterprise.devices.length +
    enterprise.applications.length +
    enterprise.files.length;

  process.stdout.write(
    [
      `Generated ${options.id}`,
      `  seed          ${options.seed}`,
      `  organization  ${enterprise.profile.organizationName}`,
      `  entities      ${entityCount}`,
      `  staff         ${enterprise.users.length}`,
      `  devices       ${enterprise.devices.length}`,
      `  accounts      ${enterprise.accounts.length}`,
      `  background    ${compiled.backgroundEventCount} events`,
      `  incident      ${compiled.incident.events.length} events`,
      `  total         ${compiled.totalEventCount} events`,
      `  victim        ${compiled.incident.victimUserId}`,
      `  written       ${options.out}`,
      "",
    ].join("\n"),
  );
}

// Only run when invoked as a program, so the arg parser can be tested.
if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) ===
    resolve(process.argv[1])
) {
  main();
}
