/**
 * Generates every shipped scenario as a build step.
 *
 * These are build artifacts, not source. Committing them put a 4.8MB file in
 * git that was rewritten wholesale on every generator change, and adding the
 * plan library would have made it four such files. Generating them during
 * the build keeps them out of history and guarantees they always match the
 * generator that produced them.
 */

import {
  spawnSync,
} from "node:child_process";

import {
  existsSync,
} from "node:fs";

import {
  dirname,
  join,
  resolve,
} from "node:path";

import {
  fileURLToPath,
} from "node:url";

interface ScenarioBuild {
  readonly out: string;
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly plan?: string;
  readonly headcount?: number;
  readonly days?: number;
}

const BUILDS: readonly ScenarioBuild[] = [
  {
    out: "apps/web/public/scenarios/generated-enterprise.json",
    id: "scenario-generated-enterprise-001",
    name: "Generated enterprise: external credential compromise",
    description:
      "A compromised Finance account inside a generated 120-person enterprise. Five days of ordinary working history precede the intrusion, so the account's normal devices, addresses, and applications are all observable. Nothing is pre-filtered.",
    plan: "credential-compromise",
  },
  {
    out: "apps/web/public/scenarios/generated-insider.json",
    id: "scenario-generated-insider-001",
    name: "Generated enterprise: privileged insider",
    description:
      "Nothing in this incident comes from outside. Every address is corporate and every credential is valid. The signal is deviation from one person's own established pattern.",
    plan: "privileged-insider",
  },
  {
    out: "apps/web/public/scenarios/generated-service-account.json",
    id: "scenario-generated-service-001",
    name: "Generated enterprise: service account abuse",
    description:
      "A valid privileged credential used from a workstation it has no history with, moving between servers over SMB. All traffic stays internal.",
    plan: "service-account-abuse",
  },
];

function findWorkspaceRoot(): string {
  let directory = dirname(
    fileURLToPath(import.meta.url),
  );

  for (let depth = 0; depth < 10; depth += 1) {
    const candidate = resolve(
      directory,
      "pnpm-workspace.yaml",
    );

    if (existsSync(candidate)) {
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

function main(): void {
  const root = findWorkspaceRoot();

  const cli = join(
    root,
    "packages",
    "fabric",
    "dist",
    "cli.js",
  );

  for (const build of BUILDS) {
    const args = [
      cli,
      "--out",
      build.out,
      "--id",
      build.id,
      "--name",
      build.name,
      "--description",
      build.description,
    ];

    if (build.plan) {
      args.push("--plan", build.plan);
    }

    if (build.headcount) {
      args.push(
        "--headcount",
        String(build.headcount),
      );
    }

    if (build.days) {
      args.push(
        "--duration-hours",
        String(build.days),
      );
    }

    const result = spawnSync(
      process.execPath,
      args,
      { stdio: "inherit" },
    );

    if (result.status !== 0) {
      throw new Error(
        `Failed to generate ${build.out}`,
      );
    }
  }
}

main();
