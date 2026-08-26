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
  /** Days of baseline history. Fewer keeps the shipped bundle smaller. */
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
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-service-account.json",
    id: "scenario-generated-service-001",
    name: "Generated enterprise: service account abuse",
    description:
      "A valid privileged credential used from a workstation it has no history with, moving between servers over SMB. All traffic stays internal.",
    plan: "service-account-abuse",
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-dormant.json",
    id: "scenario-generated-dormant-001",
    name: "Generated enterprise: dormant account revived",
    description:
      "Every sign-in in this incident is unremarkable: valid credential, corporate address, ordinary hour. The only anomalous event happened before any of them.",
    plan: "dormant-account-revival",
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-macro.json",
    id: "scenario-generated-macro-001",
    name: "Generated enterprise: phishing macro execution",
    description:
      "The account is the genuine employee's and no authentication in this incident is anomalous, because the attacker never authenticated. The chain begins with a process on the endpoint.",
    plan: "macro-execution",
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-cloud-role.json",
    id: "scenario-generated-cloud-role-001",
    name: "Generated enterprise: directory role elevation",
    description:
      "No process runs on any workstation in this incident. The whole chain is a valid password, a multi-factor prompt worn down until it was approved, and a privileged role granted to an account that never held it.",
    plan: "cloud-role-elevation",
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-phishing.json",
    id: "scenario-generated-phishing-001",
    name: "Generated enterprise: credential phishing by link",
    description:
      "No malware runs and the eventual login uses a valid credential. The whole intrusion lives in mail and identity: a lookalike-domain lure, a click to a credential-harvesting host, and a sign-in from an address the account has never used.",
    plan: "phishing-link",
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-cloud-consent.json",
    id: "scenario-generated-cloud-consent-001",
    name: "Generated enterprise: OAuth consent grant to cloud data theft",
    description:
      "Nothing touches a host. A user consents to a malicious OAuth application, and from the token that returns an attacker mints a credential, enumerates storage, and copies data to an external account -- an intrusion visible only in the cloud control-plane audit log.",
    plan: "cloud-consent-grant",
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-dns-tunnel.json",
    id: "scenario-generated-dns-tunnel-001",
    name: "Generated enterprise: DNS command-and-control and tunnelled exfiltration",
    description:
      "No process is anomalous and no sign-in is out of place. A host beacons over DNS to algorithmically-generated domains and tunnels data out inside oversized TXT query names -- an intrusion visible only in the resolver log, in the shape of the names it queries.",
    plan: "dns-tunnel",
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-web-c2.json",
    id: "scenario-generated-web-c2-001",
    name: "Generated enterprise: malicious download, web C2, and HTTP exfiltration",
    description:
      "A connection log shows only traffic to a few addresses on 443. The proxy shows the intrusion: a payload downloaded over plain HTTP, a beacon carrying a user agent no real browser sends, and a large POST to an anonymous paste service.",
    plan: "web-c2",
    days: 3,
  },
  {
    out: "apps/web/public/scenarios/generated-ransomware.json",
    id: "scenario-generated-ransomware-001",
    name: "Generated enterprise: human-operated ransomware deployment",
    description:
      "The end of the kill chain: a scheduled task for persistence, endpoint protection disabled, every volume shadow copy destroyed, then mass encryption. The shadow-copy deletion is the last high-fidelity chance to contain before the files are gone.",
    plan: "ransomware-deployment",
    days: 3,
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
        "--days",
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
