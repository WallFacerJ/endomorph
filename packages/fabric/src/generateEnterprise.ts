import type {
  Account,
  Application,
  AutorunEntry,
  Device,
  EntityStatus,
  FileEntity,
  Organization,
  User,
} from "@endomorph/domain";

import {
  RandomCursor,
} from "./randomCursor.js";

import {
  APPLICATION_PROFILES,
  FAMILY_NAMES,
  FILE_PROFILES,
  GIVEN_NAMES,
  PRIVILEGED_ROLES,
  SERVER_OPERATING_SYSTEMS,
  SERVER_PROFILES,
  WORKSTATION_OPERATING_SYSTEMS,
  type DepartmentProfile,
} from "./nameLibrary.js";

import {
  resolveEnterpriseProfile,
  type AssetContext,
  type EnterpriseProfile,
  type NetworkSegment,
} from "./enterpriseProfile.js";

/**
 * A generated enterprise.
 *
 * The entity arrays are shaped to drop straight into `WorldSeed` from
 * `@endomorph/simulation`; the context maps are Fabric enrichment that the
 * canonical domain types do not carry.
 */
export interface GeneratedEnterprise {
  readonly profile: EnterpriseProfile;

  readonly organizations: Organization[];

  readonly users: User[];

  readonly accounts: Account[];

  readonly devices: Device[];

  readonly applications: Application[];

  readonly files: FileEntity[];

  readonly segments: NetworkSegment[];

  /** Business context keyed by entity id. */
  readonly assetContext: Record<
    string,
    AssetContext
  >;

  /** Accounts holding privileged directory groups, for fast lookup. */
  readonly privilegedAccountIds: string[];
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Substitutes a department code and ordinal into a hostname pattern.
 *
 * Naming conventions vary more between estates than anything else, and are
 * the first thing an analyst notices is wrong. An unrecognised placeholder is
 * left alone rather than silently dropped, so a mistyped pattern shows up in
 * the hostnames instead of quietly producing plausible-looking rubbish.
 */
function formatHostname(
  pattern: string,
  code: string,
  ordinal: number,
): string {
  return pattern
    .replaceAll("{code}", code)
    .replaceAll(
      "{n}",
      String(ordinal).padStart(3, "0"),
    )
    .toUpperCase();
}

/**
 * Distributes headcount across departments by weight.
 *
 * Uses largest-remainder so the parts always sum to exactly `headcount`,
 * and so a one-person change lands in a single department instead of
 * rippling through all of them.
 */
function allocateHeadcount(
  headcount: number,
  departments: readonly DepartmentProfile[],
): number[] {
  const totalWeight = departments.reduce(
    (sum, department) =>
      sum + department.weight,
    0,
  );

  const exact = departments.map(
    (department) =>
      (headcount * department.weight) /
      totalWeight,
  );

  const allocated = exact.map((value) =>
    Math.floor(value),
  );

  let remaining =
    headcount -
    allocated.reduce(
      (sum, value) => sum + value,
      0,
    );

  const byRemainder = exact
    .map((value, index) => ({
      index,
      remainder:
        value - Math.floor(value),
    }))
    .sort(
      (left, right) =>
        right.remainder -
          left.remainder ||
        left.index - right.index,
    );

  let cursor = 0;

  while (remaining > 0) {
    allocated[
      byRemainder[
        cursor % byRemainder.length
      ].index
    ] += 1;

    cursor += 1;
    remaining -= 1;
  }

  // Every department keeps at least one person so no team is a ghost.
  for (
    let index = 0;
    index < allocated.length;
    index += 1
  ) {
    if (allocated[index] === 0) {
      allocated[index] = 1;
    }
  }

  return allocated;
}

function buildEmail(
  given: string,
  family: string,
  domain: string,
  disambiguator: number,
): string {
  const local = `${slugify(given)}.${slugify(family)}`;

  return disambiguator === 0
    ? `${local}@${domain}`
    : `${local}${disambiguator + 1}@${domain}`;
}


/**
 * What legitimately starts with a corporate machine.
 *
 * Every workstation in a real estate carries a handful of these -- sync
 * clients, chat, updaters, the asset agent IT deploys -- and modelling them is
 * what stops the persistence question from answering itself. If the only
 * autorun entry in the estate were the intrusion's, "does this host have
 * persistence" would be the whole investigation. The real skill is picking the
 * odd entry out of a dozen ordinary ones, because an installer and a foothold
 * write the same kind of record and only the name and the directory tell them
 * apart.
 *
 * This is host state rather than telemetry, which is why it lives on the
 * entity: it is what a query of the machine returns, and most of it was
 * configured long before any sensor was watching.
 */
const WINDOWS_BASELINE_AUTORUNS: readonly AutorunEntry[] =
  [
  {
    name: "OneDrive",
    location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background',
  },
  {
    name: "Teams",
    location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: '"C:\\Program Files\\Microsoft Teams\\current\\Teams.exe" --minimized',
  },
  {
    name: "SecurityHealth",
    location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: "C:\\Windows\\System32\\SecurityHealthSystray.exe",
  },
  {
    name: "AcmeAssetAgent",
    location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: '"C:\\Program Files\\Acme\\AssetAgent\\agent.exe" --service',
  },
  {
    name: "ZoomUpdater",
    location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: '"C:\\Program Files\\Zoom\\bin\\Zoom.exe" --autostart',
  },
  {
    name: "GoogleChromeAutoLaunch",
    location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --no-startup-window',
  },
  {
    name: "AdobeARMservice",
    location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: '"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"',
  },
  {
    name: "IntelGraphicsTray",
    location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: "C:\\Windows\\System32\\igfxtray.exe",
  },
  {
    name: "AcmeBackup",
    location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    target: '"C:\\Program Files\\Acme\\Backup\\backupd.exe" --quiet',
  },
];

const MACOS_BASELINE_AUTORUNS: readonly AutorunEntry[] =
  [
  {
    name: "com.acme.assetagent",
    location: "/Library/LaunchAgents",
    target: "/Library/Acme/AssetAgent/agent",
  },
  {
    name: "com.microsoft.OneDriveLauncher",
    location: "~/Library/LaunchAgents",
    target: "/Applications/OneDrive.app/Contents/MacOS/OneDrive",
  },
  {
    name: "com.tinyspeck.slackmacgap",
    location: "~/Library/LaunchAgents",
    target: "/Applications/Slack.app/Contents/MacOS/Slack",
  },
  {
    name: "com.google.keystone.agent",
    location: "~/Library/LaunchAgents",
    target: "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle",
  },
  {
    name: "com.acme.backup",
    location: "/Library/LaunchDaemons",
    target: "/Library/Acme/Backup/backupd",
  },
];

const LINUX_BASELINE_AUTORUNS: readonly AutorunEntry[] =
  [
  {
    name: "acme-asset-agent.service",
    location: "/etc/systemd/system",
    target: "/opt/acme/assetagent/agent",
  },
  {
    name: "node-exporter.service",
    location: "/etc/systemd/system",
    target: "/usr/local/bin/node_exporter",
  },
  {
    name: "docker.service",
    location: "/lib/systemd/system",
    target: "/usr/bin/dockerd",
  },
  {
    name: "unattended-upgrades.service",
    location: "/lib/systemd/system",
    target: "/usr/bin/unattended-upgrade",
  },
  {
    name: "acme-backup.timer",
    location: "/etc/systemd/system",
    target: "/opt/acme/backup/backupd",
  },
];

/**
 * The baseline for one host.
 *
 * Drawn from a fork addressed by the device id, so adding this could not
 * resequence anything already generated -- the estate and every corpus built
 * from it stay byte-identical, which was verified rather than assumed.
 */
function baselineAutoruns(
  operatingSystem: string,
  cursor: RandomCursor,
  deviceId: string,
): AutorunEntry[] {
  const catalogue =
    operatingSystem.startsWith("Windows")
      ? WINDOWS_BASELINE_AUTORUNS
      : operatingSystem.startsWith("macOS")
        ? MACOS_BASELINE_AUTORUNS
        : LINUX_BASELINE_AUTORUNS;

  const draw = cursor.fork(
    `autoruns-${deviceId}`,
  );

  /*
    Not every machine carries every entry. Estates are not uniform -- software
    arrives with the person and the role -- and a persistence listing identical
    on all 154 hosts would teach an analyst to memorise it rather than read it.
  */
  const count = draw.nextInt(
    3,
    Math.min(7, catalogue.length),
  );

  return draw
    .shuffle([...catalogue])
    .slice(0, count);
}

export function generateEnterprise(
  overrides: Partial<EnterpriseProfile> = {},
): GeneratedEnterprise {
  const profile =
    resolveEnterpriseProfile(overrides);

  const root = RandomCursor.root(
    profile.seed,
  );

  const organizationId = `org-${slugify(profile.organizationName)}`;

  const assetContext: Record<
    string,
    AssetContext
  > = {};

  // ---------------------------------------------------------------------
  // Network segments
  // ---------------------------------------------------------------------

  const segments: NetworkSegment[] =
    profile.departments.map(
      (department) => ({
        name: `${department.name} LAN`,
        cidr: `10.${department.subnetOctet}.0.0/16`,
        businessUnit: department.name,
        criticality:
          department.criticality,
      }),
    );

  segments.push({
    name: "Datacenter",
    cidr: "10.90.0.0/16",
    businessUnit: "Information Technology",
    criticality: "severe",
  });

  // ---------------------------------------------------------------------
  // Organization
  // ---------------------------------------------------------------------

  const organizations: Organization[] =
    [
      {
        id: organizationId,
        name: profile.organizationName,
        status: "active",
        departments:
          profile.departments.map(
            (department) =>
              department.name,
          ),
      },
    ];

  // ---------------------------------------------------------------------
  // Applications
  // ---------------------------------------------------------------------

  const applications: Application[] =
    APPLICATION_PROFILES.map(
      (application) => ({
        id: `app-${slugify(application.name)}`,
        organizationId,
        name: `${profile.organizationName.split(" ")[0]} ${application.name}`,
        kind: application.kind,
        status:
          "active" as EntityStatus,
      }),
    );

  // ---------------------------------------------------------------------
  // Staff, accounts, and workstations
  // ---------------------------------------------------------------------

  const users: User[] = [];
  const accounts: Account[] = [];
  const devices: Device[] = [];
  const privilegedAccountIds: string[] =
    [];

  const allocation = allocateHeadcount(
    profile.headcount,
    profile.departments,
  );

  const usedEmails = new Map<
    string,
    number
  >();

  const staffCursor =
    root.fork("staff");

  let hostOrdinal = 0;

  for (
    let departmentIndex = 0;
    departmentIndex <
    profile.departments.length;
    departmentIndex += 1
  ) {
    const department =
      profile.departments[
        departmentIndex
      ];

    const departmentCursor =
      staffCursor.fork(
        slugify(department.name),
      );

    for (
      let memberIndex = 0;
      memberIndex <
      allocation[departmentIndex];
      memberIndex += 1
    ) {
      // Forking per member by index is what keeps an existing member's
      // identity stable when headcount changes.
      const member =
        departmentCursor.fork(
          `member-${memberIndex}`,
        );

      const given = member.pick(
        GIVEN_NAMES,
      );

      const family = member.pick(
        FAMILY_NAMES,
      );

      const emailKey = `${slugify(given)}.${slugify(family)}`;

      const disambiguator =
        usedEmails.get(emailKey) ?? 0;

      usedEmails.set(
        emailKey,
        disambiguator + 1,
      );

      const userId = `user-${emailKey}${disambiguator === 0 ? "" : `-${disambiguator + 1}`}`;

      const status: EntityStatus =
        member.nextBoolean(
          profile.inactiveStaffRate,
        )
          ? member.nextBoolean(0.5)
            ? "inactive"
            : "disabled"
          : "active";

      // -- primary workstation ------------------------------------------
      hostOrdinal += 1;

      const deviceIds: string[] = [];

      const primaryDeviceId = `device-${slugify(formatHostname(profile.hostnamePattern, department.hostCode, hostOrdinal))}`;

      const primaryDeviceIdOs = member.pick(
        WORKSTATION_OPERATING_SYSTEMS,
      );

      devices.push({
        id: primaryDeviceId,
        organizationId,
        hostname:
          formatHostname(profile.hostnamePattern, department.hostCode, hostOrdinal),
        operatingSystem: primaryDeviceIdOs,
        status:
          status === "active"
            ? "active"
            : "inactive",
        ownerUserId: userId,
        ipAddresses: [
          `${profile.workstationSubnetPrefix}.${department.subnetOctet}.${member.nextInt(1, 250)}.${member.nextInt(2, 250)}`,
        ],
        autoruns: baselineAutoruns(
          primaryDeviceIdOs,
          member,
          primaryDeviceId,
        ),
      });

      deviceIds.push(primaryDeviceId);

      assetContext[primaryDeviceId] = {
        entityId: primaryDeviceId,
        criticality:
          department.criticality ===
          "severe"
            ? "high"
            : department.criticality,
        rationale: `Workstation assigned to ${department.name}.`,
        businessUnit: department.name,
      };

      if (
        member.nextBoolean(
          profile.secondDeviceRate,
        )
      ) {
        hostOrdinal += 1;

        const secondDeviceId = `device-${slugify(formatHostname(profile.hostnamePattern, department.hostCode, hostOrdinal))}`;

        const secondDeviceIdOs = member.pick(
          WORKSTATION_OPERATING_SYSTEMS,
        );

        devices.push({
          id: secondDeviceId,
          organizationId,
          hostname:
            formatHostname(profile.hostnamePattern, department.hostCode, hostOrdinal),
          operatingSystem: secondDeviceIdOs,
          status:
            status === "active"
              ? "active"
              : "inactive",
          ownerUserId: userId,
          ipAddresses: [
            `${profile.workstationSubnetPrefix}.${department.subnetOctet}.${member.nextInt(1, 250)}.${member.nextInt(2, 250)}`,
          ],
          autoruns: baselineAutoruns(
            secondDeviceIdOs,
            member,
            secondDeviceId,
          ),
        });

        deviceIds.push(secondDeviceId);

        assetContext[secondDeviceId] = {
          entityId: secondDeviceId,
          criticality: "moderate",
          rationale: `Secondary workstation assigned to ${department.name}.`,
          businessUnit: department.name,
        };
      }

      // -- accounts ------------------------------------------------------
      const accountIds: string[] = [];

      const primaryAccountId = `account-${emailKey}${disambiguator === 0 ? "" : `-${disambiguator + 1}`}`;

      accounts.push({
        id: primaryAccountId,
        organizationId,
        userId,
        username: buildEmail(
          given,
          family,
          profile.domain,
          disambiguator,
        ),
        provider: "corporate-directory",
        status,
        roles: [
          ...department.baseRoles,
        ],
      });

      accountIds.push(primaryAccountId);

      if (
        member.nextBoolean(
          profile.privilegedAccountRate,
        )
      ) {
        const adminAccountId = `${primaryAccountId}-adm`;

        const privilegedRole =
          member.pick(PRIVILEGED_ROLES);

        accounts.push({
          id: adminAccountId,
          organizationId,
          userId,
          username: `adm-${emailKey}@${profile.domain}`,
          provider:
            "corporate-directory",
          status,
          roles: [
            "domain-users",
            privilegedRole,
          ],
        });

        accountIds.push(adminAccountId);

        privilegedAccountIds.push(
          adminAccountId,
        );

        assetContext[adminAccountId] = {
          entityId: adminAccountId,
          criticality: "severe",
          rationale: `Privileged account holding ${privilegedRole}.`,
          businessUnit: department.name,
        };
      }

      users.push({
        id: userId,
        organizationId,
        displayName: `${given} ${family}`,
        email: buildEmail(
          given,
          family,
          profile.domain,
          disambiguator,
        ),
        department: department.name,
        title: member.pick(
          department.titles,
        ),
        status,
        accountIds,
        deviceIds,
      });

      assetContext[userId] = {
        entityId: userId,
        criticality:
          department.criticality,
        rationale: `${department.name} staff member.`,
        businessUnit: department.name,
      };
    }
  }

  // ---------------------------------------------------------------------
  // Servers
  // ---------------------------------------------------------------------

  const serverCursor =
    root.fork("servers");

  for (const server of SERVER_PROFILES) {
    const cursor = serverCursor.fork(
      server.hostname,
    );

    const deviceId = `device-${server.hostname}`;

    const platformPool =
      server.platform === "any"
        ? SERVER_OPERATING_SYSTEMS
        : SERVER_OPERATING_SYSTEMS.filter(
            (operatingSystem) =>
              server.platform ===
              "windows"
                ? operatingSystem.startsWith(
                    "Windows",
                  )
                : !operatingSystem.startsWith(
                    "Windows",
                  ),
          );

    const serverOs =
      cursor.pick(platformPool);

    devices.push({
      id: deviceId,
      organizationId,
      hostname:
        server.hostname.toUpperCase(),
      operatingSystem: serverOs,
      status: "active",
      ipAddresses: [
        `10.90.${cursor.nextInt(1, 20)}.${cursor.nextInt(2, 250)}`,
      ],
      autoruns: baselineAutoruns(
        serverOs,
        cursor,
        deviceId,
      ),
    });

    assetContext[deviceId] = {
      entityId: deviceId,
      criticality: server.criticality,
      rationale: `${server.role} in the datacenter segment.`,
      businessUnit:
        "Information Technology",
    };
  }

  // ---------------------------------------------------------------------
  // Files
  // ---------------------------------------------------------------------

  const files: FileEntity[] = [];

  const fileCursor = root.fork("files");

  const fileServerId =
    "device-fs-01";

  for (const fileProfile of FILE_PROFILES) {
    const cursor = fileCursor.fork(
      fileProfile.name,
    );

    const candidates = users.filter(
      (user) =>
        fileProfile.departments.includes(
          user.department,
        ) && user.status === "active",
    );

    const owner =
      candidates.length > 0
        ? cursor.pick(candidates)
        : undefined;

    const fileId = `file-${slugify(fileProfile.name)}`;

    files.push({
      id: fileId,
      organizationId,
      name: fileProfile.name,
      path: `\\\\FS-01\\Shared\\${fileProfile.directory}\\${fileProfile.name}`,
      classification:
        fileProfile.classification,
      ownerUserId: owner?.id,
      deviceId: fileServerId,
    });

    assetContext[fileId] = {
      entityId: fileId,
      criticality:
        fileProfile.classification ===
        "restricted"
          ? "severe"
          : fileProfile.classification ===
              "confidential"
            ? "high"
            : "moderate",
      rationale: `${fileProfile.classification} document on the file server.`,
      businessUnit:
        fileProfile.departments[0],
    };
  }

  assetContext[organizationId] = {
    entityId: organizationId,
    criticality: "severe",
    rationale:
      "Root organization entity.",
    businessUnit: "Enterprise",
  };

  for (const application of applications) {
    assetContext[application.id] = {
      entityId: application.id,
      criticality:
        application.kind ===
          "identity" ||
        application.kind === "siem" ||
        application.kind === "edr"
          ? "severe"
          : "high",
      rationale: `${application.kind} platform.`,
      businessUnit:
        "Information Technology",
    };
  }

  return {
    profile,
    organizations,
    users,
    accounts,
    devices,
    applications,
    files,
    segments,
    assetContext,
    privilegedAccountIds,
  };
}

/**
 * Applications ordinary staff authenticate against, used by the activity
 * generator to decide what a normal login day looks like.
 */
export function staffFacingApplicationIdsFor(
  enterprise: GeneratedEnterprise,
): string[] {
  const staffFacingNames = new Set(
    APPLICATION_PROFILES.filter(
      (application) =>
        application.staffFacing,
    ).map(
      (application) =>
        application.name,
    ),
  );

  return enterprise.applications
    .filter((application) =>
      [...staffFacingNames].some(
        (name) =>
          application.name.endsWith(
            name,
          ),
      ),
    )
    .map(
      (application) => application.id,
    );
}
