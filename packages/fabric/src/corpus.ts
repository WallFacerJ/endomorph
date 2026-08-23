import type {
  Account,
  Device,
  FileEntity,
  User,
} from "@endomorph/domain";

import type {
  SimulationEvent,
} from "@endomorph/simulation";

import type {
  GeneratedEnterprise,
} from "./generateEnterprise.js";

import type {
  GeneratedIncident,
} from "./generateIncident.js";

/**
 * Labelled telemetry corpus export.
 *
 * The investigation console is one consumer of a generated world. The other
 * is detection engineering, and it wants something the console does not: a
 * flat event stream in a schema real tooling speaks, with every record
 * labelled as benign or malicious and, when malicious, mapped to the ATT&CK
 * technique it demonstrates.
 *
 * That labelling is free here and expensive everywhere else. A corpus
 * captured from a real network has to be labelled by hand, and the labels
 * are opinions. Here the ground truth is known by construction: the
 * generator decided which events were the intrusion before it wrote them.
 *
 * Field names follow Elastic Common Schema so the output drops into the
 * tools detection engineers already use rather than requiring a translation
 * layer first.
 */

/**
 * Windows event ids for the event types that genuinely have one.
 *
 * Published Sigma rules key off `EventID` constantly, so without this a large
 * share of real-world content cannot be scored against the corpus at all.
 *
 * Two restraints keep this from becoming decoration. Event types with no
 * honest Windows equivalent are absent rather than assigned a plausible
 * number -- SESSION_STARTED is one, because a session is an abstraction over
 * the logon that 4624 already records, and emitting both would let a rule
 * count one sign-in twice. ROLE_GRANTED is another: 4728 records a group
 * membership change on a Windows domain controller, and a directory role
 * grant here carries no host at all -- the code was assigned and, because
 * codes are only attached to Windows hosts, never once applied. Dead
 * configuration that would have been a lie if it had worked.
 *
 * And the ids are only attached to Windows hosts,
 * because a macOS laptop reporting 4688 would be a fabrication that a rule
 * author would reasonably rely on.
 */
const WINDOWS_EVENT_CODES: Readonly<
  Record<string, number>
> = {
  AUTH_LOGIN_SUCCEEDED: 4624,
  AUTH_LOGIN_FAILED: 4625,
  PROCESS_STARTED: 4688,
  ACCOUNT_ENABLED: 4722,
  FILE_ACCESSED: 4663,
  NETWORK_CONNECTION: 5156,
};

export interface CorpusRecord {
  "@timestamp": string;
  "event.id": string;
  "event.kind": "event" | "alert";
  "event.type": string;
  "event.module": string;

  /**
   * Windows Security / Sysmon event id, when the host is a Windows host and
   * the event has a real equivalent there.
   */
  "event.code"?: number;
  "user.id"?: string;
  "user.name"?: string;
  "user.department"?: string;
  "account.id"?: string;
  "account.name"?: string;

  /**
   * The account that performed the action, when it differs from the one
   * acted upon.
   *
   * Identity lifecycle events name the account being changed, not the one
   * doing the changing. Without this, "who re-enabled that account" is
   * unanswerable from the corpus even though the runtime knows -- and it is
   * exactly the question that separates an administrative action from
   * self-service.
   */
  "actor.account.id"?: string;
  "actor.account.name"?: string;
  "host.id"?: string;
  "host.name"?: string;
  "host.os.full"?: string;
  "source.ip"?: string;
  "destination.ip"?: string;
  "destination.port"?: number;
  "network.protocol"?: string;
  "process.pid"?: string;
  /** Role added to the account, on a ROLE_GRANTED record. */
  "iam.role"?: string;

  "process.parent.pid"?: string;
  "process.parent.executable"?: string;
  "process.executable"?: string;
  "process.command_line"?: string;
  "file.id"?: string;
  "file.name"?: string;
  "file.classification"?: string;
  "event.outcome"?: string;
  "event.reason"?: string;
  "session.id"?: string;
  "rule.name"?: string;
  "event.severity"?: string;

  /** Ground truth. Known by construction, not inferred. */
  "label.malicious": boolean;
  "label.technique"?: string;
  "label.plan"?: string;
  "label.step"?: string;
}

export interface CorpusManifest {
  readonly generator: string;
  readonly seed: number;
  readonly organization: string;
  readonly plan: string;
  readonly planName: string;
  readonly difficulty: string;
  readonly recordCount: number;
  readonly maliciousCount: number;
  readonly benignCount: number;
  /** Malicious share of the corpus. Realistic corpora are heavily skewed. */
  readonly maliciousRatio: number;
  readonly techniques: readonly {
    readonly id: string;
    readonly name: string;
    readonly tactic: string;
    readonly eventCount: number;
  }[];
  readonly firstSeen: string;
  readonly lastSeen: string;
  readonly entityCounts: Readonly<
    Record<string, number>
  >;
}

export interface GeneratedCorpus {
  readonly records: readonly CorpusRecord[];
  readonly manifest: CorpusManifest;
}

function outcomeFor(
  event: SimulationEvent,
): string | undefined {
  switch (event.type) {
    case "AUTH_LOGIN_SUCCEEDED":
      return "success";

    case "AUTH_LOGIN_FAILED":
      return "failure";

    default:
      return undefined;
  }
}

const MODULES: Record<string, string> = {
  identity: "authentication",
  edr: "endpoint",
  network: "network",
  file_server: "file",
};

/**
 * Flattens a simulation event into an ECS-shaped record.
 *
 * Enrichment (display names, hostnames, classifications) is resolved from
 * the world, because a corpus that only carries opaque ids is useless for
 * writing readable detections against.
 */
/**
 * The entity collections a corpus record needs to resolve its references.
 *
 * Narrower than the whole generated enterprise on purpose: the browser holds
 * a compiled scenario rather than a generator run, and it has exactly these
 * four collections. Taking the wide type would have meant fabricating a
 * plausible-looking enterprise around them to satisfy a signature, which is
 * the sort of thing that later gets mistaken for real data.
 */
export interface CorpusEntities {
  readonly users: readonly User[];
  readonly accounts: readonly Account[];
  readonly devices: readonly Device[];
  readonly files: readonly FileEntity[];
}

/**
 * Indexed lookups.
 *
 * The record builder resolved each reference with a linear scan, which is
 * unnoticeable for one run of a CLI and less so for twenty thousand events
 * against a few hundred entities on someone's laptop.
 */
interface CorpusIndex {
  readonly users: Map<string, User>;
  readonly accounts: Map<string, Account>;
  readonly devices: Map<string, Device>;
  readonly files: Map<string, FileEntity>;
}

function indexEntities(
  entities: CorpusEntities,
): CorpusIndex {
  return {
    users: new Map(
      entities.users.map((user) => [
        user.id,
        user,
      ]),
    ),
    accounts: new Map(
      entities.accounts.map(
        (account) => [account.id, account],
      ),
    ),
    devices: new Map(
      entities.devices.map((device) => [
        device.id,
        device,
      ]),
    ),
    files: new Map(
      entities.files.map((file) => [
        file.id,
        file,
      ]),
    ),
  };
}

function toRecord(
  event: SimulationEvent,
  entities: CorpusIndex,
  labels: {
    malicious: boolean;
    technique?: string;
    plan?: string;
    step?: string;
  },
): CorpusRecord {
  const payload =
    event.payload as unknown as Record<
      string,
      unknown
    >;

  const read = (
    key: string,
  ): string | undefined => {
    const value = payload[key];

    return typeof value === "string"
      ? value
      : undefined;
  };

  const readNumber = (
    key: string,
  ): number | undefined => {
    const value = payload[key];

    return typeof value === "number"
      ? value
      : undefined;
  };

  const accountId = read("accountId");

  const account = accountId
    ? entities.accounts.get(accountId)
    : undefined;

  const userId =
    read("userId") ?? account?.userId;

  const user = userId
    ? entities.users.get(userId)
    : undefined;

  const deviceId = read("deviceId");

  const device = deviceId
    ? entities.devices.get(deviceId)
    : undefined;

  const fileId = read("fileId");

  const file = fileId
    ? entities.files.get(fileId)
    : undefined;

  const record: CorpusRecord = {
    "@timestamp": event.timestamp,
    "event.id": event.id,
    "event.kind":
      event.type === "ALERT_CREATED"
        ? "alert"
        : "event",
    "event.type": event.type,
    "event.module":
      MODULES[event.source] ??
      event.source,
    "label.malicious": labels.malicious,
  };

  if (user) {
    record["user.id"] = user.id;
    record["user.name"] =
      user.displayName;
    record["user.department"] =
      user.department;
  }

  if (account) {
    record["account.id"] = account.id;
    record["account.name"] =
      account.username;
  } else if (read("username")) {
    record["account.name"] =
      read("username");
  }

  if (device) {
    record["host.id"] = device.id;
    record["host.name"] =
      device.hostname;
    record["host.os.full"] =
      device.operatingSystem;

    const code =
      WINDOWS_EVENT_CODES[event.type];

    if (
      code !== undefined &&
      device.operatingSystem
        .toLowerCase()
        .includes("windows")
    ) {
      record["event.code"] = code;
    }
  }

  const assign = (
    key: keyof CorpusRecord,
    value: string | number | undefined,
  ): void => {
    if (value !== undefined) {
      (
        record as unknown as Record<
          string,
          unknown
        >
      )[key] = value;
    }
  };

  assign("source.ip", read("sourceIp"));
  assign(
    "destination.ip",
    read("destinationIp"),
  );
  assign(
    "destination.port",
    readNumber("destinationPort"),
  );
  assign(
    "network.protocol",
    read("protocol"),
  );
  assign("process.pid", read("processId"));
  assign(
    "process.parent.pid",
    read("parentProcessId"),
  );
  assign(
    "process.parent.executable",
    read("parentImage"),
  );
  assign(
    "process.executable",
    read("image"),
  );
  assign(
    "process.command_line",
    read("commandLine"),
  );
  assign("iam.role", read("role"));
  assign("session.id", read("sessionId"));
  assign("rule.name", read("title"));
  assign("event.severity", read("severity"));
  assign("event.reason", read("reason"));
  assign(
    "event.outcome",
    outcomeFor(event),
  );

  if (file) {
    record["file.id"] = file.id;
    record["file.name"] = file.name;
    record["file.classification"] =
      file.classification;
  }

  const actorId = event.actorId;

  if (
    actorId &&
    actorId !== record["account.id"]
  ) {
    const actor =
      entities.accounts.get(actorId);

    record["actor.account.id"] =
      actorId;

    if (actor) {
      record["actor.account.name"] =
        actor.username;
    }
  }

  if (labels.technique) {
    record["label.technique"] =
      labels.technique;
  }

  if (labels.plan) {
    record["label.plan"] = labels.plan;
  }

  if (labels.step) {
    record["label.step"] = labels.step;
  }

  return record;
}


/** Ground-truth labels for one event. */
export interface CorpusLabels {
  readonly malicious: boolean;
  readonly technique?: string;
  readonly plan?: string;
  readonly step?: string;
}

/**
 * Builds labelled records from events plus a labelling function.
 *
 * Separated from `buildCorpus` so a caller that holds a compiled scenario
 * rather than a generator run -- the browser -- can produce the same records
 * and score the same rules against them, instead of a second implementation
 * drifting away from this one.
 */
export function buildCorpusRecords(
  entities: CorpusEntities,
  events: readonly SimulationEvent[],
  labelsFor: (
    event: SimulationEvent,
  ) => CorpusLabels,
): CorpusRecord[] {
  const index = indexEntities(entities);

  return events.map((event) =>
    toRecord(
      event,
      index,
      labelsFor(event),
    ),
  );
}

export function buildCorpus(
  enterprise: GeneratedEnterprise,
  events: readonly SimulationEvent[],
  incident: GeneratedIncident,
): GeneratedCorpus {
  // Ground truth: the generator knows exactly which events it planted.
  const techniqueByEvent = new Map<
    string,
    string
  >();

  for (const step of incident.timeline) {
    if (step.techniqueId) {
      techniqueByEvent.set(
        step.eventId,
        step.techniqueId,
      );
    }
  }

  const maliciousIds = new Set(
    incident.events.map(
      (event) => event.id,
    ),
  );

  const records = buildCorpusRecords(
    enterprise,
    events,
    (event) => {
      const malicious = maliciousIds.has(
        event.id,
      );

      return {
        malicious,
        technique: techniqueByEvent.get(
          event.id,
        ),
        plan: malicious
          ? incident.planId
          : undefined,
        step: malicious
          ? event.id.replace(
              /^incident-/,
              "",
            )
          : undefined,
      };
    },
  );

  const maliciousCount = records.filter(
    (record) =>
      record["label.malicious"],
  ).length;

  const timestamps = records
    .map(
      (record) => record["@timestamp"],
    )
    .sort();

  return {
    records,
    manifest: {
      generator: "endomorph-fabric",
      seed: enterprise.profile.seed,
      organization:
        enterprise.profile
          .organizationName,
      plan: incident.planId,
      planName: incident.planName,
      difficulty: incident.difficulty,
      recordCount: records.length,
      maliciousCount,
      benignCount:
        records.length - maliciousCount,
      maliciousRatio:
        records.length === 0
          ? 0
          : maliciousCount /
            records.length,
      techniques:
        incident.techniques.map(
          (technique) => ({
            id: technique.id,
            name: technique.name,
            tactic: technique.tactic,
            eventCount:
              technique.eventIds.length,
          }),
        ),
      firstSeen: timestamps[0] ?? "",
      lastSeen:
        timestamps[
          timestamps.length - 1
        ] ?? "",
      entityCounts: {
        users: enterprise.users.length,
        accounts:
          enterprise.accounts.length,
        devices:
          enterprise.devices.length,
        applications:
          enterprise.applications.length,
        files: enterprise.files.length,
      },
    },
  };
}

/** Newline-delimited JSON, the lingua franca of log tooling. */
export function toNdjson(
  records: readonly CorpusRecord[],
): string {
  return `${records
    .map((record) => JSON.stringify(record))
    .join("\n")}\n`;
}
