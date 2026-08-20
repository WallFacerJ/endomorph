import type {
  Account,
  Application,
  ApplicationKind,
  Device,
  EntityId,
  EntityStatus,
  FileClassification,
  FileEntity,
  Organization,
  Session,
  SessionStatus,
  User,
} from "@polymorph/domain";

import type {
  SimulationSnapshot,
} from "./snapshot";

import type {
  WorldState,
} from "./worldState";

import {
  validateWorldState,
} from "./worldValidation";

export const SIMULATION_SERIALIZATION_VERSION = 1;

type SerializationKind =
  | "world-state"
  | "simulation-snapshot";

interface SerializationEnvelope {
  version: number;
  kind: SerializationKind;
  payload: unknown;
}

type UnknownRecord =
  Record<string, unknown>;

type EntityParser<T> = (
  value: unknown,
  path: string,
) => T;

const ENTITY_STATUSES:
  readonly EntityStatus[] = [
    "active",
    "inactive",
    "disabled",
  ];

const SESSION_STATUSES:
  readonly SessionStatus[] = [
    "active",
    "ended",
    "revoked",
  ];

const FILE_CLASSIFICATIONS:
  readonly FileClassification[] = [
    "public",
    "internal",
    "confidential",
    "restricted",
  ];

const APPLICATION_KINDS:
  readonly ApplicationKind[] = [
    "siem",
    "edr",
    "identity",
    "email",
    "hr",
    "cloud",
    "file_server",
    "custom",
  ];

function isRecord(
  value: unknown,
): value is UnknownRecord {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function requireRecord(
  value: unknown,
  path: string,
): UnknownRecord {
  if (!isRecord(value)) {
    throw new Error(
      `${path} must be an object.`,
    );
  }

  return value;
}

function requireString(
  value: unknown,
  path: string,
): string {
  if (typeof value !== "string") {
    throw new Error(
      `${path} must be a string.`,
    );
  }

  return value;
}

function requireTimestamp(
  value: unknown,
  path: string,
): string {
  const timestamp =
    requireString(value, path);

  if (
    !Number.isFinite(
      Date.parse(timestamp),
    )
  ) {
    throw new Error(
      `${path} must be a valid timestamp.`,
    );
  }

  return timestamp;
}

function optionalString(
  value: unknown,
  path: string,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  return requireString(value, path);
}

function optionalTimestamp(
  value: unknown,
  path: string,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  return requireTimestamp(value, path);
}

function requireStringArray(
  value: unknown,
  path: string,
): string[] {
  if (!Array.isArray(value)) {
    throw new Error(
      `${path} must be an array.`,
    );
  }

  return value.map(
    (item, index) =>
      requireString(
        item,
        `${path}[${index}]`,
      ),
  );
}

function requireEnum<T extends string>(
  value: unknown,
  allowed: readonly T[],
  path: string,
): T {
  const candidate =
    requireString(value, path);

  if (!allowed.includes(candidate as T)) {
    throw new Error(
      `${path} has unsupported value ${candidate}.`,
    );
  }

  return candidate as T;
}

function parseOrganization(
  value: unknown,
  path: string,
): Organization {
  const record =
    requireRecord(value, path);

  return {
    id: requireString(
      record.id,
      `${path}.id`,
    ),
    name: requireString(
      record.name,
      `${path}.name`,
    ),
    status: requireEnum(
      record.status,
      ENTITY_STATUSES,
      `${path}.status`,
    ),
    departments: requireStringArray(
      record.departments,
      `${path}.departments`,
    ),
  };
}

function parseUser(
  value: unknown,
  path: string,
): User {
  const record =
    requireRecord(value, path);
  const title = optionalString(
    record.title,
    `${path}.title`,
  );

  return {
    id: requireString(
      record.id,
      `${path}.id`,
    ),
    organizationId: requireString(
      record.organizationId,
      `${path}.organizationId`,
    ),
    displayName: requireString(
      record.displayName,
      `${path}.displayName`,
    ),
    email: requireString(
      record.email,
      `${path}.email`,
    ),
    department: requireString(
      record.department,
      `${path}.department`,
    ),
    ...(title === undefined
      ? {}
      : { title }),
    status: requireEnum(
      record.status,
      ENTITY_STATUSES,
      `${path}.status`,
    ),
    accountIds: requireStringArray(
      record.accountIds,
      `${path}.accountIds`,
    ),
    deviceIds: requireStringArray(
      record.deviceIds,
      `${path}.deviceIds`,
    ),
  };
}

function parseAccount(
  value: unknown,
  path: string,
): Account {
  const record =
    requireRecord(value, path);

  return {
    id: requireString(
      record.id,
      `${path}.id`,
    ),
    organizationId: requireString(
      record.organizationId,
      `${path}.organizationId`,
    ),
    userId: requireString(
      record.userId,
      `${path}.userId`,
    ),
    username: requireString(
      record.username,
      `${path}.username`,
    ),
    provider: requireString(
      record.provider,
      `${path}.provider`,
    ),
    status: requireEnum(
      record.status,
      ENTITY_STATUSES,
      `${path}.status`,
    ),
    roles: requireStringArray(
      record.roles,
      `${path}.roles`,
    ),
  };
}

function parseDevice(
  value: unknown,
  path: string,
): Device {
  const record =
    requireRecord(value, path);
  const ownerUserId = optionalString(
    record.ownerUserId,
    `${path}.ownerUserId`,
  );

  return {
    id: requireString(
      record.id,
      `${path}.id`,
    ),
    organizationId: requireString(
      record.organizationId,
      `${path}.organizationId`,
    ),
    hostname: requireString(
      record.hostname,
      `${path}.hostname`,
    ),
    operatingSystem: requireString(
      record.operatingSystem,
      `${path}.operatingSystem`,
    ),
    status: requireEnum(
      record.status,
      ENTITY_STATUSES,
      `${path}.status`,
    ),
    ...(ownerUserId === undefined
      ? {}
      : { ownerUserId }),
    ipAddresses: requireStringArray(
      record.ipAddresses,
      `${path}.ipAddresses`,
    ),
  };
}

function parseFile(
  value: unknown,
  path: string,
): FileEntity {
  const record =
    requireRecord(value, path);
  const ownerUserId = optionalString(
    record.ownerUserId,
    `${path}.ownerUserId`,
  );
  const deviceId = optionalString(
    record.deviceId,
    `${path}.deviceId`,
  );

  return {
    id: requireString(
      record.id,
      `${path}.id`,
    ),
    organizationId: requireString(
      record.organizationId,
      `${path}.organizationId`,
    ),
    name: requireString(
      record.name,
      `${path}.name`,
    ),
    path: requireString(
      record.path,
      `${path}.path`,
    ),
    classification: requireEnum(
      record.classification,
      FILE_CLASSIFICATIONS,
      `${path}.classification`,
    ),
    ...(ownerUserId === undefined
      ? {}
      : { ownerUserId }),
    ...(deviceId === undefined
      ? {}
      : { deviceId }),
  };
}

function parseApplication(
  value: unknown,
  path: string,
): Application {
  const record =
    requireRecord(value, path);

  return {
    id: requireString(
      record.id,
      `${path}.id`,
    ),
    organizationId: requireString(
      record.organizationId,
      `${path}.organizationId`,
    ),
    name: requireString(
      record.name,
      `${path}.name`,
    ),
    kind: requireEnum(
      record.kind,
      APPLICATION_KINDS,
      `${path}.kind`,
    ),
    status: requireEnum(
      record.status,
      ENTITY_STATUSES,
      `${path}.status`,
    ),
  };
}

function parseSession(
  value: unknown,
  path: string,
): Session {
  const record =
    requireRecord(value, path);
  const deviceId = optionalString(
    record.deviceId,
    `${path}.deviceId`,
  );
  const applicationId = optionalString(
    record.applicationId,
    `${path}.applicationId`,
  );
  const endedAt = optionalTimestamp(
    record.endedAt,
    `${path}.endedAt`,
  );

  return {
    id: requireString(
      record.id,
      `${path}.id`,
    ),
    accountId: requireString(
      record.accountId,
      `${path}.accountId`,
    ),
    ...(deviceId === undefined
      ? {}
      : { deviceId }),
    ...(applicationId === undefined
      ? {}
      : { applicationId }),
    startedAt: requireTimestamp(
      record.startedAt,
      `${path}.startedAt`,
    ),
    ...(endedAt === undefined
      ? {}
      : { endedAt }),
    status: requireEnum(
      record.status,
      SESSION_STATUSES,
      `${path}.status`,
    ),
  };
}

function parseEntityRecord<T extends {
  id: EntityId;
}>(
  value: unknown,
  path: string,
  parser: EntityParser<T>,
): Record<EntityId, T> {
  const record =
    requireRecord(value, path);

  return Object.fromEntries(
    Object.keys(record)
      .sort((left, right) =>
        left.localeCompare(right),
      )
      .map((key) => [
        key,
        parser(
          record[key],
          `${path}.${key}`,
        ),
      ]),
  );
}

function assertSemanticWorld(
  world: WorldState,
): void {
  const issues =
    validateWorldState(world);

  if (issues.length === 0) {
    return;
  }

  throw new Error(
    `Invalid world state: ${issues
      .map((issue) => issue.message)
      .join(" ")}`,
  );
}

function parseWorldState(
  value: unknown,
  path: string,
): WorldState {
  const record =
    requireRecord(value, path);

  const world: WorldState = {
    simulationTime: requireTimestamp(
      record.simulationTime,
      `${path}.simulationTime`,
    ),
    organizations: parseEntityRecord(
      record.organizations,
      `${path}.organizations`,
      parseOrganization,
    ),
    users: parseEntityRecord(
      record.users,
      `${path}.users`,
      parseUser,
    ),
    accounts: parseEntityRecord(
      record.accounts,
      `${path}.accounts`,
      parseAccount,
    ),
    devices: parseEntityRecord(
      record.devices,
      `${path}.devices`,
      parseDevice,
    ),
    files: parseEntityRecord(
      record.files,
      `${path}.files`,
      parseFile,
    ),
    applications: parseEntityRecord(
      record.applications,
      `${path}.applications`,
      parseApplication,
    ),
    sessions: parseEntityRecord(
      record.sessions,
      `${path}.sessions`,
      parseSession,
    ),
  };

  assertSemanticWorld(world);

  return world;
}

function canonicalize(
  value: unknown,
): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (!isRecord(value)) {
    return value;
  }

  const canonical: UnknownRecord = {};

  for (
    const key of Object.keys(value)
      .sort((left, right) =>
        left.localeCompare(right),
      )
  ) {
    const child = value[key];

    if (child === undefined) {
      continue;
    }

    canonical[key] =
      canonicalize(child);
  }

  return canonical;
}

function serializeEnvelope(
  kind: SerializationKind,
  payload: unknown,
): string {
  const envelope = {
    version:
      SIMULATION_SERIALIZATION_VERSION,
    kind,
    payload,
  };

  return JSON.stringify(
    canonicalize(envelope),
  );
}

function parseSerializedJson(
  serialized: string,
): unknown {
  try {
    return JSON.parse(serialized);
  } catch {
    throw new Error(
      "Serialized simulation state is not valid JSON.",
    );
  }
}

function parseEnvelope(
  serialized: string,
  expectedKind: SerializationKind,
): SerializationEnvelope {
  const value =
    parseSerializedJson(serialized);
  const record =
    requireRecord(value, "envelope");

  if (
    record.version !==
    SIMULATION_SERIALIZATION_VERSION
  ) {
    throw new Error(
      `Unsupported serialization version: ${String(record.version)}.`,
    );
  }

  const kind =
    requireString(
      record.kind,
      "envelope.kind",
    );

  if (kind !== expectedKind) {
    throw new Error(
      `Expected ${expectedKind} envelope, received ${kind}.`,
    );
  }

  return {
    version:
      SIMULATION_SERIALIZATION_VERSION,
    kind: expectedKind,
    payload: record.payload,
  };
}

function assertSnapshotEventCount(
  eventCount: number,
): void {
  if (
    !Number.isInteger(eventCount) ||
    eventCount < 0
  ) {
    throw new Error(
      "Snapshot event count must be a non-negative integer.",
    );
  }
}

export function serializeWorldState(
  world: WorldState,
): string {
  assertSemanticWorld(world);

  return serializeEnvelope(
    "world-state",
    world,
  );
}

export function deserializeWorldState(
  serialized: string,
): WorldState {
  const envelope = parseEnvelope(
    serialized,
    "world-state",
  );

  return parseWorldState(
    envelope.payload,
    "envelope.payload",
  );
}

export function serializeSimulationSnapshot(
  snapshot: SimulationSnapshot,
): string {
  assertSnapshotEventCount(
    snapshot.eventCount,
  );
  assertSemanticWorld(snapshot.world);

  return serializeEnvelope(
    "simulation-snapshot",
    snapshot,
  );
}

export function deserializeSimulationSnapshot(
  serialized: string,
): SimulationSnapshot {
  const envelope = parseEnvelope(
    serialized,
    "simulation-snapshot",
  );
  const payload = requireRecord(
    envelope.payload,
    "envelope.payload",
  );

  if (
    typeof payload.eventCount !==
    "number"
  ) {
    throw new Error(
      "envelope.payload.eventCount must be a number.",
    );
  }

  assertSnapshotEventCount(
    payload.eventCount,
  );

  return {
    eventCount: payload.eventCount,
    world: parseWorldState(
      payload.world,
      "envelope.payload.world",
    ),
  };
}
