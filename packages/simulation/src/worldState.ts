import type {
  Account,
  Application,
  Device,
  EntityId,
  FileEntity,
  Organization,
  Session,
  SimulationTimestamp,
  User,
} from "@endomorph/domain";

export interface WorldState {
  simulationTime: SimulationTimestamp;

  organizations: Record<EntityId, Organization>;

  users: Record<EntityId, User>;

  accounts: Record<EntityId, Account>;

  devices: Record<EntityId, Device>;

  files: Record<EntityId, FileEntity>;

  applications: Record<EntityId, Application>;

  sessions: Record<EntityId, Session>;
}

export interface WorldSeed {
  simulationTime: SimulationTimestamp;

  organizations?: Organization[];

  users?: User[];

  accounts?: Account[];

  devices?: Device[];

  files?: FileEntity[];

  applications?: Application[];

  sessions?: Session[];
}

function indexById<T extends { id: EntityId }>(
  entities: T[] = [],
): Record<EntityId, T> {
  return Object.fromEntries(
    entities.map((entity) => [
      entity.id,
      entity,
    ]),
  );
}

export function createWorldState(
  seed: WorldSeed,
): WorldState {
  return {
    simulationTime: seed.simulationTime,

    organizations: indexById(
      seed.organizations,
    ),

    users: indexById(
      seed.users,
    ),

    accounts: indexById(
      seed.accounts,
    ),

    devices: indexById(
      seed.devices,
    ),

    files: indexById(
      seed.files,
    ),

    applications: indexById(
      seed.applications,
    ),

    sessions: indexById(
      seed.sessions,
    ),
  };
}

export function createEmptyWorldState(
  simulationTime: SimulationTimestamp,
): WorldState {
  return createWorldState({
    simulationTime,
  });
}
