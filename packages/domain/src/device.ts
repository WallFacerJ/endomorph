import type {
  EntityId,
  EntityStatus,
} from "./types";

/**
 * A program configured to start with the machine.
 *
 * Host state rather than telemetry, which is why it lives on the entity and
 * not in the event stream: it is what a query of the machine returns, and much
 * of it was configured long before any sensor was watching.
 *
 * Modelling it matters because without a baseline the persistence question
 * degenerates. If a host's only autorun entry were the one the intrusion
 * installed, "does this machine have persistence" would answer the incident,
 * when the real skill is picking the odd entry out of a dozen legitimate ones
 * -- an installer and a foothold write the same kind of record, and only the
 * name and the directory separate them.
 */
export interface AutorunEntry {
  /** The value name, e.g. "OneDrive". */
  name: string;

  /** Where it is registered: a registry key, a plist path, a unit name. */
  location: string;

  /** What it launches. */
  target: string;
}

export interface Device {
  id: EntityId;

  organizationId: EntityId;

  hostname: string;

  operatingSystem: string;

  status: EntityStatus;

  ownerUserId?: EntityId;

  ipAddresses: string[];

  /**
   * What starts with this machine.
   *
   * Optional so hand-authored scenarios and older fixtures stay valid; a host
   * without it reports no baseline rather than an empty one.
   */
  autoruns?: AutorunEntry[];
}
