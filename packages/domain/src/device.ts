import type {
  EntityId,
  EntityStatus,
} from "./types";

export interface Device {
  id: EntityId;

  organizationId: EntityId;

  hostname: string;

  operatingSystem: string;

  status: EntityStatus;

  ownerUserId?: EntityId;

  ipAddresses: string[];
}
