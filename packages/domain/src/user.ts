import type {
  EntityId,
  EntityStatus,
} from "./types";

export interface User {
  id: EntityId;

  organizationId: EntityId;

  displayName: string;

  email: string;

  department: string;

  title?: string;

  status: EntityStatus;

  accountIds: EntityId[];

  deviceIds: EntityId[];
}
