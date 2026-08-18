import type {
  EntityId,
  EntityStatus,
} from "./types";

export interface Account {
  id: EntityId;

  organizationId: EntityId;

  userId: EntityId;

  username: string;

  provider: string;

  status: EntityStatus;

  roles: string[];
}
