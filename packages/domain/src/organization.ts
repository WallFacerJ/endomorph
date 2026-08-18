import type {
  EntityId,
  EntityStatus,
} from "./types";

export interface Organization {
  id: EntityId;

  name: string;

  status: EntityStatus;

  departments: string[];
}
