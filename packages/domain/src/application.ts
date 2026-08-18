import type {
  EntityId,
  EntityStatus,
} from "./types";

export type ApplicationKind =
  | "siem"
  | "edr"
  | "identity"
  | "email"
  | "hr"
  | "cloud"
  | "file_server"
  | "custom";

export interface Application {
  id: EntityId;

  organizationId: EntityId;

  name: string;

  kind: ApplicationKind;

  status: EntityStatus;
}
