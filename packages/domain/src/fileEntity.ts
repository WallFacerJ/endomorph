import type { EntityId } from "./types";

export type FileClassification =
  | "public"
  | "internal"
  | "confidential"
  | "restricted";

export interface FileEntity {
  id: EntityId;

  organizationId: EntityId;

  name: string;

  path: string;

  classification: FileClassification;

  ownerUserId?: EntityId;

  deviceId?: EntityId;
}
