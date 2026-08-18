import type {
  EntityId,
  SimulationTimestamp,
} from "./types";

export type SessionStatus =
  | "active"
  | "ended"
  | "revoked";

export interface Session {
  id: EntityId;

  accountId: EntityId;

  deviceId?: EntityId;

  applicationId?: EntityId;

  startedAt: SimulationTimestamp;

  endedAt?: SimulationTimestamp;

  status: SessionStatus;
}
