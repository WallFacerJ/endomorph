import type {
  EntityId,
  SimulationTimestamp,
} from "./types";

export interface DomainEvent<
  TType extends string = string,
  TPayload = unknown,
> {
  id: EntityId;

  type: TType;

  timestamp: SimulationTimestamp;

  source: string;

  actorId?: EntityId;

  subjectId?: EntityId;

  payload: TPayload;
}
