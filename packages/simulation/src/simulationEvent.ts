import type {
  DomainEvent,
  EntityId,
} from "@polymorph/domain";

export interface AccountDisabledPayload {
  accountId: EntityId;
}

export type AccountDisabledEvent =
  DomainEvent<
    "ACCOUNT_DISABLED",
    AccountDisabledPayload
  >;

export type SimulationEvent =
  AccountDisabledEvent;
