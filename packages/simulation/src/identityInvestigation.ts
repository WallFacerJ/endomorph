import type {
  Account,
  Application,
  Device,
  EntityId,
  Session,
  User,
} from "@polymorph/domain";

import type {
  AccountStatusActivity,
  IdentityActivity,
  IdentityProjectionState,
  LoginFailedActivity,
  LoginSucceededActivity,
  SessionRevokedActivity,
  SessionStartedActivity,
} from "./identityProjection";

import type {
  WorldState,
} from "./worldState";

export type IdentityAuthenticationActivity =
  | LoginSucceededActivity
  | LoginFailedActivity;

export interface IdentitySessionContext {
  session: Session;
  device: Device | undefined;
  application: Application | undefined;
  startedEvent: SessionStartedActivity | undefined;
  revokedEvent: SessionRevokedActivity | undefined;
}

export interface IdentityAccountInvestigation {
  account: Account;
  user: User;
  authentication: readonly IdentityAuthenticationActivity[];
  sessions: readonly IdentitySessionContext[];
  accountStatusActivity: readonly AccountStatusActivity[];
}

export interface IdentityInventoryEntry {
  user: User;
  accounts: readonly Account[];
  activeSessionCount: number;
  successfulLoginCount: number;
  failedLoginCount: number;
  latestAuthenticationAt: string | undefined;
}

function compareActivity(
  left: { timestamp: string; eventId: string },
  right: { timestamp: string; eventId: string },
): number {
  const timestamp = left.timestamp.localeCompare(
    right.timestamp,
  );

  return timestamp !== 0
    ? timestamp
    : left.eventId.localeCompare(right.eventId);
}

function authenticationForAccount(
  state: IdentityProjectionState,
  account: Account,
): readonly IdentityAuthenticationActivity[] {
  return state.activity
    .filter(
      (
        activity,
      ): activity is IdentityAuthenticationActivity =>
        (activity.kind === "login_succeeded" &&
          activity.accountId === account.id) ||
        (activity.kind === "login_failed" &&
          activity.username === account.username),
    )
    .slice()
    .sort(compareActivity);
}

function sessionContextsForAccount(
  world: WorldState,
  state: IdentityProjectionState,
  accountId: EntityId,
): readonly IdentitySessionContext[] {
  return Object.values(world.sessions)
    .filter((session) =>
      session.accountId === accountId,
    )
    .sort((left, right) =>
      left.startedAt.localeCompare(right.startedAt) ||
      left.id.localeCompare(right.id),
    )
    .map((session) => ({
      session,
      device: session.deviceId
        ? world.devices[session.deviceId]
        : undefined,
      application: session.applicationId
        ? world.applications[session.applicationId]
        : undefined,
      startedEvent: state.activity.find(
        (
          activity,
        ): activity is SessionStartedActivity =>
          activity.kind === "session_started" &&
          activity.sessionId === session.id,
      ),
      revokedEvent: state.activity.find(
        (
          activity,
        ): activity is SessionRevokedActivity =>
          activity.kind === "session_revoked" &&
          activity.sessionId === session.id,
      ),
    }));
}

export function getIdentityAccountInvestigation(
  world: WorldState,
  state: IdentityProjectionState,
  accountId: EntityId,
): IdentityAccountInvestigation {
  const account = world.accounts[accountId];

  if (!account) {
    throw new Error(
      `Unknown account for identity investigation: ${accountId}`,
    );
  }

  const user = world.users[account.userId];

  if (!user) {
    throw new Error(
      `Account ${accountId} references missing user ${account.userId}`,
    );
  }

  const accountStatusActivity = state.activity
    .filter(
      (
        activity,
      ): activity is AccountStatusActivity =>
        (activity.kind === "account_disabled" ||
          activity.kind === "account_enabled") &&
        activity.accountId === account.id,
    )
    .slice()
    .sort(compareActivity);

  return {
    account,
    user,
    authentication:
      authenticationForAccount(state, account),
    sessions: sessionContextsForAccount(
      world,
      state,
      account.id,
    ),
    accountStatusActivity,
  };
}

export function getIdentityInventory(
  world: WorldState,
  state: IdentityProjectionState,
): readonly IdentityInventoryEntry[] {
  return Object.values(world.users)
    .map((user) => {
      const accounts = user.accountIds
        .map((accountId) => world.accounts[accountId])
        .filter(
          (account): account is Account =>
            account !== undefined,
        )
        .sort((left, right) =>
          left.username.localeCompare(right.username),
        );

      const authentication = accounts.flatMap(
        (account) =>
          authenticationForAccount(state, account),
      );

      const sessions = accounts.flatMap(
        (account) =>
          sessionContextsForAccount(
            world,
            state,
            account.id,
          ),
      );

      return {
        user,
        accounts,
        activeSessionCount: sessions.filter(
          (context) =>
            context.session.status === "active",
        ).length,
        successfulLoginCount:
          authentication.filter(
            (activity) =>
              activity.kind === "login_succeeded",
          ).length,
        failedLoginCount:
          authentication.filter(
            (activity) =>
              activity.kind === "login_failed",
          ).length,
        latestAuthenticationAt:
          authentication
            .slice()
            .sort(compareActivity)
            .at(-1)?.timestamp,
      };
    })
    .sort((left, right) =>
      left.user.displayName.localeCompare(
        right.user.displayName,
      ) ||
      left.user.id.localeCompare(right.user.id),
    );
}

export function getIdentityActivityEventId(
  activity: IdentityActivity,
): EntityId {
  return activity.eventId;
}
