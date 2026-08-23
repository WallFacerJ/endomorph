import type {
  EntityId,
  SimulationTimestamp,
} from "@endomorph/domain";

import type {
  AuthFailureReason,
  SimulationEvent,
} from "./simulationEvent";

import type {
  Projection,
} from "./projection";

interface IdentityActivityBase {
  eventId: EntityId;

  timestamp: SimulationTimestamp;
}

export interface LoginSucceededActivity
  extends IdentityActivityBase {
  kind: "login_succeeded";

  accountId: EntityId;

  userId: EntityId;

  deviceId: EntityId | undefined;

  applicationId: EntityId | undefined;

  sourceIp: string | undefined;
}

export interface LoginFailedActivity
  extends IdentityActivityBase {
  kind: "login_failed";

  username: string;

  reason: AuthFailureReason;

  deviceId: EntityId | undefined;

  applicationId: EntityId | undefined;

  sourceIp: string | undefined;
}

export interface AccountStatusActivity
  extends IdentityActivityBase {
  kind:
    | "account_disabled"
    | "account_enabled";

  accountId: EntityId;

  reason: string | undefined;
}

/**
 * A role added to an account.
 *
 * Its own activity kind rather than folding into account status, because
 * what an analyst needs from it is the role name -- "which privilege did
 * they take" is the question, and a status change cannot carry it.
 */
export interface RoleGrantedActivity
  extends IdentityActivityBase {
  kind: "role_granted";

  accountId: EntityId;

  role: string;

  applicationId: EntityId | undefined;

  reason: string | undefined;
}

export interface SessionStartedActivity
  extends IdentityActivityBase {
  kind: "session_started";

  sessionId: EntityId;

  accountId: EntityId;

  deviceId: EntityId | undefined;

  applicationId: EntityId | undefined;
}

export interface SessionRevokedActivity
  extends IdentityActivityBase {
  kind: "session_revoked";

  sessionId: EntityId;

  reason: string | undefined;
}

/** Everything the account-lifecycle view shows: status changes and grants. */
export type AccountLifecycleActivity =
  | AccountStatusActivity
  | RoleGrantedActivity;

export type IdentityActivity =
  | LoginSucceededActivity
  | LoginFailedActivity
  | AccountStatusActivity
  | RoleGrantedActivity
  | SessionStartedActivity
  | SessionRevokedActivity;

export interface IdentityProjectionState {
  activity: readonly IdentityActivity[];

  successfulLogins: number;

  failedLogins: number;
}

function createInitialState():
  IdentityProjectionState {
  return {
    activity: [],
    successfulLogins: 0,
    failedLogins: 0,
  };
}

function appendActivity(
  state: IdentityProjectionState,
  activity: IdentityActivity,
  loginDelta:
    | "success"
    | "failure"
    | undefined = undefined,
): IdentityProjectionState {
  return {
    activity: [
      ...state.activity,
      activity,
    ],

    successfulLogins:
      state.successfulLogins +
      (loginDelta === "success"
        ? 1
        : 0),

    failedLogins:
      state.failedLogins +
      (loginDelta === "failure"
        ? 1
        : 0),
  };
}

function reduceIdentityProjection(
  state: IdentityProjectionState,
  event: SimulationEvent,
): IdentityProjectionState {
  switch (event.type) {
    case "AUTH_LOGIN_SUCCEEDED":
      return appendActivity(
        state,
        {
          kind: "login_succeeded",
          eventId: event.id,
          timestamp: event.timestamp,
          accountId:
            event.payload.accountId,
          userId:
            event.payload.userId,
          deviceId:
            event.payload.deviceId,
          applicationId:
            event.payload.applicationId,
          sourceIp:
            event.payload.sourceIp,
        },
        "success",
      );

    case "AUTH_LOGIN_FAILED":
      return appendActivity(
        state,
        {
          kind: "login_failed",
          eventId: event.id,
          timestamp: event.timestamp,
          username:
            event.payload.username,
          reason:
            event.payload.reason,
          deviceId:
            event.payload.deviceId,
          applicationId:
            event.payload.applicationId,
          sourceIp:
            event.payload.sourceIp,
        },
        "failure",
      );

    case "ACCOUNT_DISABLED":
      return appendActivity(
        state,
        {
          kind: "account_disabled",
          eventId: event.id,
          timestamp: event.timestamp,
          accountId:
            event.payload.accountId,
          reason:
            event.payload.reason,
        },
      );

    case "ACCOUNT_ENABLED":
      return appendActivity(
        state,
        {
          kind: "account_enabled",
          eventId: event.id,
          timestamp: event.timestamp,
          accountId:
            event.payload.accountId,
          reason:
            event.payload.reason,
        },
      );

    case "ROLE_GRANTED":
      return appendActivity(state, {
        kind: "role_granted",
        eventId: event.id,
        timestamp: event.timestamp,
        accountId:
          event.payload.accountId,
        role: event.payload.role,
        applicationId:
          event.payload.applicationId,
        reason: event.payload.reason,
      });

    case "SESSION_STARTED":
      return appendActivity(
        state,
        {
          kind: "session_started",
          eventId: event.id,
          timestamp: event.timestamp,
          sessionId:
            event.payload.sessionId,
          accountId:
            event.payload.accountId,
          deviceId:
            event.payload.deviceId,
          applicationId:
            event.payload.applicationId,
        },
      );

    case "SESSION_REVOKED":
      return appendActivity(
        state,
        {
          kind: "session_revoked",
          eventId: event.id,
          timestamp: event.timestamp,
          sessionId:
            event.payload.sessionId,
          reason:
            event.payload.reason,
        },
      );

    default:
      return state;
  }
}

export const identityProjection:
  Projection<IdentityProjectionState> = {
    createInitialState,
    reduce: reduceIdentityProjection,
  };
