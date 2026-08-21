import type {
  ScenarioAction,
} from "./simulationAdapter";

/**
 * Where a response action belongs.
 *
 * Professional runs do not show a row of response cards beside the
 * timeline; response work happens on the console where the analyst formed
 * the judgement. That only holds if every action has somewhere to live, so
 * routing is defined once here and asserted in tests rather than being
 * implied by two component-local filters that can drift apart.
 */
export type ActionSurface =
  | "endpoint"
  | "identity";

export function actionTargetsDevice(
  action: ScenarioAction,
  deviceId: string,
): boolean {
  return action.events.some((event) => {
    switch (event.type) {
      case "ENDPOINT_HEARTBEAT":
      case "PROCESS_STARTED":
      case "NETWORK_CONNECTION":
      case "FILE_ACCESSED":
        return (
          event.payload.deviceId ===
          deviceId
        );

      default:
        return false;
    }
  });
}

export function actionTargetsAccount(
  action: ScenarioAction,
  accountId: string,
  username: string,
  sessionIds: readonly string[],
): boolean {
  return action.events.some((event) => {
    switch (event.type) {
      case "ACCOUNT_DISABLED":
      case "ACCOUNT_ENABLED":
        return (
          event.payload.accountId ===
          accountId
        );

      case "SESSION_REVOKED":
        return sessionIds.includes(
          event.payload.sessionId,
        );

      // Credential operations are keyed by username rather than account id.
      // A password reset is an identity operation and belongs on that
      // console, not in a leftover list of answers.
      case "AUTH_LOGIN_FAILED":
      case "AUTH_LOGIN_SUCCEEDED":
        return (
          "username" in event.payload &&
          event.payload.username ===
            username
        );

      default:
        return false;
    }
  });
}

/**
 * Every surface an action can be performed from.
 *
 * An empty result means the action is unreachable in professional mode.
 */
export function routeAction(
  action: ScenarioAction,
  context: {
    deviceIds: readonly string[];
    accounts: readonly {
      id: string;
      username: string;
    }[];
    sessionIds: readonly string[];
  },
): ActionSurface[] {
  const surfaces: ActionSurface[] = [];

  if (
    context.deviceIds.some((deviceId) =>
      actionTargetsDevice(
        action,
        deviceId,
      ),
    )
  ) {
    surfaces.push("endpoint");
  }

  if (
    context.accounts.some((account) =>
      actionTargetsAccount(
        action,
        account.id,
        account.username,
        context.sessionIds,
      ),
    )
  ) {
    surfaces.push("identity");
  }

  return surfaces;
}
