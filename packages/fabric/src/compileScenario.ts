import type {
  SimulationEvent,
} from "@endomorph/simulation";

import {
  generateEnterprise,
  type GeneratedEnterprise,
} from "./generateEnterprise.js";

import {
  generateBackgroundActivity,
  DEFAULT_ACTIVITY_OPTIONS,
  type ActivityOptions,
} from "./backgroundActivity.js";

import {
  generateIncident,
  DEFAULT_INCIDENT_OPTIONS,
  type GeneratedIncident,
  type IncidentOptions,
} from "./generateIncident.js";

import type {
  EnterpriseProfile,
} from "./enterpriseProfile.js";

const MINUTES_PER_DAY = 1440;

/**
 * Compiles a generated enterprise, its background noise, and a planted
 * incident into the versioned scenario file the runtime already loads.
 *
 * The output is deliberately the existing v1 contract rather than a new one.
 * The scenario schema, compiler, projections, and browser workspaces all
 * consume it today, so emitting it means the generated world is playable
 * immediately instead of after a parallel pipeline is built.
 */

export interface CompileScenarioOptions {
  readonly id: string;

  readonly name: string;

  readonly description: string;

  readonly enterprise?: Partial<EnterpriseProfile>;

  readonly activity?: Partial<ActivityOptions>;

  readonly incident?: Partial<IncidentOptions>;
}

export interface CompiledScenario {
  readonly file: unknown;

  readonly enterprise: GeneratedEnterprise;

  readonly incident: GeneratedIncident;

  readonly backgroundEventCount: number;

  readonly totalEventCount: number;
}

export function compileScenario(
  options: CompileScenarioOptions,
): CompiledScenario {
  const enterprise = generateEnterprise(
    options.enterprise,
  );

  const activityOptions = {
    ...DEFAULT_ACTIVITY_OPTIONS,
    ...options.activity,
  };

  const background =
    generateBackgroundActivity(
      enterprise,
      activityOptions,
    );

  // The intrusion lands on the final generated day, so every earlier day is
  // untouched baseline. That is what lets an analyst say the sign-in came
  // from an address this account has never used.
  const incidentDayOffset =
    (activityOptions.days - 1) *
    MINUTES_PER_DAY;

  const incident = generateIncident(
    enterprise,
    {
      ...options.incident,
      startMinute:
        incidentDayOffset +
        (options.incident?.startMinute ??
          DEFAULT_INCIDENT_OPTIONS.startMinute),
    },
  );

  // Detection is "now" for the analyst. Background activity generated after
  // the alert has not happened yet from their point of view, and including
  // it would also put the opening history ahead of any response the analyst
  // takes -- which the event store rejects, since it appends responses to
  // the same ordered history.
  const detectionTimestamp =
    incident.events[
      incident.events.length - 1
    ].timestamp;

  // Interleaving by timestamp is what buries the chain. An analyst opening
  // the SIEM sees one stream, not a noise section followed by an attack
  // section.
  const openingEvents: SimulationEvent[] =
    [
      ...background.filter(
        (event) =>
          event.timestamp <=
          detectionTimestamp,
      ),
      ...incident.events,
    ].sort(
      (left, right) =>
        left.timestamp.localeCompare(
          right.timestamp,
        ) ||
        left.id.localeCompare(right.id),
    );

  // Responses happen at or after the last thing the analyst can see.
  const responseTimestamp =
    openingEvents[
      openingEvents.length - 1
    ].timestamp;

  /**
   * The session the investigation is anchored to.
   *
   * Most plans open one: the attacker authenticates and a session appears in
   * the incident's own events. An intrusion that never authenticates has
   * none, and pointing the investigation at an id nothing emitted produced a
   * scenario the loader refused outright -- caught by opening the page, not
   * by the suite, which validated the shape and not the reference.
   *
   * Falling back to the subject's own genuine session is not a workaround
   * for that error; it is the accurate answer. When malicious code runs
   * inside a session the real user already had open, that session is where
   * it ran, and it is what an analyst should be looking at in Identity. It
   * is benign, it is labelled benign, and it is emphatically not something
   * to revoke -- which is why this plan declares no session containment.
   */
  const investigationSessionId =
    openingEvents.some(
      (event) =>
        event.type === "SESSION_STARTED" &&
        event.payload.sessionId ===
          incident.sessionId,
    )
      ? incident.sessionId
      : ([...openingEvents]
          .reverse()
          .find(
            (event) =>
              event.type ===
                "SESSION_STARTED" &&
              event.payload.accountId ===
                incident.victimAccountId,
          )?.payload as
          | { sessionId?: string }
          | undefined
        )?.sessionId;

  if (!investigationSessionId) {
    throw new Error(
      `Scenario ${options.id}: no session exists for account ${incident.victimAccountId}, so the investigation has nothing to anchor to.`,
    );
  }

  const victim = enterprise.users.find(
    (user) =>
      user.id === incident.victimUserId,
  );

  const victimDevice =
    enterprise.devices.find(
      (device) =>
        device.id ===
        incident.victimDeviceId,
    );

  /**
   * Whether the plan declares this response as available.
   *
   * The compiler used to emit all four actions for every incident and ignore
   * `containment` entirely, which was invisible while every plan happened to
   * open a session. It stopped being invisible with an intrusion where the
   * attacker never authenticates: `action-revoke-session` had no session to
   * point at, so it routed to no console and, in professional mode where the
   * response row is hidden, became unreachable -- a run that cannot be
   * completed. The objective that depends on it had the same problem.
   */
  /*
    What this incident actually does, so a response can only claim to stop
    what is there.

    The isolate action told every analyst it "stops the beacon and any
    further lateral movement". Privileged-insider does neither -- it is an
    administrator reading a file share from their own desk -- and each of the
    other plans does one or the other, not both. A response that overstates
    what it achieves is teaching the wrong thing about containment.
  */
  const incidentConnections =
    incident.events.filter(
      (event) =>
        event.type ===
        "NETWORK_CONNECTION",
    );

  const beacons =
    incidentConnections.some(
      (event) =>
        !(
          event.payload as {
            destinationIp?: string;
          }
        ).destinationIp?.startsWith(
          "10.",
        ),
    );

  const movesLaterally =
    incidentConnections.some(
      (event) =>
        (
          event.payload as {
            destinationPort?: number;
          }
        ).destinationPort === 445,
    );

  const isolationStops = [
    beacons ? "the beacon" : undefined,
    movesLaterally
      ? "any further movement between hosts"
      : undefined,
  ].filter(
    (value): value is string =>
      value !== undefined,
  );

  const isolateDescription = `Cut ${
    victimDevice?.hostname ?? "the host"
  } off from the network while preserving it for investigation.${
    isolationStops.length > 0
      ? ` Stops ${isolationStops.join(
          " and ",
        )}.`
      : " Anything still running on it loses its outbound path."
  }`;

  /*
    Why the half-measure is penalised, said in terms of this incident.

    It used to be one fixed sentence for every scenario: "The established
    session survives a password reset, and the host continues beaconing."
    Neither half is true everywhere. Three of the five plans have no beacon
    at all, and the macro intrusion never opens a session -- that is its
    entire premise. So four scenarios out of five explained a scored penalty
    with something that did not happen, which is the same failing as ground
    truth that lies, only pointed at the analyst's feedback instead of the
    data.

    Built from what the incident actually leaves behind.
  */
  const remaining: string[] = [];

  if (incident.containment.disableAccount) {
    remaining.push(
      "the credential is still enabled",
    );
  }

  if (incident.containment.revokeSession) {
    remaining.push(
      "the session opened with it stays open",
    );
  }

  if (incident.containment.isolateDevice) {
    remaining.push(
      `${victimDevice?.hostname ?? "the host"} is still on the network`,
    );
  }

  const halfMeasureRationale =
    remaining.length > 0
      ? `A password reset changes the credential and nothing else: ${remaining.join(
          ", ",
        )}. Containment is incomplete.`
      : "A password reset changes the credential and nothing else. Containment is incomplete.";

  const supportsAction = (
    actionId: string,
  ): boolean => {
    if (
      actionId === "action-revoke-session"
    ) {
      return incident.containment
        .revokeSession;
    }

    if (
      actionId === "action-disable-account"
    ) {
      return incident.containment
        .disableAccount;
    }

    if (
      actionId === "action-isolate-device"
    ) {
      return incident.containment
        .isolateDevice;
    }

    // The half-measure is always offered: its whole purpose is to be a
    // plausible wrong answer, and removing it where it is wrong would remove
    // the decision being tested.
    return true;
  };

  const scenario = {
    id: options.id,
    name: options.name,
    description: `${options.description} Incident: ${incident.planName} (${incident.difficulty}).`,

    initialWorld: {
      simulationTime:
        enterprise.profile.startTime,
      organizations:
        enterprise.organizations,
      users: enterprise.users,
      accounts: enterprise.accounts,
      devices: enterprise.devices,
      files: enterprise.files,
      applications:
        enterprise.applications,
      sessions: [],
    },

    openingEvents,

    actions: ([
      {
        id: "action-isolate-device",
        label: `Isolate ${victimDevice?.hostname ?? "the workstation"}`,
        description: isolateDescription,
        events: [
          {
            id: "response-isolate-heartbeat",
            type: "ENDPOINT_HEARTBEAT",
            timestamp: responseTimestamp,
            source: "edr",
            subjectId:
              incident.victimDeviceId,
            payload: {
              deviceId:
                incident.victimDeviceId,
              status: "inactive",
              ipAddresses:
                victimDevice?.ipAddresses ??
                [],
            },
          },
        ],
      },
      {
        id: "action-disable-account",
        label: `Disable ${victim?.displayName ?? "the compromised account"}`,
        description:
          "Disable the compromised account in the directory so the credential cannot be reused.",
        events: [
          {
            id: "response-disable-account",
            type: "ACCOUNT_DISABLED",
            timestamp: responseTimestamp,
            source: "identity",
            subjectId:
              incident.victimAccountId,
            payload: {
              accountId:
                incident.victimAccountId,
              reason:
                "Confirmed credential compromise.",
            },
          },
        ],
      },
      {
        id: "action-revoke-session",
        label:
          "Revoke the attacker's session",
        description: `Terminate the session this account has open on ${
          victimDevice?.hostname ??
          "the host"
        }.`,
        events: [
          {
            id: "response-revoke-session",
            type: "SESSION_REVOKED",
            timestamp: responseTimestamp,
            source: "identity",
            subjectId:
              investigationSessionId,
            payload: {
              sessionId:
                investigationSessionId,
              reason:
                "Session originated from attacker infrastructure.",
            },
          },
        ],
      },
      {
        id: "action-reset-password-only",
        label:
          "Reset the password and take no further action",
        description:
          "Force a password reset and take no other action.",
        // A plausible-looking half-measure. It reads like real remediation,
        // which is the point: the penalty has to be earned by reasoning
        // about the evidence, not by spotting the obviously wrong card.
        assessment: {
          penalty: 25,
          rationale: halfMeasureRationale,
        },
        events: [
          {
            id: "response-password-reset",
            type: "AUTH_LOGIN_FAILED",
            timestamp: responseTimestamp,
            source: "identity",
            subjectId:
              incident.victimUserId,
            payload: {
              username: `${victim?.email ?? "unknown"}`,
              reason: "invalid_credentials",
              sourceIp:
                incident.attackerIp,
            },
          },
        ],
      },
    ] as const).filter((action) =>
      supportsAction(action.id),
    ),

    objectives: [
      {
        id: "objective-account-disabled",
        kind: "account_status",
        label:
          "Compromised account disabled",
        description:
          "The account used from attacker infrastructure is no longer usable.",
        accountId:
          incident.victimAccountId,
        expectedStatus: "disabled",
      },
      {
        id: "objective-device-isolated",
        kind: "device_status",
        label: "Compromised endpoint isolated",
        description:
          "The host is off the network, so anything still running on it cannot reach out.",
        deviceId: incident.victimDeviceId,
        expectedStatus: "inactive",
      },
      {
        id: "objective-session-revoked",
        kind: "session_status",
        label:
          "Attacker session revoked",
        description:
          "The session established from the unfamiliar address is terminated.",
        sessionId:
          investigationSessionId,
        expectedStatus: "revoked",
      },
    ].filter((objective) => {
      if (
        objective.kind ===
        "session_status"
      ) {
        return incident.containment
          .revokeSession;
      }

      if (
        objective.kind === "device_status"
      ) {
        return incident.containment
          .isolateDevice;
      }

      return incident.containment
        .disableAccount;
    }),

    investigation: {
      alertId: incident.alertId,
      userId: incident.victimUserId,
      accountId: incident.victimAccountId,
      deviceId: incident.victimDeviceId,
      sessionId: investigationSessionId,
      primaryActionId:
        incident.containment
          .disableAccount
          ? "action-disable-account"
          : "action-isolate-device",
      responseActionIds: [
        "action-isolate-device",
        "action-disable-account",
        "action-revoke-session",
        "action-reset-password-only",
      ].filter(supportsAction),
    },

    groundTruth: {
      summary: `${incident.summary}

What this incident teaches: ${incident.lesson}`,
      timeline: incident.timeline,
      techniques: incident.techniques,
      severity: incident.alertSeverity,
    },

    questions: incident.questions,
  };


  return {
    file: {
      version: 1,
      kind: "endomorph-scenario",
      scenario,
    },
    enterprise,
    incident,
    backgroundEventCount:
      background.length,
    totalEventCount:
      openingEvents.length,
  };
}
