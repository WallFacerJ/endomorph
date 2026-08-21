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

  const scenario = {
    id: options.id,
    name: options.name,
    description: options.description,

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

    actions: [
      {
        id: "action-isolate-device",
        label: `Isolate ${victimDevice?.hostname ?? "the workstation"}`,
        description:
          "Cut the host off from the network while preserving it for investigation. Stops the beacon and any further lateral movement.",
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
        description:
          "Terminate the active session established from the unfamiliar address.",
        events: [
          {
            id: "response-revoke-session",
            type: "SESSION_REVOKED",
            timestamp: responseTimestamp,
            source: "identity",
            subjectId:
              incident.sessionId,
            payload: {
              sessionId:
                incident.sessionId,
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
          "Force a password reset but leave the session and host untouched.",
        // A plausible-looking half-measure. It reads like real remediation,
        // which is the point: the penalty has to be earned by reasoning
        // about the evidence, not by spotting the obviously wrong card.
        assessment: {
          penalty: 25,
          rationale:
            "The established session survives a password reset, and the host continues beaconing. Containment is incomplete.",
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
    ],

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
        id: "objective-session-revoked",
        kind: "session_status",
        label:
          "Attacker session revoked",
        description:
          "The session established from the unfamiliar address is terminated.",
        sessionId: incident.sessionId,
        expectedStatus: "revoked",
      },
    ],

    investigation: {
      alertId: incident.alertId,
      userId: incident.victimUserId,
      accountId: incident.victimAccountId,
      deviceId: incident.victimDeviceId,
      sessionId: incident.sessionId,
      primaryActionId:
        "action-disable-account",
      responseActionIds: [
        "action-isolate-device",
        "action-disable-account",
        "action-revoke-session",
        "action-reset-password-only",
      ],
    },

    groundTruth: {
      summary: incident.summary,
      timeline: incident.timeline,
      techniques: incident.techniques,
      severity: "high",
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
