import type {
  SimulationEvent,
} from "@endomorph/simulation";

import {
  RandomCursor,
} from "./randomCursor.js";

import type {
  GeneratedEnterprise,
} from "./generateEnterprise.js";

/**
 * A planted incident.
 *
 * The attack is generated against the same enterprise the noise is generated
 * from, so every actor, host, and document in the chain is a real entity an
 * analyst can pivot to. The chain is deliberately not self-announcing: apart
 * from the closing alert, each step looks like something that also occurs
 * benignly somewhere in the background floor.
 */

export interface IncidentGroundTruthStep {
  readonly eventId: string;
  readonly significance: string;
}

export interface GeneratedIncident {
  readonly events: SimulationEvent[];

  readonly alertId: string;

  readonly victimUserId: string;

  readonly victimAccountId: string;

  readonly victimDeviceId: string;

  readonly sessionId: string;

  /** Server reached by lateral movement, if the chain got that far. */
  readonly lateralTargetDeviceId: string;

  /** Restricted document the intruder opened. */
  readonly targetFileId: string;

  readonly attackerIp: string;

  readonly summary: string;

  readonly timeline: IncidentGroundTruthStep[];
}

export interface IncidentOptions {
  /** Minutes after the start of the day when the intrusion begins. */
  readonly startMinute: number;

  /** Failed sign-ins before the intruder guesses correctly. */
  readonly sprayAttempts: number;
}

export const DEFAULT_INCIDENT_OPTIONS: IncidentOptions =
  {
    // Late in the working day, so nearly a full day of ordinary activity
    // precedes detection and the analyst has real history to sift through.
    startMinute: 470,
    sprayAttempts: 4,
  };

/** Hosting ranges that do not belong to any generated department subnet. */
const ATTACKER_IPS: readonly string[] = [
  "185.220.101.44",
  "45.153.160.132",
  "193.32.127.201",
  "91.219.236.18",
];

const C2_IPS: readonly string[] = [
  "185.220.101.79",
  "45.153.160.208",
];

function isoAt(
  startMilliseconds: number,
  offsetMinutes: number,
): string {
  return new Date(
    startMilliseconds +
      Math.round(offsetMinutes * 60000),
  ).toISOString();
}

/**
 * Plants an account-compromise chain into a generated enterprise.
 *
 * Password spray -> successful sign-in from unfamiliar infrastructure ->
 * encoded PowerShell -> C2 beacon -> host and domain discovery -> access to
 * a restricted document -> lateral movement to a server -> detection.
 */
export function generateIncident(
  enterprise: GeneratedEnterprise,
  overrides: Partial<IncidentOptions> = {},
): GeneratedIncident {
  const options = {
    ...DEFAULT_INCIDENT_OPTIONS,
    ...overrides,
  };

  const cursor = RandomCursor.root(
    enterprise.profile.seed,
  ).fork("incident");

  const startMilliseconds = Date.parse(
    enterprise.profile.startTime,
  );

  // -----------------------------------------------------------------------
  // Cast the incident from real generated entities
  // -----------------------------------------------------------------------

  // A Finance analyst is a plausible target and gives the incident real
  // business stakes through the documents that department owns.
  const candidates = enterprise.users.filter(
    (user) =>
      user.status === "active" &&
      user.department === "Finance" &&
      user.deviceIds.length > 0,
  );

  if (candidates.length === 0) {
    throw new Error(
      "Enterprise has no eligible incident victim.",
    );
  }

  const victim = cursor.pick(candidates);

  const victimAccountId =
    victim.accountIds.find(
      (accountId) =>
        !accountId.endsWith("-adm"),
    );

  if (!victimAccountId) {
    throw new Error(
      "Incident victim has no primary account.",
    );
  }

  const victimAccount =
    enterprise.accounts.find(
      (account) =>
        account.id === victimAccountId,
    );

  if (!victimAccount) {
    throw new Error(
      "Incident victim account is missing.",
    );
  }

  const victimDeviceId =
    victim.deviceIds[0];

  const victimDevice =
    enterprise.devices.find(
      (device) =>
        device.id === victimDeviceId,
    );

  if (!victimDevice) {
    throw new Error(
      "Incident victim device is missing.",
    );
  }

  const lateralTarget =
    enterprise.devices.find(
      (device) =>
        device.hostname === "FS-01",
    ) ??
    enterprise.devices.find(
      (device) => !device.ownerUserId,
    );

  if (!lateralTarget) {
    throw new Error(
      "Enterprise has no server to move laterally to.",
    );
  }

  const restrictedFiles =
    enterprise.files.filter(
      (file) =>
        file.classification ===
        "restricted",
    );

  const targetFile =
    restrictedFiles.length > 0
      ? cursor.pick(restrictedFiles)
      : enterprise.files[0];

  const identityApplication =
    enterprise.applications.find(
      (application) =>
        application.kind === "identity",
    );

  const edrApplication =
    enterprise.applications.find(
      (application) =>
        application.kind === "edr",
    );

  const attackerIp = cursor.pick(
    ATTACKER_IPS,
  );

  const c2Ip = cursor.pick(C2_IPS);

  const victimIp =
    victimDevice.ipAddresses[0];

  const sessionId = `session-incident-${victim.id}`;

  const events: SimulationEvent[] = [];

  const timeline: IncidentGroundTruthStep[] =
    [];

  let minute = options.startMinute;

  const emit = (
    id: string,
    significance: string,
    advanceBy: number,
    event: Omit<
      SimulationEvent,
      "id" | "timestamp"
    >,
  ): void => {
    events.push({
      ...event,
      id,
      timestamp: isoAt(
        startMilliseconds,
        minute,
      ),
    } as SimulationEvent);

    timeline.push({
      eventId: id,
      significance,
    });

    minute += advanceBy;
  };

  // -----------------------------------------------------------------------
  // 1. Password spray against the victim
  // -----------------------------------------------------------------------

  for (
    let attempt = 0;
    attempt < options.sprayAttempts;
    attempt += 1
  ) {
    emit(
      `incident-spray-${attempt + 1}`,
      `Failed sign-in for ${victimAccount.username} from ${attackerIp}, an address outside every corporate subnet.`,
      cursor.nextInt(1, 3),
      {
        type: "AUTH_LOGIN_FAILED",
        source: "identity",
        subjectId: victim.id,
        payload: {
          username:
            victimAccount.username,
          reason: "invalid_credentials",
          applicationId:
            identityApplication?.id,
          sourceIp: attackerIp,
        },
      },
    );
  }

  // -----------------------------------------------------------------------
  // 2. Successful sign-in from the same infrastructure
  // -----------------------------------------------------------------------

  emit(
    "incident-auth-success",
    `Successful sign-in for ${victimAccount.username} from ${attackerIp} minutes after repeated failures. This is the compromise point.`,
    1,
    {
      type: "AUTH_LOGIN_SUCCEEDED",
      source: "identity",
      actorId: victimAccount.id,
      subjectId: victim.id,
      payload: {
        accountId: victimAccount.id,
        userId: victim.id,
        deviceId: victimDevice.id,
        applicationId:
          identityApplication?.id,
        sourceIp: attackerIp,
      },
    },
  );

  emit(
    "incident-session-started",
    "Interactive session established on the compromised account.",
    3,
    {
      type: "SESSION_STARTED",
      source: "identity",
      actorId: victimAccount.id,
      subjectId: sessionId,
      payload: {
        sessionId,
        accountId: victimAccount.id,
        deviceId: victimDevice.id,
        applicationId:
          identityApplication?.id,
      },
    },
  );

  // -----------------------------------------------------------------------
  // 3. Encoded PowerShell on the victim workstation
  // -----------------------------------------------------------------------

  emit(
    "incident-powershell",
    "Base64-encoded PowerShell launched with an execution-policy bypass and a hidden window. No business process on this host runs this way.",
    2,
    {
      type: "PROCESS_STARTED",
      source: "edr",
      subjectId: victimDevice.id,
      payload: {
        deviceId: victimDevice.id,
        processId: "7734",
        image:
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        commandLine:
          "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        parentProcessId: "4102",
        accountId: victimAccount.id,
      },
    },
  );

  emit(
    "incident-beacon-1",
    `Outbound connection to ${c2Ip} on 443 immediately after the encoded command. Beaconing to attacker infrastructure.`,
    4,
    {
      type: "NETWORK_CONNECTION",
      source: "network",
      subjectId: victimDevice.id,
      payload: {
        deviceId: victimDevice.id,
        protocol: "tcp",
        sourceIp: victimIp,
        destinationIp: c2Ip,
        sourcePort: 51422,
        destinationPort: 443,
      },
    },
  );

  // -----------------------------------------------------------------------
  // 4. Discovery
  // -----------------------------------------------------------------------

  emit(
    "incident-discovery-whoami",
    "Host and privilege discovery from the compromised session.",
    2,
    {
      type: "PROCESS_STARTED",
      source: "edr",
      subjectId: victimDevice.id,
      payload: {
        deviceId: victimDevice.id,
        processId: "7801",
        image:
          "C:\\Windows\\System32\\whoami.exe",
        commandLine: "whoami /groups",
        parentProcessId: "7734",
        accountId: victimAccount.id,
      },
    },
  );

  emit(
    "incident-discovery-net",
    "Domain administrator enumeration. The intruder is looking for an escalation path.",
    3,
    {
      type: "PROCESS_STARTED",
      source: "edr",
      subjectId: victimDevice.id,
      payload: {
        deviceId: victimDevice.id,
        processId: "7822",
        image:
          "C:\\Windows\\System32\\net.exe",
        commandLine:
          'net group "Domain Admins" /domain',
        parentProcessId: "7734",
        accountId: victimAccount.id,
      },
    },
  );

  emit(
    "incident-beacon-2",
    "Second beacon to the same infrastructure, consistent with a callback interval.",
    5,
    {
      type: "NETWORK_CONNECTION",
      source: "network",
      subjectId: victimDevice.id,
      payload: {
        deviceId: victimDevice.id,
        protocol: "tcp",
        sourceIp: victimIp,
        destinationIp: c2Ip,
        sourcePort: 51488,
        destinationPort: 443,
      },
    },
  );

  // -----------------------------------------------------------------------
  // 5. Collection
  // -----------------------------------------------------------------------

  emit(
    "incident-file-access",
    `Restricted document ${targetFile.name} opened by an account that has no routine history with it. This is the business impact.`,
    3,
    {
      type: "FILE_ACCESSED",
      source: "file_server",
      actorId: victimAccount.id,
      subjectId: targetFile.id,
      payload: {
        fileId: targetFile.id,
        operation: "read",
        deviceId: victimDevice.id,
        accountId: victimAccount.id,
      },
    },
  );

  // -----------------------------------------------------------------------
  // 6. Lateral movement
  // -----------------------------------------------------------------------

  emit(
    "incident-lateral",
    `SMB connection from the compromised workstation to ${lateralTarget.hostname}. Scope now extends beyond the initial host.`,
    2,
    {
      type: "NETWORK_CONNECTION",
      source: "network",
      subjectId: victimDevice.id,
      payload: {
        deviceId: victimDevice.id,
        protocol: "tcp",
        sourceIp: victimIp,
        destinationIp:
          lateralTarget.ipAddresses[0],
        sourcePort: 51533,
        destinationPort: 445,
      },
    },
  );

  // -----------------------------------------------------------------------
  // 7. Detection
  // -----------------------------------------------------------------------

  const alertId = "alert-incident-001";

  events.push({
    id: alertId,
    type: "ALERT_CREATED",
    timestamp: isoAt(
      startMilliseconds,
      minute,
    ),
    source: "edr",
    subjectId: victimDevice.id,
    payload: {
      alertId,
      title: `Suspicious encoded PowerShell on ${victimDevice.hostname}`,
      severity: "high",
      applicationId: edrApplication?.id,
      relatedEventIds: [
        "incident-powershell",
        "incident-beacon-1",
      ],
      relatedEntityIds: [
        victimDevice.id,
        victim.id,
        victimAccount.id,
      ],
    },
  } as SimulationEvent);

  timeline.push({
    eventId: alertId,
    significance:
      "Endpoint detection fires on the encoded command. Everything before this is what the analyst has to reconstruct.",
  });

  return {
    events,
    alertId,
    victimUserId: victim.id,
    victimAccountId: victimAccount.id,
    victimDeviceId: victimDevice.id,
    sessionId,
    lateralTargetDeviceId:
      lateralTarget.id,
    targetFileId: targetFile.id,
    attackerIp,
    summary: `${victim.displayName} (${victim.department}) had their account compromised from ${attackerIp} after a short password spray. The intruder ran encoded PowerShell on ${victimDevice.hostname}, beaconed to ${c2Ip}, enumerated domain administrators, opened the restricted document ${targetFile.name}, and moved laterally to ${lateralTarget.hostname} over SMB before endpoint detection fired.`,
    timeline,
  };
}
