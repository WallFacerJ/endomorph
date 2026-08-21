import type {
  SimulationEvent,
} from "@endomorph/simulation";

import {
  RandomCursor,
} from "./randomCursor.js";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

import {
  selectAttackPlan,
  type AttackPlan,
  type AttackTactic,
  type IncidentCast,
} from "./attackPlan.js";

import type {
  GeneratedEnterprise,
} from "./generateEnterprise.js";

/**
 * Renders an attack plan against a generated enterprise.
 *
 * This used to be one hard-coded chain. It is now a renderer: the plan
 * supplies the steps, the ATT&CK mapping, and the questions, and this
 * resolves a cast from the generated world and plays them. Adding an
 * intrusion means adding data.
 */

export interface IncidentGroundTruthStep {
  readonly eventId: string;
  readonly significance: string;
  readonly techniqueId?: string;
  readonly reasoning?: string;
}

export interface IncidentTechnique {
  readonly id: string;
  readonly name: string;
  readonly tactic: AttackTactic;
  readonly eventIds: readonly string[];
}

export interface IncidentQuestion {
  readonly id: string;
  readonly prompt: string;
  readonly accepted: readonly string[];
  readonly hint?: string;
  readonly surface:
    | "siem"
    | "endpoint"
    | "identity"
    | "case";
  readonly points: number;
  readonly evidenceEventId?: string;
}

export interface GeneratedIncident {
  readonly planId: string;
  readonly planName: string;
  readonly difficulty: string;
  readonly lesson: string;

  readonly events: SimulationEvent[];

  readonly alertId: string;
  readonly alertSeverity: string;

  readonly victimUserId: string;
  readonly victimAccountId: string;
  readonly victimDeviceId: string;
  readonly sessionId: string;
  readonly lateralTargetDeviceId: string;
  readonly targetFileId: string;
  readonly attackerIp: string;

  readonly summary: string;
  readonly timeline: IncidentGroundTruthStep[];
  readonly techniques: IncidentTechnique[];
  readonly questions: IncidentQuestion[];

  readonly containment: AttackPlan["containment"];
}

export interface IncidentOptions {
  /** Minutes after the start of history when the intrusion begins. */
  readonly startMinute: number;

  /** Force a specific plan. Otherwise chosen deterministically by seed. */
  readonly planId?: string;

  /** Plans to choose from. Defaults to the shipped library. */
  readonly plans?: readonly AttackPlan[];
}

export const DEFAULT_INCIDENT_OPTIONS: IncidentOptions =
  {
    // Late in the working day, so nearly a full day of ordinary activity
    // precedes detection and the analyst has real history to sift through.
    startMinute: 470,
  };

/** Hosting ranges that belong to no generated department subnet. */
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
 * Resolves the entities a plan needs.
 *
 * Throws rather than silently substituting. A plan that requires a
 * privileged account and quietly gets an ordinary one would render an
 * incident whose ground truth is a lie.
 */
function resolveCast(
  enterprise: GeneratedEnterprise,
  plan: AttackPlan,
  cursor: RandomCursor,
): IncidentCast {
  const candidates =
    enterprise.users.filter(
      (user) =>
        user.status === "active" &&
        user.deviceIds.length > 0 &&
        (plan.requires.departments ===
          undefined ||
          plan.requires.departments.includes(
            user.department,
          )) &&
        (!plan.requires
          .privilegedAccount ||
          user.accountIds.some(
            (accountId) =>
              enterprise.privilegedAccountIds.includes(
                accountId,
              ),
          )),
    );

  if (candidates.length === 0) {
    throw new Error(
      `No eligible subject for plan ${plan.id}. Requirements: ${JSON.stringify(
        plan.requires,
      )}`,
    );
  }

  const subject = cursor.pick(candidates);

  const subjectAccount =
    enterprise.accounts.find(
      (account) =>
        account.userId === subject.id &&
        !account.id.endsWith("-adm"),
    );

  if (!subjectAccount) {
    throw new Error(
      `Subject ${subject.id} has no primary account.`,
    );
  }

  const privilegedAccount =
    enterprise.accounts.find(
      (account) =>
        account.userId === subject.id &&
        enterprise.privilegedAccountIds.includes(
          account.id,
        ),
    );

  if (
    plan.requires.privilegedAccount &&
    !privilegedAccount
  ) {
    throw new Error(
      `Plan ${plan.id} requires a privileged account and subject ${subject.id} has none.`,
    );
  }

  const subjectDevice =
    enterprise.devices.find(
      (device) =>
        device.id === subject.deviceIds[0],
    );

  if (!subjectDevice) {
    throw new Error(
      `Subject ${subject.id} has no device.`,
    );
  }

  const servers = enterprise.devices.filter(
    (device) => !device.ownerUserId,
  );

  const lateralTarget =
    servers.find(
      (device) =>
        device.hostname === "FS-01",
    ) ?? servers[0];

  const secondaryTarget =
    servers.find(
      (device) =>
        device.id !== lateralTarget?.id,
    ) ?? lateralTarget;

  if (!lateralTarget || !secondaryTarget) {
    throw new Error(
      "Enterprise has no servers to move laterally to.",
    );
  }

  // A disabled account belonging to someone other than the subject. These
  // exist in the generated world as ordinary attrition noise.
  const dormantAccount =
    enterprise.accounts.find(
      (account) =>
        account.status === "disabled" &&
        account.userId !== subject.id,
    );

  const dormantUser = dormantAccount
    ? enterprise.users.find(
        (user) =>
          user.id ===
          dormantAccount.userId,
      )
    : undefined;

  if (
    plan.requires.dormantAccount &&
    (!dormantAccount || !dormantUser)
  ) {
    throw new Error(
      `Plan ${plan.id} requires a dormant account and none exist in this enterprise.`,
    );
  }

  const restricted =
    enterprise.files.filter(
      (file) =>
        file.classification ===
        "restricted",
    );

  if (
    plan.requires.restrictedFile &&
    restricted.length === 0
  ) {
    throw new Error(
      `Plan ${plan.id} requires a restricted document and none exist.`,
    );
  }

  const targetFile =
    restricted.length > 0
      ? cursor.pick(restricted)
      : enterprise.files[0];

  if (!targetFile) {
    throw new Error(
      "Enterprise has no files.",
    );
  }

  return {
    subject,
    subjectAccount,
    privilegedAccount,
    subjectDevice,
    dormantUser,
    dormantAccount,
    lateralTarget,
    secondaryTarget,
    targetFile,
    identityApplication:
      enterprise.applications.find(
        (application) =>
          application.kind === "identity",
      ),
    edrApplication:
      enterprise.applications.find(
        (application) =>
          application.kind === "edr",
      ),
    externalIp: cursor.pick(ATTACKER_IPS),
    c2Ip: cursor.pick(C2_IPS),
    subjectIp:
      subjectDevice.ipAddresses[0],
    sessionId: `session-incident-${subject.id}`,
  };
}

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

  const plan = selectAttackPlan(
    options.plans ?? ATTACK_PLANS,
    cursor.fork("plan"),
    options.planId,
  );

  const cast = resolveCast(
    enterprise,
    plan,
    cursor.fork("cast"),
  );

  const startMilliseconds = Date.parse(
    enterprise.profile.startTime,
  );

  const events: SimulationEvent[] = [];

  const timeline: IncidentGroundTruthStep[] =
    [];

  // Step id -> emitted event ids, so techniques and questions can reference
  // a step by name without knowing how many times it repeated.
  const emittedByStep = new Map<
    string,
    string[]
  >();

  let minute = options.startMinute;

  for (const step of plan.steps) {
    const repeat = step.repeat ?? 1;

    for (
      let index = 0;
      index < repeat;
      index += 1
    ) {
      const eventId =
        repeat > 1
          ? `incident-${step.id}-${index + 1}`
          : `incident-${step.id}`;

      events.push({
        ...step.build(cast, index),
        id: eventId,
        timestamp: isoAt(
          startMilliseconds,
          minute,
        ),
      } as SimulationEvent);

      timeline.push({
        eventId,
        significance:
          step.significance(cast),
        techniqueId: step.techniqueId,
        reasoning:
          step.reasoning?.(cast),
      });

      const existing =
        emittedByStep.get(step.id) ?? [];

      existing.push(eventId);

      emittedByStep.set(
        step.id,
        existing,
      );

      minute += step.advanceBy;
    }
  }

  const techniques: IncidentTechnique[] =
    plan.techniques.map((technique) => ({
      id: technique.id,
      name: technique.name,
      tactic: technique.tactic,
      eventIds: plan.steps
        .filter(
          (step) =>
            step.techniqueId ===
            technique.id,
        )
        .flatMap(
          (step) =>
            emittedByStep.get(step.id) ??
            [],
        ),
    }));

  const resolveStepEvent = (
    stepId: string | undefined,
  ): string | undefined => {
    if (!stepId) {
      return undefined;
    }

    const direct =
      emittedByStep.get(stepId);

    if (direct && direct.length > 0) {
      return direct[0];
    }

    // Questions may also cite an exact emitted id, e.g. "spray-1".
    const exact = `incident-${stepId}`;

    return events.some(
      (event) => event.id === exact,
    )
      ? exact
      : undefined;
  };

  const alertId = "alert-incident-001";

  const relatedEventIds =
    plan.alertStepIds.flatMap(
      (stepId) => {
        const resolved =
          resolveStepEvent(stepId);

        return resolved ? [resolved] : [];
      },
    );

  events.push({
    id: alertId,
    type: "ALERT_CREATED",
    timestamp: isoAt(
      startMilliseconds,
      minute,
    ),
    source: "edr",
    subjectId: cast.subjectDevice.id,
    payload: {
      alertId,
      title: plan.alertTitle(cast),
      severity: plan.alertSeverity,
      applicationId:
        cast.edrApplication?.id,
      relatedEventIds:
        relatedEventIds.length > 0
          ? relatedEventIds
          : [events[0].id],
      relatedEntityIds: [
        cast.subjectDevice.id,
        cast.subject.id,
        cast.subjectAccount.id,
      ],
    },
  } as SimulationEvent);

  timeline.push({
    eventId: alertId,
    significance:
      "Detection fires. Everything before this is what the analyst has to reconstruct.",
  });

  const questions: IncidentQuestion[] =
    plan.questions.map((question) => ({
      id: question.id,
      prompt: question.prompt(cast),
      accepted: [
        ...new Set(
          question
            .accepted(cast)
            .flatMap((value) => [
              value,
              value.toLowerCase(),
            ]),
        ),
      ],
      hint: question.hint,
      surface: question.surface,
      points: question.points,
      evidenceEventId: resolveStepEvent(
        question.evidenceStepId,
      ),
    }));

  return {
    planId: plan.id,
    planName: plan.name,
    difficulty: plan.difficulty,
    lesson: plan.lesson,
    events,
    alertId,
    alertSeverity: plan.alertSeverity,
    victimUserId: cast.subject.id,
    victimAccountId:
      cast.privilegedAccount?.id ??
      cast.subjectAccount.id,
    victimDeviceId: cast.subjectDevice.id,
    sessionId: cast.sessionId,
    lateralTargetDeviceId:
      cast.lateralTarget.id,
    targetFileId: cast.targetFile.id,
    attackerIp: cast.externalIp,
    summary: plan.summary(cast),
    timeline,
    techniques,
    questions,
    containment: plan.containment,
  };
}
