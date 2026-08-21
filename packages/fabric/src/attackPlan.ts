import type {
  Account,
  Application,
  Device,
  FileEntity,
  User,
} from "@endomorph/domain";

import type {
  SimulationEvent,
} from "@endomorph/simulation";

import type {
  RandomCursor,
} from "./randomCursor.js";

/**
 * Attack plans as data.
 *
 * The first version of this generator hard-coded one intrusion. Changing the
 * seed produced different names and addresses but always the same chain, the
 * same techniques, and the same questions -- an analyst learned nothing the
 * second time. Depth without variety.
 *
 * A plan declares its steps, its ATT&CK mapping, and its questions. The
 * renderer resolves a cast from the generated enterprise and plays the plan
 * against it. Adding an intrusion means adding data, not editing the
 * renderer -- which is also what makes the library safely extensible by
 * generation rather than by hand: a plan is validated structurally and then
 * proven by the same determinism and coherence tests every other plan passes.
 */

export type AttackTactic =
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "collection"
  | "command_and_control"
  | "exfiltration"
  | "impact";

export type PlanDifficulty =
  | "guided"
  | "standard"
  | "advanced";

/**
 * The entities a plan operates on, resolved from the generated enterprise.
 *
 * Every plan gets the same cast shape so the renderer stays uniform; a plan
 * declares which parts it actually requires through `requires`.
 */
export interface IncidentCast {
  readonly subject: User;
  readonly subjectAccount: Account;
  readonly subjectDevice: Device;

  /** Elevated account belonging to the subject, when the plan needs one. */
  readonly privilegedAccount?: Account;

  readonly lateralTarget: Device;
  readonly secondaryTarget: Device;
  readonly targetFile: FileEntity;

  readonly identityApplication?: Application;
  readonly edrApplication?: Application;

  /** Address outside every corporate subnet. */
  readonly externalIp: string;

  /** Second external address, for command and control. */
  readonly c2Ip: string;

  readonly subjectIp: string;

  readonly sessionId: string;
}

export interface PlanRequirements {
  /** The subject must hold an elevated directory group. */
  readonly privilegedAccount?: boolean;

  /** The subject must belong to one of these departments. */
  readonly departments?: readonly string[];

  /** A restricted-classification document must exist. */
  readonly restrictedFile?: boolean;
}

export interface AttackStep {
  /** Stable id; also the event id, so ground truth can reference it. */
  readonly id: string;

  readonly techniqueId: string;

  readonly significance: (
    cast: IncidentCast,
  ) => string;

  /**
   * What an analyst should conclude from this step, and what to check next.
   *
   * The significance line says what happened; on its own that reads as a
   * narration of the answer rather than teaching. Reasoning is the part
   * that transfers: why this observation is suspicious, what it rules in or
   * out, and where it points.
   */
  readonly reasoning?: (
    cast: IncidentCast,
  ) => string;

  /** Minutes to advance after this step. */
  readonly advanceBy: number;

  /** Emitted `repeat` times, with `-1`, `-2`… appended to the id. */
  readonly repeat?: number;

  readonly build: (
    cast: IncidentCast,
    index: number,
  ) => Omit<
    SimulationEvent,
    "id" | "timestamp"
  >;
}

export interface PlanTechnique {
  readonly id: string;
  readonly name: string;
  readonly tactic: AttackTactic;
}

export interface PlanQuestion {
  readonly id: string;
  readonly prompt: (
    cast: IncidentCast,
  ) => string;
  readonly accepted: (
    cast: IncidentCast,
  ) => readonly string[];
  readonly hint?: string;
  readonly surface:
    | "siem"
    | "endpoint"
    | "identity"
    | "case";
  readonly points: number;
  readonly evidenceStepId?: string;
}

export interface AttackPlan {
  readonly id: string;

  readonly name: string;

  readonly difficulty: PlanDifficulty;

  /** What the analyst is meant to take away. Shown after finalization. */
  readonly lesson: string;

  readonly requires: PlanRequirements;

  readonly techniques: readonly PlanTechnique[];

  readonly steps: readonly AttackStep[];

  readonly questions: readonly PlanQuestion[];

  readonly alertTitle: (
    cast: IncidentCast,
  ) => string;

  readonly alertSeverity:
    | "low"
    | "medium"
    | "high"
    | "critical";

  /** Which emitted steps the detection cites. */
  readonly alertStepIds: readonly string[];

  readonly summary: (
    cast: IncidentCast,
  ) => string;

  /** Response actions this plan expects to be available. */
  readonly containment: {
    readonly isolateDevice: boolean;
    readonly disableAccount: boolean;
    readonly revokeSession: boolean;
  };
}

/** Chooses a plan deterministically, honouring an explicit request. */
export function selectAttackPlan(
  plans: readonly AttackPlan[],
  cursor: RandomCursor,
  requestedId?: string,
): AttackPlan {
  if (requestedId) {
    const requested = plans.find(
      (plan) => plan.id === requestedId,
    );

    if (!requested) {
      throw new Error(
        `Unknown attack plan: ${requestedId}. Known plans: ${plans
          .map((plan) => plan.id)
          .join(", ")}`,
      );
    }

    return requested;
  }

  return cursor.pick(plans);
}
