import type {
  EntityStatus,
  SessionStatus,
} from "@polymorph/domain";

import type {
  WorldState,
} from "./worldState";

export interface AccountStatusScenarioObjective {
  id: string;

  kind: "account_status";

  label: string;

  description: string;

  accountId: string;

  expectedStatus: EntityStatus;
}

export interface SessionStatusScenarioObjective {
  id: string;

  kind: "session_status";

  label: string;

  description: string;

  sessionId: string;

  expectedStatus: SessionStatus;
}

export type ScenarioObjective =
  | AccountStatusScenarioObjective
  | SessionStatusScenarioObjective;

export interface ScenarioObjectiveResult {
  id: string;

  label: string;

  description: string;

  met: boolean;
}

export type ScenarioOutcomeStatus =
  | "in_progress"
  | "succeeded"
  | "failed";

export interface ScenarioOutcome {
  status: ScenarioOutcomeStatus;

  objectives:
    readonly ScenarioObjectiveResult[];
}

function evaluateObjective(
  objective: ScenarioObjective,
  world: WorldState,
): ScenarioObjectiveResult {
  switch (objective.kind) {
    case "account_status": {
      const account =
        world.accounts[
          objective.accountId
        ];

      if (!account) {
        throw new Error(
          `Scenario objective ${objective.id} references missing account: ${objective.accountId}`,
        );
      }

      return {
        id: objective.id,
        label: objective.label,
        description:
          objective.description,
        met:
          account.status ===
          objective.expectedStatus,
      };
    }

    case "session_status": {
      const session =
        world.sessions[
          objective.sessionId
        ];

      if (!session) {
        throw new Error(
          `Scenario objective ${objective.id} references missing session: ${objective.sessionId}`,
        );
      }

      return {
        id: objective.id,
        label: objective.label,
        description:
          objective.description,
        met:
          session.status ===
          objective.expectedStatus,
      };
    }
  }
}

export function evaluateScenarioOutcome(
  objectives:
    readonly ScenarioObjective[],
  world: WorldState,
): ScenarioOutcome {
  const results = objectives.map(
    (objective) =>
      evaluateObjective(
        objective,
        world,
      ),
  );

  return {
    status:
      results.every(
        (result) => result.met,
      )
        ? "succeeded"
        : "in_progress",
    objectives: results,
  };
}

export function finalizeScenarioOutcome(
  outcome: ScenarioOutcome,
): ScenarioOutcome {
  return {
    status:
      outcome.status === "succeeded"
        ? "succeeded"
        : "failed",
    objectives:
      outcome.objectives.map(
        (objective) => ({
          ...objective,
        }),
      ),
  };
}
