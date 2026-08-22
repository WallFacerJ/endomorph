import type {
  EntityStatus,
  SessionStatus,
} from "@endomorph/domain";

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

/**
 * Whether a host has been cut off.
 *
 * For an intrusion that persists through a run key and beacons out,
 * isolating the endpoint is the containment that matters -- disabling the
 * credential leaves the malware running. Without this objective an analyst
 * who did the right thing was told the scenario failed.
 */
export interface DeviceStatusScenarioObjective {
  id: string;

  kind: "device_status";

  label: string;

  description: string;

  deviceId: string;

  expectedStatus: EntityStatus;
}

export type ScenarioObjective =
  | AccountStatusScenarioObjective
  | SessionStatusScenarioObjective
  | DeviceStatusScenarioObjective;

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

    case "device_status": {
      const device =
        world.devices[objective.deviceId];

      if (!device) {
        throw new Error(
          `Scenario objective ${objective.id} references missing device: ${objective.deviceId}`,
        );
      }

      return {
        id: objective.id,
        label: objective.label,
        description:
          objective.description,
        met:
          device.status ===
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
