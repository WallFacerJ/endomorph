import {
  InMemoryEventStore,
} from "./eventStore";

import {
  replayEvents,
} from "./replay";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  evaluateScenarioOutcome,
  finalizeScenarioOutcome,
} from "./scenarioOutcome";

import type {
  ScenarioObjective,
  ScenarioOutcome,
} from "./scenarioOutcome";

import {
  evaluateScenarioScore,
} from "./scenarioScore";

import type {
  ScenarioScore,
} from "./scenarioScore";

import type {
  WorldState,
} from "./worldState";

import {
  validateWorldState,
} from "./worldValidation";

export interface ScenarioActionAssessment {
  penalty: number;

  rationale: string;
}

export interface ScenarioAction {
  id: string;

  label: string;

  description: string;

  events: readonly SimulationEvent[];

  assessment?: ScenarioActionAssessment;
}

export interface ScenarioInvestigationContext {
  alertId: string;

  userId: string;

  accountId: string;

  deviceId: string;

  sessionId: string;

  primaryActionId: string;

  responseActionIds:
    readonly string[];
}

export interface ScenarioDefinition {
  id: string;

  name: string;

  description: string;

  initialWorld: WorldState;

  openingEvents: readonly SimulationEvent[];

  actions: readonly ScenarioAction[];

  objectives:
    readonly ScenarioObjective[];

  investigation:
    ScenarioInvestigationContext;
}

export interface ScenarioState {
  world: WorldState;

  events: readonly SimulationEvent[];

  performedActionIds: readonly string[];

  outcome: ScenarioOutcome;

  score: ScenarioScore;

  finalized: boolean;
}

function replayValidatedHistory(
  initialWorld: WorldState,
  events: readonly SimulationEvent[],
): WorldState {
  new InMemoryEventStore(events);

  return replayEvents(
    initialWorld,
    events,
  );
}

function requireValidInitialWorld(
  scenario: ScenarioDefinition,
): void {
  const issues =
    validateWorldState(
      scenario.initialWorld,
    );

  if (issues.length === 0) {
    return;
  }

  throw new Error(
    `Scenario ${scenario.id} has an invalid initial world: ${issues[0].message}`,
  );
}

function requireUniqueActionIds(
  scenario: ScenarioDefinition,
): void {
  const seen = new Set<string>();

  for (const action of scenario.actions) {
    if (seen.has(action.id)) {
      throw new Error(
        `Scenario ${scenario.id} defines duplicate action id: ${action.id}`,
      );
    }

    seen.add(action.id);

    if (action.assessment) {
      if (
        !Number.isInteger(
          action.assessment.penalty,
        ) ||
        action.assessment.penalty < 0 ||
        action.assessment.penalty > 100
      ) {
        throw new Error(
          `Scenario ${scenario.id} action ${action.id} defines invalid response penalty: ${action.assessment.penalty}`,
        );
      }

      if (
        action.assessment.rationale
          .trim().length === 0
      ) {
        throw new Error(
          `Scenario ${scenario.id} action ${action.id} must define a non-empty assessment rationale.`,
        );
      }
    }
  }
}

function requireValidObjectives(
  scenario: ScenarioDefinition,
  openingWorld: WorldState,
): void {
  if (scenario.objectives.length === 0) {
    throw new Error(
      `Scenario ${scenario.id} must define at least one objective.`,
    );
  }

  const seen = new Set<string>();

  for (const objective of scenario.objectives) {
    if (seen.has(objective.id)) {
      throw new Error(
        `Scenario ${scenario.id} defines duplicate objective id: ${objective.id}`,
      );
    }

    seen.add(objective.id);

    switch (objective.kind) {
      case "account_status":
        if (
          !openingWorld.accounts[
            objective.accountId
          ]
        ) {
          throw new Error(
            `Scenario ${scenario.id} objective ${objective.id} references missing account: ${objective.accountId}`,
          );
        }
        break;

      case "session_status":
        if (
          !openingWorld.sessions[
            objective.sessionId
          ]
        ) {
          throw new Error(
            `Scenario ${scenario.id} objective ${objective.id} references missing session: ${objective.sessionId}`,
          );
        }
        break;
    }
  }
}

export function validateScenarioDefinition(
  scenario: ScenarioDefinition,
): void {
  requireValidInitialWorld(scenario);
  requireUniqueActionIds(scenario);

  const openingWorld =
    replayValidatedHistory(
      scenario.initialWorld,
      scenario.openingEvents,
    );

  requireValidObjectives(
    scenario,
    openingWorld,
  );

  for (const action of scenario.actions) {
    replayValidatedHistory(
      openingWorld,
      action.events,
    );

    replayValidatedHistory(
      scenario.initialWorld,
      [
        ...scenario.openingEvents,
        ...action.events,
      ],
    );
  }
}

function resolveActions(
  scenario: ScenarioDefinition,
  actionIds: readonly string[],
): readonly ScenarioAction[] {
  const actionById =
    new Map(
      scenario.actions.map(
        (action) => [
          action.id,
          action,
        ],
      ),
    );

  const selected =
    new Set<string>();

  return actionIds.map((actionId) => {
    if (selected.has(actionId)) {
      throw new Error(
        `Scenario action already performed: ${actionId}`,
      );
    }

    selected.add(actionId);

    const action =
      actionById.get(actionId);

    if (!action) {
      throw new Error(
        `Unknown scenario action: ${actionId}`,
      );
    }

    return action;
  });
}

function responsePenalties(
  actions: readonly ScenarioAction[],
): readonly number[] {
  return actions.flatMap(
    (action) =>
      action.assessment
        ? [action.assessment.penalty]
        : [],
  );
}

export function getScenarioState(
  scenario: ScenarioDefinition,
  performedActionIds:
    readonly string[] = [],
): ScenarioState {
  validateScenarioDefinition(scenario);

  const actions =
    resolveActions(
      scenario,
      performedActionIds,
    );

  const events = [
    ...scenario.openingEvents,
    ...actions.flatMap(
      (action) => action.events,
    ),
  ];

  const world = replayValidatedHistory(
    scenario.initialWorld,
    events,
  );

  const outcome =
    evaluateScenarioOutcome(
      scenario.objectives,
      world,
    );

  return {
    world,
    events,
    performedActionIds: [
      ...performedActionIds,
    ],
    outcome,
    // Active investigation deliberately exposes objective progress only.
    // Response-quality assessment remains hidden until finalization.
    score:
      evaluateScenarioScore(outcome),
    finalized: false,
  };
}

export function finalizeScenarioState(
  scenario: ScenarioDefinition,
  performedActionIds:
    readonly string[] = [],
): ScenarioState {
  const active =
    getScenarioState(
      scenario,
      performedActionIds,
    );
  const actions =
    resolveActions(
      scenario,
      performedActionIds,
    );
  const outcome =
    finalizeScenarioOutcome(
      active.outcome,
    );

  return {
    ...active,
    outcome,
    score:
      evaluateScenarioScore(
        outcome,
        responsePenalties(actions),
      ),
    finalized: true,
  };
}
