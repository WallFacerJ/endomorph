import {
  InMemoryEventStore,
} from "./eventStore";

import {
  replayEvents,
} from "./replay";

import type {
  SimulationEvent,
} from "./simulationEvent";

import type {
  WorldState,
} from "./worldState";

import {
  validateWorldState,
} from "./worldValidation";

export interface ScenarioAction {
  id: string;

  label: string;

  description: string;

  events: readonly SimulationEvent[];
}

export interface ScenarioDefinition {
  id: string;

  name: string;

  description: string;

  initialWorld: WorldState;

  openingEvents: readonly SimulationEvent[];

  actions: readonly ScenarioAction[];
}

export interface ScenarioState {
  world: WorldState;

  events: readonly SimulationEvent[];

  performedActionIds: readonly string[];
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

  return {
    world: replayValidatedHistory(
      scenario.initialWorld,
      events,
    ),
    events,
    performedActionIds: [
      ...performedActionIds,
    ],
  };
}
