import {
  createWorldState,
} from "./worldState";

import type {
  WorldSeed,
} from "./worldState";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  getScenarioState,
  validateScenarioDefinition,
} from "./scenario";

import type {
  ScenarioAction,
  ScenarioDefinition,
  ScenarioInvestigationContext,
} from "./scenario";

export interface ScenarioDefinitionInput {
  id: string;

  name: string;

  description: string;

  initialWorld: WorldSeed;

  openingEvents:
    readonly SimulationEvent[];

  actions:
    readonly ScenarioAction[];

  investigation:
    ScenarioInvestigationContext;
}

function requireInvestigationContext(
  scenario: ScenarioDefinition,
): void {
  const context =
    scenario.investigation;
  const state =
    getScenarioState(scenario);

  if (!state.world.users[context.userId]) {
    throw new Error(
      `Scenario ${scenario.id} investigation references missing user: ${context.userId}`,
    );
  }

  if (!state.world.accounts[context.accountId]) {
    throw new Error(
      `Scenario ${scenario.id} investigation references missing account: ${context.accountId}`,
    );
  }

  if (!state.world.devices[context.deviceId]) {
    throw new Error(
      `Scenario ${scenario.id} investigation references missing device: ${context.deviceId}`,
    );
  }

  if (!state.world.sessions[context.sessionId]) {
    throw new Error(
      `Scenario ${scenario.id} investigation references missing session: ${context.sessionId}`,
    );
  }

  const hasAlert =
    scenario.openingEvents.some(
      (event) =>
        event.type === "ALERT_CREATED" &&
        event.payload.alertId ===
          context.alertId,
    );

  if (!hasAlert) {
    throw new Error(
      `Scenario ${scenario.id} investigation references missing alert: ${context.alertId}`,
    );
  }

  const hasAction =
    scenario.actions.some(
      (action) =>
        action.id ===
        context.primaryActionId,
    );

  if (!hasAction) {
    throw new Error(
      `Scenario ${scenario.id} investigation references missing primary action: ${context.primaryActionId}`,
    );
  }
}

export function compileScenarioDefinition(
  input: ScenarioDefinitionInput,
): ScenarioDefinition {
  const scenario: ScenarioDefinition = {
    id: input.id,
    name: input.name,
    description: input.description,
    initialWorld:
      createWorldState(
        input.initialWorld,
      ),
    openingEvents:
      structuredClone(
        input.openingEvents,
      ),
    actions:
      input.actions.map((action) => ({
        id: action.id,
        label: action.label,
        description: action.description,
        events:
          structuredClone(
            action.events,
          ),
      })),
    investigation: {
      ...input.investigation,
    },
  };

  validateScenarioDefinition(scenario);
  requireInvestigationContext(scenario);

  return scenario;
}
