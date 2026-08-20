import {
  parseScenarioFile,
  parseScenarioJson,
} from "@polymorph/schema";

import type {
  ScenarioEventSpec,
  ScenarioFile,
  ScenarioSpec,
} from "@polymorph/schema";

import {
  assertNever,
} from "./assertNever";

import {
  createWorldState,
} from "./worldState";

import type {
  SimulationEvent,
} from "./simulationEvent";

import {
  getScenarioState,
  validateScenarioDefinition,
} from "./scenario";

import type {
  ScenarioDefinition,
} from "./scenario";

function compileEvent(
  event: ScenarioEventSpec,
): SimulationEvent {
  switch (event.type) {
    case "AUTH_LOGIN_SUCCEEDED":
    case "AUTH_LOGIN_FAILED":
    case "ACCOUNT_DISABLED":
    case "ACCOUNT_ENABLED":
    case "SESSION_STARTED":
    case "SESSION_REVOKED":
    case "PROCESS_STARTED":
    case "FILE_ACCESSED":
    case "NETWORK_CONNECTION":
    case "ENDPOINT_HEARTBEAT":
    case "ALERT_CREATED":
      return event;

    default:
      return assertNever(event);
  }
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

export function compileScenarioSpec(
  spec: ScenarioSpec,
): ScenarioDefinition {
  const scenario: ScenarioDefinition = {
    id: spec.id,
    name: spec.name,
    description: spec.description,
    initialWorld:
      createWorldState(
        spec.initialWorld,
      ),
    openingEvents:
      spec.openingEvents.map(
        compileEvent,
      ),
    actions:
      spec.actions.map((action) => ({
        id: action.id,
        label: action.label,
        description: action.description,
        events:
          action.events.map(
            compileEvent,
          ),
      })),
    investigation: {
      ...spec.investigation,
    },
  };

  validateScenarioDefinition(scenario);
  requireInvestigationContext(scenario);

  return scenario;
}

export function compileScenarioFile(
  file: ScenarioFile,
): ScenarioDefinition {
  return compileScenarioSpec(
    file.scenario,
  );
}

export function compileScenarioInput(
  input: unknown,
): ScenarioDefinition {
  return compileScenarioFile(
    parseScenarioFile(input),
  );
}

export function compileScenarioJson(
  serialized: string,
): ScenarioDefinition {
  return compileScenarioFile(
    parseScenarioJson(serialized),
  );
}
