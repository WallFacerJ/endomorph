import type {
  EntityId,
} from "@polymorph/domain";

import type {
  SimulationEvent,
} from "./simulationEvent";

export interface AnalystFinding {
  id: EntityId;

  title: string;

  summary: string;

  evidenceEventIds: readonly EntityId[];
}

export interface AnalystCaseState {
  collectedEventIds: readonly EntityId[];

  findings: readonly AnalystFinding[];
}

export interface AnalystFindingInput {
  id: EntityId;

  title: string;

  summary: string;

  evidenceEventIds: readonly EntityId[];
}

export function createAnalystCaseState():
  AnalystCaseState {
  return {
    collectedEventIds: [],
    findings: [],
  };
}

function requireAvailableEvent(
  eventId: EntityId,
  availableEvents: readonly SimulationEvent[],
): void {
  if (
    availableEvents.some(
      (event) => event.id === eventId,
    )
  ) {
    return;
  }

  throw new Error(
    `Analyst evidence references unavailable event: ${eventId}`,
  );
}

export function collectAnalystEvidence(
  state: AnalystCaseState,
  eventId: EntityId,
  availableEvents: readonly SimulationEvent[],
): AnalystCaseState {
  requireAvailableEvent(
    eventId,
    availableEvents,
  );

  if (
    state.collectedEventIds.includes(
      eventId,
    )
  ) {
    return state;
  }

  return {
    ...state,
    collectedEventIds: [
      ...state.collectedEventIds,
      eventId,
    ],
  };
}

function requireFindingText(
  value: string,
  field: "title" | "summary",
): string {
  const trimmed = value.trim();

  if (trimmed.length > 0) {
    return trimmed;
  }

  throw new Error(
    `Analyst finding ${field} must not be empty.`,
  );
}

function requireFindingEvidence(
  state: AnalystCaseState,
  evidenceEventIds: readonly EntityId[],
  availableEvents: readonly SimulationEvent[],
): readonly EntityId[] {
  if (evidenceEventIds.length === 0) {
    throw new Error(
      "Analyst finding must reference at least one collected evidence event.",
    );
  }

  const unique = new Set<EntityId>();

  for (const eventId of evidenceEventIds) {
    if (unique.has(eventId)) {
      throw new Error(
        `Analyst finding references duplicate evidence event: ${eventId}`,
      );
    }

    unique.add(eventId);
    requireAvailableEvent(
      eventId,
      availableEvents,
    );

    if (
      !state.collectedEventIds.includes(
        eventId,
      )
    ) {
      throw new Error(
        `Analyst finding references uncollected evidence event: ${eventId}`,
      );
    }
  }

  return [...unique];
}

export function addAnalystFinding(
  state: AnalystCaseState,
  input: AnalystFindingInput,
  availableEvents: readonly SimulationEvent[],
): AnalystCaseState {
  if (
    state.findings.some(
      (finding) => finding.id === input.id,
    )
  ) {
    throw new Error(
      `Analyst finding id already exists: ${input.id}`,
    );
  }

  const finding: AnalystFinding = {
    id: input.id,
    title: requireFindingText(
      input.title,
      "title",
    ),
    summary: requireFindingText(
      input.summary,
      "summary",
    ),
    evidenceEventIds:
      requireFindingEvidence(
        state,
        input.evidenceEventIds,
        availableEvents,
      ),
  };

  return {
    ...state,
    findings: [
      ...state.findings,
      finding,
    ],
  };
}

export function resolveCollectedEvidence(
  state: AnalystCaseState,
  availableEvents: readonly SimulationEvent[],
): readonly SimulationEvent[] {
  const eventById = new Map(
    availableEvents.map(
      (event) => [event.id, event],
    ),
  );

  return state.collectedEventIds.map(
    (eventId) => {
      const event = eventById.get(eventId);

      if (!event) {
        throw new Error(
          `Analyst evidence references unavailable event: ${eventId}`,
        );
      }

      return event;
    },
  );
}
