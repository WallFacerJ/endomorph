import type {
  EntityId,
  SimulationTimestamp,
} from "@endomorph/domain";

import type {
  SiemEventRecord,
} from "./siemProjection";

import type {
  WorldState,
} from "./worldState";

/**
 * Incident command state.
 *
 * The v1 case was a list of collected event ids plus free-text findings --
 * note-taking beside the investigation rather than the place the
 * investigation is run from. Testers correctly called it unnecessary.
 *
 * The difference here is that the operationally useful parts are *derived*
 * from the analyst's own work rather than typed in again. Collecting an
 * event teaches the case which entities are involved, how they connect, and
 * which indicators are in play. The analyst supplies judgement --
 * hypotheses, tasks, decisions, phase -- and the case assembles the picture.
 */

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/** Incident-handling lifecycle, in order. */
export const INCIDENT_PHASES = [
  "triage",
  "investigation",
  "containment",
  "eradication",
  "recovery",
  "lessons_learned",
] as const;

export type IncidentPhase =
  (typeof INCIDENT_PHASES)[number];

export type HypothesisStatus =
  | "proposed"
  | "supported"
  | "refuted";

export type TaskStatus =
  | "open"
  | "in_progress"
  | "done"
  | "blocked";

export interface IncidentHypothesis {
  id: EntityId;

  /** What the analyst thinks happened, stated so it can be wrong. */
  statement: string;

  status: HypothesisStatus;

  /** Evidence the analyst attached in support or refutation. */
  evidenceEventIds: readonly EntityId[];
}

export interface IncidentTask {
  id: EntityId;

  title: string;

  owner: string;

  status: TaskStatus;

  phase: IncidentPhase;
}

export interface IncidentDecision {
  id: EntityId;

  summary: string;

  rationale: string;

  phase: IncidentPhase;
}

// ---------------------------------------------------------------------------
// Derived views
// ---------------------------------------------------------------------------

export type EvidenceNodeKind =
  | "user"
  | "account"
  | "device"
  | "application"
  | "file"
  | "session"
  | "address"
  | "alert";

export interface EvidenceGraphNode {
  id: string;

  kind: EvidenceNodeKind;

  /** Display name resolved from the world where one exists. */
  label: string;

  /** Collected events that referenced this node. */
  eventIds: readonly EntityId[];

  /** True when the entity is not part of the synthetic enterprise. */
  external: boolean;
}

export interface EvidenceGraphEdge {
  from: string;

  to: string;

  /** Collected events that put these two nodes together. */
  eventIds: readonly EntityId[];
}

export interface EvidenceGraph {
  nodes: readonly EvidenceGraphNode[];

  edges: readonly EvidenceGraphEdge[];
}

export type IndicatorKind =
  | "address"
  | "command_line"
  | "process_image"
  | "username";

export interface IncidentIndicator {
  kind: IndicatorKind;

  value: string;

  firstSeen: SimulationTimestamp;

  lastSeen: SimulationTimestamp;

  eventIds: readonly EntityId[];

  /**
   * True when the value does not belong to the synthetic enterprise -- an
   * address outside every known device, for instance. These are the ones
   * worth escalating.
   */
  external: boolean;
}

export interface IncidentCaseState {
  phase: IncidentPhase;

  hypotheses: readonly IncidentHypothesis[];

  tasks: readonly IncidentTask[];

  decisions: readonly IncidentDecision[];
}

export function createIncidentCaseState():
  IncidentCaseState {
  return {
    phase: "triage",
    hypotheses: [],
    tasks: [],
    decisions: [],
  };
}

// ---------------------------------------------------------------------------
// Entity resolution
// ---------------------------------------------------------------------------

const ENTITY_FIELD_KINDS: ReadonlyArray<
  readonly [string, EvidenceNodeKind]
> = [
  ["userId", "user"],
  ["accountId", "account"],
  ["deviceId", "device"],
  ["applicationId", "application"],
  ["fileId", "file"],
  ["sessionId", "session"],
  ["alertId", "alert"],
];

const ADDRESS_FIELDS = [
  "sourceIp",
  "destinationIp",
] as const;

function labelFor(
  world: WorldState,
  kind: EvidenceNodeKind,
  id: string,
): { label: string; external: boolean } {
  switch (kind) {
    case "user": {
      const user = world.users[id];

      return user
        ? {
            label: user.displayName,
            external: false,
          }
        : { label: id, external: true };
    }

    case "account": {
      const account = world.accounts[id];

      return account
        ? {
            label: account.username,
            external: false,
          }
        : { label: id, external: true };
    }

    case "device": {
      const device = world.devices[id];

      return device
        ? {
            label: device.hostname,
            external: false,
          }
        : { label: id, external: true };
    }

    case "application": {
      const application =
        world.applications[id];

      return application
        ? {
            label: application.name,
            external: false,
          }
        : { label: id, external: true };
    }

    case "file": {
      const file = world.files[id];

      return file
        ? {
            label: file.name,
            external: false,
          }
        : { label: id, external: true };
    }

    default:
      return { label: id, external: false };
  }
}

/** Every address that belongs to a device in the synthetic enterprise. */
function knownAddresses(
  world: WorldState,
): ReadonlySet<string> {
  const addresses = new Set<string>();

  for (const device of Object.values(
    world.devices,
  )) {
    for (const address of device.ipAddresses) {
      addresses.add(address);
    }
  }

  return addresses;
}

function readString(
  record: SiemEventRecord,
  field: string,
): string | undefined {
  const value = record.fields[field];

  return typeof value === "string"
    ? value
    : undefined;
}

// ---------------------------------------------------------------------------
// Evidence graph
// ---------------------------------------------------------------------------

/**
 * Builds the entity graph implied by the analyst's collected evidence.
 *
 * Nothing here is typed in by hand. Collect a login and the case learns the
 * account, the user, the device, the application, and the address, plus the
 * fact that they occurred together. That is what makes the case worth
 * opening: it assembles a picture the analyst never has to restate.
 */
export function buildEvidenceGraph(
  world: WorldState,
  records: readonly SiemEventRecord[],
  collectedEventIds: readonly EntityId[],
): EvidenceGraph {
  const collected = new Set(
    collectedEventIds,
  );

  const corporate = knownAddresses(world);

  const nodes = new Map<
    string,
    {
      kind: EvidenceNodeKind;
      label: string;
      external: boolean;
      eventIds: Set<EntityId>;
    }
  >();

  const edges = new Map<
    string,
    Set<EntityId>
  >();

  for (const record of records) {
    if (!collected.has(record.eventId)) {
      continue;
    }

    const touched: string[] = [];

    const remember = (
      id: string,
      kind: EvidenceNodeKind,
    ): void => {
      const existing = nodes.get(id);

      if (existing) {
        existing.eventIds.add(
          record.eventId,
        );
      } else {
        const resolved =
          kind === "address"
            ? {
                label: id,
                external:
                  !corporate.has(id),
              }
            : labelFor(world, kind, id);

        nodes.set(id, {
          kind,
          label: resolved.label,
          external: resolved.external,
          eventIds: new Set([
            record.eventId,
          ]),
        });
      }

      if (!touched.includes(id)) {
        touched.push(id);
      }
    };

    for (const [
      field,
      kind,
    ] of ENTITY_FIELD_KINDS) {
      const value = readString(
        record,
        field,
      );

      if (value) {
        remember(value, kind);
      }
    }

    for (const field of ADDRESS_FIELDS) {
      const value = readString(
        record,
        field,
      );

      if (value) {
        remember(value, "address");
      }
    }

    // Every pair of entities named by one event is connected by it.
    for (
      let left = 0;
      left < touched.length;
      left += 1
    ) {
      for (
        let right = left + 1;
        right < touched.length;
        right += 1
      ) {
        const key = [
          touched[left],
          touched[right],
        ]
          .sort()
          .join(" ");

        const existing = edges.get(key);

        if (existing) {
          existing.add(record.eventId);
        } else {
          edges.set(
            key,
            new Set([record.eventId]),
          );
        }
      }
    }
  }

  return {
    nodes: [...nodes.entries()]
      .map(([id, node]) => ({
        id,
        kind: node.kind,
        label: node.label,
        external: node.external,
        eventIds: [
          ...node.eventIds,
        ].sort(),
      }))
      .sort(
        (left, right) =>
          right.eventIds.length -
            left.eventIds.length ||
          left.id.localeCompare(right.id),
      ),

    edges: [...edges.entries()]
      .map(([key, eventIds]) => {
        const [from, to] =
          key.split(" ");

        return {
          from,
          to,
          eventIds: [...eventIds].sort(),
        };
      })
      .sort(
        (left, right) =>
          right.eventIds.length -
            left.eventIds.length ||
          left.from.localeCompare(
            right.from,
          ) ||
          left.to.localeCompare(right.to),
      ),
  };
}

// ---------------------------------------------------------------------------
// Indicators
// ---------------------------------------------------------------------------

/**
 * Extracts indicators of compromise from collected evidence.
 *
 * Addresses outside every corporate subnet are flagged external, which is
 * the distinction that usually matters during triage.
 */
export function extractIncidentIndicators(
  world: WorldState,
  records: readonly SiemEventRecord[],
  collectedEventIds: readonly EntityId[],
): readonly IncidentIndicator[] {
  const collected = new Set(
    collectedEventIds,
  );

  const corporate = knownAddresses(world);

  const found = new Map<
    string,
    {
      kind: IndicatorKind;
      value: string;
      firstSeen: SimulationTimestamp;
      lastSeen: SimulationTimestamp;
      eventIds: EntityId[];
      external: boolean;
    }
  >();

  const remember = (
    kind: IndicatorKind,
    value: string,
    record: SiemEventRecord,
    external: boolean,
  ): void => {
    const key = `${kind} ${value}`;

    const existing = found.get(key);

    if (existing) {
      existing.eventIds.push(
        record.eventId,
      );

      if (
        record.timestamp <
        existing.firstSeen
      ) {
        existing.firstSeen =
          record.timestamp;
      }

      if (
        record.timestamp >
        existing.lastSeen
      ) {
        existing.lastSeen =
          record.timestamp;
      }

      return;
    }

    found.set(key, {
      kind,
      value,
      firstSeen: record.timestamp,
      lastSeen: record.timestamp,
      eventIds: [record.eventId],
      external,
    });
  };

  for (const record of records) {
    if (!collected.has(record.eventId)) {
      continue;
    }

    for (const field of ADDRESS_FIELDS) {
      const value = readString(
        record,
        field,
      );

      if (value) {
        remember(
          "address",
          value,
          record,
          !corporate.has(value),
        );
      }
    }

    const commandLine = readString(
      record,
      "commandLine",
    );

    if (commandLine) {
      remember(
        "command_line",
        commandLine,
        record,
        false,
      );
    }

    const image = readString(
      record,
      "image",
    );

    if (image) {
      remember(
        "process_image",
        image,
        record,
        false,
      );
    }

    const username = readString(
      record,
      "username",
    );

    if (username) {
      remember(
        "username",
        username,
        record,
        false,
      );
    }
  }

  return [...found.values()]
    .map((indicator) => ({
      ...indicator,
      eventIds: [
        ...new Set(indicator.eventIds),
      ].sort(),
    }))
    .sort(
      (left, right) =>
        Number(right.external) -
          Number(left.external) ||
        right.eventIds.length -
          left.eventIds.length ||
        left.value.localeCompare(
          right.value,
        ),
    );
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

export interface IncidentReport {
  phase: IncidentPhase;

  evidenceCount: number;

  entityCount: number;

  externalIndicators: readonly IncidentIndicator[];

  openTasks: readonly IncidentTask[];

  supportedHypotheses: readonly IncidentHypothesis[];

  /** Ordered evidence, so the report reads as a narrative. */
  timeline: readonly SiemEventRecord[];

  decisions: readonly IncidentDecision[];
}

/**
 * Assembles a report from the case's actual state.
 *
 * Nothing is authored twice: the timeline is the collected evidence in
 * order, the indicators come from that evidence, and the decisions are the
 * ones the analyst recorded.
 */
export function buildIncidentReport(
  world: WorldState,
  records: readonly SiemEventRecord[],
  collectedEventIds: readonly EntityId[],
  caseState: IncidentCaseState,
): IncidentReport {
  const collected = new Set(
    collectedEventIds,
  );

  const timeline = records
    .filter((record) =>
      collected.has(record.eventId),
    )
    .slice()
    .sort((left, right) =>
      left.timestamp.localeCompare(
        right.timestamp,
      ),
    );

  const indicators =
    extractIncidentIndicators(
      world,
      records,
      collectedEventIds,
    );

  const graph = buildEvidenceGraph(
    world,
    records,
    collectedEventIds,
  );

  return {
    phase: caseState.phase,
    evidenceCount: timeline.length,
    entityCount: graph.nodes.length,
    externalIndicators:
      indicators.filter(
        (indicator) =>
          indicator.external,
      ),
    openTasks: caseState.tasks.filter(
      (task) =>
        task.status !== "done",
    ),
    supportedHypotheses:
      caseState.hypotheses.filter(
        (hypothesis) =>
          hypothesis.status ===
          "supported",
      ),
    timeline,
    decisions: caseState.decisions,
  };
}
