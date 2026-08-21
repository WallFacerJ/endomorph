import type {
  EntityId,
} from "@endomorph/domain";

import {
  buildEvidenceGraph,
  type EvidenceNodeKind,
} from "./incidentCase";

import type {
  SiemEventRecord,
} from "./siemProjection";

import type {
  WorldState,
} from "./worldState";

/**
 * How much of the incident the analyst actually reached.
 *
 * Objective scoring answers "did the world end up in the right state" -- it
 * cannot distinguish an analyst who scoped the intrusion from one who read
 * the alert, guessed correctly, and stopped. Coverage answers the second
 * question, and only became measurable once the case began deriving
 * entities from collected evidence.
 *
 * The comparison is between two evidence graphs: the one implied by the
 * scenario's ground-truth events, and the one implied by the analyst's
 * collected evidence. Reusing the same derivation for both means coverage
 * cannot drift from what the case shows.
 */

export interface CoverageEntity {
  id: string;

  kind: EvidenceNodeKind;

  label: string;

  reached: boolean;
}

export interface InvestigationCoverage {
  entities: readonly CoverageEntity[];

  reached: readonly CoverageEntity[];

  missed: readonly CoverageEntity[];

  /** 0-100. 100 when the scenario declares no ground truth. */
  percentage: number;
}

export function assessInvestigationCoverage(
  world: WorldState,
  records: readonly SiemEventRecord[],
  collectedEventIds: readonly EntityId[],
  groundTruthEventIds: readonly EntityId[],
): InvestigationCoverage {
  const significant = buildEvidenceGraph(
    world,
    records,
    groundTruthEventIds,
  );

  const reachedIds = new Set(
    buildEvidenceGraph(
      world,
      records,
      collectedEventIds,
    ).nodes.map((node) => node.id),
  );

  const entities: CoverageEntity[] =
    significant.nodes.map((node) => ({
      id: node.id,
      kind: node.kind,
      label: node.label,
      reached: reachedIds.has(node.id),
    }));

  const reached = entities.filter(
    (entity) => entity.reached,
  );

  const missed = entities.filter(
    (entity) => !entity.reached,
  );

  return {
    entities,
    reached,
    missed,
    percentage:
      entities.length === 0
        ? 100
        : Math.round(
            (reached.length /
              entities.length) *
              100,
          ),
  };
}
