import type {
  ScenarioGroundTruthEvent,
} from "./simulationAdapter";

/**
 * Which of the incident's key events the analyst actually banked as evidence.
 *
 * Coverage answers which entities were reached; this answers the sharper
 * question of whether the smoking guns themselves were collected. An analyst
 * can reach the compromised host and still never bank the encoded PowerShell
 * or the C2 beacon that prove what happened on it -- and for a review the
 * difference between "found the evidence" and "was near it" is the whole
 * point.
 *
 * The incident's ground-truth timeline is the set of events that matter by
 * construction, so the measure is deterministic: an event either is in the
 * collected set or it is not. The missed steps are named by what they were,
 * so the result reads as "you never collected the beacon" rather than an
 * opaque ratio.
 */
export interface KeyEvidenceStep {
  readonly eventId: string;

  readonly title?: string;

  readonly techniqueId?: string;

  readonly significance: string;
}

export interface KeyEvidenceSummary {
  readonly captured: number;

  readonly total: number;

  readonly missed: readonly KeyEvidenceStep[];
}

export function summarizeKeyEvidence(
  timeline: readonly ScenarioGroundTruthEvent[],
  collectedEventIds: readonly string[],
): KeyEvidenceSummary | undefined {
  if (timeline.length === 0) {
    return undefined;
  }

  const collected = new Set(
    collectedEventIds,
  );

  const missed = timeline
    .filter(
      (step) =>
        !collected.has(step.eventId),
    )
    .map((step) => ({
      eventId: step.eventId,
      ...(step.title
        ? { title: step.title }
        : {}),
      ...(step.techniqueId
        ? {
            techniqueId:
              step.techniqueId,
          }
        : {}),
      significance: step.significance,
    }));

  return {
    captured:
      timeline.length - missed.length,
    total: timeline.length,
    missed,
  };
}
