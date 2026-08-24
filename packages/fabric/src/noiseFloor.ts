import type {
  CorpusRecord,
} from "./corpus.js";

/**
 * How well the malicious activity is buried in benign look-alikes.
 *
 * The recurring objection to synthetic detection data is that its false
 * positives do not transfer: if the benign traffic is too clean, a rule scores
 * a false-positive count of zero here and drowns in production. The answer is
 * not to assert the noise is realistic but to measure it. For each malicious
 * technique, this counts the benign events that share its event types -- the
 * false positives an unspecific rule keyed on that behaviour would eat. A
 * technique whose malicious events are the only ones of their type is
 * trivially detectable and the corpus is lying; one buried among thousands of
 * identical-type benign events is realistically hard, and the number says by
 * how much.
 *
 * It is a floor, not a verdict: a specific rule does better than an unspecific
 * one, and closing that gap is the detection engineer's job. What the floor
 * establishes is that there is a gap to close, which a corpus with separable
 * malicious traffic cannot offer.
 */

export interface TechniqueNoiseFloor {
  readonly technique: string;

  readonly maliciousEvents: number;

  /** The event types the technique's malicious events use. */
  readonly eventTypes: readonly string[];

  /** Benign events sharing those event types -- the unspecific-rule FP floor. */
  readonly benignLookalikes: number;

  /** Benign look-alikes per malicious event: the size of the haystack. */
  readonly lookalikeRatio: number;
}

export interface NoiseFloorReport {
  readonly malicious: number;

  readonly benign: number;

  readonly techniques: readonly TechniqueNoiseFloor[];
}

function round(value: number): number {
  return Math.round(value * 10) / 10;
}

export function computeNoiseFloor(
  records: readonly CorpusRecord[],
): NoiseFloorReport {
  const benignByType = new Map<
    string,
    number
  >();

  const maliciousByTechnique = new Map<
    string,
    {
      count: number;
      eventTypes: Set<string>;
    }
  >();

  let malicious = 0;
  let benign = 0;

  for (const record of records) {
    const eventType =
      record["event.type"];

    if (record["label.malicious"]) {
      malicious += 1;

      const technique =
        record["label.technique"];

      // A malicious record with no technique is scored elsewhere but has no
      // place in a per-technique floor.
      if (!technique) {
        continue;
      }

      const entry =
        maliciousByTechnique.get(
          technique,
        ) ?? {
          count: 0,
          eventTypes: new Set<string>(),
        };

      entry.count += 1;
      entry.eventTypes.add(eventType);
      maliciousByTechnique.set(
        technique,
        entry,
      );
    } else {
      benign += 1;
      benignByType.set(
        eventType,
        (benignByType.get(eventType) ??
          0) + 1,
      );
    }
  }

  const techniques: TechniqueNoiseFloor[] =
    [...maliciousByTechnique.entries()]
      .map(([technique, entry]) => {
        const eventTypes = [
          ...entry.eventTypes,
        ].sort();

        const benignLookalikes =
          eventTypes.reduce(
            (sum, eventType) =>
              sum +
              (benignByType.get(
                eventType,
              ) ?? 0),
            0,
          );

        return {
          technique,
          maliciousEvents: entry.count,
          eventTypes,
          benignLookalikes,
          lookalikeRatio: round(
            benignLookalikes /
              entry.count,
          ),
        };
      })
      .sort((left, right) =>
        left.technique.localeCompare(
          right.technique,
        ),
      );

  return {
    malicious,
    benign,
    techniques,
  };
}
