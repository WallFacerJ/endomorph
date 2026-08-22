/**
 * Bucketing for the volume charts.
 *
 * Kept out of the component module because Fast Refresh only works when a
 * file exports components alone -- the fourth time in this project a helper
 * has had to move out from beside the component that uses it.
 */

export interface VolumeBucket {
  readonly label: string;
  readonly total: number;
  readonly notable: number;
}

/**
 * Buckets a set of timestamps into a fixed number of intervals.
 *
 * Exported because both the alert queue and the search results need the same
 * buckets, and computing them twice from the same events invites the two
 * charts to disagree about a window boundary.
 */
export function bucketByTime(
  timestamps: readonly string[],
  notableTimestamps: readonly string[],
  bucketCount = 48,
): readonly VolumeBucket[] {
  if (timestamps.length === 0) {
    return [];
  }

  const times = timestamps
    .map((value) => Date.parse(value))
    .filter((value) =>
      Number.isFinite(value),
    );

  if (times.length === 0) {
    return [];
  }

  const start = Math.min(...times);
  const end = Math.max(...times);

  // A single instant is not a distribution; one bucket avoids dividing by a
  // zero-width span and drawing a chart that implies a trend.
  const span = Math.max(end - start, 1);

  const buckets: {
    label: string;
    total: number;
    notable: number;
  }[] = Array.from(
      { length: bucketCount },
      (_unused, index) => ({
        label: new Date(
          start +
            (span * index) / bucketCount,
        ).toISOString(),
        total: 0,
        notable: 0,
      }),
    );

  const indexFor = (value: number) =>
    Math.min(
      bucketCount - 1,
      Math.floor(
        ((value - start) / span) *
          bucketCount,
      ),
    );

  for (const value of times) {
    buckets[indexFor(value)].total += 1;
  }

  for (const value of notableTimestamps) {
    const parsed = Date.parse(value);

    if (Number.isFinite(parsed)) {
      buckets[indexFor(parsed)]
        .notable += 1;
    }
  }

  return buckets;
}

