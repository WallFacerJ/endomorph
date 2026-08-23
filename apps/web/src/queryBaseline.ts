import type {
  SiemEventRecord,
} from "./simulationAdapter";

/**
 * How normal the current search result is.
 *
 * The instructor content asks for this constantly and the console could not
 * answer it. "Compare against where this account normally authenticates."
 * "Determine whether the account ever legitimately touched this document
 * before." "Build that baseline from the account's own history first." Every
 * one of those is the same operation -- has this been seen before, and how
 * often -- and the only way to perform it was to scroll twenty thousand
 * events and count by eye.
 *
 * A generated enterprise is built precisely so this question has an answer:
 * several days of ordinary working history precede the intrusion, so an
 * address the account has never used stands out against days when it used
 * others. That property was in the data and unreachable from the interface.
 *
 * This is not a detection. It says how rare something is, which is the input
 * to a judgement rather than the judgement -- plenty of rare things are
 * benign, and the point is to make the rarity visible rather than to call it
 * suspicious.
 */

export interface QueryBaseline {
  readonly matches: number;

  readonly firstSeen?: string;
  readonly lastSeen?: string;

  /** Distinct calendar days the matches fall on. */
  readonly activeDays: number;

  /** Days covered by the retained telemetry as a whole. */
  readonly retainedDays: number;

  /**
   * True when every match falls on the most recent day of telemetry.
   *
   * The strongest form of "this is new": whatever the query describes has no
   * history behind it at all.
   */
  readonly onlyToday: boolean;
}

function dayOf(
  timestamp: string,
): string | undefined {
  const parsed = Date.parse(timestamp);

  return Number.isFinite(parsed)
    ? new Date(parsed)
        .toISOString()
        .slice(0, 10)
    : undefined;
}

export function summariseQueryBaseline(
  matches: readonly SiemEventRecord[],
  allRecords: readonly SiemEventRecord[],
): QueryBaseline | undefined {
  if (matches.length === 0) {
    return undefined;
  }

  const matchDays = new Set<string>();

  let first: string | undefined;
  let last: string | undefined;

  for (const record of matches) {
    const day = dayOf(record.timestamp);

    if (day) {
      matchDays.add(day);
    }

    if (
      first === undefined ||
      record.timestamp < first
    ) {
      first = record.timestamp;
    }

    if (
      last === undefined ||
      record.timestamp > last
    ) {
      last = record.timestamp;
    }
  }

  const retainedDays = new Set<string>();

  let latestDay: string | undefined;

  for (const record of allRecords) {
    const day = dayOf(record.timestamp);

    if (!day) {
      continue;
    }

    retainedDays.add(day);

    if (
      latestDay === undefined ||
      day > latestDay
    ) {
      latestDay = day;
    }
  }

  return {
    matches: matches.length,
    firstSeen: first,
    lastSeen: last,
    activeDays: matchDays.size,
    retainedDays: retainedDays.size,
    onlyToday:
      latestDay !== undefined &&
      matchDays.size === 1 &&
      matchDays.has(latestDay),
  };
}

/**
 * The one-line reading, so the panel says what the numbers mean.
 *
 * Deliberately descriptive rather than evaluative: "on 1 of 4 retained days"
 * is a fact, "suspicious" would be a conclusion the analyst is supposed to
 * reach themselves.
 */
export function describeQueryBaseline(
  baseline: QueryBaseline,
): string {
  if (baseline.onlyToday) {
    return baseline.retainedDays > 1
      ? `Everything matching this query happened on the most recent day. Nothing like it appears in the ${
          baseline.retainedDays - 1
        } day(s) of history before it.`
      : "Everything matching this query happened on the only day of telemetry retained.";
  }

  if (
    baseline.activeDays ===
    baseline.retainedDays
  ) {
    return `Matches appear on every one of the ${baseline.retainedDays} retained days, so this is part of the environment's routine.`;
  }

  return `Matches appear on ${baseline.activeDays} of the ${baseline.retainedDays} retained days.`;
}
