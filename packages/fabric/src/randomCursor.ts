/**
 * Deterministic splittable pseudo-random source for Fabric generation.
 *
 * A cursor is addressed by its fork path rather than by how much of the
 * stream has already been consumed. Two cursors reached by the same path
 * from the same root seed always produce the same sequence, regardless of
 * the order the forks were taken or how many values their siblings drew.
 *
 * That property is what keeps a generated enterprise stable while it is
 * still being authored: adding a device under `devices` cannot resequence
 * anything drawn under `users`.
 */

const FNV_OFFSET_BASIS = 2166136261;

const FNV_PRIME = 16777619;

const MULBERRY_INCREMENT = 0x6d2b79f5;

const UINT32_RANGE = 4294967296;

/**
 * Derives a child seed from a parent seed and a label.
 *
 * FNV-1a over the label, then an avalanche pass so that labels differing
 * by a single character produce unrelated streams.
 */
function deriveSeed(
  parentSeed: number,
  label: string,
): number {
  let hash =
    (parentSeed ^ FNV_OFFSET_BASIS) >>>
    0;

  for (
    let index = 0;
    index < label.length;
    index += 1
  ) {
    hash ^= label.charCodeAt(index);

    hash = Math.imul(
      hash,
      FNV_PRIME,
    );
  }

  hash ^= hash >>> 16;

  hash = Math.imul(
    hash,
    2246822507,
  );

  hash ^= hash >>> 13;

  hash = Math.imul(
    hash,
    3266489909,
  );

  hash ^= hash >>> 16;

  return hash >>> 0;
}

export class RandomCursor {
  /**
   * Immutable stream identity. Child seeds derive from this rather than
   * from `state`, so forking never depends on prior consumption.
   */
  private readonly seed: number;

  private readonly segments: readonly string[];

  private state: number;

  private constructor(
    seed: number,
    segments: readonly string[],
  ) {
    this.seed = seed >>> 0;
    this.segments = segments;
    this.state = seed >>> 0;
  }

  /**
   * Creates the root cursor for a run.
   */
  static root(
    seed: number,
  ): RandomCursor {
    if (
      !Number.isInteger(seed) ||
      !Number.isFinite(seed)
    ) {
      throw new Error(
        "Random seed must be a finite integer.",
      );
    }

    return new RandomCursor(
      seed,
      [],
    );
  }

  /**
   * The fork path of this cursor, for debugging and provenance.
   */
  get path(): string {
    return this.segments.join("/");
  }

  /**
   * Derives an independent child stream.
   *
   * The child depends only on this cursor's path and the label, never on
   * how many values this cursor or any sibling has drawn.
   */
  fork(
    label: string,
  ): RandomCursor {
    if (label.length === 0) {
      throw new Error(
        "Fork label must not be empty.",
      );
    }

    return new RandomCursor(
      deriveSeed(
        this.seed,
        label,
      ),
      [...this.segments, label],
    );
  }

  /**
   * Rewinds this cursor to the start of its stream.
   */
  reset(): void {
    this.state = this.seed;
  }

  /**
   * Next value in [0, 1). Mulberry32.
   */
  next(): number {
    this.state =
      (this.state +
        MULBERRY_INCREMENT) >>>
      0;

    let value = this.state;

    value = Math.imul(
      value ^ (value >>> 15),
      value | 1,
    );

    value ^=
      value +
      Math.imul(
        value ^ (value >>> 7),
        value | 61,
      );

    return (
      ((value ^ (value >>> 14)) >>>
        0) /
      UINT32_RANGE
    );
  }

  /**
   * Next integer in [minInclusive, maxExclusive).
   */
  nextInt(
    minInclusive: number,
    maxExclusive: number,
  ): number {
    if (
      !Number.isInteger(
        minInclusive,
      ) ||
      !Number.isInteger(
        maxExclusive,
      ) ||
      maxExclusive <= minInclusive
    ) {
      throw new Error(
        "Integer range must satisfy minInclusive < maxExclusive.",
      );
    }

    const range =
      maxExclusive - minInclusive;

    return (
      minInclusive +
      Math.floor(this.next() * range)
    );
  }

  /**
   * True with the given probability in [0, 1].
   */
  nextBoolean(
    probability: number,
  ): boolean {
    if (
      !Number.isFinite(probability) ||
      probability < 0 ||
      probability > 1
    ) {
      throw new Error(
        "Probability must be between 0 and 1.",
      );
    }

    return this.next() < probability;
  }

  /**
   * Picks one item.
   */
  pick<T>(
    items: readonly T[],
  ): T {
    if (items.length === 0) {
      throw new Error(
        "Cannot pick from an empty collection.",
      );
    }

    return items[
      this.nextInt(
        0,
        items.length,
      )
    ];
  }

  /**
   * Returns a shuffled copy. The input is not mutated.
   */
  shuffle<T>(
    items: readonly T[],
  ): T[] {
    const result = [...items];

    for (
      let index = result.length - 1;
      index > 0;
      index -= 1
    ) {
      const swap = this.nextInt(
        0,
        index + 1,
      );

      const held = result[index];
      result[index] = result[swap];
      result[swap] = held;
    }

    return result;
  }
}
