export class SeededRandom {
  private state: number;

  constructor(seed: number) {
    if (
      !Number.isFinite(seed) ||
      !Number.isInteger(seed)
    ) {
      throw new Error(
        "Random seed must be a finite integer.",
      );
    }

    this.state = seed >>> 0;
  }

  next(): number {
    this.state = (
      this.state + 0x6d2b79f5
    ) >>> 0;

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
      (value ^ (value >>> 14)) >>> 0
    ) / 4294967296;
  }

  nextInt(
    minInclusive: number,
    maxExclusive: number,
  ): number {
    if (
      !Number.isInteger(minInclusive) ||
      !Number.isInteger(maxExclusive) ||
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

  pick<T>(
    items: readonly T[],
  ): T {
    if (items.length === 0) {
      throw new Error(
        "Cannot pick from an empty collection.",
      );
    }

    const index = this.nextInt(
      0,
      items.length,
    );

    return items[index];
  }
}
