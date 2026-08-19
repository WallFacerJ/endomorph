import {
  describe,
  expect,
  it,
} from "vitest";

import {
  SeededRandom,
} from "./seededRandom";

describe("SeededRandom", () => {
  it("produces identical sequences from identical seeds", () => {
    const first =
      new SeededRandom(1337);

    const second =
      new SeededRandom(1337);

    const firstSequence =
      Array.from(
        { length: 10 },
        () => first.next(),
      );

    const secondSequence =
      Array.from(
        { length: 10 },
        () => second.next(),
      );

    expect(firstSequence)
      .toEqual(secondSequence);
  });

  it("produces different sequences from different seeds", () => {
    const first =
      new SeededRandom(1337);

    const second =
      new SeededRandom(9001);

    const firstSequence = [
      first.next(),
      first.next(),
      first.next(),
    ];

    const secondSequence = [
      second.next(),
      second.next(),
      second.next(),
    ];

    expect(firstSequence)
      .not.toEqual(secondSequence);
  });

  it("produces values between zero and one", () => {
    const random =
      new SeededRandom(42);

    for (
      let index = 0;
      index < 100;
      index += 1
    ) {
      const value = random.next();

      expect(value)
        .toBeGreaterThanOrEqual(0);

      expect(value)
        .toBeLessThan(1);
    }
  });

  it("produces integers inside the requested range", () => {
    const random =
      new SeededRandom(42);

    for (
      let index = 0;
      index < 100;
      index += 1
    ) {
      const value =
        random.nextInt(10, 20);

      expect(Number.isInteger(value))
        .toBe(true);

      expect(value)
        .toBeGreaterThanOrEqual(10);

      expect(value)
        .toBeLessThan(20);
    }
  });

  it("makes deterministic selections from collections", () => {
    const devices = [
      "FIN-LT-01",
      "FIN-LT-02",
      "FIN-LT-03",
      "FIN-LT-04",
    ];

    const first =
      new SeededRandom(1337);

    const second =
      new SeededRandom(1337);

    expect(first.pick(devices))
      .toBe(second.pick(devices));
  });

  it("rejects invalid seeds and empty selections", () => {
    expect(
      () => new SeededRandom(
        Number.NaN,
      ),
    ).toThrow(
      "Random seed must be a finite integer.",
    );

    const random =
      new SeededRandom(1337);

    expect(
      () => random.pick([]),
    ).toThrow(
      "Cannot pick from an empty collection.",
    );
  });
});
