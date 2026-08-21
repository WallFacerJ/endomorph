import {
  describe,
  expect,
  it,
} from "vitest";

import {
  RandomCursor,
} from "./randomCursor.js";

function draw(
  cursor: RandomCursor,
  count: number,
): number[] {
  return Array.from(
    { length: count },
    () => cursor.next(),
  );
}

function drawPinned(
  cursor: RandomCursor,
  count: number,
): number[] {
  return draw(cursor, count).map(
    (value) =>
      Number(value.toFixed(10)),
  );
}

describe("RandomCursor", () => {
  describe("seed determinism", () => {
    it("produces identical sequences from identical seeds", () => {
      const first =
        RandomCursor.root(1337);

      const second =
        RandomCursor.root(1337);

      expect(draw(first, 32)).toEqual(
        draw(second, 32),
      );
    });

    it("produces different sequences from different seeds", () => {
      const first =
        RandomCursor.root(1337);

      const second =
        RandomCursor.root(9001);

      expect(
        draw(first, 32),
      ).not.toEqual(draw(second, 32));
    });

    it("stays in [0, 1)", () => {
      const cursor =
        RandomCursor.root(7);

      for (const value of draw(
        cursor,
        1000,
      )) {
        expect(
          value,
        ).toBeGreaterThanOrEqual(0);

        expect(value).toBeLessThan(1);
      }
    });

    it("rejects a non-integer seed", () => {
      expect(() =>
        RandomCursor.root(1.5),
      ).toThrow();

      expect(() =>
        RandomCursor.root(Number.NaN),
      ).toThrow();
    });

    it("rewinds to the start of its stream on reset", () => {
      const cursor =
        RandomCursor.root(1337);

      const first = draw(cursor, 16);

      cursor.reset();

      expect(draw(cursor, 16)).toEqual(
        first,
      );
    });
  });

  describe("fork determinism", () => {
    it("produces identical sequences for the same fork path", () => {
      const first = RandomCursor.root(
        1337,
      )
        .fork("world")
        .fork("devices");

      const second = RandomCursor.root(
        1337,
      )
        .fork("world")
        .fork("devices");

      expect(draw(first, 32)).toEqual(
        draw(second, 32),
      );
    });

    it("gives different labels different streams", () => {
      const root =
        RandomCursor.root(1337);

      expect(
        draw(root.fork("users"), 32),
      ).not.toEqual(
        draw(root.fork("devices"), 32),
      );
    });

    it("gives near-identical labels unrelated streams", () => {
      const root =
        RandomCursor.root(1337);

      expect(
        draw(
          root.fork("device-1"),
          32,
        ),
      ).not.toEqual(
        draw(
          root.fork("device-2"),
          32,
        ),
      );
    });

    it("distinguishes the same label at different depths", () => {
      const root =
        RandomCursor.root(1337);

      expect(
        draw(root.fork("users"), 32),
      ).not.toEqual(
        draw(
          root
            .fork("world")
            .fork("users"),
          32,
        ),
      );
    });

    it("records the fork path", () => {
      const cursor = RandomCursor.root(
        1337,
      )
        .fork("world")
        .fork("devices");

      expect(cursor.path).toBe(
        "world/devices",
      );

      expect(
        RandomCursor.root(1337).path,
      ).toBe("");
    });

    it("rejects an empty fork label", () => {
      expect(() =>
        RandomCursor.root(1337).fork(""),
      ).toThrow();
    });
  });

  describe("sibling independence", () => {
    it("is unaffected by how much a sibling has drawn", () => {
      const undisturbed =
        RandomCursor.root(1337);

      const expected = draw(
        undisturbed.fork("devices"),
        32,
      );

      const disturbed =
        RandomCursor.root(1337);

      // Drain a sibling heavily before forking the stream under test.
      draw(
        disturbed.fork("users"),
        5000,
      );

      expect(
        draw(
          disturbed.fork("devices"),
          32,
        ),
      ).toEqual(expected);
    });

    it("is unaffected by fork order", () => {
      const forward =
        RandomCursor.root(1337);

      const users =
        forward.fork("users");

      const devices =
        forward.fork("devices");

      const reversed =
        RandomCursor.root(1337);

      const reversedDevices =
        reversed.fork("devices");

      const reversedUsers =
        reversed.fork("users");

      expect(draw(users, 32)).toEqual(
        draw(reversedUsers, 32),
      );

      expect(draw(devices, 32)).toEqual(
        draw(reversedDevices, 32),
      );
    });

    it("is unaffected by consumption of the parent", () => {
      const undisturbed =
        RandomCursor.root(1337);

      const expected = draw(
        undisturbed.fork("devices"),
        32,
      );

      const disturbed =
        RandomCursor.root(1337);

      draw(disturbed, 5000);

      expect(
        draw(
          disturbed.fork("devices"),
          32,
        ),
      ).toEqual(expected);
    });

    it("keeps an entity stream stable when a sibling entity is added", () => {
      // The authoring failure this design exists to prevent: generating one
      // more device must not resequence anything drawn for the users.
      const before =
        RandomCursor.root(1337);

      const beforeDevices =
        before.fork("devices");

      for (
        let index = 0;
        index < 3;
        index += 1
      ) {
        draw(
          beforeDevices.fork(
            "device-" + index,
          ),
          8,
        );
      }

      const beforeUsers = draw(
        before.fork("users"),
        32,
      );

      const after =
        RandomCursor.root(1337);

      const afterDevices =
        after.fork("devices");

      for (
        let index = 0;
        index < 4;
        index += 1
      ) {
        draw(
          afterDevices.fork(
            "device-" + index,
          ),
          8,
        );
      }

      expect(
        draw(after.fork("users"), 32),
      ).toEqual(beforeUsers);
    });
  });

  describe("derived helpers", () => {
    it("keeps nextInt within bounds", () => {
      const cursor =
        RandomCursor.root(1337);

      for (
        let index = 0;
        index < 1000;
        index += 1
      ) {
        const value = cursor.nextInt(
          5,
          10,
        );

        expect(
          value,
        ).toBeGreaterThanOrEqual(5);

        expect(value).toBeLessThan(10);
      }
    });

    it("rejects an inverted nextInt range", () => {
      const cursor =
        RandomCursor.root(1337);

      expect(() =>
        cursor.nextInt(10, 5),
      ).toThrow();

      expect(() =>
        cursor.nextInt(5, 5),
      ).toThrow();
    });

    it("picks deterministically", () => {
      const items = [
        "a",
        "b",
        "c",
        "d",
      ];

      const first =
        RandomCursor.root(1337);

      const second =
        RandomCursor.root(1337);

      expect(
        Array.from(
          { length: 32 },
          () => first.pick(items),
        ),
      ).toEqual(
        Array.from(
          { length: 32 },
          () => second.pick(items),
        ),
      );
    });

    it("rejects picking from an empty collection", () => {
      expect(() =>
        RandomCursor.root(1337).pick(
          [],
        ),
      ).toThrow();
    });

    it("shuffles deterministically without mutating the input", () => {
      const items = [
        1, 2, 3, 4, 5, 6, 7, 8,
      ];

      const first = RandomCursor.root(
        1337,
      ).shuffle(items);

      const second = RandomCursor.root(
        1337,
      ).shuffle(items);

      expect(first).toEqual(second);

      expect(items).toEqual([
        1, 2, 3, 4, 5, 6, 7, 8,
      ]);

      expect(
        [...first].sort(
          (left, right) => left - right,
        ),
      ).toEqual(items);
    });

    it("honours nextBoolean probability bounds", () => {
      const cursor =
        RandomCursor.root(1337);

      expect(cursor.nextBoolean(1)).toBe(
        true,
      );

      expect(cursor.nextBoolean(0)).toBe(
        false,
      );

      expect(() =>
        cursor.nextBoolean(1.5),
      ).toThrow();
    });
  });

  describe("cross-process stability", () => {
    // Determinism has to hold across builds and machines, not just within a
    // single run. These pin the exact stream so a change to the generator
    // algorithm or to seed derivation fails loudly instead of silently
    // invalidating every previously generated world.
    it("pins the root stream", () => {
      expect(
        drawPinned(
          RandomCursor.root(1337),
          4,
        ),
      ).toEqual([
        0.1844118326, 0.1899892513,
        0.8104719922, 0.6437488222,
      ]);
    });

    it("pins a forked stream", () => {
      expect(
        drawPinned(
          RandomCursor.root(1337)
            .fork("world")
            .fork("devices"),
          4,
        ),
      ).toEqual([
        0.9277254029, 0.8349385548,
        0.6204085103, 0.1203795448,
      ]);
    });
  });
});
