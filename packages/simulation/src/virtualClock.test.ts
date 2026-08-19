import {
  describe,
  expect,
  it,
} from "vitest";

import {
  VirtualClock,
} from "./virtualClock";

describe("VirtualClock", () => {
  it("starts at an explicit simulation time", () => {
    const clock = new VirtualClock(
      "2026-08-18T09:00:00Z",
    );

    expect(clock.now())
      .toBe("2026-08-18T09:00:00.000Z");
  });

  it("advances simulation time without using wall-clock time", () => {
    const clock = new VirtualClock(
      "2026-08-18T09:00:00Z",
    );

    clock.advanceMinutes(15);

    expect(clock.now())
      .toBe("2026-08-18T09:15:00.000Z");
  });

  it("supports deterministic sequences of time advancement", () => {
    const first = new VirtualClock(
      "2026-08-18T09:00:00Z",
    );

    const second = new VirtualClock(
      "2026-08-18T09:00:00Z",
    );

    first.advanceMinutes(5);
    first.advanceSeconds(30);

    second.advanceMinutes(5);
    second.advanceSeconds(30);

    expect(first.now())
      .toBe(second.now());
  });

  it("rejects invalid initial timestamps", () => {
    expect(
      () => new VirtualClock(
        "not-a-timestamp",
      ),
    ).toThrow(
      "Invalid simulation timestamp",
    );
  });

  it("rejects backwards advancement", () => {
    const clock = new VirtualClock(
      "2026-08-18T09:00:00Z",
    );

    expect(
      () => clock.advanceSeconds(-1),
    ).toThrow(
      "Clock advancement must be a non-negative finite number.",
    );
  });
});
