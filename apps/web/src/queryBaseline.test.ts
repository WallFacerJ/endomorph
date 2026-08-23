import {
  describe,
  expect,
  it,
} from "vitest";

import {
  describeQueryBaseline,
  summariseQueryBaseline,
} from "./queryBaseline";

import type {
  SiemEventRecord,
} from "./simulationAdapter";

function record(
  timestamp: string,
): SiemEventRecord {
  return {
    eventId: `event-${timestamp}`,
    timestamp,
    eventType: "AUTH_LOGIN_SUCCEEDED",
    family: "authentication",
    source: "identity",
    message: "signed in",
  } as unknown as SiemEventRecord;
}

const fourDays = [
  record("2026-08-20T09:00:00Z"),
  record("2026-08-21T09:00:00Z"),
  record("2026-08-22T09:00:00Z"),
  record("2026-08-23T09:00:00Z"),
];

describe("summariseQueryBaseline", () => {
  it("reports nothing for a query that matched nothing", () => {
    expect(
      summariseQueryBaseline(
        [],
        fourDays,
      ),
    ).toBeUndefined();
  });

  it("recognises a value with no history behind it", () => {
    /*
      The strongest reading the console can offer, and the one the scenarios
      ask for in as many words: the account signed in from an address it had
      never used. Everything matching falls on the most recent day.
    */
    const baseline =
      summariseQueryBaseline(
        [
          record(
            "2026-08-23T10:15:00Z",
          ),
          record(
            "2026-08-23T10:22:00Z",
          ),
        ],
        fourDays,
      );

    expect(baseline?.onlyToday).toBe(
      true,
    );

    expect(baseline?.activeDays).toBe(1);
    expect(baseline?.retainedDays).toBe(
      4,
    );

    expect(
      describeQueryBaseline(baseline!),
    ).toContain(
      "3 day(s) of history before it",
    );
  });

  it("recognises something the environment does every day", () => {
    const baseline =
      summariseQueryBaseline(
        fourDays,
        fourDays,
      );

    expect(baseline?.onlyToday).toBe(
      false,
    );

    expect(
      describeQueryBaseline(baseline!),
    ).toContain(
      "part of the environment's routine",
    );
  });

  it("does not call a gap on the latest day new", () => {
    // Matches on three of four days, none of them the most recent. That is
    // not a value without history; it is one that stopped.
    const baseline =
      summariseQueryBaseline(
        fourDays.slice(0, 3),
        fourDays,
      );

    expect(baseline?.onlyToday).toBe(
      false,
    );

    expect(baseline?.activeDays).toBe(3);
  });

  it("keeps the earliest and latest match", () => {
    const baseline =
      summariseQueryBaseline(
        [
          record(
            "2026-08-22T18:00:00Z",
          ),
          record(
            "2026-08-20T06:00:00Z",
          ),
        ],
        fourDays,
      );

    expect(baseline?.firstSeen).toBe(
      "2026-08-20T06:00:00Z",
    );

    expect(baseline?.lastSeen).toBe(
      "2026-08-22T18:00:00Z",
    );
  });

  it("survives a record whose timestamp cannot be parsed", () => {
    // The corpus is generated and its timestamps are sound, but a baseline
    // that throws would take the whole search view down with it.
    const baseline =
      summariseQueryBaseline(
        [record("not-a-timestamp")],
        fourDays,
      );

    expect(baseline?.matches).toBe(1);
    expect(baseline?.activeDays).toBe(0);
  });
});
