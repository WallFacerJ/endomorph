import {
  describe,
  expect,
  it,
} from "vitest";

import {
  summarizeKeyEvidence,
} from "./keyEvidence";

import type {
  ScenarioGroundTruthEvent,
} from "./simulationAdapter";

const timeline: readonly ScenarioGroundTruthEvent[] =
  [
    {
      eventId: "evt-a",
      title: "Spray",
      significance: "x",
      techniqueId: "T1110.003",
    },
    {
      eventId: "evt-b",
      significance: "no title here",
    },
  ];

describe("summarizeKeyEvidence", () => {
  it("returns undefined when there is no ground-truth timeline", () => {
    expect(
      summarizeKeyEvidence([], ["evt-a"]),
    ).toBeUndefined();
  });

  it("counts captured key events and names the misses", () => {
    const summary =
      summarizeKeyEvidence(timeline, [
        "evt-a",
        "unrelated",
      ]);

    expect(summary?.captured).toBe(1);
    expect(summary?.total).toBe(2);
    expect(summary?.missed).toEqual([
      {
        eventId: "evt-b",
        significance: "no title here",
      },
    ]);
  });

  it("treats every key event as captured when all are collected", () => {
    const summary =
      summarizeKeyEvidence(timeline, [
        "evt-a",
        "evt-b",
      ]);

    expect(summary?.captured).toBe(2);
    expect(summary?.missed).toEqual([]);
  });
});
