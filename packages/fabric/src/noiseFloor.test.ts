import {
  describe,
  expect,
  it,
} from "vitest";

import {
  computeNoiseFloor,
} from "./noiseFloor.js";

import type {
  CorpusRecord,
} from "./corpus.js";

function record(
  eventType: string,
  malicious: boolean,
  technique?: string,
): CorpusRecord {
  return {
    "@timestamp":
      "2026-08-20T10:00:00.000Z",
    "event.id": Math.random().toString(),
    "event.kind": "event",
    "event.type": eventType,
    "event.module": "test",
    "label.malicious": malicious,
    ...(technique
      ? { "label.technique": technique }
      : {}),
  } as CorpusRecord;
}

describe("computeNoiseFloor", () => {
  it("counts the benign events that share a technique's event types", () => {
    // One malicious PowerShell launch, buried among 300 benign ones: a rule
    // keyed on "process started" eats all 300.
    const records: CorpusRecord[] = [
      record(
        "process_start",
        true,
        "T1059.001",
      ),
      ...Array.from(
        { length: 300 },
        () =>
          record("process_start", false),
      ),
      // Unrelated benign traffic of another type does not count.
      ...Array.from({ length: 50 }, () =>
        record("network_flow", false),
      ),
    ];

    const report =
      computeNoiseFloor(records);

    const technique =
      report.techniques[0];

    expect(technique.technique).toBe(
      "T1059.001",
    );
    expect(
      technique.maliciousEvents,
    ).toBe(1);
    expect(
      technique.benignLookalikes,
    ).toBe(300);
    expect(
      technique.lookalikeRatio,
    ).toBe(300);
  });

  it("reports a trivially separable technique as an empty haystack", () => {
    // The malicious event is the only one of its type. A rule keyed on the
    // type has zero false positives -- which, for real data, would be a
    // warning that the corpus is too clean to trust.
    const report = computeNoiseFloor([
      record(
        "role_grant",
        true,
        "T1098.003",
      ),
      ...Array.from({ length: 100 }, () =>
        record("process_start", false),
      ),
    ]);

    const technique =
      report.techniques[0];

    expect(
      technique.benignLookalikes,
    ).toBe(0);
    expect(
      technique.lookalikeRatio,
    ).toBe(0);
  });

  it("sums look-alikes across every type a technique touches", () => {
    const report = computeNoiseFloor([
      record("process_start", true, "T"),
      record("network_flow", true, "T"),
      ...Array.from({ length: 10 }, () =>
        record("process_start", false),
      ),
      ...Array.from({ length: 4 }, () =>
        record("network_flow", false),
      ),
    ]);

    const technique =
      report.techniques[0];

    expect(
      technique.eventTypes,
    ).toEqual([
      "network_flow",
      "process_start",
    ]);
    expect(
      technique.benignLookalikes,
    ).toBe(14);
    expect(
      technique.lookalikeRatio,
    ).toBe(7);
  });

  it("counts malicious and benign totals and sorts techniques by id", () => {
    const report = computeNoiseFloor([
      record("a", true, "T1110.003"),
      record("a", true, "T1003.001"),
      record("a", false),
    ]);

    expect(report.malicious).toBe(2);
    expect(report.benign).toBe(1);
    expect(
      report.techniques.map(
        (technique) =>
          technique.technique,
      ),
    ).toEqual([
      "T1003.001",
      "T1110.003",
    ]);
  });
});
