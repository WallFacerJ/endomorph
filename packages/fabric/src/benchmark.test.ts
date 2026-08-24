import {
  describe,
  expect,
  it,
} from "vitest";

import {
  buildBenchmarkManifest,
  BENCHMARK_VERSION,
} from "./benchmark.js";

import type {
  CorpusManifest,
} from "./corpus.js";

function manifest(
  overrides: Partial<CorpusManifest>,
): CorpusManifest {
  return {
    generator: "endomorph-fabric",
    seed: 20260820,
    organization: "Acme Financial",
    plan: "plan",
    planName: "Plan",
    difficulty: "standard",
    recordCount: 1000,
    maliciousCount: 10,
    benignCount: 990,
    maliciousRatio: 0.01,
    techniques: [],
    firstSeen: "2026-08-20T08:00:00.000Z",
    lastSeen: "2026-08-20T18:00:00.000Z",
    entityCounts: {},
    ...overrides,
  };
}

describe("buildBenchmarkManifest", () => {
  it("aggregates counts and stamps the benchmark version", () => {
    const result = buildBenchmarkManifest({
      seed: 20260820,
      corpusFormat: "ecs",
      generatedAt: "2026-08-24",
      entries: [
        {
          manifest: manifest({
            plan: "a",
            recordCount: 1000,
            maliciousCount: 10,
            benignCount: 990,
          }),
          file: "a.ndjson",
        },
        {
          manifest: manifest({
            plan: "b",
            recordCount: 2000,
            maliciousCount: 30,
            benignCount: 1970,
          }),
          file: "b.ndjson",
        },
      ],
    });

    expect(result.version).toBe(
      BENCHMARK_VERSION,
    );
    expect(result.totals.plans).toBe(2);
    expect(result.totals.records).toBe(
      3000,
    );
    expect(
      result.totals.malicious,
    ).toBe(40);
    expect(result.totals.benign).toBe(
      2960,
    );
    expect(
      result.totals.maliciousRatio,
    ).toBeCloseTo(40 / 3000, 5);
  });

  it("unions techniques and counts how many plans exercise each", () => {
    const shared = {
      id: "T1059.001",
      name: "PowerShell",
      tactic: "execution",
    };

    const result = buildBenchmarkManifest({
      seed: 1,
      corpusFormat: "ecs",
      generatedAt: "2026-08-24",
      entries: [
        {
          manifest: manifest({
            plan: "a",
            techniques: [
              {
                ...shared,
                eventCount: 2,
              },
            ],
          }),
          file: "a.ndjson",
        },
        {
          manifest: manifest({
            plan: "b",
            techniques: [
              {
                ...shared,
                eventCount: 3,
              },
              {
                id: "T1110.003",
                name: "Password spray",
                tactic: "credential-access",
                eventCount: 4,
              },
            ],
          }),
          file: "b.ndjson",
        },
      ],
    });

    expect(
      result.totals.distinctTechniques,
    ).toBe(2);

    const powershell =
      result.techniques.find(
        (technique) =>
          technique.id === "T1059.001",
      );

    expect(powershell?.plans).toBe(2);
    expect(
      powershell?.maliciousEvents,
    ).toBe(5);

    // Techniques are sorted by id for a stable, diffable file.
    expect(
      result.techniques.map(
        (technique) => technique.id,
      ),
    ).toEqual([
      "T1059.001",
      "T1110.003",
    ]);
  });

  it("attaches the noise floor to matching techniques when supplied", () => {
    const result = buildBenchmarkManifest({
      seed: 1,
      corpusFormat: "ecs",
      generatedAt: "2026-08-24",
      entries: [
        {
          manifest: manifest({
            plan: "a",
            techniques: [
              {
                id: "T1059.001",
                name: "PowerShell",
                tactic: "execution",
                eventCount: 2,
              },
            ],
          }),
          file: "a.ndjson",
        },
      ],
      noiseFloor: [
        {
          technique: "T1059.001",
          maliciousEvents: 2,
          eventTypes: ["PROCESS_STARTED"],
          benignLookalikes: 863,
          lookalikeRatio: 431.5,
        },
      ],
    });

    const technique =
      result.techniques[0];

    expect(
      technique.benignLookalikes,
    ).toBe(863);
    expect(
      technique.lookalikeRatio,
    ).toBe(431.5);
  });

  it("leaves techniques without a difficulty figure when no floor is supplied", () => {
    // A missing floor is absent, not a misleading zero that would read as a
    // trivially separable technique.
    const result = buildBenchmarkManifest({
      seed: 1,
      corpusFormat: "ecs",
      generatedAt: "2026-08-24",
      entries: [
        {
          manifest: manifest({
            plan: "a",
            techniques: [
              {
                id: "T1059.001",
                name: "PowerShell",
                tactic: "execution",
                eventCount: 2,
              },
            ],
          }),
          file: "a.ndjson",
        },
      ],
    });

    expect(
      result.techniques[0]
        .benignLookalikes,
    ).toBeUndefined();
  });

  it("indexes each plan to its corpus file", () => {
    const result = buildBenchmarkManifest({
      seed: 1,
      corpusFormat: "ocsf",
      generatedAt: "2026-08-24",
      entries: [
        {
          manifest: manifest({
            plan: "macro-execution",
          }),
          file: "macro-execution.ocsf.json",
        },
      ],
    });

    expect(result.plans[0].file).toBe(
      "macro-execution.ocsf.json",
    );
    expect(result.corpusFormat).toBe(
      "ocsf",
    );
  });
});
