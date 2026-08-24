import type {
  CorpusManifest,
} from "./corpus.js";

/**
 * The Endomorph Detection Benchmark: the shipped corpus as one citable thing.
 *
 * The evaluator can already export a corpus per plan, but a pile of NDJSON
 * files is not a benchmark -- a benchmark is a named, versioned artifact with
 * a manifest that says what it contains, so a detection engineer can score
 * against it, cite it, and diff two versions of it. This aggregates the
 * per-plan corpus manifests into that top-level record: aggregate counts, the
 * union of techniques with how many plans exercise each, and a per-plan index
 * pointing at the files. It is a pure function of the manifests the generator
 * already produces, so the benchmark cannot drift from the data it describes.
 */

export const BENCHMARK_VERSION = "1.0";

export interface BenchmarkTechnique {
  readonly id: string;

  readonly name: string;

  readonly tactic: string;

  /** How many plans in the benchmark exercise this technique. */
  readonly plans: number;

  /** Total malicious events demonstrating it across the benchmark. */
  readonly maliciousEvents: number;
}

export interface BenchmarkPlanEntry {
  readonly plan: string;

  readonly planName: string;

  readonly difficulty: string;

  readonly recordCount: number;

  readonly maliciousCount: number;

  readonly maliciousRatio: number;

  readonly techniques: readonly string[];

  /** The corpus file this plan was written to, relative to the manifest. */
  readonly file: string;
}

export interface BenchmarkManifest {
  readonly format: "endomorph-benchmark";

  readonly version: string;

  readonly generator: string;

  readonly seed: number;

  readonly generatedAt: string;

  readonly corpusFormat: string;

  readonly totals: {
    readonly plans: number;
    readonly records: number;
    readonly malicious: number;
    readonly benign: number;
    readonly maliciousRatio: number;
    readonly distinctTechniques: number;
  };

  readonly techniques: readonly BenchmarkTechnique[];

  readonly plans: readonly BenchmarkPlanEntry[];
}

export interface BenchmarkInput {
  readonly seed: number;

  readonly corpusFormat: string;

  readonly generatedAt: string;

  readonly entries: readonly {
    readonly manifest: CorpusManifest;
    readonly file: string;
  }[];
}

function round(value: number): number {
  return Math.round(value * 100000) / 100000;
}

export function buildBenchmarkManifest(
  input: BenchmarkInput,
): BenchmarkManifest {
  const plans: BenchmarkPlanEntry[] =
    input.entries.map((entry) => ({
      plan: entry.manifest.plan,
      planName: entry.manifest.planName,
      difficulty:
        entry.manifest.difficulty,
      recordCount:
        entry.manifest.recordCount,
      maliciousCount:
        entry.manifest.maliciousCount,
      maliciousRatio: round(
        entry.manifest.maliciousRatio,
      ),
      techniques:
        entry.manifest.techniques.map(
          (technique) => technique.id,
        ),
      file: entry.file,
    }));

  // Union of techniques across plans, in first-seen order for a stable file.
  const techniqueOrder: string[] = [];
  const techniques = new Map<
    string,
    BenchmarkTechnique
  >();

  for (const entry of input.entries) {
    for (const technique of entry
      .manifest.techniques) {
      const existing = techniques.get(
        technique.id,
      );

      if (existing) {
        techniques.set(technique.id, {
          ...existing,
          plans: existing.plans + 1,
          maliciousEvents:
            existing.maliciousEvents +
            technique.eventCount,
        });
      } else {
        techniqueOrder.push(technique.id);
        techniques.set(technique.id, {
          id: technique.id,
          name: technique.name,
          tactic: technique.tactic,
          plans: 1,
          maliciousEvents:
            technique.eventCount,
        });
      }
    }
  }

  const records = input.entries.reduce(
    (sum, entry) =>
      sum + entry.manifest.recordCount,
    0,
  );

  const malicious = input.entries.reduce(
    (sum, entry) =>
      sum +
      entry.manifest.maliciousCount,
    0,
  );

  return {
    format: "endomorph-benchmark",
    version: BENCHMARK_VERSION,
    generator: "endomorph-fabric",
    seed: input.seed,
    generatedAt: input.generatedAt,
    corpusFormat: input.corpusFormat,
    totals: {
      plans: input.entries.length,
      records,
      malicious,
      benign: records - malicious,
      maliciousRatio:
        records === 0
          ? 0
          : round(malicious / records),
      distinctTechniques:
        techniques.size,
    },
    techniques: techniqueOrder
      .map(
        (id) => techniques.get(id)!,
      )
      .sort((left, right) =>
        left.id.localeCompare(right.id),
      ),
    plans,
  };
}
