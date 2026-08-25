/**
 * Corpus export and detection evaluation.
 *
 *   pnpm evaluate                       score the shipped ruleset
 *   pnpm evaluate -- --export out.ndjson  also write the corpus
 *
 * Runs every plan in the library, so a rule's score is reported against the
 * incident it targets *and* against the incidents it does not -- which is
 * where false positives actually come from.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";

import {
  dirname,
  join,
} from "node:path";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

import {
  buildCorpus,
} from "./corpus.js";

import {
  parseEnterpriseProfile,
} from "./profileFile.js";

import {
  CORPUS_FORMATS,
  extensionFor,
  formatCorpus,
  isCorpusFormat,
} from "./corpusFormats.js";

import {
  DETECTION_RULES,
} from "./detectionLibrary.js";

import {
  evaluateRuleset,
} from "./detection.js";

import {
  importSigmaRules,
} from "./sigma.js";

import {
  importKqlRules,
} from "./kql.js";

import {
  importSplRules,
} from "./spl.js";

import {
  importEqlRules,
} from "./eql.js";

import {
  resolveFromRoot,
} from "./workspaceRoot.js";

import {
  renderCoverageReport,
} from "./coverageReport.js";

import {
  renderCoverageBadge,
} from "./coverageBadge.js";

import {
  renderCohortReview,
} from "./cohortReview.js";

import {
  buildPlanReport,
  compareToBaseline,
  summarise,
} from "./detectionReport.js";

import type {
  DetectionReport,
  PlanReport,
} from "./detectionReport.js";

import {
  summariseRobustness,
} from "./robustness.js";

import type {
  RobustnessSummary,
} from "./robustness.js";

import {
  buildBenchmarkManifest,
  BENCHMARK_VERSION,
} from "./benchmark.js";

import {
  computeNoiseFloor,
} from "./noiseFloor.js";

import type {
  TechniqueNoiseFloor,
} from "./noiseFloor.js";

import type {
  DetectionRule,
} from "./detection.js";

import {
  generateBackgroundActivity,
} from "./backgroundActivity.js";

import {
  generateEnterprise,
} from "./generateEnterprise.js";

import {
  generateIncident,
} from "./generateIncident.js";

/**
 * Pads to a fixed width, truncating when the value is longer.
 *
 * padEnd alone does not shorten, so a rule id wider than its column ran
 * straight into the next one and the table stopped being a table.
 */
function pad(
  value: string | number,
  width: number,
): string {
  const text = String(value);

  return text.length >= width
    ? `${text.slice(0, width - 2)} `
    : text.padEnd(width);
}

/**
 * Scores the ruleset against one seeded enterprise, across every plan, and
 * returns the per-seed report. Pure of output so the robustness mode can call
 * it many times without printing a table each time.
 */
function evaluateSeed(
  rules: readonly DetectionRule[],
  seed: number,
  profileOverrides:
    | Parameters<
        typeof generateEnterprise
      >[0]
    | undefined,
): DetectionReport {
  const enterprise = generateEnterprise(
    profileOverrides
      ? { ...profileOverrides, seed }
      : { seed },
  );

  const background =
    generateBackgroundActivity(
      enterprise,
      { days: 3 },
    );

  const planReports: PlanReport[] = [];

  for (const plan of ATTACK_PLANS) {
    const incident = generateIncident(
      enterprise,
      { planId: plan.id },
    );

    const detection =
      incident.events[
        incident.events.length - 1
      ].timestamp;

    const events = [
      ...background.filter(
        (event) =>
          event.timestamp <= detection,
      ),
      ...incident.events,
    ].sort((left, right) =>
      left.timestamp.localeCompare(
        right.timestamp,
      ),
    );

    const corpus = buildCorpus(
      enterprise,
      events,
      incident,
    );

    const report = evaluateRuleset(
      rules,
      corpus.records,
    );

    planReports.push(
      buildPlanReport(
        plan.id,
        plan.name,
        corpus.manifest.recordCount,
        corpus.manifest.maliciousCount,
        report,
      ),
    );
  }

  return summarise(
    seed,
    rules.length,
    planReports,
  );
}

function printRobustness(
  summary: RobustnessSummary,
): void {
  process.stdout.write(
    `Endomorph rule robustness\n  ${summary.seeds.length} seeds: ${summary.seeds[0]}..${summary.seeds[summary.seeds.length - 1]}\n\n`,
  );

  process.stdout.write(
    `  ${pad("RULE", 26)}${pad("TECHNIQUE", 12)}${pad("DETECTED", 10)}${pad("RECALL min/mean/max", 22)}${pad("FP mean/max", 14)}VERDICT\n`,
  );

  for (const rule of summary.rules) {
    process.stdout.write(
      `  ${pad(rule.ruleId, 26)}${pad(
        rule.technique ?? "-",
        12,
      )}${pad(
        `${rule.detectedOn}/${rule.seeds}`,
        10,
      )}${pad(
        `${rule.recall.min.toFixed(2)} ${rule.recall.mean.toFixed(2)} ${rule.recall.max.toFixed(2)}`,
        22,
      )}${pad(
        `${rule.falsePositives.mean.toFixed(1)}/${rule.falsePositives.max}`,
        14,
      )}${rule.verdict.toUpperCase()}\n`,
    );
  }

  const everySeed =
    summary.techniques.filter(
      (technique) =>
        technique.coveredOnEverySeed,
    ).length;

  const fragile = summary.rules.filter(
    (rule) => rule.verdict === "fragile",
  );

  process.stdout.write(
    `\n  techniques covered on every seed   ${everySeed}/${summary.techniques.length}\n`,
  );

  if (fragile.length > 0) {
    process.stdout.write(
      `  FRAGILE rules (miss their technique on at least one enterprise): ${fragile
        .map((rule) => rule.ruleId)
        .join(", ")}\n`,
    );
  }

  process.stdout.write("\n");
}

function printNoiseFloor(
  techniques: readonly TechniqueNoiseFloor[],
): void {
  const sorted = [...techniques].sort(
    (left, right) =>
      right.lookalikeRatio -
      left.lookalikeRatio,
  );

  process.stdout.write(
    `  ${pad("TECHNIQUE", 12)}${pad("MAL", 6)}${pad("BENIGN LOOK-ALIKES", 20)}${pad("PER MALICIOUS", 15)}EVENT TYPES
`,
  );

  for (const technique of sorted) {
    process.stdout.write(
      `  ${pad(
        technique.technique,
        12,
      )}${pad(
        technique.maliciousEvents,
        6,
      )}${pad(
        technique.benignLookalikes,
        20,
      )}${pad(
        technique.lookalikeRatio === 0
          ? "0 (exposed)"
          : `${technique.lookalikeRatio}x`,
        15,
      )}${technique.eventTypes.join(", ")}
`,
    );
  }

  const buried = sorted.filter(
    (technique) =>
      technique.lookalikeRatio >= 10,
  ).length;

  const exposed = sorted.filter(
    (technique) =>
      technique.benignLookalikes === 0,
  ).length;

  process.stdout.write(
    `
  ${buried}/${sorted.length} techniques are buried among 10x or more benign look-alikes;
  ${exposed} are exposed (no benign event of their type -- a corpus with many of these would be too clean to trust).

`,
  );
}

function main(): void {
  const argv = process.argv.slice(2);

  const exportIndex =
    argv.indexOf("--export");

  const exportPath =
    exportIndex >= 0
      ? argv[exportIndex + 1]
      : undefined;

  const seedIndex = argv.indexOf("--seed");

  const seed =
    seedIndex >= 0
      ? Number(argv[seedIndex + 1])
      : 20260820;

  // Optional Sigma import. Rules that the supported subset cannot express
  // are reported rather than dropped silently, because a rule that quietly
  // matches nothing looks exactly like coverage.
  const sigmaIndex = argv.indexOf("--sigma");

  const sigmaDir =
    sigmaIndex >= 0
      ? argv[sigmaIndex + 1]
      : undefined;

  let rules: DetectionRule[] = [
    ...DETECTION_RULES,
  ];

  if (sigmaDir) {
    const sigmaRoot =
      resolveFromRoot(sigmaDir);

    if (!existsSync(sigmaRoot)) {
      throw new Error(
        `Sigma directory not found: ${sigmaRoot}`,
      );
    }

    const documents = readdirSync(
      sigmaRoot,
    )
      .filter(
        (name) =>
          name.endsWith(".yml") ||
          name.endsWith(".yaml"),
      )
      .map((name) => ({
        source: name,
        yaml: readFileSync(
          `${sigmaRoot}/${name}`,
          "utf8",
        ),
      }));

    const imported =
      importSigmaRules(documents);

    // Replaces the built-in set rather than adding to it: the point of
    // pointing at a rule directory is to score *that* ruleset, and mixing
    // in rules the author did not write would make the numbers meaningless.
    rules = [...imported.rules];

    process.stdout.write(
      `Sigma import from ${sigmaDir}
  imported ${imported.rules.length}, skipped ${imported.skipped.length}
`,
    );

    for (const skip of imported.skipped) {
      process.stdout.write(
        `  SKIPPED ${skip.source}: ${skip.reason}
`,
      );
    }

    process.stdout.write("\n");
  }

  // The same idea for Kusto: point at a folder of .kql queries and score that
  // ruleset. If both --sigma and --kql are given the later block wins, made
  // explicit here rather than silently merging two authors' rules.
  const kqlIndex = argv.indexOf("--kql");

  const kqlDir =
    kqlIndex >= 0
      ? argv[kqlIndex + 1]
      : undefined;

  if (kqlDir) {
    const kqlRoot =
      resolveFromRoot(kqlDir);

    if (!existsSync(kqlRoot)) {
      throw new Error(
        `KQL directory not found: ${kqlRoot}`,
      );
    }

    const kqlDocuments = readdirSync(
      kqlRoot,
    )
      .filter((name) =>
        name.endsWith(".kql"),
      )
      .map((name) => ({
        source: name,
        query: readFileSync(
          `${kqlRoot}/${name}`,
          "utf8",
        ),
      }));

    const importedKql =
      importKqlRules(kqlDocuments);

    rules = [...importedKql.rules];

    process.stdout.write(
      `KQL import from ${kqlDir}
  imported ${importedKql.rules.length}, skipped ${importedKql.skipped.length}
`,
    );

    for (const skip of importedKql.skipped) {
      process.stdout.write(
        `  SKIPPED ${skip.source}: ${skip.reason}
`,
      );
    }

    process.stdout.write("\n");
  }

  const splIndex = argv.indexOf("--spl");

  const splDir =
    splIndex >= 0
      ? argv[splIndex + 1]
      : undefined;

  if (splDir) {
    const splRoot =
      resolveFromRoot(splDir);

    if (!existsSync(splRoot)) {
      throw new Error(
        `SPL directory not found: ${splRoot}`,
      );
    }

    const splDocuments = readdirSync(
      splRoot,
    )
      .filter((name) =>
        name.endsWith(".spl"),
      )
      .map((name) => ({
        source: name,
        query: readFileSync(
          `${splRoot}/${name}`,
          "utf8",
        ),
      }));

    const importedSpl =
      importSplRules(splDocuments);

    rules = [...importedSpl.rules];

    process.stdout.write(
      `SPL import from ${splDir}
  imported ${importedSpl.rules.length}, skipped ${importedSpl.skipped.length}
`,
    );

    for (const skip of importedSpl.skipped) {
      process.stdout.write(
        `  SKIPPED ${skip.source}: ${skip.reason}
`,
      );
    }

    process.stdout.write("\n");
  }

  const eqlIndex = argv.indexOf("--eql");

  const eqlDir =
    eqlIndex >= 0
      ? argv[eqlIndex + 1]
      : undefined;

  if (eqlDir) {
    const eqlRoot =
      resolveFromRoot(eqlDir);

    if (!existsSync(eqlRoot)) {
      throw new Error(
        `EQL directory not found: ${eqlRoot}`,
      );
    }

    const eqlDocuments = readdirSync(
      eqlRoot,
    )
      .filter((name) =>
        name.endsWith(".eql"),
      )
      .map((name) => ({
        source: name,
        query: readFileSync(
          `${eqlRoot}/${name}`,
          "utf8",
        ),
      }));

    const importedEql =
      importEqlRules(eqlDocuments);

    rules = [...importedEql.rules];

    process.stdout.write(
      `EQL import from ${eqlDir}
  imported ${importedEql.rules.length}, skipped ${importedEql.skipped.length}
`,
    );

    for (const skip of importedEql.skipped) {
      process.stdout.write(
        `  SKIPPED ${skip.source}: ${skip.reason}
`,
      );
    }

    process.stdout.write("\n");
  }

  const flag = (name: string) => {
    const index = argv.indexOf(
      `--${name}`,
    );

    return index >= 0
      ? argv[index + 1]
      : undefined;
  };

  const jsonPath = flag("json");

  const baselinePath = flag("baseline");

  /*
    A client-facing deliverable rather than an engineer's output. The console
    table and the JSON are the right shapes for someone changing the rules;
    "here is what your ruleset catches and what it misses" is a different
    conversation and has to survive being emailed.
  */
  const coveragePath = flag("report");

  /*
    The destination platform. ECS NDJSON is the neutral shape and is not what
    any of the three common destinations actually ingest, so "load this into
    your Splunk" hid a transformation step -- exactly the sort of thing that
    gets written badly once per engagement.
  */
  const requestedFormat =
    flag("format") ?? "ecs";

  if (!isCorpusFormat(requestedFormat)) {
    throw new Error(
      `Unknown export format "${requestedFormat}". Known formats: ${CORPUS_FORMATS.join(
        ", ",
      )}.`,
    );
  }

  const destinationIndex = flag("index");

  /*
    A client environment profile. Generating an estate that carries the
    client's department names, host codes and subnets is what separates a
    demo from an engagement -- an analyst training against something shaped
    like their own network is doing a different exercise from one training
    against Acme Financial.
  */
  const profilePath = flag("profile");

  const profileOverrides = profilePath
    ? parseEnterpriseProfile(
        JSON.parse(
          readFileSync(
            resolveFromRoot(profilePath),
            "utf8",
          ),
        ),
      )
    : undefined;

  /*
    Robustness mode: the measurement no fixed corpus can make. Score the same
    ruleset against many seeded enterprises -- staff, hosts, and addresses all
    different, the techniques the same -- and report whether each rule holds.
    A rule that catches its technique on every seed is detecting behaviour; one
    that misses on some memorised this world. This is the whole pitch of a
    generated corpus over a captured one, so it gets its own path and returns
    before the single-seed report.
  */
  const robustnessArg =
    flag("robustness");

  if (robustnessArg !== undefined) {
    const count = Math.max(
      2,
      Math.floor(Number(robustnessArg)),
    );

    if (!Number.isFinite(count)) {
      throw new Error(
        `--robustness expects a seed count, got "${robustnessArg}".`,
      );
    }

    const seeds = Array.from(
      { length: count },
      (_unused, index) => seed + index,
    );

    process.stdout.write(
      `Endomorph rule robustness across ${count} seeds\n  this scores the ruleset against ${count} independently generated enterprises\n\n`,
    );

    const reports = seeds.map((each) =>
      evaluateSeed(
        rules,
        each,
        profileOverrides,
      ),
    );

    const robustness =
      summariseRobustness(reports);

    printRobustness(robustness);

    if (jsonPath) {
      const target =
        resolveFromRoot(jsonPath);

      mkdirSync(dirname(target), {
        recursive: true,
      });

      writeFileSync(
        target,
        `${JSON.stringify(robustness, null, 2)}\n`,
        "utf8",
      );

      process.stdout.write(
        `Robustness report written to ${jsonPath}\n\n`,
      );
    }

    const fragile =
      robustness.rules.filter(
        (rule) =>
          rule.verdict === "fragile",
      );

    if (fragile.length > 0) {
      // A rule that only fires on some enterprises is a finding, not a pass:
      // exit non-zero so a CI gate on rule quality can catch it.
      process.exitCode = 1;
    }

    return;
  }

  /*
    Benchmark mode: write the shipped corpus as one citable, versioned artifact
    -- every plan's labelled telemetry plus a top-level manifest that says what
    the set contains. A pile of NDJSON files is data; a benchmark is data with
    a manifest a detection engineer can score against, cite, and diff. The
    corpus files are byte-deterministic for a given seed; only the manifest's
    generatedAt stamp varies, and the version and seed identify the set.
  */
  const benchmarkDir = flag("benchmark");

  if (benchmarkDir !== undefined) {
    const outDir =
      resolveFromRoot(benchmarkDir);

    mkdirSync(outDir, {
      recursive: true,
    });

    const enterprise =
      generateEnterprise(
        profileOverrides
          ? { ...profileOverrides, seed }
          : { seed },
      );

    const background =
      generateBackgroundActivity(
        enterprise,
        { days: 3 },
      );

    process.stdout.write(
      `Endomorph Detection Benchmark v${BENCHMARK_VERSION}
  seed ${seed}  |  format ${requestedFormat}  |  ${ATTACK_PLANS.length} plans

`,
    );

    const entries: {
      manifest: ReturnType<
        typeof buildCorpus
      >["manifest"];
      file: string;
    }[] = [];

    // The difficulty half of the benchmark: how buried each technique is,
    // merged across plans so the manifest carries it beside the coverage.
    const floorByTechnique = new Map<
      string,
      TechniqueNoiseFloor
    >();

    for (const plan of ATTACK_PLANS) {
      const incident = generateIncident(
        enterprise,
        { planId: plan.id },
      );

      const detection =
        incident.events[
          incident.events.length - 1
        ].timestamp;

      const events = [
        ...background.filter(
          (event) =>
            event.timestamp <=
            detection,
        ),
        ...incident.events,
      ].sort((left, right) =>
        left.timestamp.localeCompare(
          right.timestamp,
        ),
      );

      const corpus = buildCorpus(
        enterprise,
        events,
        incident,
      );

      for (const technique of computeNoiseFloor(
        corpus.records,
      ).techniques) {
        const existing =
          floorByTechnique.get(
            technique.technique,
          );

        if (
          !existing ||
          technique.benignLookalikes >
            existing.benignLookalikes
        ) {
          floorByTechnique.set(
            technique.technique,
            technique,
          );
        }
      }

      const fileName = `${plan.id}${extensionFor(
        requestedFormat,
      )}`;

      writeFileSync(
        join(outDir, fileName),
        formatCorpus(corpus.records, {
          format: requestedFormat,
          index: destinationIndex,
        }),
        "utf8",
      );

      entries.push({
        manifest: corpus.manifest,
        file: fileName,
      });

      process.stdout.write(
        `  ${pad(plan.id, 26)}${pad(
          `${corpus.manifest.recordCount} records`,
          16,
        )}${pad(
          `${corpus.manifest.maliciousCount} malicious`,
          16,
        )}-> ${fileName}
`,
      );
    }

    const benchmark =
      buildBenchmarkManifest({
        seed,
        corpusFormat: requestedFormat,
        generatedAt: new Date()
          .toISOString()
          .slice(0, 10),
        entries,
        noiseFloor: [
          ...floorByTechnique.values(),
        ],
      });

    writeFileSync(
      join(outDir, "benchmark.json"),
      `${JSON.stringify(benchmark, null, 2)}
`,
      "utf8",
    );

    process.stdout.write(
      `
  ${benchmark.totals.records} records, ${benchmark.totals.malicious} malicious (${(
        benchmark.totals.maliciousRatio *
        100
      ).toFixed(3)}%), ${benchmark.totals.distinctTechniques} techniques across ${benchmark.totals.plans} plans
  manifest written to ${benchmarkDir}/benchmark.json

`,
    );

    return;
  }

  /*
    Noise-floor mode: the measured answer to "your false positives won't
    transfer because the benign traffic is too clean". For each technique, how
    many benign events share its event types -- the false positives an
    unspecific rule keyed on that behaviour would eat. A technique with a large
    haystack is realistically hard; one with none is a corpus telling on
    itself.
  */
  if (argv.includes("--noise-floor")) {
    const enterprise =
      generateEnterprise(
        profileOverrides
          ? { ...profileOverrides, seed }
          : { seed },
      );

    const background =
      generateBackgroundActivity(
        enterprise,
        { days: 3 },
      );

    process.stdout.write(
      `Endomorph corpus noise floor
  seed ${seed}: how many benign events share each technique's event types

`,
    );

    const byTechnique = new Map<
      string,
      TechniqueNoiseFloor
    >();

    for (const plan of ATTACK_PLANS) {
      const incident = generateIncident(
        enterprise,
        { planId: plan.id },
      );

      const detection =
        incident.events[
          incident.events.length - 1
        ].timestamp;

      const events = [
        ...background.filter(
          (event) =>
            event.timestamp <=
            detection,
        ),
        ...incident.events,
      ].sort((left, right) =>
        left.timestamp.localeCompare(
          right.timestamp,
        ),
      );

      const corpus = buildCorpus(
        enterprise,
        events,
        incident,
      );

      for (const technique of computeNoiseFloor(
        corpus.records,
      ).techniques) {
        const existing =
          byTechnique.get(
            technique.technique,
          );

        // The same technique can appear in more than one plan; keep the
        // instance with the most malicious events, as the fullest picture.
        if (
          !existing ||
          technique.maliciousEvents >
            existing.maliciousEvents
        ) {
          byTechnique.set(
            technique.technique,
            technique,
          );
        }
      }
    }

    printNoiseFloor([
      ...byTechnique.values(),
    ]);

    return;
  }

  const planReports: PlanReport[] = [];

  const enterprise = generateEnterprise(
    profileOverrides
      ? { ...profileOverrides, seed }
      : { seed },
  );

  if (profilePath) {
    process.stdout.write(
      `Environment profile: ${profileOverrides?.organizationName} (${profileOverrides?.departments.length} departments)
`,
    );
  }

  const background =
    generateBackgroundActivity(
      enterprise,
      { days: 3 },
    );

  process.stdout.write(
    `Endomorph detection evaluation\n  seed ${seed}  |  ${enterprise.users.length} staff  |  ${background.length} benign events\n\n`,
  );

  for (const plan of ATTACK_PLANS) {
    const incident = generateIncident(
      enterprise,
      { planId: plan.id },
    );

    const detection =
      incident.events[
        incident.events.length - 1
      ].timestamp;

    const events = [
      ...background.filter(
        (event) =>
          event.timestamp <= detection,
      ),
      ...incident.events,
    ].sort((left, right) =>
      left.timestamp.localeCompare(
        right.timestamp,
      ),
    );

    const corpus = buildCorpus(
      enterprise,
      events,
      incident,
    );

    const report = evaluateRuleset(
      rules,
      corpus.records,
    );

    process.stdout.write(
      `${plan.name}  (${plan.id})\n` +
        `  corpus ${corpus.manifest.recordCount} records, ${corpus.manifest.maliciousCount} malicious (${(
          corpus.manifest.maliciousRatio *
          100
        ).toFixed(3)}%)\n\n`,
    );

    process.stdout.write(
      `  ${pad("RULE", 26)}${pad("TECHNIQUE", 12)}${pad("TP", 5)}${pad("FP", 7)}${pad("FN", 5)}${pad("PREC", 8)}${pad("RECALL", 8)}\n`,
    );

    for (const evaluation of report.evaluations) {
      if (
        evaluation.matched === 0 &&
        evaluation.falseNegatives === 0
      ) {
        continue;
      }

      process.stdout.write(
        `  ${pad(evaluation.ruleId, 26)}${pad(
          evaluation.technique ?? "-",
          12,
        )}${pad(evaluation.truePositives, 5)}${pad(
          evaluation.falsePositives,
          7,
        )}${pad(evaluation.falseNegatives, 5)}${pad(
          evaluation.precision.toFixed(3),
          8,
        )}${pad(
          evaluation.recall.toFixed(3),
          8,
        )}\n`,
      );
    }

    process.stdout.write(
      `\n  techniques covered   ${report.coveredTechniques.length}/${
        report.coveredTechniques.length +
        report.uncoveredTechniques.length
      }\n`,
    );

    if (
      report.uncoveredTechniques.length >
      0
    ) {
      process.stdout.write(
        `  UNCOVERED            ${report.uncoveredTechniques.join(", ")}\n`,
      );
    }

    process.stdout.write("\n");

    if (exportPath) {
      const target = resolveFromRoot(
        exportPath.replace(
          /\.(ndjson|json)$/,
          "",
        ) +
          `-${plan.id}${extensionFor(
            requestedFormat,
          )}`,
      );

      mkdirSync(dirname(target), {
        recursive: true,
      });

      writeFileSync(
        target,
        formatCorpus(corpus.records, {
          format: requestedFormat,
          index: destinationIndex,
        }),
        "utf8",
      );

      writeFileSync(
        target.replace(
          /\.(ndjson|json)$/,
          ".manifest.json",
        ),
        `${JSON.stringify(
          corpus.manifest,
          null,
          2,
        )}\n`,
        "utf8",
      );

      process.stdout.write(
        `  exported ${target}\n\n`,
      );
    }

    planReports.push(
      buildPlanReport(
        plan.id,
        plan.name,
        corpus.manifest.recordCount,
        corpus.manifest.maliciousCount,
        report,
      ),
    );
  }

  const summary = summarise(
    seed,
    rules.length,
    planReports,
  );

  if (jsonPath) {
    const target =
      resolveFromRoot(jsonPath);

    mkdirSync(dirname(target), {
      recursive: true,
    });

    writeFileSync(
      target,
      `${JSON.stringify(summary, null, 2)}\n`,
      "utf8",
    );

    process.stdout.write(
      `Report written to ${jsonPath}\n\n`,
    );
  }

  if (coveragePath) {
    const target =
      resolveFromRoot(coveragePath);

    mkdirSync(dirname(target), {
      recursive: true,
    });

    writeFileSync(
      target,
      renderCoverageReport({
        report: summary,
        plans: ATTACK_PLANS,
        rulesetName: sigmaDir
          ? `Ruleset from ${sigmaDir}`
          : "Endomorph shipped ruleset",
        generatedAt: new Date()
          .toISOString()
          .slice(0, 10),
      }),
      "utf8",
    );

    process.stdout.write(
      `Coverage report written to ${coveragePath}

`,
    );
  }

  const badgePath = flag("badge");

  if (badgePath) {
    const target =
      resolveFromRoot(badgePath);

    mkdirSync(dirname(target), {
      recursive: true,
    });

    writeFileSync(
      target,
      renderCoverageBadge({
        covered:
          summary.totals
            .coveredTechniques,
        total:
          summary.totals.totalTechniques,
      }),
      "utf8",
    );

    process.stdout.write(
      `Coverage badge written to ${badgePath} (${summary.totals.coveredTechniques}/${summary.totals.totalTechniques} techniques)\n\n`,
    );
  }

  /*
    The instructor's half of the assessment story. The product has no
    accounts and no backend, which normally rules out seeing thirty results
    side by side -- but every run exports a structured record, so the
    collection problem is solvable with paste.
  */
  const cohortPath = flag("cohort-tool");

  if (cohortPath) {
    const target =
      resolveFromRoot(cohortPath);

    mkdirSync(dirname(target), {
      recursive: true,
    });

    writeFileSync(
      target,
      renderCohortReview(),
      "utf8",
    );

    process.stdout.write(
      `Cohort review tool written to ${cohortPath}

`,
    );
  }

  if (baselinePath) {
    const baselineFile =
      resolveFromRoot(baselinePath);

    if (!existsSync(baselineFile)) {
      throw new Error(
        `Baseline not found: ${baselineFile}`,
      );
    }

    const baseline = JSON.parse(
      readFileSync(baselineFile, "utf8"),
    ) as DetectionReport;

    const result = compareToBaseline(
      baseline,
      summary,
    );

    process.stdout.write(
      `Baseline comparison against ${baselinePath}\n`,
    );

    if (result.findings.length === 0) {
      process.stdout.write(
        "  no change\n\n",
      );
    }

    for (const finding of result.findings) {
      process.stdout.write(
        `  ${
          finding.severity ===
          "regression"
            ? "REGRESSION "
            : finding.severity ===
                "notice"
              ? "notice     "
              : "improvement"
        }  ${finding.planId}: ${finding.message}\n`,
      );
    }

    if (result.regressed) {
      process.stdout.write(
        "\nDetection coverage regressed against the baseline.\n",
      );

      process.exitCode = 1;
    } else if (
      result.findings.length > 0
    ) {
      process.stdout.write(
        "\nNo regressions. Review the notices, then update the baseline to accept these changes.\n",
      );
    }
  }
}

main();
