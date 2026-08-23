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
  resolveFromRoot,
} from "./workspaceRoot.js";

import {
  renderCoverageReport,
} from "./coverageReport.js";

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
