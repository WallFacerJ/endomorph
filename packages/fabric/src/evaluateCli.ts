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
  mkdirSync,
  writeFileSync,
} from "node:fs";

import {
  dirname,
  resolve,
} from "node:path";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

import {
  buildCorpus,
  toNdjson,
} from "./corpus.js";

import {
  DETECTION_RULES,
} from "./detectionLibrary.js";

import {
  evaluateRuleset,
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

function pad(
  value: string | number,
  width: number,
): string {
  return String(value).padEnd(width);
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

  const enterprise = generateEnterprise({
    seed,
  });

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
      DETECTION_RULES,
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
      const target = resolve(
        process.cwd(),
        exportPath.replace(
          /\.ndjson$/,
          "",
        ) + `-${plan.id}.ndjson`,
      );

      mkdirSync(dirname(target), {
        recursive: true,
      });

      writeFileSync(
        target,
        toNdjson(corpus.records),
        "utf8",
      );

      writeFileSync(
        target.replace(
          /\.ndjson$/,
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
  }
}

main();
