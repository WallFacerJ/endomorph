import type {
  AttackPlan,
  AttackTactic,
} from "./attackPlan.js";

import type {
  DetectionReport,
} from "./detectionReport.js";

/**
 * A coverage report somebody can hand to a client.
 *
 * The evaluation already produces the numbers; they came out as a console
 * table and a JSON file, which are the right shapes for an engineer and the
 * wrong shape for the conversation the numbers are actually for. "Here is
 * what your detection ruleset catches, here is what it misses, and here is
 * what it costs you in noise" is a deliverable, and it has to survive being
 * emailed.
 *
 * Self-contained HTML with no external references, for the same reason the
 * product is: it has to open from an attachment on a machine with no network
 * and no build step.
 *
 * Everything in it is measured rather than asserted. That is the whole point
 * of scoring against a generated corpus -- ground truth is known by
 * construction, so "your rules miss this technique" is a count and not an
 * opinion, and it is reproducible from the seed printed at the top.
 */

const TACTIC_ORDER: readonly AttackTactic[] =
  [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
  ];

const TACTIC_LABELS: Readonly<
  Record<AttackTactic, string>
> = {
  initial_access: "Initial access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation:
    "Privilege escalation",
  defense_evasion: "Defense evasion",
  credential_access: "Credential access",
  discovery: "Discovery",
  lateral_movement: "Lateral movement",
  collection: "Collection",
  command_and_control:
    "Command and control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

interface TechniqueRow {
  readonly id: string;
  readonly name: string;
  readonly tactic: AttackTactic;
  readonly covered: boolean;
  readonly plans: readonly string[];
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/**
 * Collapses the per-plan results into one view of the estate.
 *
 * A technique counts as covered when at least one plan that demonstrates it
 * had a rule fire on it. Reporting per-plan coverage separately would let a
 * ruleset look better than it is: catching credential dumping in one
 * incident and missing it in another is not "covered", and this is the
 * number a client will quote back.
 */
function collectTechniques(
  report: DetectionReport,
  plans: readonly AttackPlan[],
): readonly TechniqueRow[] {
  const meta = new Map<
    string,
    { name: string; tactic: AttackTactic }
  >();

  for (const plan of plans) {
    for (const technique of plan.techniques) {
      meta.set(technique.id, {
        name: technique.name,
        tactic: technique.tactic,
      });
    }
  }

  const covered = new Set<string>();
  const seen = new Map<string, Set<string>>();

  for (const plan of report.plans) {
    for (const technique of plan.coveredTechniques) {
      covered.add(technique);
    }

    for (const technique of [
      ...plan.coveredTechniques,
      ...plan.uncoveredTechniques,
    ]) {
      const planNames =
        seen.get(technique) ??
        new Set<string>();

      planNames.add(plan.planName);
      seen.set(technique, planNames);
    }
  }

  return [...seen.entries()]
    .map(([id, planNames]) => ({
      id,
      name: meta.get(id)?.name ?? id,
      tactic:
        meta.get(id)?.tactic ?? "execution",
      covered: covered.has(id),
      plans: [...planNames].sort(),
    }))
    .sort(
      (left, right) =>
        TACTIC_ORDER.indexOf(left.tactic) -
          TACTIC_ORDER.indexOf(
            right.tactic,
          ) ||
        left.id.localeCompare(right.id),
    );
}

function renderMatrix(
  techniques: readonly TechniqueRow[],
): string {
  const byTactic = new Map<
    AttackTactic,
    TechniqueRow[]
  >();

  for (const technique of techniques) {
    const bucket =
      byTactic.get(technique.tactic) ?? [];

    bucket.push(technique);
    byTactic.set(technique.tactic, bucket);
  }

  const columns = TACTIC_ORDER.filter(
    (tactic) => byTactic.has(tactic),
  );

  return `<div class="matrix">${columns
    .map((tactic) => {
      const cells = (
        byTactic.get(tactic) ?? []
      )
        .map(
          (technique) =>
            `<li class="cell ${
              technique.covered
                ? "covered"
                : "uncovered"
            }" title="${escapeHtml(
              technique.plans.join(", "),
            )}"><code>${escapeHtml(
              technique.id,
            )}</code><span>${escapeHtml(
              technique.name,
            )}</span></li>`,
        )
        .join("");

      return `<div class="column"><h3>${escapeHtml(
        TACTIC_LABELS[tactic],
      )}</h3><ul>${cells}</ul></div>`;
    })
    .join("")}</div>`;
}

function renderNoise(
  report: DetectionReport,
): string {
  /*
    Aggregated across plans, because a rule's noise is a property of the
    ruleset and not of one incident. Ranked by false positives, since that is
    the number an analyst pays for in attention.
  */
  const totals = new Map<
    string,
    {
      truePositives: number;
      falsePositives: number;
    }
  >();

  for (const plan of report.plans) {
    for (const rule of plan.rules) {
      const running =
        totals.get(rule.ruleId) ?? {
          truePositives: 0,
          falsePositives: 0,
        };

      running.truePositives +=
        rule.truePositives;

      running.falsePositives +=
        rule.falsePositives;

      totals.set(rule.ruleId, running);
    }
  }

  const rows = [...totals.entries()]
    .map(([ruleId, counts]) => ({
      ruleId,
      ...counts,
      precision:
        counts.truePositives +
          counts.falsePositives ===
        0
          ? 0
          : counts.truePositives /
            (counts.truePositives +
              counts.falsePositives),
    }))
    .sort(
      (left, right) =>
        right.falsePositives -
        left.falsePositives,
    );

  return rows
    .map(
      (row) =>
        `<tr class="${
          row.truePositives === 0
            ? "silent"
            : ""
        }"><th scope="row"><code>${escapeHtml(
          row.ruleId,
        )}</code></th><td class="num">${
          row.truePositives
        }</td><td class="num">${
          row.falsePositives
        }</td><td class="num">${(
          row.precision * 100
        ).toFixed(1)}%</td></tr>`,
    )
    .join("");
}

export interface CoverageReportOptions {
  readonly report: DetectionReport;
  readonly plans: readonly AttackPlan[];

  /** Named on the cover, so a client report says whose ruleset it is. */
  readonly rulesetName: string;

  readonly generatedAt: string;
}

export function renderCoverageReport(
  options: CoverageReportOptions,
): string {
  const {
    report,
    plans,
    rulesetName,
    generatedAt,
  } = options;

  const techniques = collectTechniques(
    report,
    plans,
  );

  const uncovered = techniques.filter(
    (technique) => !technique.covered,
  );

  const coveredCount =
    techniques.length - uncovered.length;

  const percentage =
    techniques.length === 0
      ? 0
      : Math.round(
          (coveredCount /
            techniques.length) *
            100,
        );

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection coverage, ${escapeHtml(
    rulesetName,
  )}</title>
<style>
  :root {
    color-scheme: light;
    --ink: #12181f;
    --muted: #5a6a7a;
    --line: #d8e0e8;
    --panel: #f6f8fa;
    --covered: #1a7f4b;
    --uncovered: #b3261e;
    --warn: #a1670a;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 40px 32px 64px;
    background: #fff;
    color: var(--ink);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main { max-width: 1100px; margin: 0 auto; }
  h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: -0.02em; }
  h2 { margin: 40px 0 4px; font-size: 18px; letter-spacing: -0.01em; }
  h3 { margin: 0 0 8px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
  p { margin: 6px 0 0; }
  .lede { max-width: 70ch; color: var(--muted); }
  .headline {
    display: flex; flex-wrap: wrap; gap: 28px;
    margin: 24px 0 8px; padding: 18px 20px;
    border: 1px solid var(--line); border-radius: 12px; background: var(--panel);
  }
  .headline div { display: grid; gap: 2px; }
  .headline dt, .headline .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); }
  .headline .value { font-size: 26px; font-weight: 650; font-variant-numeric: tabular-nums; }
  /*
    Wraps rather than scrolls. Twelve tactics side by side is 2,000px, so a
    horizontally scrolling matrix loses its right-hand columns the moment
    this is printed, exported to PDF or read in an email client -- which is
    where a client report is actually read.
  */
  .matrix { display: grid; grid-template-columns: repeat(auto-fill, minmax(176px, 1fr)); gap: 14px 10px; align-items: start; }
  .column { min-width: 0; }
  .column ul { margin: 0; padding: 0; list-style: none; display: grid; gap: 6px; }
  .cell { padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px; display: grid; gap: 2px; }
  .cell code { font-size: 12px; font-weight: 650; }
  .cell span { font-size: 12px; color: var(--muted); }
  .cell.covered { border-left: 4px solid var(--covered); }
  .cell.uncovered { border-left: 4px solid var(--uncovered); background: #fdf6f5; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); }
  thead th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  tr.silent th code { color: var(--warn); }
  .gap { margin-top: 12px; padding: 14px 16px; border: 1px solid var(--line); border-left: 4px solid var(--uncovered); border-radius: 8px; background: #fdf6f5; }
  .gap ul { margin: 8px 0 0; padding-left: 18px; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  @media print {
    body { padding: 0; }
    .cell, table, .gap { break-inside: avoid; }
    h2 { break-after: avoid; }
  }
</style>
</head>
<body>
<main>
  <h1>Detection coverage</h1>
  <p class="lede">${escapeHtml(
    rulesetName,
  )}, measured against ${
    report.plans.length
  } generated intrusions in a synthetic enterprise. Ground truth is known by construction, so every number here is counted rather than estimated, and the whole measurement reproduces from the seed below.</p>

  <div class="headline">
    <div><span class="label">Techniques covered</span><span class="value">${coveredCount} / ${
    techniques.length
  }</span></div>
    <div><span class="label">Coverage</span><span class="value">${percentage}%</span></div>
    <div><span class="label">Rules evaluated</span><span class="value">${
      report.ruleCount
    }</span></div>
    <div><span class="label">True positives</span><span class="value">${
      report.totals.truePositives
    }</span></div>
    <div><span class="label">False positives</span><span class="value">${
      report.totals.falsePositives
    }</span></div>
    <div><span class="label">Seed</span><span class="value">${
      report.seed
    }</span></div>
  </div>

  <h2>ATT&amp;CK coverage</h2>
  <p class="lede">A technique counts as covered when a rule fired on it in an incident that demonstrated it. Catching something in one incident and missing it in another does not count.</p>
  ${renderMatrix(techniques)}

  ${
    uncovered.length > 0
      ? `<div class="gap"><strong>${
          uncovered.length
        } technique(s) went undetected in every incident that used them.</strong><ul>${uncovered
          .map(
            (technique) =>
              `<li><code>${escapeHtml(
                technique.id,
              )}</code> ${escapeHtml(
                technique.name,
              )}, seen in ${escapeHtml(
                technique.plans.join(", "),
              )}</li>`,
          )
          .join("")}</ul></div>`
      : ""
  }

  <h2>Rule performance</h2>
  <p class="lede">Aggregated across every incident, because noise is a property of the ruleset rather than of one case. Rules with no true positives anywhere are marked: they cost attention and returned nothing.</p>
  <table>
    <thead><tr><th scope="col">Rule</th><th scope="col" class="num">True positives</th><th scope="col" class="num">False positives</th><th scope="col" class="num">Precision</th></tr></thead>
    <tbody>${renderNoise(report)}</tbody>
  </table>

  <h2>Incidents used</h2>
  <table>
    <thead><tr><th scope="col">Incident</th><th scope="col" class="num">Records</th><th scope="col" class="num">Malicious</th><th scope="col" class="num">Techniques covered</th></tr></thead>
    <tbody>${report.plans
      .map(
        (plan) =>
          `<tr><th scope="row">${escapeHtml(
            plan.planName,
          )}</th><td class="num">${plan.recordCount.toLocaleString()}</td><td class="num">${
            plan.maliciousCount
          }</td><td class="num">${
            plan.coveredTechniques.length
          } / ${
            plan.coveredTechniques.length +
            plan.uncoveredTechniques.length
          }</td></tr>`,
      )
      .join("")}</tbody>
  </table>

  <footer>
    Generated by ${escapeHtml(
      report.generator,
    )} on ${escapeHtml(
    generatedAt,
  )} from seed ${
    report.seed
  }. Re-running the same seed produces the same incidents and the same numbers, so this report can be reproduced and differences attributed to rule changes rather than to sampling.
  </footer>
</main>
</body>
</html>
`;
}
