import type {
  IncidentReport,
  InvestigationCoverage,
  ScenarioDefinition,
  ScenarioState,
} from "./simulationAdapter";

import {
  summarizePerformedResponses,
} from "./performedResponses";

import {
  summarizeKeyEvidence,
} from "./keyEvidence";

/**
 * The case, as a document somebody can take away.
 *
 * The Case view already says of its timeline: "Your collected evidence in
 * order. This is the report." It was not one -- there was no way to get it
 * out of the page, which for a product whose whole output is an analyst's
 * write-up is most of the value left on the table. An instructor reviewing a
 * run, or an analyst pasting into a ticket, needs the text.
 *
 * Markdown rather than JSON: the audience is a person, and the destinations
 * are ticketing systems, chat and documents, all of which render it.
 *
 * Everything here is read from state the run already holds. The report
 * asserts nothing the console did not already show, which is the same rule
 * the case itself follows -- nothing is authored twice.
 */

export interface CaseReportInput {
  readonly scenario: ScenarioDefinition;
  readonly state: ScenarioState;
  readonly report: IncidentReport;
  readonly questionAnswers: Readonly<
    Record<string, string>
  >;
  readonly questionScore: {
    readonly earned: number;
    readonly available: number;
  };

  /**
   * How much of the incident the analyst reached, when the scenario has
   * ground truth to measure against. Undefined on the hand-authored
   * scenarios, which declare none.
   */
  readonly coverage?: InvestigationCoverage;

  /**
   * The evidence the analyst banked, for measuring which of the incident's
   * key events were actually collected. The same list the case and coverage
   * read, passed in rather than re-derived.
   */
  readonly collectedEventIds: readonly string[];
  readonly formatTimestamp: (
    timestamp: string | undefined,
  ) => string;
}

function section(
  heading: string,
  body: readonly string[],
): readonly string[] {
  return body.length > 0
    ? [`## ${heading}`, "", ...body, ""]
    : [];
}

export function buildCaseReport(
  input: CaseReportInput,
): string {
  const {
    scenario,
    state,
    report,
    questionAnswers,
    questionScore,
    coverage,
    collectedEventIds,
    formatTimestamp,
  } = input;

  const lines: string[] = [
    `# ${scenario.name}`,
    "",
    scenario.description,
    "",
    `- **Status:** ${state.finalized ? state.outcome.status : "in progress"}`,
    `- **Phase:** ${report.phase}`,
    `- **Evidence collected:** ${report.evidenceCount}`,
    `- **Entities in scope:** ${report.entityCount}`,
    "",
  ];

  /*
    Only after finalizing. Before that the score is not settled, and writing
    a number into a document people will paste elsewhere would give it a
    permanence it has not earned.
  */
  if (state.finalized) {
    lines.push(
      `- **Objective score:** ${state.score.percentage}%`,
      `- **Questions:** ${questionScore.earned}/${questionScore.available} points`,
      "",
    );

    if (
      coverage &&
      coverage.entities.length > 0
    ) {
      lines.push(
        `- **Incident coverage:** reached ${coverage.reached.length} of ${coverage.entities.length} entities (${coverage.percentage}%)`,
        "",
      );
    }

    const keyEvidence =
      summarizeKeyEvidence(
        scenario.groundTruth?.timeline ??
          [],
        collectedEventIds,
      );

    if (keyEvidence) {
      lines.push(
        `- **Key evidence collected:** ${keyEvidence.captured} of ${keyEvidence.total} incident events`,
        "",
      );
    }
  }

  lines.push(
    ...section(
      "Response objectives",
      state.outcome.objectives.map(
        (objective) =>
          `- [${objective.met ? "x" : " "}] ${objective.label} — ${objective.description}`,
      ),
    ),
  );

  lines.push(
    ...section(
      "Hypotheses",
      report.supportedHypotheses.map(
        (hypothesis) =>
          `- ${hypothesis.statement}`,
      ),
    ),
  );

  lines.push(
    ...section(
      "External indicators",
      report.externalIndicators.map(
        (indicator) =>
          `- \`${indicator.value}\` (${indicator.kind.replaceAll(
            "_",
            " ",
          )})`,
      ),
    ),
  );

  lines.push(
    ...section(
      "Evidence",
      report.timeline.map(
        (record) =>
          `- **${formatTimestamp(
            record.timestamp,
          )}** — ${record.eventType} — ${record.message}`,
      ),
    ),
  );

  lines.push(
    ...section(
      "Decisions",
      report.decisions.map(
        (decision) =>
          `- **${decision.summary}**${
            decision.rationale
              ? ` — ${decision.rationale}`
              : ""
          }`,
      ),
    ),
  );

  // Named for a human the same way the record names them for a machine: a
  // finalized run that took a harmful action should say so in the document,
  // not only dock the score. Omitted entirely when nothing was penalized.
  if (state.finalized) {
    const harmful =
      summarizePerformedResponses(
        scenario.actions ?? [],
        state.performedActionIds ?? [],
      ).filter(
        (response) => response.penalized,
      );

    lines.push(
      ...section(
        "Response quality",
        harmful.map(
          (response) =>
            `- **${response.label}** (−${response.penalty})${
              response.rationale
                ? ` — ${response.rationale}`
                : ""
            }`,
        ),
      ),
    );
  }

  // The incident's key events the analyst never banked -- the smoking guns
  // that were there to be collected and were not. Named by what they were,
  // so the omission is legible rather than an id.
  if (state.finalized) {
    const keyEvidence =
      summarizeKeyEvidence(
        scenario.groundTruth?.timeline ??
          [],
        collectedEventIds,
      );

    lines.push(
      ...section(
        "Key evidence not collected",
        (keyEvidence?.missed ?? []).map(
          (step) =>
            `- ${step.title ?? step.significance}${
              step.techniqueId
                ? ` (${step.techniqueId})`
                : ""
            }`,
        ),
      ),
    );
  }

  // The entities the incident involved that the analyst never opened. This
  // is the coverage number made specific: a correct containment reached
  // without scoping the intrusion leaves exactly this list behind.
  if (
    state.finalized &&
    coverage &&
    coverage.missed.length > 0
  ) {
    lines.push(
      ...section(
        "Entities not reached",
        coverage.missed.map(
          (entity) =>
            `- ${entity.label} (${entity.kind})`,
        ),
      ),
    );
  }

  lines.push(
    ...section(
      "Open tasks",
      report.openTasks.map(
        (task) =>
          `- ${task.title} (${task.owner})`,
      ),
    ),
  );

  const answered = (
    scenario.questions ?? []
  )
    .map((question) => ({
      question,
      answer: (
        questionAnswers[question.id] ??
        ""
      ).trim(),
    }))
    .filter(
      (entry) => entry.answer.length > 0,
    );

  lines.push(
    ...section(
      "Investigation answers",
      answered.map(
        (entry) =>
          `- **${entry.question.prompt}**\n  ${entry.answer}`,
      ),
    ),
  );

  // Named so a reader knows whether the numbers above are reproducible. That
  // is the whole premise of a seeded generator -- and a claim the
  // hand-authored scenarios cannot make, so the footer states which case
  // this document is rather than promising identical replay for both.
  const seed =
    scenario.provenance?.seed;

  lines.push(
    "---",
    "",
    seed === undefined
      ? `Generated by Endomorph from scenario \`${scenario.id}\`. This scenario is hand-authored and records no generation seed.`
      : `Generated by Endomorph from scenario \`${scenario.id}\` (seed ${seed}). The same scenario and seed replay identically.`,
    "",
  );

  return lines.join("\n");
}
