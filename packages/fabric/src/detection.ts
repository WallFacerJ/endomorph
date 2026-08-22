import type {
  CorpusRecord,
} from "./corpus.js";

/**
 * Detection rule evaluation against a labelled corpus.
 *
 * This is the capability the generator makes possible and that a captured
 * corpus cannot: because ground truth is known by construction, a rule's
 * true positives, false positives and false negatives are computable rather
 * than estimated. A detection engineer can ask "does my rule actually catch
 * this technique, and what does it cost me in noise" and get a number.
 *
 * The rule shape is deliberately Sigma-like -- named selections, a condition
 * over them, and optional thresholds -- so that importing Sigma later is a
 * translation rather than a redesign.
 */

export type FieldMatcher =
  | string
  | number
  | readonly (string | number)[]
  | {
      /** Substring match, case-insensitive. */
      readonly contains: string;
    }
  | {
      readonly startsWith: string;
    }
  | {
      readonly regex: string;
    }
  | {
      /** Matches when any nested matcher does. */
      readonly anyOf: readonly FieldMatcher[];
    };

/** A selection matches when every field in it matches. */
export type Selection = Readonly<
  Record<string, FieldMatcher>
>;

export interface DetectionThreshold {
  /** Group matching records by these fields before counting. */
  readonly groupBy: readonly string[];

  /** Minimum records in the window to fire. */
  readonly count: number;

  readonly withinMinutes: number;
}

export interface DetectionRule {
  readonly id: string;

  readonly name: string;

  /** ATT&CK technique the rule intends to detect. */
  readonly technique?: string;

  readonly severity:
    | "low"
    | "medium"
    | "high"
    | "critical";

  /** All selections must match for a record to be a candidate. */
  readonly selections: readonly Selection[];

  /**
   * Alternatives: the record matches when *any* of these does.
   *
   * Sigma's `1 of selection_*` is an OR across selection groups, which an
   * AND-only list cannot express. Published rules use it constantly.
   */
  readonly anySelections?: readonly Selection[];

  /** Records matching any of these are excluded. */
  readonly exclusions?: readonly Selection[];

  /**
   * When present, individual matches do not fire; only groups that reach
   * `count` within the window do, and every record in a firing group is
   * reported.
   */
  readonly threshold?: DetectionThreshold;
}

function valueOf(
  record: CorpusRecord,
  field: string,
): string | number | undefined {
  const value = (
    record as unknown as Record<
      string,
      unknown
    >
  )[field];

  return typeof value === "string" ||
    typeof value === "number"
    ? value
    : undefined;
}

function matchesField(
  actual: string | number | undefined,
  matcher: FieldMatcher,
): boolean {
  if (actual === undefined) {
    return false;
  }

  const text = String(actual);

  if (Array.isArray(matcher)) {
    return matcher.some(
      (candidate) =>
        String(candidate).toLowerCase() ===
        text.toLowerCase(),
    );
  }

  if (
    typeof matcher === "string" ||
    typeof matcher === "number"
  ) {
    return (
      String(matcher).toLowerCase() ===
      text.toLowerCase()
    );
  }

  if ("contains" in matcher) {
    return text
      .toLowerCase()
      .includes(
        matcher.contains.toLowerCase(),
      );
  }

  if ("startsWith" in matcher) {
    return text
      .toLowerCase()
      .startsWith(
        matcher.startsWith.toLowerCase(),
      );
  }

  if ("regex" in matcher) {
    return new RegExp(
      matcher.regex,
      "i",
    ).test(text);
  }

  if ("anyOf" in matcher) {
    return matcher.anyOf.some(
      (nested) =>
        matchesField(actual, nested),
    );
  }

  return false;
}

function matchesSelection(
  record: CorpusRecord,
  selection: Selection,
): boolean {
  return Object.entries(selection).every(
    ([field, matcher]) =>
      matchesField(
        valueOf(record, field),
        matcher,
      ),
  );
}

function candidateMatches(
  record: CorpusRecord,
  rule: DetectionRule,
): boolean {
  const selected = rule.selections.every(
    (selection) =>
      matchesSelection(record, selection),
  );

  if (!selected) {
    return false;
  }

  const alternatives =
    rule.anySelections ?? [];

  if (
    alternatives.length > 0 &&
    !alternatives.some((selection) =>
      matchesSelection(record, selection),
    )
  ) {
    return false;
  }

  return !(rule.exclusions ?? []).some(
    (exclusion) =>
      matchesSelection(record, exclusion),
  );
}

/**
 * Applies a threshold, returning only records inside a firing group.
 *
 * A sliding window over each group: if any window of `withinMinutes`
 * contains at least `count` records, the whole group fires. This is how
 * spray and brute-force detections behave in practice.
 */
function applyThreshold(
  candidates: readonly CorpusRecord[],
  threshold: DetectionThreshold,
): CorpusRecord[] {
  const groups = new Map<
    string,
    CorpusRecord[]
  >();

  for (const record of candidates) {
    const key = threshold.groupBy
      .map((field) =>
        String(
          valueOf(record, field) ?? "",
        ),
      )
      .join("|");

    const existing = groups.get(key);

    if (existing) {
      existing.push(record);
    } else {
      groups.set(key, [record]);
    }
  }

  const firing: CorpusRecord[] = [];

  const windowMs =
    threshold.withinMinutes * 60000;

  for (const group of groups.values()) {
    const ordered = [...group].sort(
      (left, right) =>
        left["@timestamp"].localeCompare(
          right["@timestamp"],
        ),
    );

    let fired = false;

    for (
      let start = 0;
      start < ordered.length;
      start += 1
    ) {
      const windowStart = Date.parse(
        ordered[start]["@timestamp"],
      );

      let inWindow = 0;

      for (
        let index = start;
        index < ordered.length;
        index += 1
      ) {
        if (
          Date.parse(
            ordered[index]["@timestamp"],
          ) -
            windowStart <=
          windowMs
        ) {
          inWindow += 1;
        } else {
          break;
        }
      }

      if (inWindow >= threshold.count) {
        fired = true;
        break;
      }
    }

    if (fired) {
      firing.push(...ordered);
    }
  }

  return firing;
}

export interface RuleEvaluation {
  readonly ruleId: string;
  readonly ruleName: string;
  readonly technique?: string;

  readonly matched: number;

  /** Matched and genuinely malicious. */
  readonly truePositives: number;

  /** Matched but benign. Every one of these is analyst time wasted. */
  readonly falsePositives: number;

  /**
   * Malicious records demonstrating the rule's technique that it missed.
   * Scoped to the technique so a rule is not blamed for missing steps it
   * never claimed to detect.
   */
  readonly falseNegatives: number;

  readonly precision: number;
  readonly recall: number;
  readonly f1: number;

  readonly matchedEventIds: readonly string[];
  readonly falsePositiveEventIds: readonly string[];
  readonly missedEventIds: readonly string[];
}

function ratio(
  numerator: number,
  denominator: number,
): number {
  return denominator === 0
    ? 0
    : Number(
        (numerator / denominator).toFixed(
          4,
        ),
      );
}

export function evaluateRule(
  rule: DetectionRule,
  corpus: readonly CorpusRecord[],
): RuleEvaluation {
  const candidates = corpus.filter(
    (record) =>
      candidateMatches(record, rule),
  );

  const matched = rule.threshold
    ? applyThreshold(
        candidates,
        rule.threshold,
      )
    : candidates;

  const matchedIds = new Set(
    matched.map(
      (record) => record["event.id"],
    ),
  );

  const truePositives = matched.filter(
    (record) =>
      record["label.malicious"],
  );

  const falsePositives = matched.filter(
    (record) =>
      !record["label.malicious"],
  );

  // A rule is only accountable for the technique it claims.
  const shouldHaveMatched = rule.technique
    ? corpus.filter(
        (record) =>
          record["label.malicious"] &&
          record["label.technique"] ===
            rule.technique,
      )
    : corpus.filter(
        (record) =>
          record["label.malicious"],
      );

  const missed = shouldHaveMatched.filter(
    (record) =>
      !matchedIds.has(
        record["event.id"],
      ),
  );

  const precision = ratio(
    truePositives.length,
    matched.length,
  );

  // Recall against nothing is vacuously perfect, not zero. Reporting 0 when
  // the corpus contains no instance of the rule's technique makes a rule
  // look broken on every incident it was never meant to catch.
  const recall =
    shouldHaveMatched.length === 0
      ? 1
      : ratio(
          truePositives.length,
          shouldHaveMatched.length,
        );

  return {
    ruleId: rule.id,
    ruleName: rule.name,
    technique: rule.technique,
    matched: matched.length,
    truePositives: truePositives.length,
    falsePositives:
      falsePositives.length,
    falseNegatives: missed.length,
    precision,
    recall,
    f1:
      precision + recall === 0
        ? 0
        : Number(
            (
              (2 * precision * recall) /
              (precision + recall)
            ).toFixed(4),
          ),
    matchedEventIds: matched
      .map(
        (record) => record["event.id"],
      )
      .slice(0, 25),
    falsePositiveEventIds:
      falsePositives
        .map(
          (record) =>
            record["event.id"],
        )
        .slice(0, 25),
    missedEventIds: missed
      .map(
        (record) => record["event.id"],
      )
      .slice(0, 25),
  };
}

export interface CoverageReport {
  readonly evaluations: readonly RuleEvaluation[];

  /** Techniques present in the corpus that no rule detected at all. */
  readonly uncoveredTechniques: readonly string[];

  readonly coveredTechniques: readonly string[];

  readonly totalTruePositives: number;
  readonly totalFalsePositives: number;
}

export function evaluateRuleset(
  rules: readonly DetectionRule[],
  corpus: readonly CorpusRecord[],
): CoverageReport {
  const evaluations = rules.map((rule) =>
    evaluateRule(rule, corpus),
  );

  const present = new Set(
    corpus
      .filter(
        (record) =>
          record["label.malicious"] &&
          record["label.technique"],
      )
      .map(
        (record) =>
          record[
            "label.technique"
          ] as string,
      ),
  );

  const detected = new Set(
    evaluations
      .filter(
        (evaluation) =>
          evaluation.truePositives > 0 &&
          evaluation.technique,
      )
      .map(
        (evaluation) =>
          evaluation.technique as string,
      ),
  );

  return {
    evaluations,
    coveredTechniques: [...present]
      .filter((technique) =>
        detected.has(technique),
      )
      .sort(),
    uncoveredTechniques: [...present]
      .filter(
        (technique) =>
          !detected.has(technique),
      )
      .sort(),
    totalTruePositives:
      evaluations.reduce(
        (total, evaluation) =>
          total + evaluation.truePositives,
        0,
      ),
    totalFalsePositives:
      evaluations.reduce(
        (total, evaluation) =>
          total +
          evaluation.falsePositives,
        0,
      ),
  };
}
