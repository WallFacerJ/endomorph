import type {
  DetectionRule,
  FieldMatcher,
  Selection,
} from "./detection.js";

/**
 * Elastic EQL rule import.
 *
 * Elastic is a top-tier SIEM, and its detections are written as EQL -- an
 * event query language of the form `<category> where <condition>`. This
 * translates the condition into the same internal rule the Sigma, KQL, and SPL
 * importers produce, so an Elastic author scores their own query unchanged.
 *
 * EQL is ECS-native, and so is this corpus, so most field names map almost
 * one-to-one (`process.command_line`, `destination.ip`, `user.name`). The
 * leading category (`process where`, `network where`, `any where`) selects the
 * event class rather than expressing detection logic and is dropped, the way
 * the SPL importer drops `index=`.
 *
 * As with the others, a construct the subset cannot express -- a `sequence`,
 * a function call, a field-to-field comparison, a numeric range, grouping
 * parentheses, mixed and/or, an unmapped field -- is reported by name with a
 * reason rather than imported as a query that silently matches nothing.
 *
 * Supported: `<category> where <condition>`; predicates `field : value`
 * (wildcard match), `field like value` / `field like~ value`, `field == value`,
 * `field != value`, `field regex value`, and `field in (a, b)`, joined by
 * `and` (a conjunction) or `or` (a disjunction, not mixed at the top level),
 * with an optional leading `not`. Values are quoted strings or numbers; `*`
 * wildcards inside a value map to the closest matcher. Metadata is read from
 * leading `// title:` and `// technique:` comments.
 */

const FIELD_MAP: Readonly<
  Record<string, string>
> = {
  // ECS process fields.
  "process.name": "process.executable",
  "process.executable":
    "process.executable",
  "process.command_line":
    "process.command_line",
  "process.args":
    "process.command_line",
  "process.parent.name":
    "process.parent.executable",
  "process.parent.executable":
    "process.parent.executable",
  "process.pid": "process.pid",

  // Identity and accounts.
  "user.name": "account.name",
  "user.target.name": "account.name",
  "source.user.name":
    "actor.account.name",
  "user.roles": "iam.role",

  // Host and network.
  "host.name": "host.name",
  "host.hostname": "host.name",
  "destination.ip": "destination.ip",
  "destination.port":
    "destination.port",
  "source.ip": "source.ip",
  "network.protocol":
    "network.protocol",

  // Files and events.
  "file.name": "file.name",
  "file.path": "file.name",
  "event.code": "event.code",
  "event.outcome": "event.outcome",
  "event.type": "event.type",

  // Endomorph-native passthroughs.
  "event.module": "event.module",
  "event.reason": "event.reason",
  "iam.role": "iam.role",
  "account.name": "account.name",
  "actor.account.name":
    "actor.account.name",

  // Mail / URL fields.
  "email.from.address": "email.from.address",
  "email.subject": "email.subject",
  "email.direction": "email.direction",
  "url.original": "url.original",

  // Cloud control-plane fields.
  "cloud.action": "cloud.action",
  "cloud.service": "cloud.service",
  "cloud.resource": "cloud.resource",
  "cloud.application": "cloud.application",


  // DNS fields.
  "dns.question.name": "dns.question.name",
  "dns.question.type": "dns.question.type",
  "dns.resolved_ip": "dns.resolved_ip",

};

export interface EqlDocument {
  readonly source: string;
  readonly query: string;
}

export interface EqlImportResult {
  readonly rules: DetectionRule[];
  readonly skipped: {
    readonly source: string;
    readonly title: string;
    readonly reason: string;
  }[];
}

class UnsupportedEql extends Error {}

function escapeRegex(
  value: string,
): string {
  return value.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&",
  );
}

/** A wildcarded EQL value becomes the closest internal matcher. */
function matcherForValue(
  raw: string,
): FieldMatcher {
  const starts = raw.startsWith("*");
  const ends = raw.endsWith("*");
  const core = raw.replace(
    /^\*+|\*+$/g,
    "",
  );
  const hasInner = core.includes("*");

  if (hasInner) {
    const pattern = raw
      .split("*")
      .map((part) => escapeRegex(part))
      .join(".*");

    return { regex: `^${pattern}$` };
  }

  if (starts && ends) {
    return { contains: core };
  }

  if (ends) {
    return { startsWith: core };
  }

  if (starts) {
    return {
      regex: `${escapeRegex(core)}$`,
    };
  }

  const asNumber = Number(core);
  return core !== "" &&
    !Number.isNaN(asNumber) &&
    String(asNumber) === core
    ? asNumber
    : core;
}

function unquote(raw: string): string {
  const trimmed = raw.trim();

  if (trimmed.startsWith('"""')) {
    return trimmed
      .replace(/^"""/, "")
      .replace(/"""$/, "");
  }

  return (trimmed.startsWith('"') &&
    trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") &&
      trimmed.endsWith("'"))
    ? trimmed.slice(1, -1)
    : trimmed;
}

interface Predicate {
  readonly field: string;
  readonly operator: string;
  readonly value: string;
  readonly negated: boolean;
}

const OPERATORS: readonly {
  readonly token: string;
  readonly negated: boolean;
}[] = [
  { token: "regexp~", negated: false },
  { token: "regexp", negated: false },
  { token: "regex~", negated: false },
  { token: "regex", negated: false },
  { token: "like~", negated: false },
  { token: "like", negated: false },
  { token: "==", negated: false },
  { token: "!=", negated: true },
  // ":" is EQL's wildcard match; kept last so word operators win first.
  { token: ":", negated: false },
];

function parsePredicate(
  text: string,
): Predicate {
  const trimmed = text.trim();

  // A numeric range or a field-to-field comparison has no matcher here; refuse
  // it by name rather than silently dropping the condition.
  if (/[<>]=?/.test(trimmed)) {
    throw new UnsupportedEql(
      `Numeric comparison in "${trimmed}" is not supported; the matcher expresses equality and wildcards, not ranges.`,
    );
  }

  for (const {
    token,
    negated,
  } of OPERATORS) {
    const isWord = /^[a-z]/i.test(token);
    const escaped = token.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&",
    );

    const pattern = isWord
      ? new RegExp(
          `^(.+?)\\s+${escaped}\\s+(.+)$`,
          "i",
        )
      : new RegExp(
          `^(.+?)\\s*${escaped}\\s*(.+)$`,
        );

    const match = trimmed.match(pattern);

    if (match) {
      return {
        field: match[1].trim(),
        operator: token,
        value: match[2].trim(),
        negated,
      };
    }
  }

  throw new UnsupportedEql(
    `Could not parse the condition "${trimmed}"; supported operators are :, ==, !=, like, regex, and in.`,
  );
}

function mapField(name: string): string {
  const mapped = FIELD_MAP[name];

  if (!mapped) {
    throw new UnsupportedEql(
      `Unmapped field "${name}". Add it to the field map or the rule would silently match nothing.`,
    );
  }

  return mapped;
}

function matcherFor(
  predicate: Predicate,
): FieldMatcher {
  const { operator, value } = predicate;

  switch (operator) {
    case "regex":
    case "regexp":
    case "regex~":
    case "regexp~":
      return { regex: unquote(value) };

    case "==":
    case "!=": {
      // An exact value (a function call cannot be matched); numeric when numeric.
      const literal = unquote(value);

      if (/\w\s*\(/.test(literal)) {
        throw new UnsupportedEql(
          `Function call in "${literal}" is not supported; only literal values are matched.`,
        );
      }

      const asNumber = Number(literal);
      return literal !== "" &&
        !Number.isNaN(asNumber) &&
        String(asNumber) === literal
        ? asNumber
        : literal;
    }

    default:
      // ":" / like / like~ : a wildcard match.
      return matcherForValue(
        unquote(value),
      );
  }
}

/** Splits a condition on a top-level `and` or `or`, refusing a mix. */
function splitConjunction(text: string): {
  parts: string[];
  disjunction: boolean;
} {
  const hasAnd = /\s+and\s+/i.test(text);
  const hasOr = /\s+or\s+/i.test(text);

  if (hasAnd && hasOr) {
    throw new UnsupportedEql(
      "Mixed and/or at the top level is not supported; split the rule or keep the predicates all-and or all-or.",
    );
  }

  const parts = text
    .split(
      hasOr
        ? /\s+or\s+/i
        : /\s+and\s+/i,
    )
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  return { parts, disjunction: hasOr };
}

export function convertEqlRule(
  document: EqlDocument,
): DetectionRule {
  const lines = document.query.split(
    /\r?\n/,
  );

  let title = document.source;
  let technique: string | undefined;

  for (const line of lines) {
    const titleMatch = line.match(
      /^\s*\/\/\s*title:\s*(.+)$/i,
    );
    if (titleMatch) {
      title = titleMatch[1].trim();
    }

    const techniqueMatch = line.match(
      /^\s*\/\/\s*technique:\s*(T[0-9.]+)/i,
    );
    if (techniqueMatch) {
      technique = techniqueMatch[1];
    }
  }

  const body = lines
    .map((line) =>
      line.replace(/\/\/.*$/, ""),
    )
    .join(" ")
    .trim();

  // A sequence/sample query correlates events over time -- a different, richer
  // thing than a per-event rule, and refused rather than half-imported.
  if (/^\s*(sequence|sample)\b/i.test(body)) {
    throw new UnsupportedEql(
      "A sequence/sample query correlates multiple events and cannot be scored as a per-event rule.",
    );
  }

  if (body.includes("|")) {
    throw new UnsupportedEql(
      "EQL pipes (| head, | tail, | filter) are not supported; only the where condition is scored.",
    );
  }

  // `<category> where <condition>` -- the category selects the event class and
  // is dropped, like a data-source selector.
  const whereMatch = body.match(
    /^\s*[\w.]+\s+where\s+(.+)$/i,
  );

  if (!whereMatch) {
    throw new UnsupportedEql(
      "No `<category> where <condition>` form found; only the filtering condition is scored.",
    );
  }

  const condition = whereMatch[1].trim();

  if (/^\s*true\s*$/i.test(condition)) {
    throw new UnsupportedEql(
      "A `where true` condition matches every event of its category and expresses no detection.",
    );
  }

  // Strip in-lists before rejecting grouping parentheses.
  const inRe =
    /(not\s+)?([\w.]+)\s+in\s*\(([^)]*)\)/gi;

  const positive: Record<
    string,
    FieldMatcher
  > = {};
  const exclusions: Record<
    string,
    FieldMatcher
  > = {};
  const anySelections: Selection[] = [];

  let working = condition;

  const inTerms: {
    field: string;
    values: string[];
    negated: boolean;
  }[] = [];

  working = working.replace(
    inRe,
    (_match, not, field, list) => {
      inTerms.push({
        field: String(field),
        values: String(list)
          .split(",")
          .map((item) =>
            unquote(item.trim()),
          ),
        negated: Boolean(not),
      });
      return " __IN__ ";
    },
  );

  if (/[()]/.test(working)) {
    throw new UnsupportedEql(
      "Grouping parentheses are not supported; the subset parses a flat conjunction or disjunction.",
    );
  }

  const { parts, disjunction } =
    splitConjunction(working);

  const place = (
    field: string,
    matcher: FieldMatcher,
    negated: boolean,
  ) => {
    if (disjunction) {
      if (negated) {
        throw new UnsupportedEql(
          "Negated predicates inside an `or` are not supported.",
        );
      }
      anySelections.push({
        [field]: matcher,
      });
    } else if (negated) {
      exclusions[field] = matcher;
    } else {
      positive[field] = matcher;
    }
  };

  let inCursor = 0;

  for (const part of parts) {
    if (part === "__IN__") {
      const term = inTerms[inCursor];
      inCursor += 1;
      place(
        mapField(term.field),
        {
          anyOf: term.values.map((value) =>
            matcherForValue(value),
          ),
        },
        term.negated,
      );
      continue;
    }

    const predicate = parsePredicate(part);
    place(
      mapField(predicate.field),
      matcherFor(predicate),
      predicate.negated,
    );
  }

  const rule: DetectionRule = {
    id: title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, ""),
    name: title,
    ...(technique ? { technique } : {}),
    severity: "medium",
    selections:
      Object.keys(positive).length > 0
        ? [positive]
        : [],
    ...(anySelections.length > 0
      ? { anySelections }
      : {}),
    ...(Object.keys(exclusions).length > 0
      ? { exclusions: [exclusions] }
      : {}),
  };

  if (
    rule.selections.length === 0 &&
    anySelections.length === 0
  ) {
    throw new UnsupportedEql(
      "The condition reduced to no positive term; a rule that is all exclusions would match everything benign.",
    );
  }

  return rule;
}

export function importEqlRules(
  documents: readonly EqlDocument[],
): EqlImportResult {
  const rules: DetectionRule[] = [];
  const skipped: EqlImportResult["skipped"] =
    [];

  for (const document of documents) {
    try {
      rules.push(
        convertEqlRule(document),
      );
    } catch (error) {
      skipped.push({
        source: document.source,
        title: document.source,
        reason:
          error instanceof Error
            ? error.message
            : "Unsupported EQL.",
      });
    }
  }

  return { rules, skipped };
}
