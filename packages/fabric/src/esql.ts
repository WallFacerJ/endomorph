import type {
  DetectionRule,
  FieldMatcher,
  Selection,
} from "./detection.js";

/**
 * Elastic ES|QL rule import.
 *
 * ES|QL is Elastic's piped query language (`FROM ... | WHERE ... | STATS ...`),
 * increasingly the way Elastic detections are written alongside EQL. This
 * translates the `WHERE` filtering into the same internal rule the Sigma, KQL,
 * SPL, and EQL importers produce, so an Elastic author scores their own query
 * unchanged.
 *
 * ES|QL is ECS-native, and so is this corpus, so field names map almost
 * one-to-one. The `FROM` source command selects the index and is dropped, the
 * way the SPL importer drops `index=`. A transforming command -- `STATS`,
 * `EVAL`, `DISSECT`, `GROK`, `ENRICH` -- changes the shape of the result, so
 * scoring the `WHERE` filter beneath it would be a different, wrong number; it
 * is refused by name rather than silently ignored. Ordering commands (`SORT`,
 * `LIMIT`, `KEEP`, `DROP`) do not affect matching and are skipped.
 *
 * Supported in `WHERE`: `field == value`, `field != value`, `field LIKE
 * "pattern"` (with `*`/`?` wildcards), `field RLIKE "regex"`, and `field IN (a,
 * b)`, joined by `AND` (a conjunction) or `OR` (a disjunction, not mixed at the
 * top level), with an optional leading `NOT`. Numeric range comparisons and
 * function calls are refused. Metadata is read from leading `// title:` and
 * `// technique:` comments.
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

  // Mail.
  "email.from.address":
    "email.from.address",
  "email.subject": "email.subject",
  "email.direction": "email.direction",
  "url.original": "url.original",

  // Cloud control plane.
  "cloud.action": "cloud.action",
  "cloud.service": "cloud.service",
  "cloud.resource": "cloud.resource",
  "cloud.application":
    "cloud.application",

  // DNS.
  "dns.question.name":
    "dns.question.name",
  "dns.question.type":
    "dns.question.type",
  "dns.resolved_ip": "dns.resolved_ip",

  // Endomorph-native passthroughs.
  "event.module": "event.module",
  "event.reason": "event.reason",
  "iam.role": "iam.role",
  "account.name": "account.name",
  "actor.account.name":
    "actor.account.name",
};

export interface EsqlDocument {
  readonly source: string;
  readonly query: string;
}

export interface EsqlImportResult {
  readonly rules: DetectionRule[];
  readonly skipped: {
    readonly source: string;
    readonly title: string;
    readonly reason: string;
  }[];
}

class UnsupportedEsql extends Error {}

function escapeRegex(
  value: string,
): string {
  return value.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&",
  );
}

/** A LIKE pattern (with `*` and `?` wildcards) becomes the closest matcher. */
function matcherForLike(
  raw: string,
): FieldMatcher {
  const hasQuestion = raw.includes("?");
  const starts = raw.startsWith("*");
  const ends = raw.endsWith("*");
  const core = raw.replace(/^\*+|\*+$/g, "");
  const hasInner = core.includes("*");

  if (!hasQuestion && !hasInner) {
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
    // No wildcard: exact, numeric when numeric.
    const asNumber = Number(core);
    return core !== "" &&
      !Number.isNaN(asNumber) &&
      String(asNumber) === core
      ? asNumber
      : core;
  }

  // A wildcard the fast paths can't express: build an anchored regex, mapping
  // `*` to `.*` and `?` to a single character.
  const pattern = raw
    .split(/([*?])/)
    .map((part) =>
      part === "*"
        ? ".*"
        : part === "?"
          ? "."
          : escapeRegex(part),
    )
    .join("");

  return { regex: `^${pattern}$` };
}

function unquote(raw: string): string {
  const trimmed = raw.trim();

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
  { token: "RLIKE", negated: false },
  { token: "NOT LIKE", negated: true },
  { token: "LIKE", negated: false },
  { token: "==", negated: false },
  { token: "!=", negated: true },
];

function parsePredicate(
  text: string,
): Predicate {
  const trimmed = text.trim();

  if (/[<>]=?/.test(trimmed)) {
    throw new UnsupportedEsql(
      `Numeric comparison in "${trimmed}" is not supported; the matcher expresses equality and wildcards, not ranges.`,
    );
  }

  if (/\w\s*\(/.test(trimmed)) {
    throw new UnsupportedEsql(
      `Function call in "${trimmed}" is not supported; only field-to-literal predicates are matched.`,
    );
  }

  for (const {
    token,
    negated,
  } of OPERATORS) {
    const isWord = /[a-z]/i.test(
      token[0],
    );
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
        operator: token
          .toUpperCase()
          .replace("NOT ", ""),
        value: match[2].trim(),
        negated,
      };
    }
  }

  throw new UnsupportedEsql(
    `Could not parse the predicate "${trimmed}"; supported operators are ==, !=, LIKE, RLIKE, and IN.`,
  );
}

function mapField(name: string): string {
  const mapped = FIELD_MAP[name];

  if (!mapped) {
    throw new UnsupportedEsql(
      `Unmapped field "${name}". Add it to the field map or the rule would silently match nothing.`,
    );
  }

  return mapped;
}

function matcherFor(
  predicate: Predicate,
): FieldMatcher {
  const { operator, value } = predicate;

  if (operator === "RLIKE") {
    return { regex: unquote(value) };
  }

  if (operator === "LIKE") {
    return matcherForLike(unquote(value));
  }

  // == / != : an exact value, numeric when it looks numeric.
  const literal = unquote(value);
  const asNumber = Number(literal);
  return literal !== "" &&
    !Number.isNaN(asNumber) &&
    String(asNumber) === literal
    ? asNumber
    : literal;
}

function splitConjunction(text: string): {
  parts: string[];
  disjunction: boolean;
} {
  const hasAnd = /\s+and\s+/i.test(text);
  const hasOr = /\s+or\s+/i.test(text);

  if (hasAnd && hasOr) {
    throw new UnsupportedEsql(
      "Mixed AND/OR at the top level is not supported; split the rule or keep the predicates all-AND or all-OR.",
    );
  }

  const parts = text
    .split(hasOr ? /\s+or\s+/i : /\s+and\s+/i)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  return { parts, disjunction: hasOr };
}

/** Pulls the WHERE filtering out of a piped ES|QL query. */
function extractWhere(query: string): string {
  const body = query
    .split(/\r?\n/)
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join(" ")
    .trim();

  const commands = body
    .split("|")
    .map((command) => command.trim())
    .filter((command) => command.length > 0);

  const wheres: string[] = [];

  for (const command of commands) {
    if (/^from\b/i.test(command)) {
      continue; // source selector, dropped
    }

    if (
      /^(stats|eval|dissect|grok|enrich|mv_expand)\b/i.test(
        command,
      )
    ) {
      throw new UnsupportedEsql(
        `The "${command.split(/\s+/)[0]}" command transforms the results; only a WHERE filter is scored.`,
      );
    }

    const whereMatch = command.match(
      /^where\s+(.+)$/i,
    );

    if (whereMatch) {
      wheres.push(whereMatch[1].trim());
      continue;
    }

    // sort / limit / keep / drop / rename: do not affect matching, skipped.
  }

  if (wheres.length === 0) {
    throw new UnsupportedEsql(
      "No WHERE clause found; only the filtering part of an ES|QL query is scored.",
    );
  }

  return wheres.join(" AND ");
}

export function convertEsqlRule(
  document: EsqlDocument,
): DetectionRule {
  const lines = document.query.split(/\r?\n/);

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

  const condition = extractWhere(
    document.query,
  );

  // Strip IN-lists before rejecting grouping parentheses.
  const inRe =
    /(not\s+)?([\w.]+)\s+in\s*\(([^)]*)\)/gi;

  const inTerms: {
    field: string;
    values: string[];
    negated: boolean;
  }[] = [];

  let working = condition.replace(
    inRe,
    (_match, not, field, list) => {
      inTerms.push({
        field: String(field),
        values: String(list)
          .split(",")
          .map((item) => unquote(item.trim())),
        negated: Boolean(not),
      });
      return " __IN__ ";
    },
  );

  if (/[()]/.test(working)) {
    throw new UnsupportedEsql(
      "Grouping parentheses are not supported; the subset parses a flat conjunction or disjunction.",
    );
  }

  const { parts, disjunction } =
    splitConjunction(working);

  const positive: Record<
    string,
    FieldMatcher
  > = {};
  const exclusions: Record<
    string,
    FieldMatcher
  > = {};
  const anySelections: Selection[] = [];

  const place = (
    field: string,
    matcher: FieldMatcher,
    negated: boolean,
  ) => {
    if (disjunction) {
      if (negated) {
        throw new UnsupportedEsql(
          "Negated predicates inside an OR are not supported.",
        );
      }
      anySelections.push({ [field]: matcher });
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
            matcherForLike(value),
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
    throw new UnsupportedEsql(
      "The condition reduced to no positive term; a rule that is all exclusions would match everything benign.",
    );
  }

  return rule;
}

export function importEsqlRules(
  documents: readonly EsqlDocument[],
): EsqlImportResult {
  const rules: DetectionRule[] = [];
  const skipped: EsqlImportResult["skipped"] =
    [];

  for (const document of documents) {
    try {
      rules.push(convertEsqlRule(document));
    } catch (error) {
      skipped.push({
        source: document.source,
        title: document.source,
        reason:
          error instanceof Error
            ? error.message
            : "Unsupported ES|QL.",
      });
    }
  }

  return { rules, skipped };
}
