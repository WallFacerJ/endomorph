import type {
  DetectionRule,
  FieldMatcher,
  Selection,
} from "./detection.js";

/**
 * Kusto (KQL) rule import.
 *
 * Sigma is a minority dialect; a great many detection engineers write KQL for
 * Microsoft Sentinel and Defender. This translates the subset of a KQL query
 * that a detection actually turns on -- the `where` predicates -- into the same
 * internal rule the Sigma importer produces, so a KQL author can score their
 * own rule against the labelled corpus without rewriting it.
 *
 * As with Sigma, a construct the subset cannot express is reported with a
 * reason rather than dropped. A rule that quietly matches nothing is
 * indistinguishable from one that works, and that is the failure this whole
 * codebase spends its effort against, so an unmapped field or an unsupported
 * operator refuses loudly instead of importing a rule that lies.
 *
 * Supported: one or more `| where` clauses; predicates of the form
 * `Field OP Value` joined by `and` (a conjunction) or `or` (a disjunction, not
 * mixed with `and` at the top level); the operators ==, =~, !=, contains,
 * !contains, has, !has, startswith, endswith, matches regex, and in (...);
 * string, number, and list values. Metadata is read from leading comments:
 * `// title:` and `// technique:`.
 *
 * Not supported (skipped with a reason): grouping parentheses, mixed and/or,
 * summarize/join/extend and other tabular operators, and fields with no mapping
 * to the corpus.
 */

const FIELD_MAP: Readonly<
  Record<string, string>
> = {
  // Microsoft Defender / Sentinel process columns.
  FileName: "process.executable",
  FolderPath: "process.executable",
  ProcessCommandLine:
    "process.command_line",
  InitiatingProcessFileName:
    "process.parent.executable",
  InitiatingProcessCommandLine:
    "process.parent.executable",
  ProcessId: "process.pid",
  InitiatingProcessId:
    "process.parent.pid",

  // Identity and accounts.
  AccountName: "account.name",
  TargetAccount: "account.name",
  InitiatingProcessAccountName:
    "actor.account.name",
  Role: "iam.role",
  RoleName: "iam.role",

  // Host and network.
  DeviceName: "host.name",
  Computer: "host.name",
  RemoteIP: "destination.ip",
  RemoteUrl: "destination.ip",
  LocalIP: "source.ip",
  RemotePort: "destination.port",
  Protocol: "network.protocol",

  // Files.
  TargetFileName: "file.name",

  // Sign-in / audit style columns.
  ResultType: "event.outcome",
  Status: "event.outcome",
  IPAddress: "source.ip",

  // Endomorph-native passthroughs, so a rule can be written directly against
  // the corpus field names.
  "event.type": "event.type",
  "event.module": "event.module",
  "event.outcome": "event.outcome",
  "event.reason": "event.reason",
  "event.code": "event.code",
  "iam.role": "iam.role",
  "process.executable": "process.executable",
  "process.command_line":
    "process.command_line",
  "process.parent.executable":
    "process.parent.executable",
  "account.name": "account.name",
  "actor.account.name":
    "actor.account.name",
  "host.name": "host.name",
  "source.ip": "source.ip",
  "destination.ip": "destination.ip",
  "destination.port": "destination.port",
  "network.protocol": "network.protocol",
  "file.name": "file.name",
  "file.classification":
    "file.classification",
  "user.department": "user.department",

  // Mail / URL fields.
  "email.from.address": "email.from.address",
  "email.subject": "email.subject",
  "email.direction": "email.direction",
  "url.original": "url.original",
  SenderFromAddress: "email.from.address",
  Subject: "email.subject",
  Url: "url.original",

  // Cloud control-plane fields.
  "cloud.action": "cloud.action",
  "cloud.service": "cloud.service",
  "cloud.resource": "cloud.resource",
  "cloud.application": "cloud.application",
  OperationName: "cloud.action",
  Operation: "cloud.action",

  // DNS fields.
  "dns.question.name": "dns.question.name",
  "dns.question.type": "dns.question.type",
  "dns.resolved_ip": "dns.resolved_ip",
  QueryName: "dns.question.name",
  Query: "dns.question.name",

  // Web / proxy fields.
  "url.domain": "url.domain",
  "http.request.method": "http.request.method",
  "user_agent.original": "user_agent.original",
  RequestURL: "url.original",
  UserAgent: "user_agent.original",
};

export interface KqlDocument {
  readonly source: string;
  readonly query: string;
}

export interface KqlImportResult {
  readonly rules: DetectionRule[];
  readonly skipped: {
    readonly source: string;
    readonly title: string;
    readonly reason: string;
  }[];
}

class UnsupportedKql extends Error {}

function escapeRegex(
  value: string,
): string {
  return value.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&",
  );
}

/** Two operands and an operator, already stripped of surrounding whitespace. */
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
  // Longer tokens first so "matches regex" is not read as "matches".
  { token: "matches regex", negated: false },
  { token: "!contains", negated: true },
  { token: "contains_cs", negated: false },
  { token: "contains", negated: false },
  { token: "!startswith", negated: true },
  { token: "startswith", negated: false },
  { token: "!endswith", negated: true },
  { token: "endswith", negated: false },
  { token: "!has", negated: true },
  { token: "has", negated: false },
  { token: "!in", negated: true },
  { token: "in", negated: false },
  { token: "==", negated: false },
  { token: "=~", negated: false },
  { token: "!=", negated: true },
];

function unquote(raw: string): string {
  const trimmed = raw.trim();

  if (
    (trimmed.startsWith('"') &&
      trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") &&
      trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }

  return trimmed;
}

function parsePredicate(
  text: string,
): Predicate {
  // Find the operator by scanning the known set; a whitespace-delimited word
  // operator must sit between spaces, a symbol operator need not.
  for (const {
    token,
    negated,
  } of OPERATORS) {
    const isWord = /^[a-z]/i.test(token);
    const pattern = isWord
      ? new RegExp(
          `^(.+?)\\s+${token.replace(
            /[.*+?^${}()|[\]\\]/g,
            "\\$&",
          )}\\s+(.+)$`,
          "i",
        )
      : new RegExp(
          `^(.+?)\\s*${token.replace(
            /[.*+?^${}()|[\]\\]/g,
            "\\$&",
          )}\\s*(.+)$`,
        );

    const match = text.match(pattern);

    if (match) {
      return {
        field: match[1].trim(),
        operator: token,
        value: match[2].trim(),
        negated,
      };
    }
  }

  throw new UnsupportedKql(
    `Could not parse the predicate "${text.trim()}"; supported operators are ==, =~, !=, contains, has, startswith, endswith, matches regex, and in.`,
  );
}

function mapField(name: string): string {
  const mapped = FIELD_MAP[name];

  if (!mapped) {
    throw new UnsupportedKql(
      `Unmapped field "${name}". Add it to the field map or the rule would silently match nothing.`,
    );
  }

  return mapped;
}

function matcherFor(
  predicate: Predicate,
): FieldMatcher {
  const { operator, value } = predicate;

  if (
    operator === "in" ||
    operator === "!in"
  ) {
    const inner = value
      .trim()
      .replace(/^\(/, "")
      .replace(/\)$/, "");

    return inner
      .split(",")
      .map((item) => unquote(item));
  }

  const literal = unquote(value);

  switch (operator) {
    case "contains":
    case "contains_cs":
    case "!contains":
    case "has":
    case "!has":
      // `has` is a term match in KQL; contains is a superset and is the
      // closest the internal matcher offers.
      return { contains: literal };

    case "startswith":
    case "!startswith":
      return { startsWith: literal };

    case "endswith":
    case "!endswith":
      // The internal matcher expresses endsWith as an anchored regex.
      return {
        regex: `${escapeRegex(literal)}$`,
      };

    case "matches regex":
      return { regex: literal };

    default: {
      // == / =~ / != : an exact value, numeric when it looks numeric.
      const asNumber = Number(literal);
      return literal !== "" &&
        !Number.isNaN(asNumber) &&
        String(asNumber) === literal
        ? asNumber
        : literal;
    }
  }
}

/** Splits a predicate list on a top-level `and` or `or`, refusing a mix. */
function splitConjunction(text: string): {
  parts: string[];
  disjunction: boolean;
} {
  const hasAnd =
    /\s+and\s+/i.test(text);
  const hasOr = /\s+or\s+/i.test(text);

  if (hasAnd && hasOr) {
    throw new UnsupportedKql(
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

export function convertKqlRule(
  document: KqlDocument,
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

  // Drop comments and flatten to one line for clause scanning.
  const body = lines
    .map((line) =>
      line.replace(/\/\/.*$/, ""),
    )
    .join(" ")
    .trim();

  // Collect every `| where <predicates>` segment; multiple whas AND together.
  const segments = body
    .split("|")
    .map((segment) => segment.trim())
    .filter((segment) =>
      /^where\s+/i.test(segment),
    )
    .map((segment) =>
      segment.replace(/^where\s+/i, ""),
    );

  if (segments.length === 0) {
    throw new UnsupportedKql(
      "No `where` clause found; only the filtering part of a KQL query is scored.",
    );
  }

  // Parentheses that are not an in-list are grouping this subset does not
  // parse. Strip in-lists first, then refuse any remaining parens.
  const withoutInLists = segments
    .join(" and ")
    .replace(
      /\b!?in\s*\([^)]*\)/gi,
      "IN_LIST",
    );

  if (/[()]/.test(withoutInLists)) {
    throw new UnsupportedKql(
      "Grouping parentheses are not supported; the subset parses a flat conjunction or disjunction.",
    );
  }

  const { parts, disjunction } =
    splitConjunction(
      segments.join(" and "),
    );

  const positive: Record<
    string,
    FieldMatcher
  > = {};
  const exclusions: Record<
    string,
    FieldMatcher
  > = {};
  const anySelections: Selection[] = [];

  for (const part of parts) {
    const predicate = parsePredicate(part);
    const field = mapField(
      predicate.field,
    );
    const matcher = matcherFor(predicate);

    if (disjunction) {
      if (predicate.negated) {
        throw new UnsupportedKql(
          "Negated predicates inside an `or` are not supported.",
        );
      }
      anySelections.push({
        [field]: matcher,
      });
    } else if (predicate.negated) {
      exclusions[field] = matcher;
    } else {
      positive[field] = matcher;
    }
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
    ...(Object.keys(exclusions).length >
    0
      ? { exclusions: [exclusions] }
      : {}),
  };

  if (
    rule.selections.length === 0 &&
    anySelections.length === 0
  ) {
    throw new UnsupportedKql(
      "The rule reduced to no positive condition; a rule that is all exclusions would match everything benign.",
    );
  }

  return rule;
}

export function importKqlRules(
  documents: readonly KqlDocument[],
): KqlImportResult {
  const rules: DetectionRule[] = [];
  const skipped: KqlImportResult["skipped"] =
    [];

  for (const document of documents) {
    try {
      rules.push(
        convertKqlRule(document),
      );
    } catch (error) {
      skipped.push({
        source: document.source,
        title: document.source,
        reason:
          error instanceof Error
            ? error.message
            : "Unsupported KQL.",
      });
    }
  }

  return { rules, skipped };
}
