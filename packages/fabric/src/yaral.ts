import type {
  DetectionRule,
  FieldMatcher,
  Selection,
} from "./detection.js";

/**
 * Chronicle YARA-L 2.0 rule import.
 *
 * YARA-L is Google Chronicle's (Security Operations) detection language: a
 * `rule NAME { meta: ... events: ... condition: ... }` block whose `events`
 * section filters Chronicle's Unified Data Model (UDM). This translates the
 * single-event `events` predicates into the same internal rule the Sigma, KQL,
 * SPL, EQL, and ES|QL importers produce, so a Chronicle author scores their own
 * rule unchanged.
 *
 * The work is mapping UDM field paths (`$e.principal.process.command_line`) onto
 * this corpus's ECS-style fields, and translating the handful of UDM
 * `metadata.event_type` enums (`PROCESS_LAUNCH`, `NETWORK_DNS`) onto the event
 * types the corpus actually emits. An event type with no faithful equivalent is
 * refused by name rather than silently matching nothing.
 *
 * Supported in `events`: `$var.field = value` and `$var.field != value`, where
 * value is a `"string"` (exact match), a `/regex/` (with an optional trailing
 * `nocase`, which is already the default here since matching is
 * case-insensitive), or a number, joined by newline or `and` (a conjunction) or
 * `or` (a disjunction, not mixed at the top level). A `!=` predicate becomes an
 * exclusion. The `condition` must be a single event variable; multi-event
 * correlation, aggregation (`#e > N`), grouping parentheses, and numeric range
 * comparisons are Chronicle features this scoring model does not express, and
 * are refused rather than approximated.
 */

const FIELD_MAP: Readonly<
  Record<string, string>
> = {
  // Process, principal and target both fold onto the one process on the event.
  "principal.process.command_line":
    "process.command_line",
  "target.process.command_line":
    "process.command_line",
  "principal.process.file.full_path":
    "process.executable",
  "principal.process.file.name":
    "process.executable",
  "target.process.file.full_path":
    "process.executable",
  "target.process.file.name":
    "process.executable",
  "principal.process.pid": "process.pid",
  "principal.process.parent_process.file.full_path":
    "process.parent.executable",
  "principal.process.parent_process.file.name":
    "process.parent.executable",

  // Users and accounts.
  "principal.user.userid": "account.name",
  "target.user.userid": "account.name",
  "principal.user.user_display_name":
    "account.name",
  "target.user.user_display_name":
    "account.name",
  "principal.user.attribute.roles.name":
    "iam.role",
  "target.user.attribute.roles.name":
    "iam.role",

  // Hosts.
  "principal.hostname": "host.name",
  "principal.asset.hostname": "host.name",
  "target.hostname": "host.name",
  "principal.asset.asset_id": "host.id",

  // Network.
  "principal.ip": "source.ip",
  "src.ip": "source.ip",
  "target.ip": "destination.ip",
  "target.port": "destination.port",
  "network.ip_protocol":
    "network.protocol",

  // DNS.
  "network.dns.questions.name":
    "dns.question.name",
  "network.dns_domain":
    "dns.question.name",
  "network.dns.questions.type":
    "dns.question.type",

  // Web / HTTP.
  "network.http.method":
    "http.request.method",
  "network.http.user_agent":
    "user_agent.original",
  "target.url": "url.original",
  "principal.url": "url.original",
  "target.domain.name": "url.domain",

  // Files.
  "about.file.full_path": "file.name",
  "about.file.name": "file.name",
  "target.file.full_path": "file.name",

  // Mail.
  "network.email.from": "email.from.address",
  "network.email.subject": "email.subject",

  // Metadata and event classification.
  "metadata.event_type": "event.type",
  "security_result.summary": "rule.name",
};

/**
 * UDM event-type enums translated onto the event types this corpus emits. A
 * rule keyed on an event type with no faithful equivalent is skipped, not
 * silently reshaped into one that matches nothing.
 */
const EVENT_TYPE_MAP: Readonly<
  Record<string, string>
> = {
  PROCESS_LAUNCH: "PROCESS_STARTED",
  NETWORK_DNS: "DNS_QUERY",
  NETWORK_HTTP: "WEB_REQUEST",
  NETWORK_CONNECTION: "NETWORK_CONNECTION",
  EMAIL_TRANSACTION: "EMAIL_RECEIVED",
  FILE_OPEN: "FILE_ACCESSED",
  FILE_READ: "FILE_ACCESSED",
  USER_LOGIN: "AUTH_LOGIN_SUCCEEDED",
};

/** The event types the corpus emits, so a native value passes through. */
const NATIVE_EVENT_TYPES: ReadonlySet<string> =
  new Set([
    "PROCESS_STARTED",
    "DNS_QUERY",
    "WEB_REQUEST",
    "NETWORK_CONNECTION",
    "EMAIL_RECEIVED",
    "FILE_ACCESSED",
    "AUTH_LOGIN_SUCCEEDED",
    "AUTH_LOGIN_FAILED",
    "ROLE_GRANTED",
    "ACCOUNT_ENABLED",
    "ACCOUNT_DISABLED",
    "SESSION_STARTED",
    "SESSION_REVOKED",
    "CLOUD_AUDIT",
    "ENDPOINT_HEARTBEAT",
    "ALERT_CREATED",
  ]);

export interface YaralDocument {
  readonly source: string;
  readonly text: string;
}

export interface YaralImportResult {
  readonly rules: DetectionRule[];
  readonly skipped: {
    readonly source: string;
    readonly title: string;
    readonly reason: string;
  }[];
}

class UnsupportedYaral extends Error {}

interface Predicate {
  readonly field: string;
  readonly operator: "=" | "!=";
  readonly value: string;
  readonly nocase: boolean;
}

function stripComments(text: string): string {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n");
}

/** Every `rule NAME { ... }` block in the document, brace-matched. */
function extractRuleBlocks(
  text: string,
): { name: string; body: string }[] {
  const blocks: {
    name: string;
    body: string;
  }[] = [];
  const header = /rule\s+([A-Za-z0-9_]+)\s*\{/g;

  let match: RegExpExecArray | null;
  while ((match = header.exec(text))) {
    const name = match[1];
    let depth = 1;
    let index = header.lastIndex;
    const start = index;

    while (index < text.length && depth > 0) {
      const char = text[index];
      if (char === "{") {
        depth += 1;
      } else if (char === "}") {
        depth -= 1;
      }
      index += 1;
    }

    if (depth !== 0) {
      throw new UnsupportedYaral(
        `Rule "${name}" is missing a closing brace.`,
      );
    }

    blocks.push({
      name,
      body: text.slice(start, index - 1),
    });
    header.lastIndex = index;
  }

  return blocks;
}

/** Split a rule body into its named sections (meta / events / condition). */
function sectionsOf(
  body: string,
): Record<string, string> {
  const sections: Record<string, string> = {};
  const keyword =
    /^\s*(meta|events|condition|outcome|options|match)\s*:/gim;

  const marks: {
    name: string;
    start: number;
    contentStart: number;
  }[] = [];

  let match: RegExpExecArray | null;
  while ((match = keyword.exec(body))) {
    marks.push({
      name: match[1].toLowerCase(),
      start: match.index,
      contentStart:
        match.index + match[0].length,
    });
  }

  marks.forEach((mark, position) => {
    const end =
      position + 1 < marks.length
        ? marks[position + 1].start
        : body.length;
    sections[mark.name] = body
      .slice(mark.contentStart, end)
      .trim();
  });

  return sections;
}

/**
 * Replace `"string"` and `/regex/` literals with placeholders, so a scan for
 * the `and` / `or` keywords cannot trip over an `or` sitting inside a literal.
 */
function maskLiterals(text: string): {
  masked: string;
  literals: string[];
} {
  const literals: string[] = [];
  const masked = text.replace(
    /"(?:[^"\\]|\\.)*"|\/(?:[^/\\]|\\.)*\//g,
    (literal) => {
      literals.push(literal);
      return ` §${literals.length - 1}§ `;
    },
  );
  return { masked, literals };
}

function restoreLiterals(
  text: string,
  literals: readonly string[],
): string {
  return text.replace(
    /§(\d+)§/g,
    (_match, index) =>
      literals[Number(index)],
  );
}

function parsePredicate(
  raw: string,
): Predicate {
  const trimmed = raw.trim();

  if (/[<>]=?/.test(trimmed)) {
    throw new UnsupportedYaral(
      `Range comparison in "${trimmed}" is not supported; the matcher expresses equality and regex, not ranges.`,
    );
  }

  const match = trimmed.match(
    /^\$\w+\.([\w.]+)\s*(!=|=)\s*(.+?)(\s+nocase)?$/i,
  );

  if (!match) {
    throw new UnsupportedYaral(
      `Could not parse the predicate "${trimmed}"; expected $var.field = value.`,
    );
  }

  return {
    field: match[1].trim(),
    operator: match[2] as "=" | "!=",
    value: match[3].trim(),
    nocase: Boolean(match[4]),
  };
}

function mapField(name: string): string {
  const mapped = FIELD_MAP[name];

  if (!mapped) {
    throw new UnsupportedYaral(
      `Unmapped UDM field "${name}". Add it to the field map or the rule would silently match nothing.`,
    );
  }

  return mapped;
}

function unquote(raw: string): string {
  const trimmed = raw.trim();
  return trimmed.startsWith('"') &&
    trimmed.endsWith('"')
    ? trimmed.slice(1, -1)
    : trimmed;
}

function matcherFor(
  field: string,
  predicate: Predicate,
): FieldMatcher {
  const { value } = predicate;

  // A `/regex/` literal.
  if (
    value.startsWith("/") &&
    value.endsWith("/") &&
    value.length >= 2
  ) {
    return {
      regex: value.slice(1, -1),
    };
  }

  const literal = unquote(value);

  // metadata.event_type carries a UDM enum that must be translated onto the
  // event types this corpus actually emits.
  if (field === "event.type") {
    const upper = literal.toUpperCase();
    if (NATIVE_EVENT_TYPES.has(upper)) {
      return upper;
    }
    const translated = EVENT_TYPE_MAP[upper];
    if (!translated) {
      throw new UnsupportedYaral(
        `UDM event_type "${literal}" has no faithful equivalent in this corpus; refusing rather than matching nothing.`,
      );
    }
    return translated;
  }

  const asNumber = Number(literal);
  return literal !== "" &&
    !Number.isNaN(asNumber) &&
    String(asNumber) === literal
    ? asNumber
    : literal;
}

export function convertYaralRule(block: {
  name: string;
  body: string;
}): DetectionRule {
  const sections = sectionsOf(block.body);

  if (!sections.events) {
    throw new UnsupportedYaral(
      "No events section; only the event filtering of a YARA-L rule is scored.",
    );
  }

  if (
    sections.match ||
    sections.outcome
  ) {
    throw new UnsupportedYaral(
      "A match or outcome section marks a multi-event or aggregating rule, which this scoring model does not express.",
    );
  }

  const condition = (
    sections.condition ?? "$e"
  ).trim();

  if (!/^\$\w+$/.test(condition)) {
    throw new UnsupportedYaral(
      `Condition "${condition}" is not a single event variable; multi-event correlation and aggregation are not scored.`,
    );
  }

  // Metadata: pick up an ATT&CK technique wherever it is written.
  let technique: string | undefined;
  const techniqueMatch = (
    sections.meta ?? ""
  ).match(/\b(T\d{4}(?:\.\d{3})?)\b/);
  if (techniqueMatch) {
    technique = techniqueMatch[1];
  }

  // Join event predicates (newline is an implicit AND), then mask literals so
  // the and/or scan is safe.
  const joined = sections.events
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .join(" and ");

  const { masked, literals } =
    maskLiterals(joined);

  if (/[()]/.test(masked)) {
    throw new UnsupportedYaral(
      "Grouping parentheses are not supported; the subset parses a flat conjunction or disjunction.",
    );
  }

  const hasAnd = /\sand\s/i.test(masked);
  const hasOr = /\sor\s/i.test(masked);

  if (hasAnd && hasOr) {
    throw new UnsupportedYaral(
      "Mixed and/or at the top level is not supported; keep the predicates all-and or all-or, or split the rule.",
    );
  }

  const disjunction = hasOr;
  const chunks = masked
    .split(disjunction ? /\sor\s/i : /\sand\s/i)
    .map((chunk) =>
      restoreLiterals(chunk, literals).trim(),
    )
    .filter((chunk) => chunk.length > 0);

  const positive: Record<
    string,
    FieldMatcher
  > = {};
  const exclusions: Record<
    string,
    FieldMatcher
  > = {};
  const anySelections: Selection[] = [];

  for (const chunk of chunks) {
    const predicate = parsePredicate(chunk);
    const field = mapField(predicate.field);
    const matcher = matcherFor(
      field,
      predicate,
    );

    if (predicate.operator === "!=") {
      if (disjunction) {
        throw new UnsupportedYaral(
          "A negated predicate inside an or is not supported.",
        );
      }
      exclusions[field] = matcher;
    } else if (disjunction) {
      anySelections.push({
        [field]: matcher,
      });
    } else {
      positive[field] = matcher;
    }
  }

  const rule: DetectionRule = {
    id: block.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, ""),
    name: block.name,
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
    throw new UnsupportedYaral(
      "The events section reduced to no positive term; a rule that is all exclusions would match everything benign.",
    );
  }

  return rule;
}

export function importYaralRules(
  documents: readonly YaralDocument[],
): YaralImportResult {
  const rules: DetectionRule[] = [];
  const skipped: YaralImportResult["skipped"] =
    [];

  for (const document of documents) {
    let blocks: {
      name: string;
      body: string;
    }[];

    try {
      blocks = extractRuleBlocks(
        stripComments(document.text),
      );
    } catch (error) {
      skipped.push({
        source: document.source,
        title: document.source,
        reason:
          error instanceof Error
            ? error.message
            : "Unparseable YARA-L.",
      });
      continue;
    }

    if (blocks.length === 0) {
      skipped.push({
        source: document.source,
        title: document.source,
        reason:
          "No rule block found; expected rule NAME { ... }.",
      });
      continue;
    }

    for (const block of blocks) {
      try {
        rules.push(
          convertYaralRule(block),
        );
      } catch (error) {
        skipped.push({
          source: document.source,
          title: block.name,
          reason:
            error instanceof Error
              ? error.message
              : "Unsupported YARA-L.",
        });
      }
    }
  }

  return { rules, skipped };
}
