import type {
  DetectionRule,
  FieldMatcher,
  Selection,
} from "./detection.js";

/**
 * Splunk (SPL) rule import.
 *
 * Splunk is the largest SIEM, so a great many detections are written as SPL
 * searches. This translates the filtering part of a search -- the base search
 * terms, or a `| search` / `| where` segment -- into the same internal rule the
 * Sigma and KQL importers produce, so a Splunk author scores their own search
 * against the labelled corpus unchanged.
 *
 * SPL expresses matching with wildcards inside quoted values rather than with
 * named operators: `field="*x*"` is a substring match, `field="x*"` a prefix,
 * `field="*x"` a suffix. Those map onto the internal matcher directly. Data-
 * source selectors (`index=`, `sourcetype=`, `source=`) are dropped -- they
 * choose the logs, not the detection.
 *
 * As with the other importers, a construct the subset cannot express -- a
 * stats/eval/transforming command, a grouping parenthesis, mixed AND/OR, an
 * unmapped field -- is reported by name with a reason rather than imported as a
 * search that silently matches nothing.
 *
 * Supported: a base search or a `| search`/`| where` segment; `field=value`,
 * `field!=value`, `NOT field=value`, and `field IN (a, b)` terms joined by
 * implicit AND or explicit `OR` (not mixed at the top level); quoted or bare
 * values with `*` wildcards. Metadata is read from leading `// title:` and
 * `// technique:` comments.
 */

const FIELD_MAP: Readonly<
  Record<string, string>
> = {
  // Sysmon / CIM process fields.
  Image: "process.executable",
  process_name: "process.executable",
  process_path: "process.executable",
  New_Process_Name: "process.executable",
  CommandLine: "process.command_line",
  process: "process.command_line",
  process_command_line:
    "process.command_line",
  ParentImage:
    "process.parent.executable",
  parent_process_name:
    "process.parent.executable",
  ProcessId: "process.pid",

  // Identity and accounts.
  User: "account.name",
  user: "account.name",
  user_name: "account.name",
  Account_Name: "account.name",
  src_user: "actor.account.name",
  Role: "iam.role",

  // Host and network.
  ComputerName: "host.name",
  host: "host.name",
  dvc: "host.name",
  dest: "destination.ip",
  dest_ip: "destination.ip",
  DestinationIp: "destination.ip",
  src: "source.ip",
  src_ip: "source.ip",
  SourceIp: "source.ip",
  dest_port: "destination.port",
  DestinationPort: "destination.port",
  transport: "network.protocol",

  // Files and events.
  TargetFilename: "file.name",
  file_name: "file.name",
  EventCode: "event.code",
  EventID: "event.code",
  action: "event.outcome",
  status: "event.outcome",

  // Endomorph-native passthroughs.
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
  "file.name": "file.name",

  // Mail / URL fields.
  "email.from.address": "email.from.address",
  "email.subject": "email.subject",
  "email.direction": "email.direction",
  "url.original": "url.original",
  sender: "email.from.address",
  subject: "email.subject",
  url: "url.original",

  // Cloud control-plane fields.
  "cloud.action": "cloud.action",
  "cloud.service": "cloud.service",
  "cloud.resource": "cloud.resource",
  "cloud.application": "cloud.application",
  action_name: "cloud.action",
};

/** Selectors that choose the data source rather than express detection logic. */
const DROPPED_FIELDS = new Set([
  "index",
  "sourcetype",
  "source",
  "eventtype",
  "tag",
]);

export interface SplDocument {
  readonly source: string;
  readonly query: string;
}

export interface SplImportResult {
  readonly rules: DetectionRule[];
  readonly skipped: {
    readonly source: string;
    readonly title: string;
    readonly reason: string;
  }[];
}

class UnsupportedSpl extends Error {}

function escapeRegex(
  value: string,
): string {
  return value.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&",
  );
}

/** A wildcarded SPL value becomes the closest internal matcher. */
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
    // An internal wildcard needs a real pattern; anchor it so it is exact
    // except where the author asked for a gap.
    const pattern = raw
      .split("*")
      .map((part) => escapeRegex(part))
      .join(".*");

    return {
      regex: `^${starts ? "" : ""}${pattern}$`,
    };
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

  // No wildcard: an exact value, numeric when it looks numeric.
  const asNumber = Number(core);
  return core !== "" &&
    !Number.isNaN(asNumber) &&
    String(asNumber) === core
    ? asNumber
    : core;
}

interface Term {
  readonly field: string;
  readonly values: readonly string[];
  readonly negated: boolean;
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

/**
 * Splits a base search into terms, keeping quoted values and IN-lists whole.
 * A term is `NOT? field (=|!=|IN) value`.
 */
function tokenize(
  search: string,
): { terms: Term[]; disjunction: boolean } {
  // Reject transforming/eval commands: only the filtering part is scored.
  const disjunction = /\bOR\b/.test(
    search,
  );

  if (
    disjunction &&
    /\bAND\b/.test(search)
  ) {
    throw new UnsupportedSpl(
      "Mixed AND/OR at the top level is not supported.",
    );
  }

  const terms: Term[] = [];

  // field IN (a, b, c)
  const inRe =
    /(NOT\s+)?([\w.]+)\s+IN\s*\(([^)]*)\)/gi;
  let working = search;

  working = working.replace(
    inRe,
    (_match, not, field, list) => {
      terms.push({
        field,
        values: String(list)
          .split(",")
          .map((item) =>
            unquote(item.trim()),
          ),
        negated: Boolean(not),
      });
      return " ";
    },
  );

  // Remaining grouping parens are unsupported.
  if (/[()]/.test(working)) {
    throw new UnsupportedSpl(
      "Grouping parentheses are not supported.",
    );
  }

  // field=value / field!=value, with quoted or bare values, optional NOT.
  const termRe =
    /(NOT\s+)?([\w.]+)\s*(!?=)\s*("[^"]*"|'[^']*'|\S+)/gi;
  let match: RegExpExecArray | null;

  while (
    (match = termRe.exec(working)) !==
    null
  ) {
    const [, not, field, op, value] =
      match;
    terms.push({
      field,
      values: [unquote(value)],
      negated:
        Boolean(not) || op === "!=",
    });
  }

  if (terms.length === 0) {
    throw new UnsupportedSpl(
      "No field=value terms found; only the filtering part of a search is scored.",
    );
  }

  return { terms, disjunction };
}

function extractSearch(
  query: string,
): string {
  const lines = query.split(/\r?\n/);
  const body = lines
    .map((line) =>
      line.replace(/\/\/.*$/, ""),
    )
    .join(" ")
    .trim();

  // Reject transforming commands outright; scoring the filter of a search
  // that then aggregates would be a different, wrong number.
  const segments = body
    .split("|")
    .map((segment) => segment.trim());

  for (const segment of segments) {
    if (
      /^(stats|eval|rex|table|top|timechart|chart|dedup|sort|rename|join|transaction)\b/i.test(
        segment,
      )
    ) {
      throw new UnsupportedSpl(
        `The "${segment.split(/\s+/)[0]}" command transforms the results; only a filtering search is scored.`,
      );
    }
  }

  // Prefer an explicit `| search`/`| where` segment; otherwise the base search.
  const filtering = segments.find(
    (segment) =>
      /^(search|where)\b/i.test(segment),
  );

  const base = filtering
    ? filtering.replace(
        /^(search|where)\s+/i,
        "",
      )
    : segments[0].replace(
        /^search\s+/i,
        "",
      );

  return base.trim();
}

export function convertSplRule(
  document: SplDocument,
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

  const { terms, disjunction } =
    tokenize(extractSearch(document.query));

  const positive: Record<
    string,
    FieldMatcher
  > = {};
  const exclusions: Record<
    string,
    FieldMatcher
  > = {};
  const anySelections: Selection[] = [];

  for (const term of terms) {
    if (
      DROPPED_FIELDS.has(
        term.field.toLowerCase(),
      )
    ) {
      continue;
    }

    const field = FIELD_MAP[term.field];

    if (!field) {
      throw new UnsupportedSpl(
        `Unmapped field "${term.field}". Add it to the field map or the search would silently match nothing.`,
      );
    }

    const matcher =
      term.values.length > 1
        ? {
            anyOf: term.values.map(
              (value) =>
                matcherForValue(value),
            ),
          }
        : matcherForValue(
            term.values[0],
          );

    if (disjunction) {
      if (term.negated) {
        throw new UnsupportedSpl(
          "Negated terms inside an OR are not supported.",
        );
      }
      anySelections.push({
        [field]: matcher,
      });
    } else if (term.negated) {
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
    throw new UnsupportedSpl(
      "The search reduced to no positive term once data-source selectors were dropped; a search that is all exclusions would match everything benign.",
    );
  }

  return rule;
}

export function importSplRules(
  documents: readonly SplDocument[],
): SplImportResult {
  const rules: DetectionRule[] = [];
  const skipped: SplImportResult["skipped"] =
    [];

  for (const document of documents) {
    try {
      rules.push(
        convertSplRule(document),
      );
    } catch (error) {
      skipped.push({
        source: document.source,
        title: document.source,
        reason:
          error instanceof Error
            ? error.message
            : "Unsupported SPL.",
      });
    }
  }

  return { rules, skipped };
}
