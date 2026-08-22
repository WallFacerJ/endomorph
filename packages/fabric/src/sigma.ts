import {
  load,
} from "js-yaml";

import type {
  DetectionRule,
  FieldMatcher,
  Selection,
} from "./detection.js";

/**
 * Sigma rule import.
 *
 * Sigma is the portable detection format the community actually writes in,
 * and SigmaHQ publishes thousands of rules. Scoring those against a corpus
 * whose ground truth is known by construction is the thing this project can
 * do that a captured corpus cannot -- precision and recall become
 * computable rather than estimated.
 *
 * The internal rule shape was designed Sigma-like from the start, so this is
 * a translation rather than a redesign.
 *
 * A deliberate choice runs through the whole file: anything not understood
 * throws. Silently skipping an unsupported modifier or condition would
 * produce a rule that quietly matches nothing, and a detection that never
 * fires is the worst possible failure -- it looks like coverage while
 * providing none. That already happened once here, from a stray escape in a
 * regex, and it is not going to happen again through a parser.
 */

export class SigmaUnsupportedError extends Error {
  constructor(message: string) {
    super(message);
    this.name =
      "SigmaUnsupportedError";
  }
}

/**
 * Sigma field names to corpus fields.
 *
 * Sigma rules are written against log sources -- Windows process creation,
 * Sysmon, authentication -- and name fields the way those sources do. The
 * corpus is ECS-shaped, so importing means translating vocabularies.
 * Anything unmapped throws rather than matching nothing.
 */
const FIELD_MAP: Readonly<
  Record<string, string>
> = {
  // Process creation
  Image: "process.executable",
  OriginalFileName: "process.executable",
  CommandLine: "process.command_line",
  ParentImage: "process.parent.pid",
  ParentCommandLine:
    "process.parent.pid",
  ProcessId: "process.pid",
  ParentProcessId:
    "process.parent.pid",

  // Identity and accounts
  User: "account.name",
  TargetUserName: "account.name",
  SubjectUserName: "account.name",
  AccountName: "account.name",
  LogonType: "event.type",

  // Host
  Computer: "host.name",
  ComputerName: "host.name",
  Hostname: "host.name",

  // Network
  SourceIp: "source.ip",
  src_ip: "source.ip",
  DestinationIp: "destination.ip",
  dst_ip: "destination.ip",
  DestinationPort: "destination.port",
  dst_port: "destination.port",
  Protocol: "network.protocol",

  // Files
  TargetFilename: "file.name",
  FileName: "file.name",

  // Endomorph-native passthroughs, so a rule can be written directly
  // against the corpus without a translation table.
  "event.type": "event.type",
  "event.module": "event.module",
  "event.outcome": "event.outcome",
  "process.executable": "process.executable",
  "process.command_line":
    "process.command_line",
  "account.name": "account.name",
  "actor.account.name": "actor.account.name",
  "actor.account.id": "actor.account.id",
  SubjectAccountName: "actor.account.name",
  "host.name": "host.name",
  "source.ip": "source.ip",
  "destination.ip": "destination.ip",
  "destination.port":
    "destination.port",
  "file.name": "file.name",
  "file.classification":
    "file.classification",
  "user.department": "user.department",
};

export interface SigmaRule {
  title?: string;
  id?: string;
  status?: string;
  level?: string;
  tags?: string[];
  logsource?: Record<string, unknown>;
  detection?: Record<string, unknown>;
}

function mapField(
  rawField: string,
): { field: string; modifiers: string[] } {
  const [name, ...modifiers] =
    rawField.split("|");

  const mapped = FIELD_MAP[name];

  if (!mapped) {
    throw new SigmaUnsupportedError(
      `Unmapped Sigma field "${name}". Add it to FIELD_MAP or the rule will silently match nothing.`,
    );
  }

  return { field: mapped, modifiers };
}

function toMatcher(
  modifiers: readonly string[],
  value: unknown,
): FieldMatcher {
  const values = Array.isArray(value)
    ? value
    : [value];

  const literals = values.map((entry) => {
    if (
      typeof entry === "string" ||
      typeof entry === "number"
    ) {
      return entry;
    }

    throw new SigmaUnsupportedError(
      `Unsupported Sigma value type: ${typeof entry}`,
    );
  });

  const unsupported = modifiers.filter(
    (modifier) =>
      ![
        "contains",
        "startswith",
        "endswith",
        "re",
        "all",
      ].includes(modifier),
  );

  if (unsupported.length > 0) {
    throw new SigmaUnsupportedError(
      `Unsupported Sigma modifier(s): ${unsupported.join(", ")}`,
    );
  }

  // `|all` requires every listed value to match the same field, which this
  // matcher shape cannot express in one entry. Rejecting is honest;
  // pretending it is an OR would silently loosen the rule.
  if (modifiers.includes("all")) {
    throw new SigmaUnsupportedError(
      "The |all modifier is not supported; it would require an AND across one field.",
    );
  }

  if (literals.length !== 1) {
    if (
      modifiers.includes("contains") ||
      modifiers.includes("startswith") ||
      modifiers.includes("endswith") ||
      modifiers.includes("re")
    ) {
      throw new SigmaUnsupportedError(
        "A value list combined with a string modifier is not supported.",
      );
    }

    return literals;
  }

  const single = String(literals[0]);

  if (modifiers.includes("re")) {
    return { regex: single };
  }

  if (modifiers.includes("contains")) {
    return { contains: single };
  }

  if (modifiers.includes("startswith")) {
    return { startsWith: single };
  }

  if (modifiers.includes("endswith")) {
    // The internal matcher has no endsWith; a regex anchored at the end is
    // exact rather than approximate.
    return {
      regex: `${escapeRegex(single)}$`,
    };
  }

  return literals[0];
}

function escapeRegex(
  value: string,
): string {
  return value.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&",
  );
}

function toSelection(
  raw: unknown,
  name: string,
): Selection {
  if (
    raw === null ||
    typeof raw !== "object" ||
    Array.isArray(raw)
  ) {
    throw new SigmaUnsupportedError(
      `Selection "${name}" must be a map; lists of maps are not supported.`,
    );
  }

  const selection: Record<
    string,
    FieldMatcher
  > = {};

  for (const [
    rawField,
    value,
  ] of Object.entries(
    raw as Record<string, unknown>,
  )) {
    const { field, modifiers } =
      mapField(rawField);

    selection[field] = toMatcher(
      modifiers,
      value,
    );
  }

  return selection;
}

/** `attack.t1059.001` -> `T1059.001` */
function techniqueFromTags(
  tags: readonly string[] | undefined,
): string | undefined {
  const tag = (tags ?? []).find(
    (candidate) =>
      /^attack\.t\d{4}(\.\d{3})?$/i.test(
        candidate,
      ),
  );

  return tag
    ? tag.replace(/^attack\./i, "").toUpperCase()
    : undefined;
}

function severityFrom(
  level: string | undefined,
): DetectionRule["severity"] {
  switch ((level ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "low":
    case "informational":
      return "low";
    default:
      return "medium";
  }
}

/**
 * Parses the condition.
 *
 * Sigma's condition grammar is large. The supported subset covers the
 * overwhelming majority of published rules: a single selection, a
 * conjunction of selections, and negated selections used as filters.
 * Aggregations, `1 of`, and `|count()` throw.
 */
function parseCondition(
  condition: string,
  available: readonly string[],
): {
  required: string[];
  excluded: string[];
} {
  const normalized = condition
    .trim()
    .replace(/\s+/g, " ");

  if (/\|/.test(normalized)) {
    throw new SigmaUnsupportedError(
      `Aggregation conditions are not supported: "${condition}"`,
    );
  }

  if (/\bor\b/i.test(normalized)) {
    throw new SigmaUnsupportedError(
      `Disjunctions across selections are not supported: "${condition}"`,
    );
  }

  if (/\b\d+ of\b/i.test(normalized)) {
    throw new SigmaUnsupportedError(
      `"N of" conditions are not supported: "${condition}"`,
    );
  }

  const required: string[] = [];
  const excluded: string[] = [];

  const expandAll = (
    pattern: string,
  ): string[] => {
    const prefix = pattern.replace(
      /\*$/,
      "",
    );

    const matches = available.filter(
      (name) => name.startsWith(prefix),
    );

    if (matches.length === 0) {
      throw new SigmaUnsupportedError(
        `Condition references "${pattern}" but no selection matches it.`,
      );
    }

    return matches;
  };

  const tokens = normalized.split(
    /\s+and\s+/i,
  );

  for (const token of tokens) {
    const negated = /^not\s+/i.test(
      token,
    );

    const bare = token
      .replace(/^not\s+/i, "")
      .replace(/^all\s+of\s+/i, "")
      .replace(/[()]/g, "")
      .trim();

    if (bare.length === 0) {
      continue;
    }

    const names = bare.includes("*")
      ? expandAll(bare)
      : [bare];

    for (const name of names) {
      if (!available.includes(name)) {
        throw new SigmaUnsupportedError(
          `Condition references unknown selection "${name}".`,
        );
      }

      if (negated) {
        excluded.push(name);
      } else {
        required.push(name);
      }
    }
  }

  if (required.length === 0) {
    throw new SigmaUnsupportedError(
      `Condition "${condition}" selects nothing.`,
    );
  }

  return { required, excluded };
}

export function convertSigmaRule(
  rule: SigmaRule,
): DetectionRule {
  const detection = rule.detection;

  if (!detection) {
    throw new SigmaUnsupportedError(
      "Rule has no detection block.",
    );
  }

  const condition =
    detection["condition"];

  if (typeof condition !== "string") {
    throw new SigmaUnsupportedError(
      "Rule has no string condition; list conditions are not supported.",
    );
  }

  const selectionNames = Object.keys(
    detection,
  ).filter(
    (key) =>
      key !== "condition" &&
      key !== "timeframe",
  );

  const { required, excluded } =
    parseCondition(
      condition,
      selectionNames,
    );

  return {
    id:
      rule.id ??
      rule.title ??
      "sigma-rule",
    name: rule.title ?? "Untitled Sigma rule",
    technique: techniqueFromTags(
      rule.tags,
    ),
    severity: severityFrom(rule.level),
    selections: required.map((name) =>
      toSelection(
        detection[name],
        name,
      ),
    ),
    exclusions:
      excluded.length > 0
        ? excluded.map((name) =>
            toSelection(
              detection[name],
              name,
            ),
          )
        : undefined,
  };
}

export interface SigmaImportResult {
  readonly rules: readonly DetectionRule[];
  /** Rules that could not be translated, with the reason. */
  readonly skipped: readonly {
    readonly source: string;
    readonly title: string;
    readonly reason: string;
  }[];
}

/**
 * Imports a batch of Sigma documents.
 *
 * Individual failures are collected rather than thrown, because a
 * thousand-rule corpus will always contain constructs this subset does not
 * cover, and one unsupported rule should not abort the run. The reasons are
 * reported so the gap is visible rather than silent.
 */
export function importSigmaRules(
  documents: readonly {
    source: string;
    yaml: string;
  }[],
): SigmaImportResult {
  const rules: DetectionRule[] = [];

  const skipped: {
    source: string;
    title: string;
    reason: string;
  }[] = [];

  for (const document of documents) {
    let parsed: unknown;

    try {
      parsed = load(document.yaml);
    } catch (error) {
      skipped.push({
        source: document.source,
        title: "(unparsed)",
        reason: `YAML error: ${(error as Error).message}`,
      });

      continue;
    }

    const rule = parsed as SigmaRule;

    try {
      rules.push(
        convertSigmaRule(rule),
      );
    } catch (error) {
      skipped.push({
        source: document.source,
        title:
          rule?.title ?? "(untitled)",
        reason: (error as Error).message,
      });
    }
  }

  return { rules, skipped };
}
