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
  ProcessId: "process.pid",
  ParentProcessId:
    "process.parent.pid",
  ParentImage:
    "process.parent.executable",

  // ParentCommandLine is still deliberately absent. The generator now emits a
  // parent image, but not the parent's own command line, and mapping the two
  // together would import rules that compare an argument string against a
  // bare path -- clean import, permanent silence. An unmapped field is a
  // refusal the author can see; a wrong mapping is a rule that lies.

  // Windows event ids. Only Windows hosts carry these, and only for event
  // types with a real equivalent, so a rule keyed on one is scored against
  // the hosts that would genuinely produce it.
  EventID: "event.code",
  EventCode: "event.code",

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

  // An empty value list can never match anything. Building {anyOf: []} from
  // it replaced a loud refusal with a rule that imports cleanly and detects
  // nothing forever -- the failure this module exists to prevent.
  if (literals.length === 0) {
    throw new SigmaUnsupportedError(
      "An empty value list matches nothing.",
    );
  }

  if (literals.length !== 1) {
    const stringModifier = [
      "contains",
      "startswith",
      "endswith",
      "re",
    ].some((modifier) =>
      modifiers.includes(modifier),
    );

    // A list under a modifier is an OR over the same field, which is how
    // Sigma expresses alternatives.
    return stringModifier
      ? {
          anyOf: literals.map((literal) =>
            toMatcher(modifiers, literal),
          ),
        }
      : literals;
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
 * overwhelming majority of published rules: a conjunction of selections,
 * negated selections used as filters, and `1 of` as a disjunction across
 * selection groups. Aggregations and `N of` for N above one throw.
 *
 * `1 of` is handled as a token inside the conjunction rather than as a whole
 * condition, because `1 of selection_* and not filter_main` is far more
 * common than `1 of selection_*` alone. Treating it as the entire condition
 * made the combined form fall through to the plain-name path, where it was
 * refused for a reason that was not true.
 */
function parseCondition(
  condition: string,
  available: readonly string[],
): {
  required: string[];
  excluded: string[];
  alternatives: string[];
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

  // Match any count, then reject above one. Anchoring the digits as [2-9]\d*
  // left the guard inert for ten and above, so "10 of them" fell through to
  // be misdiagnosed as an unknown selection.
  const count = /\b(\d+) of\b/i.exec(
    normalized,
  );

  if (
    count &&
    Number(count[1]) !== 1
  ) {
    throw new SigmaUnsupportedError(
      `"N of" with N other than one is not supported: "${condition}"`,
    );
  }

  const required: string[] = [];
  const excluded: string[] = [];
  const alternatives: string[] = [];

  const resolve = (
    pattern: string,
  ): string[] => {
    if (pattern === "them") {
      return [...available];
    }

    if (!pattern.includes("*")) {
      // The plain-name path validates too; skipping it here surfaced an
      // unknown selection as a confusing "must be a map" error later.
      if (!available.includes(pattern)) {
        throw new SigmaUnsupportedError(
          `Condition references unknown selection "${pattern}".`,
        );
      }

      return [pattern];
    }

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

  // Split on "and", keeping "1 of X" and "all of X" intact as single tokens.
  const tokens = normalized.split(
    /\s+and\s+/i,
  );

  for (const token of tokens) {
    const cleaned = token
      .replace(/[()]/g, "")
      .trim();

    if (cleaned.length === 0) {
      continue;
    }

    const negated = /^not\s+/i.test(
      cleaned,
    );

    const body = cleaned
      .replace(/^not\s+/i, "")
      .trim();

    const oneOf = /^1 of (\S+)$/i.exec(
      body,
    );

    if (oneOf) {
      const names = resolve(oneOf[1]);

      if (names.length === 0) {
        throw new SigmaUnsupportedError(
          `Condition "${condition}" selects nothing.`,
        );
      }

      if (negated) {
        // "not 1 of X" excludes every alternative, which the exclusion list
        // already expresses as an OR.
        excluded.push(...names);
      } else {
        alternatives.push(...names);
      }

      continue;
    }

    const bare = body
      .replace(/^all\s+of\s+/i, "")
      .trim();

    for (const name of resolve(bare)) {
      if (negated) {
        excluded.push(name);
      } else {
        required.push(name);
      }
    }
  }

  // A condition that constrains nothing would produce a rule matching every
  // record in the corpus, which is worse than one matching none: it looks
  // like total coverage.
  if (
    required.length === 0 &&
    alternatives.length === 0
  ) {
    throw new SigmaUnsupportedError(
      `Condition "${condition}" selects nothing.`,
    );
  }

  return {
    required,
    excluded,
    alternatives,
  };
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

  const {
    required,
    excluded,
    alternatives,
  } = parseCondition(
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
    anySelections:
      alternatives.length > 0
        ? alternatives.map((name) =>
            toSelection(
              detection[name],
              name,
            ),
          )
        : undefined,
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
