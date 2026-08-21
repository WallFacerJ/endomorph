import type {
  SimulationTimestamp,
} from "@polymorph/domain";

import type {
  SiemEventRecord,
  SiemFieldValue,
} from "./siemProjection";

export type SiemSortOrder =
  | "asc"
  | "desc";

export interface SiemSearchRequest {
  query?: string;
  startTime?: SimulationTimestamp;
  endTime?: SimulationTimestamp;
  order?: SiemSortOrder;
}

export interface SiemFacetCount {
  value: string;
  count: number;
}

export interface SiemSearchFacets {
  families: readonly SiemFacetCount[];
  eventTypes: readonly SiemFacetCount[];
  sources: readonly SiemFacetCount[];
  severities: readonly SiemFacetCount[];
}

export interface SiemSearchResult {
  records: readonly SiemEventRecord[];
  total: number;
  facets: SiemSearchFacets;
}

interface SearchTerm {
  field: string | undefined;
  value: string;
  negated: boolean;
}

const FIELD_ALIASES:
  Readonly<Record<string, string>> = {
    type: "eventType",
    eventtype: "eventType",
    event: "eventType",
    family: "family",
    source: "source",
    actor: "actorId",
    actorid: "actorId",
    subject: "subjectId",
    subjectid: "subjectId",
    severity: "severity",
    id: "eventId",
    eventid: "eventId",
    message: "message",
  };

function normalize(value: string): string {
  return value.toLocaleLowerCase("en-US");
}

function tokenize(query: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | undefined;

  for (let index = 0;
    index < query.length;
    index += 1) {
    const character = query[index];

    if (quote) {
      if (character === quote) {
        quote = undefined;
      } else {
        current += character;
      }

      continue;
    }

    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }

    if (/\s/.test(character)) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }

      continue;
    }

    current += character;
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

function parseTerm(token: string): SearchTerm {
  const negated = token.startsWith("-");
  const source = negated
    ? token.slice(1)
    : token;

  const colonIndex = source.indexOf(":");
  const equalsIndex = source.indexOf("=");
  const indexes = [colonIndex, equalsIndex]
    .filter((index) => index > 0);
  const separatorIndex = indexes.length === 0
    ? -1
    : Math.min(...indexes);

  if (separatorIndex < 0) {
    return {
      field: undefined,
      value: source,
      negated,
    };
  }

  const field = source
    .slice(0, separatorIndex)
    .trim();
  const value = source
    .slice(separatorIndex + 1)
    .trim();

  if (!field || !value) {
    return {
      field: undefined,
      value: source,
      negated,
    };
  }

  return {
    field,
    value,
    negated,
  };
}

function parseQuery(query: string): SearchTerm[] {
  return tokenize(query)
    .map(parseTerm)
    .filter((term) => term.value.length > 0);
}

function fieldValues(
  record: SiemEventRecord,
  field: string,
): readonly SiemFieldValue[] {
  const normalizedField = normalize(field);
  const alias =
    FIELD_ALIASES[normalizedField];

  if (alias) {
    switch (alias) {
      case "eventId":
        return [record.eventId];
      case "eventType":
        return [record.eventType];
      case "family":
        return [record.family];
      case "source":
        return [record.source];
      case "actorId":
        return record.actorId
          ? [record.actorId]
          : [];
      case "subjectId":
        return record.subjectId
          ? [record.subjectId]
          : [];
      case "severity":
        return record.severity
          ? [record.severity]
          : [];
      case "message":
        return [record.message];
      default:
        return [];
    }
  }

  for (const [key, value] of
    Object.entries(record.fields)) {
    if (normalize(key) === normalizedField) {
      return [value];
    }
  }

  return [];
}

function flattenValue(
  value: SiemFieldValue,
): readonly string[] {
  if (Array.isArray(value)) {
    return value.map(String);
  }

  return [String(value)];
}

function valueMatches(
  value: SiemFieldValue,
  expected: string,
): boolean {
  const needle = normalize(expected);

  return flattenValue(value).some(
    (candidate) =>
      normalize(candidate).includes(needle),
  );
}

function searchableValues(
  record: SiemEventRecord,
): readonly SiemFieldValue[] {
  return [
    record.eventId,
    record.timestamp,
    record.source,
    record.eventType,
    record.family,
    record.actorId ?? "",
    record.subjectId ?? "",
    record.severity ?? "",
    record.message,
    ...record.relatedEventIds,
    ...record.relatedEntityIds,
    ...Object.values(record.fields),
  ];
}

function termMatches(
  record: SiemEventRecord,
  term: SearchTerm,
): boolean {
  const matches = term.field
    ? fieldValues(record, term.field).some(
        (value) =>
          valueMatches(value, term.value),
      )
    : searchableValues(record).some(
        (value) =>
          valueMatches(value, term.value),
      );

  return term.negated
    ? !matches
    : matches;
}

function isWithinTimeRange(
  record: SiemEventRecord,
  request: SiemSearchRequest,
): boolean {
  if (
    request.startTime &&
    record.timestamp < request.startTime
  ) {
    return false;
  }

  if (
    request.endTime &&
    record.timestamp > request.endTime
  ) {
    return false;
  }

  return true;
}

function countFacet(
  values: readonly (string | undefined)[],
): readonly SiemFacetCount[] {
  const counts = new Map<string, number>();

  for (const value of values) {
    if (!value) {
      continue;
    }

    counts.set(
      value,
      (counts.get(value) ?? 0) + 1,
    );
  }

  return [...counts.entries()]
    .map(([value, count]) => ({
      value,
      count,
    }))
    .sort((left, right) =>
      right.count - left.count ||
      left.value.localeCompare(right.value),
    );
}

function createFacets(
  records: readonly SiemEventRecord[],
): SiemSearchFacets {
  return {
    families: countFacet(
      records.map((record) => record.family),
    ),
    eventTypes: countFacet(
      records.map((record) => record.eventType),
    ),
    sources: countFacet(
      records.map((record) => record.source),
    ),
    severities: countFacet(
      records.map((record) => record.severity),
    ),
  };
}

export function searchSiem(
  records: readonly SiemEventRecord[],
  request: SiemSearchRequest = {},
): SiemSearchResult {
  const terms = parseQuery(
    request.query?.trim() ?? "",
  );

  const order = request.order ?? "desc";

  const matched = records
    .filter((record) =>
      isWithinTimeRange(record, request) &&
      terms.every((term) =>
        termMatches(record, term),
      ),
    )
    .slice()
    .sort((left, right) => {
      const timestampOrder =
        left.timestamp.localeCompare(
          right.timestamp,
        );

      if (timestampOrder !== 0) {
        return order === "asc"
          ? timestampOrder
          : -timestampOrder;
      }

      const idOrder =
        left.eventId.localeCompare(
          right.eventId,
        );

      return order === "asc"
        ? idOrder
        : -idOrder;
    });

  return {
    records: matched,
    total: matched.length,
    facets: createFacets(matched),
  };
}
