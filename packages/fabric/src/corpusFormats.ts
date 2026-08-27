import type {
  CorpusRecord,
} from "./corpus.js";

/**
 * Corpus export in the shapes real platforms actually ingest.
 *
 * The corpus was already ECS-shaped NDJSON, which is the right neutral
 * format and is not what any of the three common destinations want. "Load
 * this into your Splunk" was a claim with a transformation step hidden
 * inside it, and the transformation is exactly the sort of thing that gets
 * written badly once per engagement.
 *
 * Every format keeps the labels. That is the whole reason to move the corpus
 * into somebody else's platform: an analyst can practise in the tool they
 * use daily, and an engineer can score their own rules there, because the
 * answer travels with the data.
 */

export type CorpusFormat =
  | "ecs"
  | "splunk"
  | "elastic"
  | "sentinel"
  | "ocsf";

export const CORPUS_FORMATS: readonly CorpusFormat[] =
  [
    "ecs",
    "splunk",
    "elastic",
    "sentinel",
    "ocsf",
  ];

export function isCorpusFormat(
  value: string,
): value is CorpusFormat {
  return (
    CORPUS_FORMATS as readonly string[]
  ).includes(value);
}

/** File extension each format is conventionally written with. */
export function extensionFor(
  format: CorpusFormat,
): string {
  return format === "sentinel"
    ? ".json"
    : ".ndjson";
}

function epochSeconds(
  timestamp: string,
): number {
  const parsed = Date.parse(timestamp);

  return Number.isFinite(parsed)
    ? parsed / 1000
    : 0;
}

/**
 * Splunk HTTP Event Collector.
 *
 * One JSON object per line, each wrapping the record in the envelope HEC
 * expects. `time` is epoch seconds, which is what stops Splunk stamping
 * every record with the moment it was ingested and flattening five days of
 * history into one instant -- the single most common way a corpus import
 * ends up useless.
 */
function toSplunk(
  records: readonly CorpusRecord[],
  index?: string,
): string {
  return `${records
    .map((record) =>
      JSON.stringify({
        time: epochSeconds(
          record["@timestamp"],
        ),
        host: record["host.name"],
        source: "endomorph",
        sourcetype: `endomorph:${record["event.module"]}`,
        ...(index ? { index } : {}),
        event: record,
      }),
    )
    .join("\n")}\n`;
}

/**
 * Elasticsearch bulk API.
 *
 * Alternating action and document lines. The document id is the event id, so
 * re-running the same seed re-indexes rather than duplicating -- a corpus
 * that doubles every time somebody repeats the import would quietly destroy
 * the precision numbers it exists to support.
 */
function toElasticBulk(
  records: readonly CorpusRecord[],
  index: string,
): string {
  return `${records
    .flatMap((record) => [
      JSON.stringify({
        index: {
          _index: index,
          _id: record["event.id"],
        },
      }),
      JSON.stringify(record),
    ])
    .join("\n")}\n`;
}

/**
 * Azure Monitor / Sentinel custom log.
 *
 * A JSON array rather than NDJSON, and `TimeGenerated` spelled exactly that
 * way, because the ingestion API keys off the name to set the record's
 * timestamp and silently uses ingestion time otherwise.
 */
function toSentinel(
  records: readonly CorpusRecord[],
): string {
  return `${JSON.stringify(
    records.map((record) => ({
      TimeGenerated: record["@timestamp"],
      ...record,
    })),
    null,
    2,
  )}\n`;
}

/**
 * Open Cybersecurity Schema Framework (OCSF).
 *
 * The vendor-neutral schema AWS Security Lake, Splunk, CrowdStrike, and the
 * rest of the OCSF membership converge on, so a corpus shaped this way lands
 * in a data lake without a per-vendor mapping written first. Each record is
 * placed in the OCSF class its family belongs to (a process start is Process
 * Activity, a login is Authentication, an alert is a Detection Finding) with
 * the framework's required envelope: category, class, type_uid, an epoch
 * millisecond `time`, and a severity on OCSF's own 0 to 6 scale.
 *
 * The ground truth rides in `unmapped`, which is precisely what OCSF reserves
 * for attributes outside the schema. That keeps every record valid OCSF while
 * the labels still travel, so the corpus stays scoreable after ingestion.
 */

interface OcsfClass {
  readonly category_uid: number;
  readonly category_name: string;
  readonly class_uid: number;
  readonly class_name: string;
}

const OCSF_FINDING: OcsfClass = {
  category_uid: 2,
  category_name: "Findings",
  class_uid: 2004,
  class_name: "Detection Finding",
};

const OCSF_BY_MODULE: Record<string, OcsfClass> = {
  endpoint: {
    category_uid: 1,
    category_name: "System Activity",
    class_uid: 1007,
    class_name: "Process Activity",
  },
  file: {
    category_uid: 1,
    category_name: "System Activity",
    class_uid: 1001,
    class_name: "File System Activity",
  },
  authentication: {
    category_uid: 3,
    category_name: "Identity & Access Management",
    class_uid: 3002,
    class_name: "Authentication",
  },
  network: {
    category_uid: 4,
    category_name: "Network Activity",
    class_uid: 4001,
    class_name: "Network Activity",
  },
  web: {
    category_uid: 4,
    category_name: "Network Activity",
    class_uid: 4002,
    class_name: "HTTP Activity",
  },
  email: {
    category_uid: 4,
    category_name: "Network Activity",
    class_uid: 4009,
    class_name: "Email Activity",
  },
  cloud: {
    category_uid: 6,
    category_name: "Application Activity",
    class_uid: 6003,
    class_name: "API Activity",
  },
};

const OCSF_UNKNOWN: OcsfClass = {
  category_uid: 0,
  category_name: "Uncategorized",
  class_uid: 0,
  class_name: "Base Event",
};

/** OCSF severity is a 0 (unknown) to 6 (fatal) scale, not a string. */
function ocsfSeverity(
  record: CorpusRecord,
): { id: number; name: string } {
  const raw = (
    record["event.severity"] ?? ""
  ).toLowerCase();

  if (raw === "critical") {
    return { id: 5, name: "Critical" };
  }
  if (raw === "high") {
    return { id: 4, name: "High" };
  }
  if (raw === "medium") {
    return { id: 3, name: "Medium" };
  }
  if (raw === "low") {
    return { id: 2, name: "Low" };
  }
  if (raw === "informational" || raw === "info") {
    return { id: 1, name: "Informational" };
  }
  // No stated severity: malicious ground truth still deserves a floor.
  return record["label.malicious"]
    ? { id: 3, name: "Medium" }
    : { id: 1, name: "Informational" };
}

function definedEntries(
  object: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(
    object,
  )) {
    if (
      value !== undefined &&
      value !== null &&
      value !== ""
    ) {
      out[key] = value;
    }
  }
  return out;
}

/** The class-specific OCSF objects for one record's family. */
function ocsfClassObjects(
  record: CorpusRecord,
): Record<string, unknown> {
  const module = record["event.module"];

  if (record["dns.question.name"]) {
    // A DNS event is HTTP Activity's sibling, class 4003.
    return {
      query: definedEntries({
        hostname: record["dns.question.name"],
        type: record["dns.question.type"],
      }),
      answers: record["dns.resolved_ip"]
        ? [
            {
              rdata: record["dns.resolved_ip"],
            },
          ]
        : undefined,
    };
  }

  switch (module) {
    case "endpoint":
      return {
        process: definedEntries({
          pid: record["process.pid"],
          cmd_line:
            record["process.command_line"],
          file: record["process.executable"]
            ? {
                path: record[
                  "process.executable"
                ],
              }
            : undefined,
          parent_process: record[
            "process.parent.pid"
          ]
            ? definedEntries({
                pid: record[
                  "process.parent.pid"
                ],
                file: record[
                  "process.parent.executable"
                ]
                  ? {
                      path: record[
                        "process.parent.executable"
                      ],
                    }
                  : undefined,
              })
            : undefined,
        }),
      };

    case "file":
      return {
        file: definedEntries({
          name: record["file.name"],
          uid: record["file.id"],
        }),
      };

    case "authentication":
      return {
        src_endpoint: record["source.ip"]
          ? { ip: record["source.ip"] }
          : undefined,
      };

    case "network":
      return {
        src_endpoint: record["source.ip"]
          ? { ip: record["source.ip"] }
          : undefined,
        dst_endpoint: definedEntries({
          ip: record["destination.ip"],
          port: record["destination.port"],
        }),
        connection_info: record[
          "network.protocol"
        ]
          ? {
              protocol_name:
                record["network.protocol"],
            }
          : undefined,
      };

    case "web":
      return {
        http_request: definedEntries({
          http_method:
            record["http.request.method"],
          url: definedEntries({
            hostname: record["url.domain"],
            url_string: record["url.original"],
          }),
          user_agent:
            record["user_agent.original"],
        }),
        http_response: record[
          "http.response.status_code"
        ]
          ? {
              code: record[
                "http.response.status_code"
              ],
            }
          : undefined,
      };

    case "email":
      return {
        email: definedEntries({
          from: record["email.from.address"],
          subject: record["email.subject"],
          direction: record["email.direction"],
        }),
      };

    case "cloud":
      return {
        api: definedEntries({
          operation: record["cloud.action"],
          service: record["cloud.service"]
            ? {
                name: record["cloud.service"],
              }
            : undefined,
        }),
        cloud: definedEntries({
          provider: record["cloud.application"],
        }),
      };

    default:
      return {};
  }
}

function toOcsfEvent(
  record: CorpusRecord,
): Record<string, unknown> {
  const isAlert =
    record["event.kind"] === "alert";
  const klass = isAlert
    ? OCSF_FINDING
    : OCSF_BY_MODULE[
        record["event.module"]
      ] ?? OCSF_UNKNOWN;
  const severity = ocsfSeverity(record);

  const base: Record<string, unknown> = {
    category_uid: klass.category_uid,
    category_name: klass.category_name,
    class_uid: klass.class_uid,
    class_name: klass.class_name,
    // activity_id 0 (Unknown) keeps the type_uid arithmetic valid while the
    // original event verb is preserved verbatim in activity_name.
    activity_id: 0,
    activity_name: record["event.type"],
    type_uid: klass.class_uid * 100,
    time: Date.parse(record["@timestamp"]),
    severity_id: severity.id,
    severity: severity.name,
    metadata: {
      version: "1.3.0",
      uid: record["event.id"],
      product: {
        name: "Endomorph",
        vendor_name: "Endomorph",
      },
      log_name: record["event.module"],
    },
    message: record["rule.name"],
    status: record["event.outcome"],
    status_detail: record["event.reason"],
    unmapped: definedEntries({
      "label.malicious":
        record["label.malicious"],
      "label.technique":
        record["label.technique"],
      "label.plan": record["label.plan"],
      "label.step": record["label.step"],
      "event.type": record["event.type"],
      "event.code": record["event.code"],
    }),
  };

  const device = definedEntries({
    hostname: record["host.name"],
    uid: record["host.id"],
    os: record["host.os.full"]
      ? { name: record["host.os.full"] }
      : undefined,
  });
  if (Object.keys(device).length > 0) {
    base.device = device;
  }

  const user = definedEntries({
    name: record["user.name"],
    uid: record["user.id"],
  });
  if (Object.keys(user).length > 0) {
    // Authentication carries the principal at the top level; every other
    // class carries it as the acting party.
    if (record["event.module"] === "authentication") {
      base.user = user;
    } else {
      base.actor = { user };
    }
  }

  if (isAlert) {
    base.finding_info = definedEntries({
      title: record["rule.name"],
      uid: record["event.id"],
    });
  }

  // A Detection Finding stands on its own envelope; the per-family activity
  // objects belong on the events, not on the alert about them.
  const merged = isAlert
    ? base
    : { ...base, ...ocsfClassObjects(record) };

  // Drop any object that ended up empty, so a record with no process detail
  // carries no hollow `process: {}` to confuse a schema validator.
  for (const [key, value] of Object.entries(
    merged,
  )) {
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(
        value as Record<string, unknown>,
      ).length === 0
    ) {
      delete merged[key];
    }
  }

  return merged;
}

/**
 * OCSF is line-delimited JSON: one event object per line, which is what
 * Security Lake's ingestion and every OCSF-aware pipeline reads.
 */
function toOcsf(
  records: readonly CorpusRecord[],
): string {
  return `${records
    .map((record) =>
      JSON.stringify(toOcsfEvent(record)),
    )
    .join("\n")}\n`;
}

export interface CorpusExportOptions {
  readonly format: CorpusFormat;

  /** Destination index or table, where the format needs one. */
  readonly index?: string;
}

export function formatCorpus(
  records: readonly CorpusRecord[],
  options: CorpusExportOptions,
): string {
  switch (options.format) {
    case "splunk":
      return toSplunk(
        records,
        options.index,
      );

    case "elastic":
      return toElasticBulk(
        records,
        options.index ?? "endomorph",
      );

    case "sentinel":
      return toSentinel(records);

    case "ocsf":
      return toOcsf(records);

    case "ecs":
      return `${records
        .map((record) =>
          JSON.stringify(record),
        )
        .join("\n")}\n`;
  }
}
