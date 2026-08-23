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
  | "sentinel";

export const CORPUS_FORMATS: readonly CorpusFormat[] =
  ["ecs", "splunk", "elastic", "sentinel"];

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

    case "ecs":
      return `${records
        .map((record) =>
          JSON.stringify(record),
        )
        .join("\n")}\n`;
  }
}
