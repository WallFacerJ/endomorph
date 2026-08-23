import {
  describe,
  expect,
  it,
} from "vitest";

import {
  formatCorpus,
  isCorpusFormat,
} from "./corpusFormats.js";

import type {
  CorpusRecord,
} from "./corpus.js";

const records: CorpusRecord[] = [
  {
    "@timestamp":
      "2026-08-20T08:00:00.000Z",
    "event.id": "bg-000001",
    "event.kind": "event",
    "event.type": "ENDPOINT_HEARTBEAT",
    "event.module": "endpoint",
    "host.name": "DC-02",
    "label.malicious": false,
  } as unknown as CorpusRecord,
  {
    "@timestamp":
      "2026-08-22T15:52:00.000Z",
    "event.id": "incident-macro-spawn",
    "event.kind": "event",
    "event.type": "PROCESS_STARTED",
    "event.module": "endpoint",
    "host.name": "HR-LT-028",
    "label.malicious": true,
    "label.technique": "T1059.001",
  } as unknown as CorpusRecord,
];

describe("corpus export formats", () => {
  it("rejects a format it does not know", () => {
    // The flag is typed at the boundary rather than trusted, so a typo is a
    // refusal rather than a silently wrong export.
    expect(isCorpusFormat("splunk")).toBe(
      true,
    );

    expect(
      isCorpusFormat("spunk"),
    ).toBe(false);
  });

  it("keeps the labels in every format", () => {
    /*
      The whole reason to move the corpus into somebody else's platform is
      that the answer travels with the data -- an analyst practises in the
      tool they use daily and an engineer scores their own rules there. An
      export that drops the labels is a pile of logs.
    */
    for (const format of [
      "ecs",
      "splunk",
      "elastic",
      "sentinel",
    ] as const) {
      const output = formatCorpus(
        records,
        { format, index: "test" },
      );

      expect(
        `${format}: ${output.includes("label.malicious")}`,
      ).toBe(`${format}: true`);

      expect(
        `${format}: ${output.includes("T1059.001")}`,
      ).toBe(`${format}: true`);
    }
  });

  it("gives Splunk the event time rather than the ingest time", () => {
    /*
      The single most common way a corpus import ends up useless: without an
      explicit `time`, Splunk stamps every record with the moment it arrived
      and five days of history collapse into one instant, which destroys
      every baseline the corpus exists to support.
    */
    const [first] = formatCorpus(
      records,
      { format: "splunk" },
    )
      .trim()
      .split("\n")
      .map(
        (line) =>
          JSON.parse(line) as {
            time: number;
          },
      );

    expect(first.time).toBe(
      Date.parse(
        "2026-08-20T08:00:00.000Z",
      ) / 1000,
    );
  });

  it("makes an Elastic re-import idempotent", () => {
    // A corpus that doubles every time somebody repeats the import would
    // quietly destroy the precision numbers it exists to support, so the
    // document id is the event id.
    const lines = formatCorpus(records, {
      format: "elastic",
      index: "endomorph",
    })
      .trim()
      .split("\n");

    expect(lines).toHaveLength(4);

    expect(
      JSON.parse(lines[0]) as unknown,
    ).toEqual({
      index: {
        _index: "endomorph",
        _id: "bg-000001",
      },
    });
  });

  it("spells TimeGenerated the way Sentinel requires", () => {
    // Azure Monitor keys off the name to set the record's timestamp and
    // silently uses ingestion time otherwise.
    const parsed = JSON.parse(
      formatCorpus(records, {
        format: "sentinel",
      }),
    ) as { TimeGenerated: string }[];

    expect(parsed[0].TimeGenerated).toBe(
      "2026-08-20T08:00:00.000Z",
    );
  });

  it("does not lose a record in any format", () => {
    expect(
      formatCorpus(records, {
        format: "ecs",
      })
        .trim()
        .split("\n"),
    ).toHaveLength(2);

    expect(
      formatCorpus(records, {
        format: "splunk",
      })
        .trim()
        .split("\n"),
    ).toHaveLength(2);

    expect(
      (
        JSON.parse(
          formatCorpus(records, {
            format: "sentinel",
          }),
        ) as unknown[]
      ).length,
    ).toBe(2);
  });

  it("survives a record whose timestamp cannot be parsed", () => {
    // Better a record at epoch zero, visibly wrong, than an export that
    // throws halfway and leaves a truncated file that looks complete.
    const output = formatCorpus(
      [
        {
          ...records[0],
          "@timestamp": "not-a-time",
        } as unknown as CorpusRecord,
      ],
      { format: "splunk" },
    );

    expect(
      (
        JSON.parse(output.trim()) as {
          time: number;
        }
      ).time,
    ).toBe(0);
  });
});
