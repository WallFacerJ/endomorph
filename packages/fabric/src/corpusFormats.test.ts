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
      "ocsf",
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

interface OcsfRow {
  class_uid: number;
  class_name: string;
  category_uid: number;
  type_uid: number;
  time: number;
  severity_id: number;
  user?: { name?: string };
  actor?: { user?: { name?: string } };
  process?: { cmd_line?: string };
  finding_info?: { title?: string };
  unmapped: Record<string, unknown>;
}

const ocsfRows = (
  input: readonly CorpusRecord[],
): OcsfRow[] =>
  formatCorpus(input, { format: "ocsf" })
    .trim()
    .split("\n")
    .map(
      (line) =>
        JSON.parse(line) as OcsfRow,
    );

describe("OCSF export", () => {
  it("places each family in its OCSF class", () => {
    const [heartbeat, process] =
      ocsfRows(records);

    // A process start is System Activity / Process Activity (1007), and the
    // type_uid is the class times 100 plus the activity id.
    expect(process.class_uid).toBe(1007);
    expect(process.class_name).toBe(
      "Process Activity",
    );
    expect(process.category_uid).toBe(1);
    expect(process.type_uid).toBe(100700);

    // Endpoint telemetry with no richer family still lands in the same class.
    expect(heartbeat.class_uid).toBe(1007);
  });

  it("maps an alert to a Detection Finding", () => {
    const [finding] = ocsfRows([
      {
        "@timestamp":
          "2026-08-22T16:00:00.000Z",
        "event.id": "alert-1",
        "event.kind": "alert",
        "event.type": "ALERT_CREATED",
        "event.module": "endpoint",
        "rule.name":
          "Domain credential theft",
        "event.severity": "critical",
        "label.malicious": true,
      } as unknown as CorpusRecord,
    ]);

    expect(finding.class_uid).toBe(2004);
    expect(finding.class_name).toBe(
      "Detection Finding",
    );
    expect(finding.category_uid).toBe(2);
    // Critical is 5 on the OCSF 0 to 6 severity scale.
    expect(finding.severity_id).toBe(5);
    expect(
      finding.finding_info?.title,
    ).toBe("Domain credential theft");
  });

  it("carries the principal where each class expects it", () => {
    const [login] = ocsfRows([
      {
        "@timestamp":
          "2026-08-22T09:00:00.000Z",
        "event.id": "login-1",
        "event.kind": "event",
        "event.type": "AUTH_LOGIN_FAILED",
        "event.module": "authentication",
        "user.name": "j.doe",
        "label.malicious": false,
      } as unknown as CorpusRecord,
    ]);

    // Authentication puts the user at the top level; other classes nest it
    // under actor.
    expect(login.user?.name).toBe("j.doe");
    expect(login.actor).toBeUndefined();

    const [process] = ocsfRows([
      {
        ...records[1],
        "user.name": "svc-backup",
      } as unknown as CorpusRecord,
    ]);
    expect(process.actor?.user?.name).toBe(
      "svc-backup",
    );
  });

  it("keeps ground truth in the OCSF unmapped object", () => {
    const [, process] = ocsfRows(records);

    // unmapped is exactly where OCSF puts attributes outside the schema, so
    // the labels travel without making the record invalid OCSF.
    expect(
      process.unmapped["label.malicious"],
    ).toBe(true);
    expect(
      process.unmapped["label.technique"],
    ).toBe("T1059.001");
  });

  it("uses epoch milliseconds for time", () => {
    const [heartbeat] = ocsfRows(records);

    expect(heartbeat.time).toBe(
      Date.parse("2026-08-20T08:00:00.000Z"),
    );
  });
});
