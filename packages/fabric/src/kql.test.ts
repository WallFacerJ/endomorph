import {
  describe,
  expect,
  it,
} from "vitest";

import {
  convertKqlRule,
  importKqlRules,
} from "./kql.js";

describe("convertKqlRule", () => {
  it("maps a conjunction of Defender columns to selections", () => {
    const rule = convertKqlRule({
      source: "test",
      query:
        "// title: Encoded PowerShell\n// technique: T1059.001\nDeviceProcessEvents\n| where FileName == \"powershell.exe\" and ProcessCommandLine contains \"-enc\"",
    });

    expect(rule.name).toBe(
      "Encoded PowerShell",
    );
    expect(rule.technique).toBe(
      "T1059.001",
    );
    expect(rule.selections).toEqual([
      {
        "process.executable":
          "powershell.exe",
        "process.command_line": {
          contains: "-enc",
        },
      },
    ]);
  });

  it("expresses endswith as an anchored regex", () => {
    const rule = convertKqlRule({
      source: "t",
      query:
        "T | where FileName endswith \"powershell.exe\"",
    });

    expect(
      rule.selections[0],
    ).toEqual({
      "process.executable": {
        regex: "powershell\\.exe$",
      },
    });
  });

  it("turns an in-list into an equals-any matcher", () => {
    const rule = convertKqlRule({
      source: "t",
      query:
        "T | where ResultType in (\"0\", \"50\")",
    });

    expect(
      rule.selections[0][
        "event.outcome"
      ],
    ).toEqual(["0", "50"]);
  });

  it("maps a top-level or to anySelections", () => {
    const rule = convertKqlRule({
      source: "t",
      query:
        "T | where FileName == \"a.exe\" or FileName == \"b.exe\"",
    });

    expect(rule.anySelections).toEqual([
      { "process.executable": "a.exe" },
      { "process.executable": "b.exe" },
    ]);
  });

  it("maps a negated predicate to an exclusion", () => {
    const rule = convertKqlRule({
      source: "t",
      query:
        "T | where ProcessCommandLine contains \"-enc\" and AccountName != \"svc-backup\"",
    });

    expect(rule.exclusions).toEqual([
      { "account.name": "svc-backup" },
    ]);
  });

  it("refuses an unmapped field rather than importing a rule that lies", () => {
    expect(() =>
      convertKqlRule({
        source: "t",
        query:
          "T | where MadeUpColumn == \"x\"",
      }),
    ).toThrow(/Unmapped field/);
  });

  it("refuses a query with no where clause", () => {
    expect(() =>
      convertKqlRule({
        source: "t",
        query:
          "DeviceProcessEvents | summarize count() by FileName",
      }),
    ).toThrow(/where/);
  });

  it("refuses grouping parentheses and mixed and/or", () => {
    expect(() =>
      convertKqlRule({
        source: "t",
        query:
          "T | where (FileName == \"a\" or FileName == \"b\") and X has \"y\"",
      }),
    ).toThrow();

    expect(() =>
      convertKqlRule({
        source: "t",
        query:
          "T | where FileName == \"a\" and ProcessCommandLine contains \"x\" or AccountName == \"z\"",
      }),
    ).toThrow(/mixed/i);
  });

  it("collects skips by source without throwing", () => {
    const result = importKqlRules([
      {
        source: "good.kql",
        query:
          "T | where FileName == \"powershell.exe\"",
      },
      {
        source: "bad.kql",
        query: "T | where Nope == \"x\"",
      },
    ]);

    expect(result.rules).toHaveLength(1);
    expect(
      result.skipped[0].source,
    ).toBe("bad.kql");
  });
});
