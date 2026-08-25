import {
  describe,
  expect,
  it,
} from "vitest";

import {
  convertSplRule,
  importSplRules,
} from "./spl.js";

describe("convertSplRule", () => {
  it("maps a base search to selections, wildcards to substring matchers", () => {
    const rule = convertSplRule({
      source: "test",
      query:
        '// title: Encoded PowerShell\n// technique: T1059.001\nindex=edr sourcetype=sysmon Image="powershell.exe" CommandLine="*-enc*"',
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

  it("reads a trailing wildcard as a prefix match", () => {
    const rule = convertSplRule({
      source: "t",
      query: 'Image="powershell*"',
    });

    expect(
      rule.selections[0][
        "process.executable"
      ],
    ).toEqual({ startsWith: "powershell" });
  });

  it("drops data-source selectors like index and sourcetype", () => {
    const rule = convertSplRule({
      source: "t",
      query:
        'index=main sourcetype=x CommandLine="*mimikatz*"',
    });

    expect(
      Object.keys(rule.selections[0]),
    ).toEqual(["process.command_line"]);
  });

  it("turns an IN list into an equals-any matcher", () => {
    const rule = convertSplRule({
      source: "t",
      query:
        'action IN ("success", "failure")',
    });

    expect(
      rule.selections[0][
        "event.outcome"
      ],
    ).toEqual({
      anyOf: ["success", "failure"],
    });
  });

  it("maps a top-level OR to anySelections", () => {
    const rule = convertSplRule({
      source: "t",
      query:
        'Image="a.exe" OR Image="b.exe"',
    });

    expect(rule.anySelections).toEqual([
      { "process.executable": "a.exe" },
      { "process.executable": "b.exe" },
    ]);
  });

  it("maps a negated term to an exclusion", () => {
    const rule = convertSplRule({
      source: "t",
      query:
        'CommandLine="*-enc*" user!="svc-backup"',
    });

    expect(rule.exclusions).toEqual([
      { "account.name": "svc-backup" },
    ]);
  });

  it("refuses an unmapped field", () => {
    expect(() =>
      convertSplRule({
        source: "t",
        query: 'MadeUpField="x"',
      }),
    ).toThrow(/Unmapped field/);
  });

  it("refuses a transforming command", () => {
    expect(() =>
      convertSplRule({
        source: "t",
        query:
          'Image="powershell.exe" | stats count by user',
      }),
    ).toThrow(/stats/);
  });

  it("refuses grouping parentheses and mixed AND/OR", () => {
    expect(() =>
      convertSplRule({
        source: "t",
        query:
          '(Image="a" OR Image="b") CommandLine="*x*"',
      }),
    ).toThrow();

    expect(() =>
      convertSplRule({
        source: "t",
        query:
          'Image="a" AND CommandLine="*x*" OR user="z"',
      }),
    ).toThrow(/mixed/i);
  });

  it("collects skips by source without throwing", () => {
    const result = importSplRules([
      {
        source: "good.spl",
        query: 'Image="powershell.exe"',
      },
      {
        source: "bad.spl",
        query: 'Nope="x"',
      },
    ]);

    expect(result.rules).toHaveLength(1);
    expect(
      result.skipped[0].source,
    ).toBe("bad.spl");
  });
});
