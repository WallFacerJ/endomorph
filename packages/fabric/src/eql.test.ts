import {
  describe,
  expect,
  it,
} from "vitest";

import {
  convertEqlRule,
  importEqlRules,
} from "./eql.js";

describe("convertEqlRule", () => {
  it("maps a where condition to selections, wildcards to substring matchers", () => {
    const rule = convertEqlRule({
      source: "test",
      query:
        '// title: Encoded PowerShell\n// technique: T1059.001\nprocess where process.name == "powershell.exe" and process.command_line : "*-enc*"',
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
    const rule = convertEqlRule({
      source: "t",
      query:
        'process where process.name : "powershell*"',
    });

    expect(
      rule.selections[0][
        "process.executable"
      ],
    ).toEqual({ startsWith: "powershell" });
  });

  it("drops the event category and reads a numeric value as a number", () => {
    const rule = convertEqlRule({
      source: "t",
      query:
        "network where destination.port == 443",
    });

    expect(rule.selections[0]).toEqual({
      "destination.port": 443,
    });
  });

  it("turns an in list into an equals-any matcher", () => {
    const rule = convertEqlRule({
      source: "t",
      query:
        'authentication where event.outcome in ("success", "failure")',
    });

    expect(
      rule.selections[0][
        "event.outcome"
      ],
    ).toEqual({
      anyOf: ["success", "failure"],
    });
  });

  it("maps a top-level or to anySelections", () => {
    const rule = convertEqlRule({
      source: "t",
      query:
        'process where process.name == "a.exe" or process.name == "b.exe"',
    });

    expect(rule.anySelections).toEqual([
      { "process.executable": "a.exe" },
      { "process.executable": "b.exe" },
    ]);
  });

  it("maps a negated term to an exclusion", () => {
    const rule = convertEqlRule({
      source: "t",
      query:
        'process where process.command_line : "*-enc*" and user.name != "svc-backup"',
    });

    expect(rule.exclusions).toEqual([
      { "account.name": "svc-backup" },
    ]);
  });

  it("maps a like predicate to a substring match", () => {
    const rule = convertEqlRule({
      source: "t",
      query:
        'process where process.command_line like "*mimikatz*"',
    });

    expect(
      rule.selections[0][
        "process.command_line"
      ],
    ).toEqual({ contains: "mimikatz" });
  });

  it("refuses an unmapped field", () => {
    expect(() =>
      convertEqlRule({
        source: "t",
        query:
          'process where made.up == "x"',
      }),
    ).toThrow(/Unmapped field/);
  });

  it("refuses a numeric range comparison", () => {
    expect(() =>
      convertEqlRule({
        source: "t",
        query:
          "process where process.pid > 1000",
      }),
    ).toThrow(/comparison/i);
  });

  it("refuses a sequence query", () => {
    expect(() =>
      convertEqlRule({
        source: "t",
        query:
          "sequence [process where true] [network where true]",
      }),
    ).toThrow(/sequence/i);
  });

  it("refuses grouping parentheses and mixed and/or", () => {
    expect(() =>
      convertEqlRule({
        source: "t",
        query:
          'process where (process.name == "a" or process.name == "b") and user.name == "z"',
      }),
    ).toThrow();

    expect(() =>
      convertEqlRule({
        source: "t",
        query:
          'process where process.name == "a" and process.command_line : "*x*" or user.name == "z"',
      }),
    ).toThrow(/mixed/i);
  });

  it("collects skips by source without throwing", () => {
    const result = importEqlRules([
      {
        source: "good.eql",
        query:
          'process where process.name == "powershell.exe"',
      },
      {
        source: "bad.eql",
        query: 'process where nope == "x"',
      },
    ]);

    expect(result.rules).toHaveLength(1);
    expect(
      result.skipped[0].source,
    ).toBe("bad.eql");
  });
});
