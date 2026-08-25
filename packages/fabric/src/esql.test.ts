import {
  describe,
  expect,
  it,
} from "vitest";

import {
  convertEsqlRule,
  importEsqlRules,
} from "./esql.js";

describe("convertEsqlRule", () => {
  it("maps a WHERE clause to selections, LIKE wildcards to substring matchers", () => {
    const rule = convertEsqlRule({
      source: "test",
      query:
        '// title: Encoded PowerShell\n// technique: T1059.001\nFROM logs-*\n| WHERE process.name == "powershell.exe" AND process.command_line LIKE "*-enc*"',
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

  it("reads a trailing LIKE wildcard as a prefix match", () => {
    const rule = convertEsqlRule({
      source: "t",
      query:
        'FROM x | WHERE process.name LIKE "powershell*"',
    });

    expect(
      rule.selections[0][
        "process.executable"
      ],
    ).toEqual({ startsWith: "powershell" });
  });

  it("drops the FROM source and reads a numeric value as a number", () => {
    const rule = convertEsqlRule({
      source: "t",
      query:
        "FROM traffic | WHERE destination.port == 443",
    });

    expect(rule.selections[0]).toEqual({
      "destination.port": 443,
    });
  });

  it("maps RLIKE to a regex matcher", () => {
    const rule = convertEsqlRule({
      source: "t",
      query:
        'FROM dns | WHERE dns.question.name RLIKE ".{50,}"',
    });

    expect(
      rule.selections[0][
        "dns.question.name"
      ],
    ).toEqual({ regex: ".{50,}" });
  });

  it("turns an IN list into an equals-any matcher", () => {
    const rule = convertEsqlRule({
      source: "t",
      query:
        'FROM x | WHERE event.outcome IN ("success", "failure")',
    });

    expect(
      rule.selections[0]["event.outcome"],
    ).toEqual({
      anyOf: ["success", "failure"],
    });
  });

  it("maps a top-level OR to anySelections", () => {
    const rule = convertEsqlRule({
      source: "t",
      query:
        'FROM x | WHERE process.name == "a.exe" OR process.name == "b.exe"',
    });

    expect(rule.anySelections).toEqual([
      { "process.executable": "a.exe" },
      { "process.executable": "b.exe" },
    ]);
  });

  it("maps a != predicate to an exclusion", () => {
    const rule = convertEsqlRule({
      source: "t",
      query:
        'FROM x | WHERE process.command_line LIKE "*-enc*" AND user.name != "svc-backup"',
    });

    expect(rule.exclusions).toEqual([
      { "account.name": "svc-backup" },
    ]);
  });

  it("refuses a transforming STATS command", () => {
    expect(() =>
      convertEsqlRule({
        source: "t",
        query:
          'FROM x | WHERE process.name == "a" | STATS count = COUNT(*) BY host.name',
      }),
    ).toThrow(/stats/i);
  });

  it("refuses an unmapped field and a numeric range", () => {
    expect(() =>
      convertEsqlRule({
        source: "t",
        query: 'FROM x | WHERE made.up == "y"',
      }),
    ).toThrow(/Unmapped field/);

    expect(() =>
      convertEsqlRule({
        source: "t",
        query:
          "FROM x | WHERE process.pid > 1000",
      }),
    ).toThrow(/comparison/i);
  });

  it("refuses a query with no WHERE", () => {
    expect(() =>
      convertEsqlRule({
        source: "t",
        query:
          "FROM x | STATS count = COUNT(*)",
      }),
    ).toThrow();
  });

  it("collects skips by source without throwing", () => {
    const result = importEsqlRules([
      {
        source: "good.esql",
        query:
          'FROM x | WHERE process.name == "powershell.exe"',
      },
      {
        source: "bad.esql",
        query: 'FROM x | WHERE nope == "y"',
      },
    ]);

    expect(result.rules).toHaveLength(1);
    expect(
      result.skipped[0].source,
    ).toBe("bad.esql");
  });
});
