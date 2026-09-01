import {
  describe,
  expect,
  it,
} from "vitest";

import {
  convertYaralRule,
  importYaralRules,
} from "./yaral.js";

const block = (body: string) => ({
  name: "test_rule",
  body,
});

describe("convertYaralRule", () => {
  it("maps UDM predicates to selections and translates the event type", () => {
    const rule = convertYaralRule(
      block(`
        meta:
          author = "sec"
          mitre = "T1003.006"
        events:
          $e.metadata.event_type = "PROCESS_LAUNCH"
          $e.principal.process.command_line = /dcsync/ nocase
        condition:
          $e
      `),
    );

    expect(rule.name).toBe("test_rule");
    expect(rule.technique).toBe("T1003.006");
    expect(rule.selections).toEqual([
      {
        // PROCESS_LAUNCH is translated onto the corpus's own event type.
        "event.type": "PROCESS_STARTED",
        "process.command_line": {
          regex: "dcsync",
        },
      },
    ]);
  });

  it("passes a native event type through untranslated", () => {
    const rule = convertYaralRule(
      block(`
        events:
          $e.metadata.event_type = "DNS_QUERY"
          $e.network.dns.questions.name = /\\.xyz$/
        condition:
          $e
      `),
    );

    expect(
      rule.selections[0]["event.type"],
    ).toBe("DNS_QUERY");
  });

  it("maps a != predicate to an exclusion", () => {
    const rule = convertYaralRule(
      block(`
        events:
          $e.principal.process.command_line = /rundll32/
          $e.principal.user.userid != "SYSTEM"
        condition:
          $e
      `),
    );

    expect(rule.exclusions).toEqual([
      { "account.name": "SYSTEM" },
    ]);
  });

  it("maps a top-level or to anySelections", () => {
    const rule = convertYaralRule(
      block(`
        events:
          $e.principal.process.command_line = /mimikatz/ or $e.principal.process.command_line = /rubeus/
        condition:
          $e
      `),
    );

    expect(rule.selections).toEqual([]);
    expect(rule.anySelections).toEqual([
      {
        "process.command_line": {
          regex: "mimikatz",
        },
      },
      {
        "process.command_line": {
          regex: "rubeus",
        },
      },
    ]);
  });

  it("refuses a UDM event type with no faithful equivalent", () => {
    expect(() =>
      convertYaralRule(
        block(`
          events:
            $e.metadata.event_type = "SCAN_VULN_HOST"
          condition:
            $e
        `),
      ),
    ).toThrow(/no faithful equivalent/);
  });

  it("refuses an unmapped UDM field", () => {
    expect(() =>
      convertYaralRule(
        block(`
          events:
            $e.principal.process.nonexistent = "x"
          condition:
            $e
        `),
      ),
    ).toThrow(/Unmapped UDM field/);
  });

  it("refuses a multi-event aggregating condition", () => {
    expect(() =>
      convertYaralRule(
        block(`
          events:
            $e.metadata.event_type = "PROCESS_LAUNCH"
          condition:
            #e > 5
        `),
      ),
    ).toThrow(/single event variable/);
  });

  it("refuses grouping parentheses", () => {
    expect(() =>
      convertYaralRule(
        block(`
          events:
            ($e.principal.process.command_line = /a/ or $e.principal.process.command_line = /b/)
          condition:
            $e
        `),
      ),
    ).toThrow(/parentheses/);
  });
});

describe("importYaralRules", () => {
  it("extracts every rule block in one document", () => {
    const result = importYaralRules([
      {
        source: "repo.yaral",
        text: `
          rule kerberoast {
            events:
              $e.principal.process.command_line = /Invoke-Kerberoast/
            condition:
              $e
          }
          rule dcsync {
            events:
              $e.principal.process.command_line = /lsadump::dcsync/
            condition:
              $e
          }
        `,
      },
    ]);

    expect(result.rules).toHaveLength(2);
    expect(
      result.rules.map((rule) => rule.name),
    ).toEqual(["kerberoast", "dcsync"]);
    expect(result.skipped).toHaveLength(0);
  });

  it("collects a skip by source and title without throwing", () => {
    const result = importYaralRules([
      {
        source: "bad.yaral",
        text: `
          rule broken {
            events:
              $e.principal.process.command_line > 5
            condition:
              $e
          }
        `,
      },
    ]);

    expect(result.rules).toHaveLength(0);
    expect(result.skipped[0].title).toBe(
      "broken",
    );
  });
});
