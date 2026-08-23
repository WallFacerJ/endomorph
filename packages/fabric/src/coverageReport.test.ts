import {
  describe,
  expect,
  it,
} from "vitest";

import {
  renderCoverageReport,
} from "./coverageReport.js";

import {
  ATTACK_PLANS,
} from "./attackPlanLibrary.js";

import type {
  DetectionReport,
} from "./detectionReport.js";

function reportWith(
  plans: DetectionReport["plans"],
): DetectionReport {
  return {
    generator: "endomorph-fabric",
    seed: 20260820,
    ruleCount: 3,
    plans,
    totals: {
      coveredTechniques: 0,
      totalTechniques: 0,
      truePositives: 0,
      falsePositives: 0,
    },
  };
}

describe("renderCoverageReport", () => {
  it("counts a technique as covered only if some incident caught it", () => {
    /*
      A ruleset that catches credential dumping in one incident and misses it
      in another has not covered credential dumping. Reporting per-plan
      coverage separately would let a ruleset look better than it is, and
      this is the number a client quotes back.
    */
    const html = renderCoverageReport({
      report: reportWith([
        {
          planId: "a",
          planName: "Incident A",
          recordCount: 10,
          maliciousCount: 2,
          coveredTechniques: ["T1003.001"],
          uncoveredTechniques: [],
          rules: [],
        },
        {
          planId: "b",
          planName: "Incident B",
          recordCount: 10,
          maliciousCount: 2,
          coveredTechniques: [],
          uncoveredTechniques: ["T1003.001"],
          rules: [],
        },
      ]),
      plans: ATTACK_PLANS,
      rulesetName: "Test ruleset",
      generatedAt: "2026-08-23",
    });

    // Caught in one of the two, so covered -- and named in both incidents.
    expect(html).toContain(
      "1 / 1",
    );

    expect(html).toContain(
      "Incident A, Incident B",
    );
  });

  it("names every technique nothing caught", () => {
    const html = renderCoverageReport({
      report: reportWith([
        {
          planId: "a",
          planName: "Incident A",
          recordCount: 10,
          maliciousCount: 2,
          coveredTechniques: [],
          uncoveredTechniques: [
            "T1003.001",
            "T1566.001",
          ],
          rules: [],
        },
      ]),
      plans: ATTACK_PLANS,
      rulesetName: "Test ruleset",
      generatedAt: "2026-08-23",
    });

    expect(html).toContain(
      "2 technique(s) went undetected",
    );

    expect(html).toContain(
      "OS Credential Dumping: LSASS Memory",
    );
  });

  it("ranks rules by what they cost in noise", () => {
    // The number an analyst pays for is attention, so the rule that produced
    // the most false positives leads regardless of how many it caught.
    const html = renderCoverageReport({
      report: reportWith([
        {
          planId: "a",
          planName: "Incident A",
          recordCount: 10,
          maliciousCount: 2,
          coveredTechniques: [],
          uncoveredTechniques: [],
          rules: [
            {
              ruleId: "quiet-rule",
              truePositives: 1,
              falsePositives: 0,
              falseNegatives: 0,
              precision: 1,
              recall: 1,
            },
            {
              ruleId: "loud-rule",
              truePositives: 1,
              falsePositives: 900,
              falseNegatives: 0,
              precision: 0.001,
              recall: 1,
            },
          ],
        },
      ]),
      plans: ATTACK_PLANS,
      rulesetName: "Test ruleset",
      generatedAt: "2026-08-23",
    });

    expect(
      html.indexOf("loud-rule"),
    ).toBeLessThan(
      html.indexOf("quiet-rule"),
    );
  });

  it("escapes anything that came from a rule name", () => {
    /*
      Rule ids and ruleset names arrive from a client's own files. A report
      that renders them raw would execute whatever a rule author put in a
      title, on the machine of whoever opened the deliverable.
    */
    const html = renderCoverageReport({
      report: reportWith([
        {
          planId: "a",
          planName: "Incident A",
          recordCount: 10,
          maliciousCount: 2,
          coveredTechniques: [],
          uncoveredTechniques: [],
          rules: [
            {
              ruleId:
                "<script>alert(1)</script>",
              truePositives: 0,
              falsePositives: 1,
              falseNegatives: 0,
              precision: 0,
              recall: 0,
            },
          ],
        },
      ]),
      plans: ATTACK_PLANS,
      rulesetName:
        '"><script>alert(2)</script>',
      generatedAt: "2026-08-23",
    });

    expect(html).not.toContain(
      "<script>alert(1)</script>",
    );

    expect(html).not.toContain(
      "<script>alert(2)</script>",
    );

    expect(html).toContain(
      "&lt;script&gt;",
    );
  });

  it("carries the seed so the measurement can be reproduced", () => {
    // The claim the report makes about itself: run the same seed, get the
    // same numbers, so a difference is a rule change and not sampling.
    const html = renderCoverageReport({
      report: reportWith([]),
      plans: ATTACK_PLANS,
      rulesetName: "Test ruleset",
      generatedAt: "2026-08-23",
    });

    expect(html).toContain("20260820");
  });
});
