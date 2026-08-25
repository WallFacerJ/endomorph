import {
  describe,
  expect,
  it,
} from "vitest";

import {
  renderCoverageBadge,
} from "./coverageBadge.js";

describe("renderCoverageBadge", () => {
  it("renders a self-contained SVG with the coverage in the label", () => {
    const svg = renderCoverageBadge({
      covered: 22,
      total: 22,
    });

    expect(svg).toContain("<svg");
    expect(svg).toContain(
      "22/22 techniques",
    );
    // Full coverage is brightgreen.
    expect(svg).toContain("#4c1");
    // No external asset that could leak a request or fail offline (the only
    // http URI is the SVG XML namespace, which is an identifier, not a fetch).
    expect(svg).not.toContain("href");
    expect(svg).not.toContain("<image");
    expect(svg).not.toContain("url(http");
  });

  it("colours by the covered ratio", () => {
    // A little under half is orange, well under is red.
    expect(
      renderCoverageBadge({
        covered: 9,
        total: 22,
      }),
    ).toContain("#fe7d37");

    expect(
      renderCoverageBadge({
        covered: 4,
        total: 22,
      }),
    ).toContain("#e05d44");
  });

  it("treats an empty benchmark as zero coverage, not a divide-by-zero", () => {
    const svg = renderCoverageBadge({
      covered: 0,
      total: 0,
    });

    expect(svg).toContain(
      "0/0 techniques",
    );
    expect(svg).toContain("#e05d44");
    expect(svg).not.toContain("NaN");
  });

  it("escapes a custom label and honours a custom value", () => {
    const svg = renderCoverageBadge({
      covered: 1,
      total: 1,
      label: "rules & <coverage>",
      value: "all good",
    });

    expect(svg).toContain(
      "rules &amp; &lt;coverage&gt;",
    );
    expect(svg).toContain("all good");
    expect(svg).not.toContain(
      "<coverage>",
    );
  });
});
