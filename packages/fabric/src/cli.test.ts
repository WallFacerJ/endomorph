import {
  describe,
  expect,
  it,
} from "vitest";

import {
  parseArgs,
} from "./cli.js";

describe("parseArgs", () => {
  it("applies defaults when given nothing", () => {
    const options = parseArgs([]);

    expect(options.seed).toBe(20260820);
    expect(options.headcount).toBe(120);
    expect(options.pretty).toBe(false);
  });

  it("ignores the bare -- separator", () => {
    // Regression. `pnpm run x -- --flag` forwards the separator through to
    // the script, and the parser used to treat it as a flag awaiting a
    // value, so every documented CLI example failed with
    // "Missing value for --".
    const options = parseArgs([
      "--",
      "--seed",
      "4242",
    ]);

    expect(options.seed).toBe(4242);
  });

  it("parses every supported flag", () => {
    const options = parseArgs([
      "--seed",
      "7",
      "--headcount",
      "40",
      "--organization",
      "Northwind Health",
      "--domain",
      "northwind.test",
      "--duration-hours",
      "6",
      "--out",
      "tmp/out.json",
      "--pretty",
    ]);

    expect(options.seed).toBe(7);
    expect(options.headcount).toBe(40);
    expect(
      options.organizationName,
    ).toBe("Northwind Health");
    expect(options.domain).toBe(
      "northwind.test",
    );
    expect(options.durationHours).toBe(
      6,
    );
    expect(options.out).toBe(
      "tmp/out.json",
    );
    expect(options.pretty).toBe(true);
  });

  it("rejects an unknown flag", () => {
    expect(() =>
      parseArgs(["--nope", "1"]),
    ).toThrow(/Unknown flag/);
  });

  it("rejects a flag with no value", () => {
    expect(() =>
      parseArgs(["--seed"]),
    ).toThrow(/Missing value/);

    expect(() =>
      parseArgs([
        "--seed",
        "--headcount",
        "10",
      ]),
    ).toThrow(/Missing value/);
  });
});
