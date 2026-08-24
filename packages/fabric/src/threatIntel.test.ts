import {
  describe,
  expect,
  it,
} from "vitest";

import {
  classifyIndicators,
} from "./threatIntel.js";

describe("classifyIndicators", () => {
  it("recognises known adversary infrastructure and names its category", () => {
    const entries = classifyIndicators([
      "185.220.101.44",
      "91.219.236.18",
    ]);

    expect(
      entries.map((entry) => [
        entry.indicator,
        entry.category,
      ]),
    ).toEqual([
      ["185.220.101.44", "tor-exit"],
      [
        "91.219.236.18",
        "hosting-provider",
      ],
    ]);

    // The note is carried, not left for the console to invent.
    expect(
      entries[0].note.length,
    ).toBeGreaterThan(0);
  });

  it("says nothing about an address it does not know", () => {
    // A corporate or residential address is absent by design: the enrichment
    // only ever speaks about infrastructure it actually recognises, so it
    // cannot label an ordinary address as malicious.
    expect(
      classifyIndicators([
        "10.20.30.40",
        "8.8.8.8",
      ]),
    ).toEqual([]);
  });

  it("returns one entry per distinct address, in a stable order", () => {
    const entries = classifyIndicators([
      "193.32.127.201",
      "185.220.101.44",
      "193.32.127.201",
    ]);

    expect(
      entries.map(
        (entry) => entry.indicator,
      ),
    ).toEqual([
      "185.220.101.44",
      "193.32.127.201",
    ]);
  });
});
