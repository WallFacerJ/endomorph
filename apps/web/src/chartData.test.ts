import {
  describe,
  expect,
  it,
} from "vitest";

import {
  bucketByTime,
} from "./chartData";

describe("bucketByTime", () => {
  it("returns nothing for no timestamps", () => {
    expect(
      bucketByTime([], []),
    ).toEqual([]);
  });

  it("counts every timestamp into a bucket", () => {
    const day = "2026-08-20T";
    const times = [
      `${day}08:00:00.000Z`,
      `${day}09:00:00.000Z`,
      `${day}10:00:00.000Z`,
      `${day}17:00:00.000Z`,
    ];

    const buckets = bucketByTime(
      times,
      [times[3]],
      8,
    );

    expect(buckets.length).toBe(8);

    const total = buckets.reduce(
      (sum, bucket) =>
        sum + bucket.total,
      0,
    );

    const notable = buckets.reduce(
      (sum, bucket) =>
        sum + bucket.notable,
      0,
    );

    expect(total).toBe(4);
    expect(notable).toBe(1);
  });

  it("collides bucket labels on a narrow window, which is why the chart keys by index not label", () => {
    /*
      The regression behind Charts keying by position. When the whole event
      window is a single millisecond, every bucket's left-edge timestamp
      rounds to the same ISO string, so the labels are not unique. A chart
      that used the label as its React key saw duplicate keys and warned; the
      fix lives in the component, and this records why it is needed rather
      than leaving it looking arbitrary.
    */
    const instant =
      "2026-08-20T15:01:00.000Z";

    const buckets = bucketByTime(
      [instant, instant, instant],
      [],
      48,
    );

    const labels = new Set(
      buckets.map(
        (bucket) => bucket.label,
      ),
    );

    // Far fewer distinct labels than buckets: the collision is real.
    expect(
      labels.size,
    ).toBeLessThan(buckets.length);

    // The counts are still correct despite the collision -- only identity,
    // not data, was ever at risk.
    expect(
      buckets.reduce(
        (sum, bucket) =>
          sum + bucket.total,
        0,
      ),
    ).toBe(3);
  });
});
