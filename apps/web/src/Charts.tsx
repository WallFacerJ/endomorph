import type {
  VolumeBucket,
} from "./chartData";

import "./Charts.css";

/**
 * The console's data visualisations.
 *
 * Hand-drawn SVG rather than a charting library, for the same reason the
 * icons are inline: the product ships as one self-contained file, and a
 * charting library is both a large dependency and far more than four small
 * charts need.
 *
 * They are instruments rather than illustrations. No animation, no gradients
 * for their own sake, tabular figures, and a fixed baseline -- an analyst
 * reads a shape and a magnitude off these, so the shape must not change for
 * decorative reasons.
 */

interface EventVolumeProps {
  readonly buckets: readonly VolumeBucket[];
  readonly height?: number;

  /** Describes the chart for a screen reader. */
  readonly label: string;
}

/**
 * Telemetry volume over the scenario window.
 *
 * The signature view of every log platform, and the one thing this console
 * had no equivalent of: a flat list of events gives an analyst no sense of
 * when the environment was busy, so nothing stands out as unusual by shape.
 * Buckets carrying a notable event are drawn in the alert colour on top of
 * the volume, so "when did this happen relative to everything else" is a
 * glance rather than a scroll.
 */
export function EventVolume({
  buckets,
  height = 56,
  label,
}: EventVolumeProps) {
  if (buckets.length === 0) {
    return null;
  }

  const peak = Math.max(
    1,
    ...buckets.map(
      (bucket) => bucket.total,
    ),
  );

  const width = buckets.length * 8;

  return (
    <figure
      className="chart chart-volume"
      aria-label={label}
    >
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={label}
      >
        {[0.25, 0.5, 0.75].map(
          (fraction) => (
            <line
              key={fraction}
              className="chart-grid"
              x1={0}
              x2={width}
              y1={height * fraction}
              y2={height * fraction}
            />
          ),
        )}

        {buckets.map((bucket, index) => {
          const barHeight =
            (bucket.total / peak) *
            (height - 2);

          const notableHeight =
            bucket.notable > 0
              ? Math.max(
                  3,
                  (bucket.notable / peak) *
                    (height - 2),
                )
              : 0;

          return (
            <g key={bucket.label}>
              <rect
                className="chart-bar"
                x={index * 8}
                y={height - barHeight}
                width={6}
                height={barHeight}
              />

              {notableHeight > 0 && (
                <rect
                  className="chart-bar-notable"
                  x={index * 8}
                  y={
                    height - notableHeight
                  }
                  width={6}
                  height={notableHeight}
                />
              )}
            </g>
          );
        })}

        <line
          className="chart-axis"
          x1={0}
          x2={width}
          y1={height}
          y2={height}
        />
      </svg>
    </figure>
  );
}

interface FacetDatum {
  readonly label: string;
  readonly value: number;
  readonly selected?: boolean;
  readonly onSelect?: () => void;
}

/**
 * Counts with a bar behind them.
 *
 * These were a plain two-column list of numbers, which is readable but makes
 * the reader do the comparison. The proportion is the useful part -- that
 * endpoint telemetry outweighs everything else by an order of magnitude is
 * the reason an unusual process is hard to see -- so it is drawn.
 */
export function FacetBars({
  data,
  label,
}: {
  readonly data: readonly FacetDatum[];
  readonly label: string;
}) {
  const peak = Math.max(
    1,
    ...data.map((datum) => datum.value),
  );

  return (
    <ul
      className="chart-facets"
      aria-label={label}
    >
      {data.map((datum) => {
        const content = (
          <>
            <span className="chart-facet-label">
              {datum.label}
            </span>

            <span className="chart-facet-value">
              {datum.value.toLocaleString()}
            </span>

            <span
              className="chart-facet-track"
              aria-hidden="true"
            >
              <span
                className="chart-facet-fill"
                style={{
                  width: `${(datum.value / peak) * 100}%`,
                }}
              />
            </span>
          </>
        );

        return (
          <li
            key={datum.label}
            className={
              datum.selected
                ? "chart-facet selected"
                : "chart-facet"
            }
          >
            {datum.onSelect ? (
              <button
                type="button"
                onClick={datum.onSelect}
              >
                {content}
              </button>
            ) : (
              <div>{content}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * A proportion, drawn as a segmented meter rather than a percentage.
 *
 * Coverage of five techniques out of six is a countable thing, so the meter
 * has six segments and not a continuous bar: a bar at 83% invites the reader
 * to treat it as a score, when what matters is which one is missing.
 */
export function SegmentMeter({
  covered,
  total,
  label,
}: {
  readonly covered: number;
  readonly total: number;
  readonly label: string;
}) {
  return (
    <span
      className="chart-segments"
      role="img"
      aria-label={`${label}: ${covered} of ${total}`}
    >
      {Array.from(
        { length: total },
        (_unused, index) => (
          <span
            key={index}
            className={
              index < covered
                ? "chart-segment filled"
                : "chart-segment"
            }
          />
        ),
      )}
    </span>
  );
}

/**
 * A single entity's activity over the window, at row scale.
 *
 * Small enough to sit inside a list row, which is the point: it lets an
 * inventory of 147 endpoints show which ones were busy and when, without
 * turning the list into a dashboard.
 */
export function Sparkline({
  values,
  label,
  width = 88,
  height = 20,
}: {
  readonly values: readonly number[];
  readonly label: string;
  readonly width?: number;
  readonly height?: number;
}) {
  if (values.length === 0) {
    return null;
  }

  const peak = Math.max(1, ...values);

  const step =
    values.length > 1
      ? width / (values.length - 1)
      : width;

  const points = values
    .map(
      (value, index) =>
        `${index * step},${
          height -
          (value / peak) * (height - 2) -
          1
        }`,
    )
    .join(" ");

  return (
    <svg
      className="chart-sparkline"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
    >
      <polyline
        className="chart-sparkline-line"
        points={points}
      />
    </svg>
  );
}
