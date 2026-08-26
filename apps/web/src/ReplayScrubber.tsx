import "./ReplayScrubber.css";

/**
 * Point-in-time replay across every console.
 *
 * This is what the architecture was built for. Because history is an
 * append-only event log and every console is a pure projection of it,
 * "what did this look like at 14:32" is answered by replaying a prefix --
 * no snapshots, no separate storage, no special-casing per tool.
 *
 * The scrub position drives the SIEM, endpoint, identity, and case views
 * simultaneously, so an analyst can rewind past the alert and watch the
 * intrusion arrive rather than reconstructing it backwards from the end.
 *
 * Response actions are disabled while rewound. Acting on a past state would
 * either rewrite history or silently apply to the present, and both are
 * worse than refusing.
 *
 * The transport jumps between incident steps only when it is given markers,
 * which happens for an instructor. Those markers are ground truth: with them
 * the buttons walk an analyst through every attacker action in order, which
 * is exactly the answer the exercise is asking for. Without them the same
 * buttons step by a slice of the stream, so rewinding stays useful without
 * telling anyone where to look.
 */

export interface ReplayMarker {
  /** Index into the event stream. */
  readonly index: number;
  readonly label: string;
  readonly eventId: string;
}

export interface ReplayScrubberProps {
  totalEvents: number;

  /**
   * Event density across the run, one value per slice.
   *
   * The track was a flat bar, so dragging it gave no sense of what was being
   * scrubbed past, 12,000 events and 200 look identical on a plain range
   * input. The density is the environment's working rhythm, which is what
   * makes a quiet stretch or a burst worth stopping on.
   */
  density?: readonly number[];

  /** Current position, or null when following the live end of history. */
  position: number | null;

  /** Position actually rendered, which may lag during a fast scrub. */
  renderedPosition: number;

  timestamp: string | undefined;

  markers: readonly ReplayMarker[];

  onScrub: (position: number | null) => void;
}

function formatTime(
  timestamp: string | undefined,
): string {
  if (!timestamp) {
    return ", ";
  }

  return `${timestamp.slice(0, 10)} ${timestamp.slice(11, 19)}`;
}

export function ReplayScrubber({
  totalEvents,
  density = [],
  position,
  renderedPosition,
  timestamp,
  markers,
  onScrub,
}: ReplayScrubberProps) {
  const live = position === null;

  const current = position ?? totalEvents;

  const guided = markers.length > 0;

  // A tenth of the run: far enough to move, small enough not to skip past
  // whatever the analyst was reading.
  const stride = Math.max(
    1,
    Math.round(totalEvents / 10),
  );

  const previousIndex = guided
    ? [...markers]
        .reverse()
        .find(
          (marker) =>
            marker.index < current,
        )?.index
    : current > 0
      ? Math.max(0, current - stride)
      : undefined;

  const nextIndex = guided
    ? markers.find(
        (marker) => marker.index > current,
      )?.index
    : current < totalEvents
      ? Math.min(
          totalEvents,
          current + stride,
        )
      : undefined;

  const backLabel = guided
    ? "Previous incident step"
    : "Rewind";

  const forwardLabel = guided
    ? "Next incident step"
    : "Advance";

  const settling =
    !live && renderedPosition !== current;

  return (
    <div
      className={
        live
          ? "replay"
          : "replay rewound"
      }
      role="region"
      aria-label="Replay"
    >
      <div className="replay-status">
        <span className="replay-badge">
          {live
            ? "Live"
            : "Viewing history"}
        </span>

        <span className="replay-clock">
          {formatTime(timestamp)}
        </span>

        <span className="replay-count">
          {current.toLocaleString()} /{" "}
          {totalEvents.toLocaleString()}{" "}
          events
          {settling ? " · settling" : ""}
        </span>
      </div>

      <div className="replay-transport">
        <button
          type="button"
          aria-label={backLabel}
          title={backLabel}
          disabled={
            previousIndex === undefined
          }
          onClick={() =>
            onScrub(previousIndex ?? 0)
          }
        >
          &#9664;&#9664;
        </button>

        <span className="replay-track">
          {density.length > 0 && (
            <span
              className="replay-density"
              aria-hidden="true"
            >
              {density.map(
                (value, index) => (
                  <span
                    key={index}
                    style={{
                      height: `${Math.max(
                        6,
                        (value /
                          Math.max(
                            1,
                            ...density,
                          )) *
                          100,
                      )}%`,
                    }}
                  />
                ),
              )}
            </span>
          )}

          <input
          type="range"
          className="replay-range"
          aria-label="Replay position"
          min={0}
          max={totalEvents}
          value={current}
          onChange={(event) => {
            const next = Number(
              event.target.value,
            );

            onScrub(
              next >= totalEvents
                ? null
                : next,
            );
          }}
          />
        </span>

        <button
          type="button"
          aria-label={forwardLabel}
          title={forwardLabel}
          disabled={
            nextIndex === undefined
          }
          onClick={() =>
            onScrub(
              nextIndex === undefined ||
                nextIndex >= totalEvents
                ? null
                : nextIndex,
            )
          }
        >
          &#9654;&#9654;
        </button>

        <button
          type="button"
          className="replay-live"
          disabled={live}
          onClick={() => onScrub(null)}
        >
          Return to now
        </button>
      </div>

      {!live && (
        <p className="replay-notice">
          Every console is showing this
          moment. Response actions are
          disabled until you return to
          now.
        </p>
      )}
    </div>
  );
}
