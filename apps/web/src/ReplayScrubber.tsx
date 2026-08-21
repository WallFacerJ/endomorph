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
 */

export interface ReplayMarker {
  /** Index into the event stream. */
  readonly index: number;
  readonly label: string;
  readonly eventId: string;
}

export interface ReplayScrubberProps {
  totalEvents: number;

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
    return "—";
  }

  return `${timestamp.slice(0, 10)} ${timestamp.slice(11, 19)}`;
}

export function ReplayScrubber({
  totalEvents,
  position,
  renderedPosition,
  timestamp,
  markers,
  onScrub,
}: ReplayScrubberProps) {
  const live = position === null;

  const current = position ?? totalEvents;

  const previousMarker = [...markers]
    .reverse()
    .find(
      (marker) => marker.index < current,
    );

  const nextMarker = markers.find(
    (marker) => marker.index > current,
  );

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
          aria-label="Previous incident step"
          title="Previous incident step"
          disabled={!previousMarker}
          onClick={() =>
            onScrub(
              previousMarker?.index ??
                0,
            )
          }
        >
          &#9664;&#9664;
        </button>

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

        <button
          type="button"
          aria-label="Next incident step"
          title="Next incident step"
          disabled={!nextMarker}
          onClick={() =>
            onScrub(nextMarker?.index ?? null)
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
