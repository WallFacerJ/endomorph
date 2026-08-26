import {
  useMemo,
  useState,
} from "react";

import {
  searchSiem,
} from "./simulationAdapter";

import type {
  AssetContext,
  AssetCriticality,
  ThreatIntelEntry,
  SiemEventRecord,
} from "./simulationAdapter";

import {
  EventVolume,
  FacetBars,
} from "./Charts";

import {
  bucketByTime,
} from "./chartData";

import type {
  WorldState,
} from "./simulationAdapter";

import {
  Icon,
} from "./Icon";

import {
  describeQueryBaseline,
  summariseQueryBaseline,
} from "./queryBaseline";

import "./SiemWorkspace.css";

/** Rows rendered at once. Matches are still counted and faceted in full. */
const RESULT_PAGE_SIZE = 200;

interface SiemWorkspaceProps {
  /**
   * The world, for showing names rather than identifiers.
   *
   * The subject column printed "device-hr-lt-028" where the rest of the
   * product, the alert, the endpoint console, the questions, all say
   * "HR-LT-028". Pivoting between consoles means recognising the same entity
   * in each, and a different spelling in every view is exactly the friction
   * that makes it feel like a different system each time.
   */
  world: WorldState;

  records: readonly SiemEventRecord[];

  /**
   * Business context per entity, when the scenario carries it. Used to flag
   * the results that touch a consequential asset, so an analyst scanning two
   * hundred rows sees which of them involve a crown jewel rather than
   * treating every subject as equal weight.
   */
  assets?: readonly AssetContext[];

  /**
   * Reputation for external indicators, when the scenario carries it. Used to
   * annotate a classified address where the analyst inspects it, so an
   * external IP in a record reads as "and here is what kind of external".
   */
  threatIntel?: readonly ThreatIntelEntry[];
  initialQuery?: string;
  finalized: boolean;
  isCollected: (eventId: string) => boolean;
  onCollect: (eventId: string) => void;
  onOpenCase: () => void;
}

type TimePreset =
  | "all"
  | "5m"
  | "15m";

/**
 * Only the top two tiers are worth a mark in a result table. Flagging every
 * moderate and low asset would paint most rows and draw the eye to nothing;
 * the point is to make the crown-jewel rows stand out of the scan.
 */
const FLAGGED_CRITICALITY:
  ReadonlySet<AssetCriticality> = new Set([
    "severe",
    "high",
  ]);

const CRITICALITY_RANK: Record<
  AssetCriticality,
  number
> = {
  severe: 3,
  high: 2,
  moderate: 1,
  low: 0,
};

const CRITICALITY_LABEL: Record<
  AssetCriticality,
  string
> = {
  severe: "Severe",
  high: "High",
  moderate: "Moderate",
  low: "Low",
};

function quoteValue(value: string): string {
  return /\s/.test(value)
    ? `"${value.replaceAll('"', '\\"')}"`
    : value;
}

/*
  Constructed once. Building an Intl.DateTimeFormat is expensive, and this was
  building a fresh one for every timestamp rendered, which, on a scenario
  with twenty thousand events, was three seconds of the finalize interaction
  by itself, more than any other single thing the app did.
*/
const CLOCK_FORMAT =
  new Intl.DateTimeFormat(
    "en-US",
    {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    },
  );

function formatTimestamp(
  timestamp: string,
): string {
  return CLOCK_FORMAT.format(
    new Date(timestamp),
  );
}

function getStartTime(
  records: readonly SiemEventRecord[],
  preset: TimePreset,
): string | undefined {
  if (preset === "all" || records.length === 0) {
    return undefined;
  }

  const latest = Math.max(
    ...records.map((record) =>
      Date.parse(record.timestamp),
    ),
  );
  const minutes = preset === "5m"
    ? 5
    : 15;

  return new Date(
    latest - minutes * 60_000,
  ).toISOString();
}

function fieldDisplayValue(
  value: string | number | readonly string[],
): string {
  return Array.isArray(value)
    ? value.join(", ")
    : String(value);
}

export function SiemWorkspace({
  world,
  records,
  assets,
  threatIntel,
  initialQuery,
  finalized,
  isCollected,
  onCollect,
  onOpenCase,
}: SiemWorkspaceProps) {
  const [query, setQuery] = useState(initialQuery ?? "");
  const [timePreset, setTimePreset] =
    useState<TimePreset>("all");
  const [selectedEventId, setSelectedEventId] =
    useState<string | null>(null);
  const [savedQueries, setSavedQueries] =
    useState<string[]>([]);

  const result = useMemo(
    () => searchSiem(records, {
      query,
      startTime: getStartTime(
        records,
        timePreset,
      ),
      order: "desc",
    }),
    [records, query, timePreset],
  );

  // A generated enterprise produces tens of thousands of records. Rendering
  // a row per match locked the workspace for several seconds; capping the
  // rendered page is also how a real SIEM behaves, and it reinforces that
  // the tool is for querying rather than scrolling.
  const visibleRecords = useMemo(
    () =>
      result.records.slice(
        0,
        RESULT_PAGE_SIZE,
      ),
    [result],
  );

  /*
    Bucketed from the matched records rather than from all telemetry, so it
    reflects the query and not the corpus.
  */
  /*
    One lookup for every kind of entity a subject id can name. Built once
    from the world rather than per row, which matters at two hundred rows.
  */
  const entityNames = useMemo(() => {
    const names = new Map<
      string,
      string
    >();

    for (const device of Object.values(
      world.devices,
    )) {
      names.set(
        device.id,
        device.hostname,
      );
    }

    for (const account of Object.values(
      world.accounts,
    )) {
      names.set(
        account.id,
        account.username,
      );
    }

    for (const user of Object.values(
      world.users,
    )) {
      names.set(
        user.id,
        user.displayName,
      );
    }

    for (const file of Object.values(
      world.files,
    )) {
      names.set(file.id, file.name);
    }

    return names;
  }, [world]);

  const assetByEntityId = useMemo(
    () =>
      new Map(
        (assets ?? []).map(
          (asset) =>
            [
              asset.entityId,
              asset,
            ] as const,
        ),
      ),
    [assets],
  );

  const threatByIndicator = useMemo(
    () =>
      new Map(
        (threatIntel ?? []).map(
          (entry) =>
            [
              entry.indicator,
              entry,
            ] as const,
        ),
      ),
    [threatIntel],
  );

  /*
    The most critical asset a row touches, across its subject and every
    related entity, but only when that reaches a tier worth flagging. A row
    can name a device in its subject and an account in its relations; the one
    that matters for triage is whichever is most consequential.
  */
  const flaggedCriticality = (
    record: SiemEventRecord,
  ): AssetContext | undefined => {
    const candidates = [
      record.subjectId,
      ...record.relatedEntityIds,
    ];

    let top: AssetContext | undefined;

    for (const id of candidates) {
      if (!id) {
        continue;
      }

      const asset =
        assetByEntityId.get(id);

      if (
        !asset ||
        !FLAGGED_CRITICALITY.has(
          asset.criticality,
        )
      ) {
        continue;
      }

      if (
        !top ||
        CRITICALITY_RANK[
          asset.criticality
        ] >
          CRITICALITY_RANK[
            top.criticality
          ]
      ) {
        top = asset;
      }
    }

    return top;
  };

  /*
    How normal this result is. The scenarios ask for exactly this in their
    reasoning, has the account used this address before, has it ever
    touched this document, and the only way to answer it was to scroll.
  */
  const baseline = useMemo(
    () =>
      summariseQueryBaseline(
        result.records,
        records,
      ),
    [result.records, records],
  );

  const resultVolume = useMemo(
    () =>
      bucketByTime(
        result.records.map(
          (record) => record.timestamp,
        ),
        result.records
          .filter(
            (record) =>
              record.eventType ===
              "ALERT_CREATED",
          )
          .map(
            (record) => record.timestamp,
          ),
        56,
      ),
    [result.records],
  );

  const selectedRecord =
    result.records.find(
      (record) =>
        record.eventId === selectedEventId,
    ) ??
    records.find(
      (record) =>
        record.eventId === selectedEventId,
    );

  const addFilter = (
    field: string,
    value: string,
  ) => {
    const filter =
      `${field}:${quoteValue(value)}`;

    setQuery((current) =>
      current.trim()
        ? `${current.trim()} ${filter}`
        : filter,
    );
  };

  const saveQuery = () => {
    const normalized = query.trim();

    if (
      !normalized ||
      savedQueries.includes(normalized)
    ) {
      return;
    }

    setSavedQueries((current) => [
      ...current,
      normalized,
    ]);
  };

  return (
    <div
      className="siem-workspace"
      role="region"
      aria-label="SIEM search workspace"
    >
      <section className="siem-search-panel">
        <div className="siem-search-heading">
          <div>
            <p className="eyebrow">
              Endomorph Ops / SIEM
            </p>
            <h3>
              <Icon name="search" size={17} />
              Search security telemetry
            </h3>
            <p>
              Search shared identity, endpoint, network, session, and detection telemetry. Use field filters such as <code>family:process</code>, <code>accountId:account-smartinez</code>, or <code>destinationIp:203.0.113.77</code>.
            </p>
          </div>
          <div className="siem-result-count">
            <strong>
              {result.total.toLocaleString()}
            </strong>
            <span>matching events</span>
          </div>
        </div>

        <div className="siem-query-row">
          <label className="siem-query-field">
            <span>Query</span>
            <input
              aria-label="SIEM query"
              value={query}
              onChange={(event) =>
                setQuery(event.target.value)
              }
              placeholder='Try: sourceIp:185.220.101.42 or "powershell"'
              spellCheck={false}
            />
          </label>

          <label className="siem-time-field">
            <span>Time range</span>
            <select
              aria-label="SIEM time range"
              value={timePreset}
              onChange={(event) =>
                setTimePreset(
                  event.target.value as TimePreset,
                )
              }
            >
              <option value="all">All time</option>
              <option value="15m">Last 15 minutes</option>
              <option value="5m">Last 5 minutes</option>
            </select>
          </label>

          <button
            type="button"
            className="secondary-button siem-save-query"
            onClick={saveQuery}
            disabled={!query.trim()}
          >
            Save query
          </button>
        </div>

        {savedQueries.length > 0 && (
          <div
            className="siem-saved-queries"
            role="region"
            aria-label="Saved SIEM queries"
          >
            <span>Saved</span>
            {savedQueries.map((savedQuery) => (
              <button
                key={savedQuery}
                type="button"
                onClick={() =>
                  setQuery(savedQuery)
                }
              >
                {savedQuery}
              </button>
            ))}
          </div>
        )}
      </section>

      <div className="siem-layout">
        <aside
          className="siem-facets"
          aria-label="SIEM facets"
        >
          <div className="siem-facet-group">
            <span className="siem-facet-title">
              Event family
            </span>
            {/*
              A count with a bar rather than a bare number: the
              proportion is the point. That endpoint telemetry
              outweighs everything else by an order of magnitude is
              exactly why one unusual process is hard to find, and a
              column of digits makes the reader work that out.
            */}
            <FacetBars
              label={`Filter by ${"family"}`}
              data={result.facets.families.map(
                (facet) => ({
                  label: facet.value,
                  value: facet.count,
                  onSelect: () =>
                    addFilter(
                      "family",
                      facet.value,
                    ),
                }),
              )}
            />
          </div>

          <div className="siem-facet-group">
            <span className="siem-facet-title">
              Source
            </span>
            {/*
              A count with a bar rather than a bare number: the
              proportion is the point. That endpoint telemetry
              outweighs everything else by an order of magnitude is
              exactly why one unusual process is hard to find, and a
              column of digits makes the reader work that out.
            */}
            <FacetBars
              label={`Filter by ${"source"}`}
              data={result.facets.sources.map(
                (facet) => ({
                  label: facet.value,
                  value: facet.count,
                  onSelect: () =>
                    addFilter(
                      "source",
                      facet.value,
                    ),
                }),
              )}
            />
          </div>

          {result.facets.severities.length > 0 && (
            <div className="siem-facet-group">
              <span className="siem-facet-title">
                Severity
              </span>
              {/*
              A count with a bar rather than a bare number: the
              proportion is the point. That endpoint telemetry
              outweighs everything else by an order of magnitude is
              exactly why one unusual process is hard to find, and a
              column of digits makes the reader work that out.
            */}
            <FacetBars
              label={`Filter by ${"severity"}`}
              data={result.facets.severities.map(
                (facet) => ({
                  label: facet.value,
                  value: facet.count,
                  onSelect: () =>
                    addFilter(
                      "severity",
                      facet.value,
                    ),
                }),
              )}
            />
            </div>
          )}
        </aside>

        <section className="siem-results-panel">
          {/*
            A histogram over the current result set, which every log platform
            puts here and this one had no equivalent of. It answers the
            question a table of the first two hundred rows cannot: when did
            the matches happen, and are they spread across the window or
            clustered. Narrowing a query redraws it, so the shape is feedback
            on the search rather than a fixed picture of the corpus.
          */}
          {resultVolume.length > 0 && (
            <div className="siem-volume">
              <div className="siem-volume-head">
                <span className="t-label">
                  {result.total.toLocaleString()}{" "}
                  matches over time
                </span>

                {baseline && (
                  <span
                    className={
                      baseline.onlyToday
                        ? "siem-baseline new"
                        : "siem-baseline"
                    }
                  >
                    <Icon
                      name={
                        baseline.onlyToday
                          ? "warning"
                          : "chart"
                      }
                      size={13}
                    />
                    {describeQueryBaseline(
                      baseline,
                    )}
                  </span>
                )}
              </div>

              <EventVolume
                buckets={resultVolume}
                height={44}
                label="Matching events over the search window"
              />
            </div>
          )}

          <div className="siem-table-wrap">
            <table className="siem-results-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Family</th>
                  <th>Event</th>
                  <th>Subject</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {visibleRecords.map((record) => (
                  <tr
                    key={record.eventId}
                    className={
                      selectedEventId === record.eventId
                        ? "selected"
                        : undefined
                    }
                    onClick={() =>
                      setSelectedEventId(record.eventId)
                    }
                  >
                    <td className="siem-time-cell">
                      {formatTimestamp(record.timestamp)}
                    </td>
                    <td>{record.source}</td>
                    <td>
                      <button
                        type="button"
                        className="siem-inline-filter"
                        onClick={(event) => {
                          event.stopPropagation();
                          addFilter(
                            "family",
                            record.family,
                          );
                        }}
                      >
                        {record.family}
                      </button>
                    </td>
                    <td>
                      <code>{record.eventType}</code>
                    </td>
                    <td>
                      {(() => {
                        const asset =
                          flaggedCriticality(
                            record,
                          );

                        return asset ? (
                          <span
                            className={`siem-criticality-dot siem-criticality-${asset.criticality}`}
                            title={`${CRITICALITY_LABEL[asset.criticality]} asset: ${asset.rationale}`}
                            aria-label={`${CRITICALITY_LABEL[asset.criticality]} criticality asset`}
                          />
                        ) : null;
                      })()}
                      {(record.subjectId &&
                        entityNames.get(
                          record.subjectId,
                        )) ??
                        record.subjectId ??
                        ", "}
                    </td>
                    <td className="siem-message-cell">
                      {record.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {result.total >
              visibleRecords.length && (
              <p className="siem-truncation-notice">
                Showing the first{" "}
                <strong>
                  {visibleRecords.length}
                </strong>{" "}
                of{" "}
                <strong>
                  {result.total}
                </strong>{" "}
                matching events. Narrow
                the query or time range to
                bring the set into view.
              </p>
            )}

            {result.records.length === 0 && (
              <div className="siem-empty-state">
                No telemetry matches this query and time range.
              </div>
            )}
          </div>
        </section>

        <aside
          className="siem-event-detail"
          aria-label="SIEM event detail"
        >
          {!selectedRecord ? (
            <div className="siem-detail-empty">
              <p className="eyebrow">Event detail</p>
              <strong>Select a result</strong>
              <p>
                Inspect normalized fields, pivot into values, and preserve relevant events as case evidence.
              </p>
            </div>
          ) : (
            <>
              <div className="siem-detail-header">
                <div>
                  <p className="eyebrow">Event detail</p>
                  <strong>{selectedRecord.eventType}</strong>
                  <small>{selectedRecord.eventId}</small>
                </div>
                <button
                  type="button"
                  className="evidence-button"
                  disabled={
                    finalized ||
                    isCollected(selectedRecord.eventId)
                  }
                  onClick={() =>
                    onCollect(selectedRecord.eventId)
                  }
                >
                  {isCollected(selectedRecord.eventId)
                    ? "Evidence collected"
                    : finalized
                      ? "Run finalized"
                      : "Collect evidence"}
                </button>
              </div>

              <dl className="siem-core-fields">
                <div>
                  <dt>Timestamp</dt>
                  <dd>{selectedRecord.timestamp}</dd>
                </div>
                <div>
                  <dt>Source</dt>
                  <dd>
                    <button
                      type="button"
                      onClick={() =>
                        addFilter(
                          "source",
                          selectedRecord.source,
                        )
                      }
                    >
                      {selectedRecord.source}
                    </button>
                  </dd>
                </div>
                <div>
                  <dt>Family</dt>
                  <dd>{selectedRecord.family}</dd>
                </div>
                <div>
                  <dt>Actor</dt>
                  <dd>{selectedRecord.actorId ?? ", "}</dd>
                </div>
                <div>
                  <dt>Subject</dt>
                  <dd>
                    {(selectedRecord.subjectId &&
                      entityNames.get(
                        selectedRecord.subjectId,
                      )) ??
                      selectedRecord.subjectId ??
                      ", "}
                  </dd>
                </div>
                <div>
                  <dt>Severity</dt>
                  <dd>{selectedRecord.severity ?? ", "}</dd>
                </div>
              </dl>

              <div className="siem-field-list">
                <div className="siem-field-list-heading">
                  <span>Normalized fields</span>
                  <small>Click a value to pivot</small>
                </div>
                {Object.entries(
                  selectedRecord.fields,
                ).map(([field, value]) => {
                  const display =
                    fieldDisplayValue(value);
                  const intel =
                    threatByIndicator.get(
                      display,
                    );

                  return (
                    <button
                      key={field}
                      type="button"
                      onClick={() =>
                        addFilter(
                          field,
                          display,
                        )
                      }
                    >
                      <span>{field}</span>
                      <code>{display}</code>
                      {intel && (
                        <span
                          className={`siem-field-intel intel-${intel.category}`}
                          title={intel.note}
                        >
                          {intel.category.replace(
                            /-/g,
                            " ",
                          )}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              <details className="siem-raw-event">
                <summary>Normalized raw record</summary>
                <pre>{JSON.stringify(
                  selectedRecord,
                  null,
                  2,
                )}</pre>
              </details>

              {isCollected(selectedRecord.eventId) && (
                <button
                  type="button"
                  className="secondary-button siem-open-case"
                  onClick={onOpenCase}
                >
                  Open case evidence
                </button>
              )}
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
