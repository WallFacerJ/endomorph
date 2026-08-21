import {
  useMemo,
  useState,
} from "react";

import {
  searchSiem,
} from "./simulationAdapter";

import type {
  SiemEventRecord,
} from "./simulationAdapter";

import "./SiemWorkspace.css";

interface SiemWorkspaceProps {
  records: readonly SiemEventRecord[];
  finalized: boolean;
  isCollected: (eventId: string) => boolean;
  onCollect: (eventId: string) => void;
  onOpenCase: () => void;
}

type TimePreset =
  | "all"
  | "5m"
  | "15m";

function quoteValue(value: string): string {
  return /\s/.test(value)
    ? `"${value.replaceAll('"', '\\"')}"`
    : value;
}

function formatTimestamp(
  timestamp: string,
): string {
  return new Intl.DateTimeFormat(
    "en-US",
    {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    },
  ).format(new Date(timestamp));
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
  records,
  finalized,
  isCollected,
  onCollect,
  onOpenCase,
}: SiemWorkspaceProps) {
  const [query, setQuery] = useState("");
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
              Polymorph Ops / SIEM
            </p>
            <h3>Search security telemetry</h3>
            <p>
              Search shared identity, endpoint, network, session, and detection telemetry. Use field filters such as <code>family:process</code>, <code>accountId:account-smartinez</code>, or <code>destinationIp:203.0.113.77</code>.
            </p>
          </div>
          <div className="siem-result-count">
            <strong>{result.total}</strong>
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
            {result.facets.families.map(
              (facet) => (
                <button
                  key={facet.value}
                  type="button"
                  onClick={() =>
                    addFilter(
                      "family",
                      facet.value,
                    )
                  }
                >
                  <span>{facet.value}</span>
                  <strong>{facet.count}</strong>
                </button>
              ),
            )}
          </div>

          <div className="siem-facet-group">
            <span className="siem-facet-title">
              Source
            </span>
            {result.facets.sources.map(
              (facet) => (
                <button
                  key={facet.value}
                  type="button"
                  onClick={() =>
                    addFilter(
                      "source",
                      facet.value,
                    )
                  }
                >
                  <span>{facet.value}</span>
                  <strong>{facet.count}</strong>
                </button>
              ),
            )}
          </div>

          {result.facets.severities.length > 0 && (
            <div className="siem-facet-group">
              <span className="siem-facet-title">
                Severity
              </span>
              {result.facets.severities.map(
                (facet) => (
                  <button
                    key={facet.value}
                    type="button"
                    onClick={() =>
                      addFilter(
                        "severity",
                        facet.value,
                      )
                    }
                  >
                    <span>{facet.value}</span>
                    <strong>{facet.count}</strong>
                  </button>
                ),
              )}
            </div>
          )}
        </aside>

        <section className="siem-results-panel">
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
                {result.records.map((record) => (
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
                      {record.subjectId ?? "—"}
                    </td>
                    <td className="siem-message-cell">
                      {record.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

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
                  <dd>{selectedRecord.actorId ?? "—"}</dd>
                </div>
                <div>
                  <dt>Subject</dt>
                  <dd>{selectedRecord.subjectId ?? "—"}</dd>
                </div>
                <div>
                  <dt>Severity</dt>
                  <dd>{selectedRecord.severity ?? "—"}</dd>
                </div>
              </dl>

              <div className="siem-field-list">
                <div className="siem-field-list-heading">
                  <span>Normalized fields</span>
                  <small>Click a value to pivot</small>
                </div>
                {Object.entries(
                  selectedRecord.fields,
                ).map(([field, value]) => (
                  <button
                    key={field}
                    type="button"
                    onClick={() =>
                      addFilter(
                        field,
                        fieldDisplayValue(value),
                      )
                    }
                  >
                    <span>{field}</span>
                    <code>{fieldDisplayValue(value)}</code>
                  </button>
                ))}
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
