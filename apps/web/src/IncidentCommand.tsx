import {
  useMemo,
  useState,
} from "react";

import {
  buildEvidenceGraph,
  buildIncidentReport,
  extractIncidentIndicators,
  INCIDENT_PHASES,
} from "./simulationAdapter";

import type {
  EvidenceGraphNode,
  IncidentCaseState,
  IncidentPhase,
  SiemEventRecord,
  WorldState,
} from "./simulationAdapter";

import "./IncidentCommand.css";

const PHASE_LABELS: Record<
  IncidentPhase,
  string
> = {
  triage: "Triage",
  investigation: "Investigation",
  containment: "Containment",
  eradication: "Eradication",
  recovery: "Recovery",
  lessons_learned: "Lessons learned",
};

const NODE_KIND_LABELS: Record<
  EvidenceGraphNode["kind"],
  string
> = {
  user: "User",
  account: "Account",
  device: "Endpoint",
  application: "Application",
  file: "File",
  session: "Session",
  address: "Address",
  alert: "Alert",
};

export interface IncidentCommandProps {
  world: WorldState;
  records: readonly SiemEventRecord[];
  collectedEventIds: readonly string[];
  caseState: IncidentCaseState;
  onCaseChange: (
    next: IncidentCaseState,
  ) => void;
  onPivotToSiem: (query: string) => void;
  readOnly: boolean;
}

export function IncidentCommand({
  world,
  records,
  collectedEventIds,
  caseState,
  onCaseChange,
  onPivotToSiem,
  readOnly,
}: IncidentCommandProps) {
  const [
    hypothesisStatement,
    setHypothesisStatement,
  ] = useState("");

  const [taskTitle, setTaskTitle] =
    useState("");

  const [taskOwner, setTaskOwner] =
    useState("Tier 2");

  const [decisionSummary, setDecisionSummary] =
    useState("");

  const [
    decisionRationale,
    setDecisionRationale,
  ] = useState("");

  // Everything below is derived from the evidence the analyst collected.
  // None of it is retyped into the case by hand.
  const graph = useMemo(
    () =>
      buildEvidenceGraph(
        world,
        records,
        collectedEventIds,
      ),
    [world, records, collectedEventIds],
  );

  const indicators = useMemo(
    () =>
      extractIncidentIndicators(
        world,
        records,
        collectedEventIds,
      ),
    [world, records, collectedEventIds],
  );

  const report = useMemo(
    () =>
      buildIncidentReport(
        world,
        records,
        collectedEventIds,
        caseState,
      ),
    [
      world,
      records,
      collectedEventIds,
      caseState,
    ],
  );

  const labelFor = (id: string) =>
    graph.nodes.find(
      (node) => node.id === id,
    )?.label ?? id;

  const addHypothesis = () => {
    const statement =
      hypothesisStatement.trim();

    if (!statement) {
      return;
    }

    onCaseChange({
      ...caseState,
      hypotheses: [
        ...caseState.hypotheses,
        {
          id: `hypothesis-${caseState.hypotheses.length + 1}`,
          statement,
          status: "proposed",
          evidenceEventIds: [
            ...collectedEventIds,
          ],
        },
      ],
    });

    setHypothesisStatement("");
  };

  const setHypothesisStatus = (
    id: string,
    status:
      | "proposed"
      | "supported"
      | "refuted",
  ) => {
    onCaseChange({
      ...caseState,
      hypotheses:
        caseState.hypotheses.map(
          (hypothesis) =>
            hypothesis.id === id
              ? { ...hypothesis, status }
              : hypothesis,
        ),
    });
  };

  const addTask = () => {
    const title = taskTitle.trim();

    if (!title) {
      return;
    }

    onCaseChange({
      ...caseState,
      tasks: [
        ...caseState.tasks,
        {
          id: `task-${caseState.tasks.length + 1}`,
          title,
          owner:
            taskOwner.trim() ||
            "Unassigned",
          status: "open",
          phase: caseState.phase,
        },
      ],
    });

    setTaskTitle("");
  };

  const advanceTask = (id: string) => {
    onCaseChange({
      ...caseState,
      tasks: caseState.tasks.map((task) =>
        task.id === id
          ? {
              ...task,
              status:
                task.status === "open"
                  ? "in_progress"
                  : task.status ===
                      "in_progress"
                    ? "done"
                    : "open",
            }
          : task,
      ),
    });
  };

  const addDecision = () => {
    const summary =
      decisionSummary.trim();

    if (!summary) {
      return;
    }

    onCaseChange({
      ...caseState,
      decisions: [
        ...caseState.decisions,
        {
          id: `decision-${caseState.decisions.length + 1}`,
          summary,
          rationale:
            decisionRationale.trim() ||
            "No rationale recorded.",
          phase: caseState.phase,
        },
      ],
    });

    setDecisionSummary("");
    setDecisionRationale("");
  };

  return (
    <section
      className="incident-command"
      aria-label="Incident command"
    >
      <header className="incident-header">
        <div>
          <p className="eyebrow">
            Endomorph Ops / Incident
            command
          </p>
          <h3>
            Incident picture assembled
            from your evidence
          </h3>
        </div>

        <dl className="incident-metrics">
          <div>
            <dt>Evidence</dt>
            <dd>
              {report.evidenceCount}
            </dd>
          </div>
          <div>
            <dt>Entities</dt>
            <dd>
              {report.entityCount}
            </dd>
          </div>
          <div>
            <dt>External IOCs</dt>
            <dd>
              {
                report
                  .externalIndicators
                  .length
              }
            </dd>
          </div>
          <div>
            <dt>Open tasks</dt>
            <dd>
              {report.openTasks.length}
            </dd>
          </div>
        </dl>
      </header>

      <div className="incident-phases">
        {INCIDENT_PHASES.map((phase) => (
          <button
            key={phase}
            type="button"
            disabled={readOnly}
            className={
              caseState.phase === phase
                ? "incident-phase active"
                : "incident-phase"
            }
            onClick={() =>
              onCaseChange({
                ...caseState,
                phase,
              })
            }
          >
            {PHASE_LABELS[phase]}
          </button>
        ))}
      </div>

      <div className="incident-grid">
        <article className="incident-panel">
          <p className="eyebrow">
            Derived
          </p>
          <h4>Evidence graph</h4>
          <p className="incident-copy">
            Entities your collected
            evidence puts in scope.
            Nothing here was typed in.
          </p>

          {graph.nodes.length === 0 ? (
            <div className="incident-empty">
              Collect evidence from SIEM,
              Endpoint, or Identity and
              the case builds itself.
            </div>
          ) : (
            <ul className="incident-nodes">
              {graph.nodes.map((node) => (
                <li key={node.id}>
                  <button
                    type="button"
                    className={
                      node.external
                        ? "incident-node external"
                        : "incident-node"
                    }
                    onClick={() =>
                      onPivotToSiem(
                        node.kind ===
                          "address"
                          ? `sourceIp:${node.id}`
                          : node.id,
                      )
                    }
                    title="Pivot to SIEM"
                  >
                    <span className="incident-node-kind">
                      {
                        NODE_KIND_LABELS[
                          node.kind
                        ]
                      }
                    </span>
                    <span className="incident-node-label">
                      {node.label}
                    </span>
                    <span className="incident-node-count">
                      {
                        node.eventIds
                          .length
                      }
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          {graph.edges.length > 0 && (
            <>
              <h4 className="incident-subhead">
                Connections
              </h4>
              <ul className="incident-edges">
                {graph.edges
                  .slice(0, 8)
                  .map((edge) => (
                    <li
                      key={`${edge.from}-${edge.to}`}
                    >
                      <span>
                        {labelFor(
                          edge.from,
                        )}
                      </span>
                      <span className="incident-edge-arrow">
                        &harr;
                      </span>
                      <span>
                        {labelFor(
                          edge.to,
                        )}
                      </span>
                      <span className="incident-node-count">
                        {
                          edge.eventIds
                            .length
                        }
                      </span>
                    </li>
                  ))}
              </ul>
            </>
          )}
        </article>

        <article className="incident-panel">
          <p className="eyebrow">
            Derived
          </p>
          <h4>Indicators</h4>
          <p className="incident-copy">
            Extracted from collected
            evidence. External values are
            flagged.
          </p>

          {indicators.length === 0 ? (
            <div className="incident-empty">
              No indicators yet.
            </div>
          ) : (
            <ul className="incident-indicators">
              {indicators
                .slice(0, 10)
                .map((indicator) => (
                  <li
                    key={`${indicator.kind}-${indicator.value}`}
                    className={
                      indicator.external
                        ? "external"
                        : undefined
                    }
                  >
                    <span className="incident-ioc-kind">
                      {indicator.kind.replace(
                        /_/g,
                        " ",
                      )}
                    </span>
                    <code>
                      {indicator.value
                        .length > 54
                        ? `${indicator.value.slice(0, 54)}…`
                        : indicator.value}
                    </code>
                    {indicator.external && (
                      <span className="incident-ioc-flag">
                        external
                      </span>
                    )}
                  </li>
                ))}
            </ul>
          )}
        </article>

        <article className="incident-panel">
          <p className="eyebrow">
            Analyst judgement
          </p>
          <h4>Hypotheses</h4>
          <p className="incident-copy">
            State what you think happened
            so the evidence can support or
            refute it.
          </p>

          {!readOnly && (
            <div className="incident-form">
              <input
                type="text"
                value={
                  hypothesisStatement
                }
                placeholder="The account was compromised from an external address"
                onChange={(event) =>
                  setHypothesisStatement(
                    event.target.value,
                  )
                }
              />
              <button
                type="button"
                onClick={addHypothesis}
              >
                Add
              </button>
            </div>
          )}

          {caseState.hypotheses
            .length === 0 ? (
            <div className="incident-empty">
              No hypotheses recorded.
            </div>
          ) : (
            <ul className="incident-hypotheses">
              {caseState.hypotheses.map(
                (hypothesis) => (
                  <li
                    key={hypothesis.id}
                  >
                    <p>
                      {
                        hypothesis.statement
                      }
                    </p>
                    <div className="incident-status-row">
                      <span
                        className={`incident-status ${hypothesis.status}`}
                      >
                        {
                          hypothesis.status
                        }
                      </span>
                      <span className="incident-evidence-count">
                        {
                          hypothesis
                            .evidenceEventIds
                            .length
                        }{" "}
                        evidence
                      </span>
                      {!readOnly && (
                        <>
                          <button
                            type="button"
                            onClick={() =>
                              setHypothesisStatus(
                                hypothesis.id,
                                "supported",
                              )
                            }
                          >
                            Support
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              setHypothesisStatus(
                                hypothesis.id,
                                "refuted",
                              )
                            }
                          >
                            Refute
                          </button>
                        </>
                      )}
                    </div>
                  </li>
                ),
              )}
            </ul>
          )}
        </article>

        <article className="incident-panel">
          <p className="eyebrow">
            Coordination
          </p>
          <h4>Tasks</h4>

          {!readOnly && (
            <div className="incident-form">
              <input
                type="text"
                value={taskTitle}
                placeholder="Isolate the affected endpoint"
                onChange={(event) =>
                  setTaskTitle(
                    event.target.value,
                  )
                }
              />
              <input
                type="text"
                className="incident-owner"
                value={taskOwner}
                onChange={(event) =>
                  setTaskOwner(
                    event.target.value,
                  )
                }
              />
              <button
                type="button"
                onClick={addTask}
              >
                Add
              </button>
            </div>
          )}

          {caseState.tasks.length ===
          0 ? (
            <div className="incident-empty">
              No tasks assigned.
            </div>
          ) : (
            <ul className="incident-tasks">
              {caseState.tasks.map(
                (task) => (
                  <li key={task.id}>
                    <button
                      type="button"
                      disabled={readOnly}
                      className={`incident-task-status ${task.status}`}
                      onClick={() =>
                        advanceTask(
                          task.id,
                        )
                      }
                    >
                      {task.status.replace(
                        /_/g,
                        " ",
                      )}
                    </button>
                    <span className="incident-task-title">
                      {task.title}
                    </span>
                    <span className="incident-task-owner">
                      {task.owner}
                    </span>
                    <span className="incident-task-phase">
                      {
                        PHASE_LABELS[
                          task.phase
                        ]
                      }
                    </span>
                  </li>
                ),
              )}
            </ul>
          )}
        </article>

        <article className="incident-panel">
          <p className="eyebrow">
            Coordination
          </p>
          <h4>Decisions</h4>

          {!readOnly && (
            <div className="incident-form column">
              <input
                type="text"
                value={decisionSummary}
                placeholder="Contain before eradicating"
                onChange={(event) =>
                  setDecisionSummary(
                    event.target.value,
                  )
                }
              />
              <input
                type="text"
                value={
                  decisionRationale
                }
                placeholder="Why"
                onChange={(event) =>
                  setDecisionRationale(
                    event.target.value,
                  )
                }
              />
              <button
                type="button"
                onClick={addDecision}
              >
                Record decision
              </button>
            </div>
          )}

          {caseState.decisions
            .length === 0 ? (
            <div className="incident-empty">
              No decisions recorded.
            </div>
          ) : (
            <ul className="incident-decisions">
              {caseState.decisions.map(
                (decision) => (
                  <li key={decision.id}>
                    <strong>
                      {decision.summary}
                    </strong>
                    <span>
                      {
                        decision.rationale
                      }
                    </span>
                    <span className="incident-task-phase">
                      {
                        PHASE_LABELS[
                          decision.phase
                        ]
                      }
                    </span>
                  </li>
                ),
              )}
            </ul>
          )}
        </article>

        <article className="incident-panel">
          <p className="eyebrow">
            Derived
          </p>
          <h4>Incident timeline</h4>
          <p className="incident-copy">
            Your collected evidence in
            order. This is the report.
          </p>

          {report.timeline.length ===
          0 ? (
            <div className="incident-empty">
              Nothing collected yet.
            </div>
          ) : (
            <ol className="incident-timeline">
              {report.timeline.map(
                (record) => (
                  <li
                    key={record.eventId}
                  >
                    <span className="incident-time">
                      {record.timestamp.slice(
                        11,
                        19,
                      )}
                    </span>
                    <span className="incident-timeline-body">
                      <code>
                        {
                          record.eventType
                        }
                      </code>
                      <span>
                        {record.message}
                      </span>
                    </span>
                  </li>
                ),
              )}
            </ol>
          )}
        </article>
      </div>
    </section>
  );
}
