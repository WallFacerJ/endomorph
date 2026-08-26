import {
  Icon,
} from "./Icon";

import type {
  ScenarioOutcome,
} from "@endomorph/simulation";

import "./MissionPanel.css";

/**
 * One place that says what the run asks of you and how much of it is done.
 *
 * The objectives already existed, but each lived beside the thing that
 * satisfied it: response objectives under the timeline, question progress in
 * the brief, evidence count in the case. An analyst was reported as being
 * unable to tell Guided from Professional at all, and then that "the
 * objectives are just spread out through the tabs", both are the same
 * finding. Scattered across six views, a checklist is not a checklist.
 *
 * Every item is derived from state the run already keeps. Nothing here is a
 * separate progress model that could drift from what the consoles show, and
 * nothing is marked done because a view was visited, only because the work
 * left an artifact behind.
 */

export interface MissionObjective {
  readonly id: string;
  readonly label: string;
  readonly detail: string;
  readonly done: boolean;

  /** Progress within the objective, where it has parts. */
  readonly progress?: {
    readonly done: number;
    readonly total: number;
  };

  /** Console that satisfies it, so the checklist is also navigation. */
  readonly view?: string;
}

interface MissionPanelProps {
  readonly objectives: readonly MissionObjective[];
  readonly outcome: ScenarioOutcome;
  readonly finalized: boolean;
  readonly score?: {
    readonly earned: number;
    readonly available: number;
  };
  readonly onNavigate: (
    view: string,
  ) => void;
}

export function MissionPanel({
  objectives,
  outcome,
  finalized,
  score,
  onNavigate,
}: MissionPanelProps) {
  const done = objectives.filter(
    (objective) => objective.done,
  ).length;

  return (
    <section
      className="mission"
      aria-label="Objectives"
    >
      <div className="console-head">
        <div className="console-head-text">
          <p className="t-eyebrow">
            Triage / Objectives
          </p>

          <h3 className="t-title">
            <Icon
              name="target"
              size={17}
            />
            What this run asks of you
          </h3>

          <p className="t-note">
            Each item checks itself off
            when the work leaves
            something behind, an
            answer, collected evidence, a
            recorded decision. Nothing is
            marked done for opening a
            tab.
          </p>
        </div>

        <div className="metric-row">
          <div className="metric">
            <span className="t-label">
              Objectives
            </span>

            <span className="metric-figure">
              <span className="t-metric">
                {done}
              </span>

              <span className="metric-sub">
                / {objectives.length}
              </span>
            </span>
          </div>

          {score && (
            <div className="metric">
              <span className="t-label">
                {finalized
                  ? "Points"
                  : "Answered"}
              </span>

              <span className="metric-figure">
                <span className="t-metric">
                  {finalized
                    ? score.earned
                    : objectives.find(
                        (objective) =>
                          objective.id ===
                          "questions",
                      )?.progress?.done ??
                      0}
                </span>

                <span className="metric-sub">
                  /{" "}
                  {finalized
                    ? score.available
                    : objectives.find(
                        (objective) =>
                          objective.id ===
                          "questions",
                      )?.progress?.total ??
                      0}
                </span>
              </span>
            </div>
          )}

          <div className="metric">
            <span className="t-label">
              Response
            </span>

            <span className="metric-figure">
              <span className="t-metric">
                {
                  outcome.objectives.filter(
                    (objective) =>
                      objective.met,
                  ).length
                }
              </span>

              <span className="metric-sub">
                /{" "}
                {
                  outcome.objectives
                    .length
                }
              </span>
            </span>
          </div>
        </div>
      </div>

      <ol className="mission-list">
        {objectives.map((objective) => (
          <li
            key={objective.id}
            className={
              objective.done
                ? "mission-item done"
                : "mission-item"
            }
          >
            <span
              className="mission-check"
              aria-hidden="true"
            >
              {objective.done && (
                <Icon
                  name="check"
                  size={13}
                />
              )}
            </span>

            <span className="mission-body">
              <span className="mission-label">
                {objective.label}

                {objective.progress && (
                  <span className="mission-progress">
                    {
                      objective.progress
                        .done
                    }
                    /
                    {
                      objective.progress
                        .total
                    }
                  </span>
                )}
              </span>

              <span className="mission-detail">
                {objective.detail}
              </span>
            </span>

            {objective.view && (
              <button
                type="button"
                className="mission-go"
                onClick={() =>
                  onNavigate(
                    objective.view as string,
                  )
                }
              >
                Open
                <Icon
                  name="chevron-right"
                  size={13}
                />
              </button>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
