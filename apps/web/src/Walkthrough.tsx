import {
  useMemo,
  useState,
} from "react";

import type {
  ScenarioDefinition,
  SiemEventRecord,
} from "./simulationAdapter";

import {
  buildWalkthroughSteps,
} from "./walkthroughSteps";

import "./Walkthrough.css";

/**
 * A step-by-step reconstruction of the incident, meant to be worked
 * alongside the investigation rather than inside it.
 *
 * The previous instructor mode revealed ground truth only after
 * finalization, which meant that during the entire investigation it did
 * nothing observable at all. This is the thing it should have been: a
 * companion an instructor can walk a room through, or a learner can consult
 * one step at a time when they are stuck.
 *
 * Steps are revealed individually. Seeing the whole answer at once is not
 * teaching, and an accidental full reveal ruins the exercise, so nothing
 * opens without an explicit click.
 */

export interface WalkthroughProps {
  scenario: ScenarioDefinition;
  records: readonly SiemEventRecord[];
  /** Detached copies drop the pop-out control. */
  detached?: boolean;
  onPopOut?: () => void;
  onClose?: () => void;
  popOutBlocked?: boolean;
}

export function Walkthrough({
  scenario,
  records,
  detached = false,
  onPopOut,
  onClose,
  popOutBlocked = false,
}: WalkthroughProps) {
  const steps = useMemo(
    () =>
      buildWalkthroughSteps(
        scenario,
        records,
      ),
    [scenario, records],
  );

  const [revealed, setRevealed] =
    useState<number[]>([]);

  const techniques =
    scenario.groundTruth?.techniques ??
    [];

  const toggle = (index: number) =>
    setRevealed((current) =>
      current.includes(index)
        ? current.filter(
            (value) => value !== index,
          )
        : [...current, index],
    );

  const allRevealed =
    revealed.length === steps.length &&
    steps.length > 0;

  return (
    <section
      className={
        detached
          ? "walkthrough detached"
          : "walkthrough"
      }
      aria-label="Incident walkthrough"
    >
      <header className="walkthrough-header">
        <div>
          <p className="walkthrough-eyebrow">
            Instructor companion
          </p>
          <h3>Incident walkthrough</h3>
          <p className="walkthrough-copy">
            {steps.length} steps.
            Revealed one at a time so
            the exercise survives a
            glance.
          </p>
        </div>

        <div className="walkthrough-actions">
          {!detached && onPopOut && (
            <button
              type="button"
              onClick={onPopOut}
            >
              Pop out
            </button>
          )}

          {onClose && (
            <button
              type="button"
              onClick={onClose}
            >
              {detached
                ? "Re-dock"
                : "Hide"}
            </button>
          )}
        </div>
      </header>

      {popOutBlocked && (
        <p className="walkthrough-notice">
          The browser blocked the
          separate window. The
          walkthrough stays docked here.
        </p>
      )}

      <div className="walkthrough-controls">
        <button
          type="button"
          onClick={() =>
            setRevealed(
              allRevealed
                ? []
                : steps.map(
                    (step) => step.index,
                  ),
            )
          }
        >
          {allRevealed
            ? "Hide all steps"
            : "Reveal all steps"}
        </button>

        <span className="walkthrough-progress">
          {revealed.length}/
          {steps.length} revealed
        </span>
      </div>

      <ol className="walkthrough-steps">
        {steps.map((step) => {
          const open = revealed.includes(
            step.index,
          );

          return (
            <li
              key={step.eventId}
              className={
                open
                  ? "walkthrough-step open"
                  : "walkthrough-step"
              }
            >
              <button
                type="button"
                className="walkthrough-step-head"
                aria-expanded={open}
                onClick={() =>
                  toggle(step.index)
                }
              >
                <span className="walkthrough-index">
                  {step.index}
                </span>

                <span className="walkthrough-step-title">
                  {/*
                    Collapsed stays deliberately non-spoiling -- the console
                    tells an instructor where to look without giving away
                    what happened. Revealed, the raw event type named the
                    record's schema rather than the step, so it falls back
                    to that only when a plan has no title.
                  */}
                  {open
                    ? (step.title ??
                      step.eventType)
                    : `Step ${step.index} — ${step.console}`}
                </span>

                <span className="walkthrough-time">
                  {open ? step.time : "•••"}
                </span>
              </button>

              {open && (
                <div className="walkthrough-step-body">
                  <div className="walkthrough-block">
                    <p className="walkthrough-block-label">
                      What happened
                    </p>
                    <p>
                      {step.significance}
                    </p>
                  </div>

                  {step.reasoning && (
                    <div className="walkthrough-block reasoning">
                      <p className="walkthrough-block-label">
                        How to reason
                        about it
                      </p>
                      <p>
                        {step.reasoning}
                      </p>
                    </div>
                  )}

                  <dl className="walkthrough-meta">
                    <div>
                      <dt>Look in</dt>
                      <dd>
                        {step.console}
                      </dd>
                    </div>

                    {step.techniqueId && (
                      <div>
                        <dt>Technique</dt>
                        <dd>
                          <code>
                            {
                              step.techniqueId
                            }
                          </code>
                        </dd>
                      </div>
                    )}

                    {step.query && (
                      <div>
                        <dt>Try</dt>
                        <dd>
                          <code>
                            {step.query}
                          </code>
                        </dd>
                      </div>
                    )}

                    <div>
                      <dt>Event</dt>
                      <dd>
                        <code>
                          {step.eventId}
                        </code>
                      </dd>
                    </div>
                  </dl>
                </div>
              )}
            </li>
          );
        })}
      </ol>

      {techniques.length > 0 && (
        <div className="walkthrough-attack">
          <h4>
            Techniques demonstrated
          </h4>
          <ul>
            {techniques.map(
              (technique) => (
                <li key={technique.id}>
                  <code>
                    {technique.id}
                  </code>
                  <span>
                    {technique.name}
                  </span>
                </li>
              ),
            )}
          </ul>
        </div>
      )}

      {scenario.groundTruth?.summary && (
        <details className="walkthrough-summary">
          <summary>
            Full incident summary
            (spoils everything)
          </summary>
          <p>
            {
              scenario.groundTruth
                .summary
            }
          </p>
        </details>
      )}
    </section>
  );
}
