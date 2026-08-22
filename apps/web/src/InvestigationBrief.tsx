import {
  useMemo,
  useState,
} from "react";

import type {
  ScenarioQuestion,
  ScenarioTechnique,
} from "./simulationAdapter";

import {
  gradeQuestions,
} from "./questionGrading";

import {
  Icon,
} from "./Icon";

import "./InvestigationBrief.css";

const TACTIC_LABELS: Record<
  string,
  string
> = {
  reconnaissance: "Reconnaissance",
  resource_development:
    "Resource Development",
  initial_access: "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation:
    "Privilege Escalation",
  defense_evasion: "Defense Evasion",
  credential_access:
    "Credential Access",
  discovery: "Discovery",
  lateral_movement: "Lateral Movement",
  collection: "Collection",
  command_and_control:
    "Command and Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

const SURFACE_LABELS: Record<
  string,
  string
> = {
  siem: "SIEM Search",
  endpoint: "Endpoint",
  identity: "Identity",
  case: "Case",
};

export interface InvestigationBriefProps {
  questions: readonly ScenarioQuestion[];
  techniques: readonly ScenarioTechnique[];
  answers: Readonly<
    Record<string, string>
  >;
  onAnswerChange: (
    questionId: string,
    answer: string,
  ) => void;
  /** Techniques the analyst has evidence for, by technique id. */
  observedTechniqueIds: readonly string[];
  finalized: boolean;
  revealAnswers: boolean;

  /**
   * Whether the technique identities may be shown during the run.
   *
   * Naming them up front tells an analyst what to go hunting for -- knowing
   * that LSASS dumping is in scope is most of the work of finding it. A real
   * analyst gets an alert, not a technique list, so Professional counts them
   * while the run is live and names them in the after-action review.
   * Guided and Instructor name them throughout; that is what those modes are
   * for.
   */
  revealTechniques: boolean;

  /**
   * Which half to render.
   *
   * A tester put it plainly: the console "takes you from the alert directly
   * into questions", and "the questions should be after the investigate tab
   * since you need to look through those to answer them". The brief is the
   * assignment and belongs at the start; the questions are the write-up and
   * belong after the tools that answer them. They are one component because
   * they share the grading, the hint state and the score.
   */
  section: "brief" | "questions";
}

export function InvestigationBrief({
  questions,
  techniques,
  answers,
  onAnswerChange,
  observedTechniqueIds,
  finalized,
  revealAnswers,
  revealTechniques,
  section,
}: InvestigationBriefProps) {
  const [showHints, setShowHints] =
    useState(false);

  const score = useMemo(
    () =>
      gradeQuestions(
        questions,
        answers,
      ),
    [questions, answers],
  );

  const graded = score.grades;
  const earned = score.earned;
  const available = score.available;

  const byTactic = useMemo(() => {
    const groups = new Map<
      string,
      ScenarioTechnique[]
    >();

    for (const technique of techniques) {
      const existing = groups.get(
        technique.tactic,
      );

      if (existing) {
        existing.push(technique);
      } else {
        groups.set(technique.tactic, [
          technique,
        ]);
      }
    }

    return [...groups.entries()];
  }, [techniques]);

  const observed = new Set(
    observedTechniqueIds,
  );

  if (
    questions.length === 0 &&
    techniques.length === 0
  ) {
    return null;
  }

  return (
    <section
      className="brief"
      aria-label="Investigation brief"
    >
      <header className="brief-header">
        <div>
          <p className="eyebrow">
            Endomorph Ops /
            Investigation brief
          </p>
          <h3>
            <Icon name="target" size={17} />
            Answer from evidence, not
            from the alert
          </h3>
          <p className="brief-copy">
            Each answer is a value
            present somewhere in the
            telemetry. None can be
            derived from the alert
            alone.
          </p>
        </div>

        <div className="brief-progress">
          <strong>
            {finalized ||
            revealAnswers
              ? `${earned}/${available}`
              : `${graded.filter((entry) => entry.answered).length}/${questions.length}`}
          </strong>
          <span>
            {finalized || revealAnswers
              ? "points"
              : "answered"}
          </span>
        </div>
      </header>

      {section === "brief" &&
        techniques.length > 0 &&
        !revealTechniques && (
          <div className="brief-attack">
            <div className="brief-attack-head">
              <h4>
                Adversary behaviour
              </h4>

              <span>
                {
                  observedTechniqueIds.length
                }
                /{techniques.length}{" "}
                techniques evidenced
              </span>
            </div>

            <p className="brief-attack-withheld">
              This incident demonstrates{" "}
              {techniques.length} ATT&amp;CK
              techniques. Which ones is
              withheld while the run is
              live &mdash; naming them
              tells you what to hunt for,
              and an alert never does.
              They are listed in full once
              you finalize, and Guided
              shows them throughout.
            </p>
          </div>
        )}

      {section === "brief" &&
        techniques.length > 0 &&
        revealTechniques && (
        <div className="brief-attack">
          <div className="brief-attack-head">
            <h4>
              Adversary behaviour
              (MITRE ATT&amp;CK)
            </h4>
            <span>
              {
                observedTechniqueIds.length
              }
              /{techniques.length}{" "}
              techniques evidenced
            </span>
          </div>

          <div className="brief-tactics">
            {byTactic.map(
              ([tactic, entries]) => (
                <div
                  key={tactic}
                  className="brief-tactic"
                >
                  <p className="brief-tactic-name">
                    {TACTIC_LABELS[
                      tactic
                    ] ?? tactic}
                  </p>

                  {entries.map(
                    (technique) => (
                      <div
                        key={
                          technique.id
                        }
                        className={
                          observed.has(
                            technique.id,
                          )
                            ? "brief-technique observed"
                            : "brief-technique"
                        }
                        title={
                          technique.name
                        }
                      >
                        <code>
                          {technique.id}
                        </code>
                        <span>
                          {
                            technique.name
                          }
                        </span>
                      </div>
                    ),
                  )}
                </div>
              ),
            )}
          </div>
        </div>
      )}

      {section === "questions" &&
        questions.length > 0 && (
        <div className="brief-questions">
          <div className="brief-questions-head">
            <h4>
              Investigation questions
            </h4>
            <button
              type="button"
              className="brief-hint-toggle"
              onClick={() =>
                setShowHints(
                  (current) => !current,
                )
              }
            >
              {showHints
                ? "Hide hints"
                : "Show hints"}
            </button>
          </div>

          <ol className="brief-question-list">
            {graded.map(
              ({
                question,
                answered,
                correct,
              }) => (
                <li
                  key={question.id}
                  className={
                    finalized ||
                    revealAnswers
                      ? correct
                        ? "brief-question correct"
                        : "brief-question incorrect"
                      : "brief-question"
                  }
                >
                  <div className="brief-question-head">
                    <p className="brief-prompt">
                      {question.prompt}
                    </p>
                    <span className="brief-points">
                      {question.points}
                      &nbsp;pts
                    </span>
                  </div>

                  <div className="brief-answer-row">
                    <input
                      type="text"
                      aria-label={
                        question.prompt
                      }
                      value={
                        answers[
                          question.id
                        ] ?? ""
                      }
                      disabled={
                        finalized
                      }
                      placeholder="Your answer"
                      onChange={(
                        event,
                      ) =>
                        onAnswerChange(
                          question.id,
                          event.target
                            .value,
                        )
                      }
                    />

                    <span className="brief-surface">
                      {SURFACE_LABELS[
                        question.surface
                      ] ??
                        question.surface}
                    </span>

                    {(finalized ||
                      revealAnswers) && (
                      <span className="brief-verdict">
                        {correct
                          ? "Correct"
                          : answered
                            ? "Incorrect"
                            : "Unanswered"}
                      </span>
                    )}
                  </div>

                  {showHints &&
                    question.hint &&
                    !finalized && (
                      <p className="brief-hint">
                        {question.hint}
                      </p>
                    )}

                  {(finalized ||
                    revealAnswers) &&
                    !correct && (
                      <p className="brief-expected">
                        Expected:{" "}
                        <code>
                          {
                            question
                              .accepted[0]
                          }
                        </code>
                      </p>
                    )}
                </li>
              ),
            )}
          </ol>
        </div>
      )}
    </section>
  );
}
