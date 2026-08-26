import {
  useEffect,
  useState,
} from "react";

import {
  computeAttackCoverage,
} from "./detectionReview";

import type {
  AttackCoverage,
} from "./detectionReview";

import "./AttackCoverageMatrix.css";

/**
 * Detection posture at a glance: an ATT&CK heatmap of what the shipped ruleset
 * actually catches across every intrusion.
 *
 * This is the number a detection manager reports and a CISO takes to the board
 * -- and here it is computed from ground truth in the browser, not asserted. A
 * technique is "covered" when a shipped rule detects it (recall > 0) on at least
 * one intrusion; the rest are present in the corpus but unmatched, which is a
 * gap the analyst can see rather than discover during an incident.
 */

const TACTIC_LABELS: Readonly<
  Record<string, string>
> = {
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
    "Command & Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

function tacticLabel(tactic: string): string {
  return (
    TACTIC_LABELS[tactic] ?? tactic
  );
}

export function AttackCoverageMatrix() {
  const [coverage, setCoverage] =
    useState<AttackCoverage | null>(null);

  useEffect(() => {
    let cancelled = false;

    // Defer so the "Computing…" state paints before the synchronous sweep
    // (generate once, play every plan, score the shipped ruleset).
    const id = window.setTimeout(() => {
      const result =
        computeAttackCoverage();
      if (!cancelled) {
        setCoverage(result);
      }
    }, 20);

    return () => {
      cancelled = true;
      window.clearTimeout(id);
    };
  }, []);

  const percent = coverage
    ? Math.round(
        (coverage.covered /
          Math.max(1, coverage.total)) *
          100,
      )
    : 0;

  return (
    <section
      className="cov"
      aria-label="ATT&CK detection coverage"
    >
      <div className="cov-head">
        <p className="eyebrow">
          Detection posture
        </p>
        <h3>
          What the shipped ruleset covers,
          by ATT&amp;CK technique
        </h3>
        <p className="cov-lede">
          Coverage counted from ground
          truth across every intrusion: a
          technique is{" "}
          <span className="cov-swatch covered" />{" "}
          covered when a shipped rule
          detects it, and{" "}
          <span className="cov-swatch uncovered" />{" "}
          a gap when the corpus contains it
          but no rule catches it.
        </p>
      </div>

      {!coverage && (
        <p className="cov-status">
          Computing coverage across all
          intrusions…
        </p>
      )}

      {coverage && (
        <>
          <div className="cov-summary">
            <div className="cov-big">
              <span className="cov-big-fig">
                {coverage.covered}
                <span className="cov-big-of">
                  {" "}
                  / {coverage.total}
                </span>
              </span>
              <span className="cov-big-lab">
                techniques covered
              </span>
            </div>
            <div className="cov-bar-wrap">
              <div className="cov-bar-track">
                <div
                  className="cov-bar-fill"
                  style={{
                    width: `${percent}%`,
                  }}
                />
              </div>
              <span className="cov-bar-pct">
                {percent}%
              </span>
            </div>
          </div>

          <div className="cov-matrix-scroll">
            <div className="cov-matrix">
              {coverage.tactics.map(
                (tactic) => (
                  <div
                    key={tactic.tactic}
                    className="cov-col"
                  >
                    <div className="cov-col-head">
                      <span className="cov-col-name">
                        {tacticLabel(
                          tactic.tactic,
                        )}
                      </span>
                      <span className="cov-col-count">
                        {tactic.covered}/
                        {tactic.total}
                      </span>
                    </div>
                    {coverage.techniques
                      .filter(
                        (technique) =>
                          technique.tactic ===
                          tactic.tactic,
                      )
                      .map(
                        (technique) => (
                          <div
                            key={
                              technique.id
                            }
                            className={`cov-cell ${
                              technique.covered
                                ? "covered"
                                : "uncovered"
                            }`}
                            title={
                              technique.covered
                                ? `${technique.id} ${technique.name} — detected by ${technique.detectingRules.join(", ")}`
                                : `${technique.id} ${technique.name} — no shipped rule detects this`
                            }
                          >
                            <span className="cov-cell-id">
                              {
                                technique.id
                              }
                            </span>
                            <span className="cov-cell-name">
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
        </>
      )}
    </section>
  );
}
