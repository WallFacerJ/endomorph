import {
  useEffect,
  useState,
} from "react";

import {
  computeAttackCoverage,
  parseRuleset,
  techniqueEvidence,
  coverageReportHtml,
} from "./detectionReview";

import type {
  AttackCoverage,
  RulesetLanguage,
  TechniqueEvidence,
} from "./detectionReview";

import "./AttackCoverageMatrix.css";

/**
 * Detection posture at a glance: an ATT&CK heatmap of what a ruleset catches
 * across every intrusion.
 *
 * By default it scores the shipped ruleset, the demo. But the real product
 * value is the "Your ruleset" mode: paste a whole detection repo (many rules
 * separated by `---`, in any of the five languages) and get *your* ATT&CK
 * coverage, computed from ground truth in the browser. A technique is covered
 * when a rule detects it (recall > 0) on at least one intrusion; the rest are
 * gaps the analyst can see rather than discover during an incident.
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

const EXAMPLE_RULESET = `title: Encoded PowerShell
detection:
  selection:
    process.command_line|contains: '-enc'
  condition: selection
tags: [attack.t1059.001]
---
title: Shadow copy deletion
detection:
  selection:
    process.command_line|re: 'vssadmin.*delete.*shadow'
  condition: selection
tags: [attack.t1490]
---
title: Password spray
detection:
  selection:
    event.type: 'AUTH_LOGIN_FAILED'
  condition: selection
tags: [attack.t1110.003]`;

function tacticLabel(tactic: string): string {
  return TACTIC_LABELS[tactic] ?? tactic;
}

function CoverageView({
  coverage,
  label,
  onSelect,
  selected,
}: {
  readonly coverage: AttackCoverage;
  readonly label: string;
  readonly onSelect: (
    id: string,
  ) => void;
  readonly selected: string | null;
}) {
  const percent = Math.round(
    (coverage.covered /
      Math.max(1, coverage.total)) *
      100,
  );

  return (
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
            {label}
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
                  .map((technique) => (
                    <button
                      type="button"
                      key={technique.id}
                      className={`cov-cell ${
                        technique.covered
                          ? "covered"
                          : "uncovered"
                      } ${
                        selected ===
                        technique.id
                          ? "selected"
                          : ""
                      }`}
                      onClick={() =>
                        onSelect(
                          technique.id,
                        )
                      }
                      title={
                        technique.covered
                          ? `${technique.id} ${technique.name}: detected by ${technique.detectingRules.join(", ")}`
                          : `${technique.id} ${technique.name}: no rule detects this. Click to see what it looks like.`
                      }
                    >
                      <span className="cov-cell-id">
                        {technique.id}
                      </span>
                      <span className="cov-cell-name">
                        {technique.name}
                      </span>
                    </button>
                  ))}
              </div>
            ),
          )}
        </div>
      </div>
    </>
  );
}

export function AttackCoverageMatrix() {
  const [shipped, setShipped] =
    useState<AttackCoverage | null>(null);

  const [source, setSource] = useState<
    "shipped" | "custom"
  >("shipped");

  const [language, setLanguage] =
    useState<RulesetLanguage>("sigma");
  const [ruleText, setRuleText] =
    useState(EXAMPLE_RULESET);
  const [custom, setCustom] =
    useState<AttackCoverage | null>(null);
  const [skipped, setSkipped] = useState<
    number
  >(0);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const id = window.setTimeout(() => {
      const result =
        computeAttackCoverage();
      if (!cancelled) {
        setShipped(result);
      }
    }, 20);
    return () => {
      cancelled = true;
      window.clearTimeout(id);
    };
  }, []);

  const score = () => {
    setBusy(true);
    window.setTimeout(() => {
      const parsed = parseRuleset(
        ruleText,
        language,
      );
      setSkipped(parsed.skipped.length);
      setCustom(
        computeAttackCoverage(
          parsed.rules,
        ),
      );
      setBusy(false);
    }, 20);
  };

  const active =
    source === "custom" ? custom : shipped;

  const downloadReport = () => {
    if (!active) {
      return;
    }
    const html = coverageReportHtml(
      active,
      source === "custom"
        ? "Your ruleset"
        : "Shipped ruleset",
    );
    const blob = new Blob([html], {
      type: "text/html",
    });
    const url =
      URL.createObjectURL(blob);
    const link =
      document.createElement("a");
    link.href = url;
    link.download =
      "endomorph-coverage-report.html";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const [selected, setSelected] =
    useState<string | null>(null);
  const [evidence, setEvidence] =
    useState<TechniqueEvidence | null>(
      null,
    );
  const [copied, setCopied] =
    useState(false);

  const selectTechnique = (
    id: string,
  ) => {
    if (selected === id) {
      setSelected(null);
      setEvidence(null);
      return;
    }
    setSelected(id);
    setCopied(false);
    setEvidence(techniqueEvidence(id));
  };

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
          What a ruleset covers, by
          ATT&amp;CK technique
        </h3>
        <p className="cov-lede">
          Coverage counted from ground
          truth across every intrusion:{" "}
          <span className="cov-swatch covered" />{" "}
          covered when a rule detects the
          technique,{" "}
          <span className="cov-swatch uncovered" />{" "}
          a gap when the corpus contains it
          but no rule catches it.
        </p>
      </div>

      <div className="cov-toolbar">
        <div
          className="cov-source"
          role="group"
          aria-label="Coverage source"
        >
          <button
            type="button"
            className={
              source === "shipped"
                ? "cov-source-btn active"
                : "cov-source-btn"
            }
            onClick={() =>
              setSource("shipped")
            }
          >
            Shipped ruleset
          </button>
          <button
            type="button"
            className={
              source === "custom"
                ? "cov-source-btn active"
                : "cov-source-btn"
            }
            onClick={() =>
              setSource("custom")
            }
          >
            Your ruleset
          </button>
        </div>

        <button
          type="button"
          className="cov-download"
          onClick={downloadReport}
          disabled={!active}
        >
          Download report
        </button>
      </div>

      {source === "custom" && (
        <div className="cov-custom">
          <div className="cov-custom-langs">
            {(
              [
                "sigma",
                "kql",
                "spl",
                "eql",
                "esql",
              ] as const
            ).map((lang) => (
              <button
                key={lang}
                type="button"
                className={
                  language === lang
                    ? "cov-lang active"
                    : "cov-lang"
                }
                onClick={() =>
                  setLanguage(lang)
                }
              >
                {lang === "esql"
                  ? "ES|QL"
                  : lang.toUpperCase()}
              </button>
            ))}
          </div>
          <p className="cov-custom-hint">
            Paste your detection repo , 
            multiple rules separated by a
            line of{" "}
            <code>---</code>. Scored across
            all {shipped?.total ?? 37}{" "}
            techniques in the corpus.
          </p>
          <textarea
            className="cov-textarea"
            spellCheck={false}
            rows={10}
            value={ruleText}
            onChange={(event) =>
              setRuleText(
                event.target.value,
              )
            }
          />
          <div className="cov-custom-actions">
            <button
              type="button"
              className="cov-score"
              onClick={score}
              disabled={busy}
            >
              {busy
                ? "Scoring…"
                : "Compute my coverage"}
            </button>
            {custom && skipped > 0 && (
              <span className="cov-skip">
                {skipped} rule(s) could not
                be imported and were skipped.
              </span>
            )}
          </div>
        </div>
      )}

      {!active && (
        <p className="cov-status">
          {source === "custom"
            ? "Paste a ruleset and compute its coverage."
            : "Computing coverage across all intrusions…"}
        </p>
      )}

      {active && (
        <CoverageView
          coverage={active}
          label={
            source === "custom"
              ? "techniques your ruleset covers"
              : "techniques covered"
          }
          onSelect={selectTechnique}
          selected={selected}
        />
      )}

      {evidence && (
        <div className="cov-evidence">
          <div className="cov-evidence-head">
            <span className="cov-evidence-id">
              {evidence.technique}
            </span>
            <span className="cov-evidence-name">
              {evidence.name}
            </span>
            <button
              type="button"
              className="cov-evidence-close"
              aria-label="Close"
              onClick={() => {
                setSelected(null);
                setEvidence(null);
              }}
            >
              ✕
            </button>
          </div>

          <p className="cov-evidence-sub">
            What this technique looks like
            in the corpus, so you know
            exactly what to detect:
          </p>
          <ul className="cov-evidence-list">
            {evidence.examples.map(
              (example, index) => (
                <li key={index}>
                  <code className="cov-evidence-type">
                    {example.eventType}
                  </code>
                  <span className="cov-evidence-detail">
                    {example.detail}
                  </span>
                </li>
              ),
            )}
          </ul>

          {evidence.starterSigma && (
            <div className="cov-evidence-rule">
              <div className="cov-evidence-rule-head">
                <span>
                  Starter Sigma rule
                </span>
                <button
                  type="button"
                  className="cov-evidence-copy"
                  onClick={() => {
                    void navigator.clipboard
                      .writeText(
                        evidence.starterSigma,
                      )
                      .then(() => {
                        setCopied(true);
                        window.setTimeout(
                          () =>
                            setCopied(
                              false,
                            ),
                          2000,
                        );
                      })
                      .catch(() => {
                        setCopied(false);
                      });
                  }}
                >
                  {copied
                    ? "Copied"
                    : "Copy"}
                </button>
              </div>
              <pre className="cov-evidence-pre">
                <code>
                  {
                    evidence.starterSigma
                  }
                </code>
              </pre>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
