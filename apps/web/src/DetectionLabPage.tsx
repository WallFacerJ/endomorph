import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  loadScenario,
  SHIPPED_SCENARIOS,
} from "./scenarioLoader";

import {
  reviewDetections,
} from "./detectionReview";

import {
  DetectionReviewPanel,
} from "./DetectionReviewPanel";

import {
  CustomRuleTester,
} from "./CustomRuleTester";

import {
  OrgProfilePanel,
} from "./OrgProfilePanel";

import {
  AttackCoverageMatrix,
} from "./AttackCoverageMatrix";

import {
  AttackStoryboard,
} from "./AttackStoryboard";

import type {
  ScenarioDefinition,
} from "./simulationAdapter";

import "./themes.css";
import "./App.css";
import "./DetectionLabPage.css";

/**
 * The detection lab, with its own front door.
 *
 * The in-investigation version of this sits behind finalizing, for a good
 * reason: during a run the labels are the answer. But a detection engineer is
 * not doing the run, they are testing a rule, and making them play an
 * investigation to reach the scorer is friction that stops the one audience
 * the wedge is for. This page skips the investigation entirely: pick a
 * scenario, see how the shipped ruleset scores against it, and bring your own
 * rule. It reveals the labels because that is the whole point here.
 *
 * Reached at `?lab`, so the default experience stays investigation-first.
 */

/** Only the generated scenarios carry ATT&CK mapping worth scoring against. */
const LAB_SCENARIOS =
  SHIPPED_SCENARIOS.filter(
    (scenario) =>
      scenario.group === "generated",
  );

function initialPath(): string {
  const requested = new URLSearchParams(
    window.location.search,
  ).get("scenario");

  const match = LAB_SCENARIOS.find(
    (scenario) =>
      scenario.path === requested,
  );

  return (
    match?.path ??
    LAB_SCENARIOS[0]?.path ??
    ""
  );
}

export function DetectionLabPage() {
  const [path, setPath] = useState(
    initialPath,
  );

  const [scenario, setScenario] =
    useState<ScenarioDefinition | null>(
      null,
    );

  const [error, setError] = useState<
    string | null
  >(null);

  const [loading, setLoading] =
    useState(true);

  useEffect(() => {
    let cancelled = false;

    setLoading(true);
    setError(null);

    loadScenario(path)
      .then((loaded) => {
        if (!cancelled) {
          setScenario(loaded);
          setLoading(false);
        }
      })
      .catch((caught: unknown) => {
        if (!cancelled) {
          setScenario(null);
          setError(
            caught instanceof Error
              ? caught.message
              : "The scenario could not be loaded.",
          );
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [path]);

  const review = useMemo(
    () =>
      scenario
        ? reviewDetections(scenario)
        : null,
    [scenario],
  );

  return (
    <div className="lab-page">
      <header className="lab-header">
        <div className="lab-header-copy">
          <p className="eyebrow">
            Endomorph · Detection Lab
          </p>
          <h1>
            Score a detection rule
            against ground truth
          </h1>
          <p className="lab-lede">
            Every event in these scenarios
            was labelled benign or
            malicious by the generator
            before it was written, so a
            rule scored here gets a
            precision and recall that are
            counted, not estimated. Pick a
            scenario, see how a sample
            ruleset does, then bring your
            own.
          </p>
        </div>

        <div className="lab-controls">
          <label htmlFor="lab-scenario">
            Scenario
          </label>
          <select
            id="lab-scenario"
            value={path}
            onChange={(event) =>
              setPath(
                event.target.value,
              )
            }
          >
            {LAB_SCENARIOS.map(
              (option) => (
                <option
                  key={option.path}
                  value={option.path}
                >
                  {option.label}
                </option>
              ),
            )}
          </select>

          <a
            className="lab-to-app"
            href={`${import.meta.env.BASE_URL}?app`}
          >
            Investigate instead →
          </a>
        </div>
      </header>

      <main className="lab-main">
        <AttackCoverageMatrix />

        {loading && (
          <p className="lab-status">
            Compiling the scenario and
            its corpus…
          </p>
        )}

        {error && (
          <p className="lab-status lab-error">
            {error}
          </p>
        )}

        {scenario && review && (
          <>
            <AttackStoryboard
              scenario={scenario}
            />
            <DetectionReviewPanel
              review={review}
            />
            <CustomRuleTester
              scenario={scenario}
              scenarioPath={path}
            />
          </>
        )}

        <OrgProfilePanel />
      </main>
    </div>
  );
}
