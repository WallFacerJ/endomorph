import {
  useEffect,
  useState,
} from "react";

import {
  SHIPPED_SCENARIOS,
} from "./scenarioLoader";

import "./ScenarioControls.css";
import "./themes.css";

interface ScenarioControlsProps {
  scenarioPath: string;
  instructorMode: boolean;
}

type InterfaceStyle =
  | "midnight"
  | "graphite";

const THEME_STORAGE_KEY =
  "polymorph-interface-style";

function readInitialStyle(): InterfaceStyle {
  const stored =
    window.localStorage.getItem(
      THEME_STORAGE_KEY,
    );

  return stored === "graphite"
    ? "graphite"
    : "midnight";
}

function navigateWith(
  scenarioPath: string,
  instructorMode: boolean,
) {
  const url = new URL(
    window.location.href,
  );

  url.searchParams.set(
    "scenario",
    scenarioPath,
  );

  if (instructorMode) {
    url.searchParams.set(
      "mode",
      "instructor",
    );
  } else {
    url.searchParams.delete("mode");
  }

  window.location.assign(url);
}

export function ScenarioControls({
  scenarioPath,
  instructorMode,
}: ScenarioControlsProps) {
  const [interfaceStyle, setInterfaceStyle] =
    useState<InterfaceStyle>(
      readInitialStyle,
    );

  useEffect(() => {
    document.documentElement.dataset.theme =
      interfaceStyle;
    window.localStorage.setItem(
      THEME_STORAGE_KEY,
      interfaceStyle,
    );
  }, [interfaceStyle]);

  const isShipped =
    SHIPPED_SCENARIOS.some(
      (scenario) =>
        scenario.path === scenarioPath,
    );

  return (
    <div
      className="scenario-controls"
      aria-label="Scenario controls"
    >
      <label>
        <span>Scenario</span>
        <select
          aria-label="Select training scenario"
          value={
            isShipped
              ? scenarioPath
              : "custom"
          }
          onChange={(event) => {
            if (
              event.target.value !==
              "custom"
            ) {
              navigateWith(
                event.target.value,
                instructorMode,
              );
            }
          }}
        >
          {SHIPPED_SCENARIOS.map(
            (scenario) => (
              <option
                key={scenario.path}
                value={scenario.path}
              >
                {scenario.label}
              </option>
            ),
          )}
          {!isShipped && (
            <option value="custom">
              Custom scenario
            </option>
          )}
        </select>
      </label>

      <label>
        <span>Style</span>
        <select
          aria-label="Select interface style"
          value={interfaceStyle}
          onChange={(event) =>
            setInterfaceStyle(
              event.target.value as InterfaceStyle,
            )
          }
        >
          <option value="midnight">
            Midnight SOC
          </option>
          <option value="graphite">
            Graphite
          </option>
        </select>
      </label>

      <button
        type="button"
        className={
          instructorMode
            ? "mode-button active"
            : "mode-button"
        }
        onClick={() =>
          navigateWith(
            scenarioPath,
            !instructorMode,
          )
        }
      >
        {instructorMode
          ? "Student mode"
          : "Instructor mode"}
      </button>

      <details className="quick-test-menu">
        <summary>Quick test</summary>
        <div className="quick-test-popover">
          <p className="quick-test-title">
            First time? Five minutes is enough.
          </p>
          <ol>
            <li>Open the alert and decide what happened.</li>
            <li>Collect one or two useful pieces of evidence.</li>
            <li>Choose the response you think is right.</li>
            <li>Finalize the investigation.</li>
            <li>Tell us where you hesitated or got confused.</li>
          </ol>
          <a
            href="https://github.com/WallFacerJ/polymorph/blob/main/TESTER_GUIDE.md"
            target="_blank"
            rel="noreferrer"
          >
            Optional deeper test guide
          </a>
        </div>
      </details>
    </div>
  );
}
