import {
  useEffect,
  useState,
} from "react";

import {
  SHIPPED_SCENARIOS,
} from "./scenarioLoader";

import {
  persistSessionMode,
  SESSION_MODES,
} from "./assistanceMode";

import type {
  SessionMode,
} from "./assistanceMode";

import "./ScenarioControls.css";
import "./themes.css";

interface ScenarioControlsProps {
  scenarioPath: string;
  sessionMode: SessionMode;
  onSessionModeChange: (
    next: SessionMode,
  ) => void;
}

type InterfaceStyle =
  | "midnight"
  | "graphite";

const THEME_STORAGE_KEY =
  "endomorph-interface-style";

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
  sessionMode: SessionMode,
) {
  const url = new URL(
    window.location.href,
  );

  url.searchParams.set(
    "scenario",
    scenarioPath,
  );

  // Carry the assistance level across a scenario switch, so an instructor
  // link stays an instructor link.
  if (sessionMode === "professional") {
    url.searchParams.delete("mode");
  } else {
    url.searchParams.set(
      "mode",
      sessionMode,
    );
  }

  window.location.assign(url);
}

export function ScenarioControls({
  scenarioPath,
  sessionMode,
  onSessionModeChange,
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

  useEffect(() => {
    persistSessionMode(sessionMode);
  }, [sessionMode]);

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
                sessionMode,
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

      {/*
        A <label> may label exactly one form control; wrapping a radiogroup
        in one is invalid and breaks accessible-name computation for the
        radios inside it. A plain container with its own labelled group is
        the correct structure.
      */}
      <div className="control-field">
        <span className="control-field-label">
          Assistance
        </span>
        <div
          className="session-modes"
          role="radiogroup"
          aria-label="Assistance level"
        >
          {SESSION_MODES.map((mode) => (
            <button
              key={mode.id}
              type="button"
              role="radio"
              aria-checked={
                sessionMode === mode.id
              }
              title={mode.adds}
              className={
                sessionMode === mode.id
                  ? "session-mode active"
                  : "session-mode"
              }
              onClick={() =>
                onSessionModeChange(
                  mode.id,
                )
              }
            >
              {mode.label}
            </button>
          ))}
        </div>
        <small className="session-mode-summary">
          {
            SESSION_MODES.find(
              (mode) =>
                mode.id === sessionMode,
            )?.summary
          }
        </small>
      </div>

      <label>
        <span>Style</span>
        <select
          aria-label="Select interface style"
          value={interfaceStyle}
          onChange={(event) =>
            setInterfaceStyle(
              event.target
                .value as InterfaceStyle,
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
            href="https://github.com/WallFacerJ/endomorph/blob/main/TESTER_GUIDE.md"
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
