import {
  SHIPPED_SCENARIOS,
} from "./scenarioLoader";

import "./ScenarioControls.css";

interface ScenarioControlsProps {
  scenarioPath: string;
  instructorMode: boolean;
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

      <a
        className="tester-guide-link"
        href="https://github.com/WallFacerJ/polymorph/blob/main/TESTER_GUIDE.md"
        target="_blank"
        rel="noreferrer"
      >
        First-time test guide
      </a>
    </div>
  );
}
