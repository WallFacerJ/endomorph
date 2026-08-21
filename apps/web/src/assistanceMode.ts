/**
 * One axis of assistance, not two.
 *
 * There used to be a Mode control (professional / guided) and a Role control
 * (student / instructor). They were genuinely different axes -- how much
 * scaffolding, versus whether answers are visible -- but nobody could say
 * what one did that the other didn't, which is a fair verdict on a design
 * that needs a paragraph to explain.
 *
 * Collapsed into a single scale where each level strictly adds to the one
 * below it. That is legible without explanation: further right means more
 * help.
 */
export type SessionMode =
  | "professional"
  | "guided"
  | "instructor";

export interface SessionModeDefinition {
  readonly id: SessionMode;
  readonly label: string;
  /** One line, shown under the control. */
  readonly summary: string;
  /** What this level adds over the previous one. */
  readonly adds: string;
}

export const SESSION_MODES: readonly SessionModeDefinition[] =
  [
    {
      id: "professional",
      label: "Professional",
      summary:
        "Work the incident with no assistance.",
      adds: "The evidence, the tools, and the response operations. No objective checklist, no running score.",
    },
    {
      id: "guided",
      label: "Guided",
      summary:
        "Adds objectives and a running score while you work.",
      adds: "Everything in Professional, plus the objective checklist, the live score, and response actions listed together.",
    },
    {
      id: "instructor",
      label: "Instructor",
      summary:
        "Adds the answers and the incident walkthrough.",
      adds: "Everything in Guided, plus ground truth, expected answers, and the step-by-step walkthrough during the run.",
    },
  ];

const STORAGE_KEY =
  "endomorph-session-mode";

function isSessionMode(
  value: string | null,
): value is SessionMode {
  return (
    value === "professional" ||
    value === "guided" ||
    value === "instructor"
  );
}

/**
 * A `?mode=` parameter wins over the stored preference, so a link an
 * instructor shares opens in the mode they meant.
 */
export function readInitialSessionMode(): SessionMode {
  try {
    const requested = new URLSearchParams(
      window.location.search,
    ).get("mode");

    if (isSessionMode(requested)) {
      return requested;
    }

    const stored =
      window.localStorage.getItem(
        STORAGE_KEY,
      );

    if (isSessionMode(stored)) {
      return stored;
    }
  } catch {
    // Storage or URL access can be blocked; fall through to the default.
  }

  return "professional";
}

export function persistSessionMode(
  mode: SessionMode,
): void {
  try {
    window.localStorage.setItem(
      STORAGE_KEY,
      mode,
    );
  } catch {
    // A blocked storage API must not break the run.
  }
}

/** Objectives, running score, and the response-card list. */
export function showsScaffolding(
  mode: SessionMode,
): boolean {
  return mode !== "professional";
}

/** Ground truth, expected answers, and the walkthrough during the run. */
export function showsAnswers(
  mode: SessionMode,
): boolean {
  return mode === "instructor";
}
