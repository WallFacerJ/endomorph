/**
 * How much scaffolding a run shows.
 *
 * Professional is the default because the product should feel like work
 * rather than school: no live objective checklist, no running score above
 * the response cards. Guided keeps that scaffolding for onboarding, layered
 * onto the same environment rather than split into a separate, shallower
 * product for beginners.
 *
 * Kept out of the component module so React Fast Refresh keeps working --
 * a file that exports both a component and shared helpers loses it.
 */
export type AssistanceMode =
  | "professional"
  | "guided";

export const ASSISTANCE_STORAGE_KEY =
  "endomorph-assistance-mode";

export function readInitialAssistance(): AssistanceMode {
  try {
    return window.localStorage.getItem(
      ASSISTANCE_STORAGE_KEY,
    ) === "guided"
      ? "guided"
      : "professional";
  } catch {
    // Storage can be blocked entirely. Default rather than break the run.
    return "professional";
  }
}

export function persistAssistance(
  mode: AssistanceMode,
): void {
  try {
    window.localStorage.setItem(
      ASSISTANCE_STORAGE_KEY,
      mode,
    );
  } catch {
    // A blocked storage API must not break the run.
  }
}
