import type {
  AnalystCaseState,
  IncidentCaseState,
} from "./simulationAdapter";

/**
 * Keeps a run across reloads.
 *
 * An investigation is meant to take thirty minutes or more. Losing all of it
 * to a stray refresh is the cheapest possible way to make a product feel
 * disposable, and it is the failure most likely to end a real evaluation
 * early.
 *
 * Storage is per scenario, so switching scenarios does not resume the wrong
 * run, and is versioned so an incompatible shape is discarded rather than
 * crashing the workspace. Every access is guarded: a browser with storage
 * blocked must still run the product, just without resume.
 */

const STORAGE_VERSION = 1;

export interface PersistedRun {
  version: number;
  scenarioPath: string;
  performedActionIds: string[];
  finalized: boolean;
  analystCase: AnalystCaseState;
  incidentCase: IncidentCaseState;
  questionAnswers: Record<string, string>;
  savedAt: string;
}

function keyFor(scenarioPath: string): string {
  return `endomorph-run:${scenarioPath}`;
}

export function loadRun(
  scenarioPath: string,
): PersistedRun | undefined {
  let raw: string | null = null;

  try {
    raw = window.localStorage.getItem(
      keyFor(scenarioPath),
    );
  } catch {
    return undefined;
  }

  if (!raw) {
    return undefined;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch {
    clearRun(scenarioPath);
    return undefined;
  }

  const candidate =
    parsed as Partial<PersistedRun>;

  // Anything that does not match the current shape is discarded rather than
  // half-restored. A partially applied run is worse than a fresh one.
  if (
    candidate?.version !==
      STORAGE_VERSION ||
    candidate.scenarioPath !==
      scenarioPath ||
    !Array.isArray(
      candidate.performedActionIds,
    ) ||
    typeof candidate.finalized !==
      "boolean" ||
    !candidate.analystCase ||
    !Array.isArray(
      candidate.analystCase
        .collectedEventIds,
    ) ||
    !candidate.incidentCase ||
    typeof candidate.questionAnswers !==
      "object" ||
    candidate.questionAnswers === null
  ) {
    clearRun(scenarioPath);
    return undefined;
  }

  return candidate as PersistedRun;
}

export function saveRun(
  run: Omit<
    PersistedRun,
    "version" | "savedAt"
  >,
): void {
  try {
    window.localStorage.setItem(
      keyFor(run.scenarioPath),
      JSON.stringify({
        ...run,
        version: STORAGE_VERSION,
        savedAt: new Date().toISOString(),
      }),
    );
  } catch {
    // Quota exceeded or storage blocked. The run continues in memory.
  }
}

export function clearRun(
  scenarioPath: string,
): void {
  try {
    window.localStorage.removeItem(
      keyFor(scenarioPath),
    );
  } catch {
    // Nothing to do; the caller is resetting anyway.
  }
}

/** True when the run contains work worth resuming. */
export function isRunMeaningful(
  run: Pick<
    PersistedRun,
    | "performedActionIds"
    | "analystCase"
    | "questionAnswers"
    | "finalized"
  >,
): boolean {
  return (
    run.finalized ||
    run.performedActionIds.length > 0 ||
    run.analystCase.collectedEventIds
      .length > 0 ||
    run.analystCase.findings.length > 0 ||
    Object.values(
      run.questionAnswers,
    ).some(
      (answer) => answer.trim().length > 0,
    )
  );
}
