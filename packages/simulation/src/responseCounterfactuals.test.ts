import {
  describe,
  expect,
  it,
} from "vitest";

import {
  compareResponsePaths,
} from "./responseCounterfactuals";

import {
  finalizeScenarioState,
  scoreResponsePathFrom,
  replayOpeningWorld,
} from "./scenario";

import {
  compileScenarioDefinition,
} from "./scenarioCompiler";

import {
  parseScenarioFile,
} from "@endomorph/schema";

import {
  readFileSync,
} from "node:fs";

import {
  join,
} from "node:path";

const scenario = compileScenarioDefinition(
  parseScenarioFile(
    JSON.parse(
      readFileSync(
        join(
          __dirname,
          "..",
          "..",
          "..",
          "apps",
          "web",
          "public",
          "scenarios",
          "account-compromise.json",
        ),
        "utf8",
      ),
    ),
  ).scenario,
);

const responseIds =
  scenario.investigation
    .responseActionIds;

describe("compareResponsePaths", () => {
  it("scores the path actually taken", () => {
    const comparison =
      compareResponsePaths(scenario, []);

    expect(
      comparison.taken.actionIds,
    ).toEqual([]);

    expect(
      comparison.taken.score
        .percentage,
    ).toBeGreaterThanOrEqual(0);
  });

  it("finds a better path than doing nothing", () => {
    const comparison =
      compareResponsePaths(scenario, []);

    // Doing nothing cannot be optimal in a scenario with objectives.
    expect(
      comparison.best.score.percentage,
    ).toBeGreaterThan(
      comparison.taken.score.percentage,
    );

    expect(comparison.optimal).toBe(
      false,
    );
  });

  it("recognises an already-optimal path", () => {
    const first = compareResponsePaths(
      scenario,
      [],
    );

    const comparison =
      compareResponsePaths(
        scenario,
        first.best.actionIds,
      );

    expect(comparison.optimal).toBe(true);

    expect(
      comparison.taken.score.percentage,
    ).toBe(
      comparison.best.score.percentage,
    );
  });

  it("attributes a score delta to each individual decision", () => {
    const comparison =
      compareResponsePaths(scenario, []);

    expect(
      comparison.influences.length,
    ).toBeGreaterThan(1);

    // At least one omitted action must be worth taking, or the best path
    // could not beat doing nothing.
    expect(
      comparison.influences.some(
        (influence) =>
          !influence.performed &&
          influence.delta > 0,
      ),
    ).toBe(true);

    for (const influence of comparison.influences) {
      expect(
        influence.explanation.length,
      ).toBeGreaterThan(10);

      expect(
        influence.label.length,
      ).toBeGreaterThan(0);
    }
  });

  it("measures an omitted action by appending it", () => {
    // Order changes the outcome here, so an influence is only meaningful
    // relative to a stated sequence. Appending models "and then I also did
    // this", which is the counterfactual an analyst who has already acted
    // is actually asking about.
    const partial = [responseIds[0]];

    const comparison =
      compareResponsePaths(
        scenario,
        partial,
      );

    for (const influence of comparison.influences) {
      if (influence.performed) {
        continue;
      }

      const appended =
        compareResponsePaths(scenario, [
          ...partial,
          influence.actionId,
        ]);

      expect(
        appended.taken.score.percentage -
          comparison.taken.score
            .percentage,
      ).toBe(influence.delta);
    }
  });

  it("searches orderings, not just sets", () => {
    // Regression, and a genuine domain property: re-enabling an account
    // after disabling it undoes containment, so the same three actions
    // score 25 or 75 depending on sequence. A set-only search would report
    // a best path that a reordering of the same actions beats.
    const comparison =
      compareResponsePaths(scenario, []);

    const inGivenOrder =
      compareResponsePaths(
        scenario,
        [...responseIds],
      ).taken.score.percentage;

    expect(
      comparison.best.score.percentage,
    ).toBeGreaterThan(inGivenOrder);
  });

  it("identifies a harmful action as negative", () => {
    // The scenario carries an intentionally harmful action with an authored
    // penalty; taking it must be measurably worse.
    const clean = compareResponsePaths(
      scenario,
      [],
    ).best.actionIds;

    const harmful = scenario.actions.find(
      (action) =>
        action.assessment !== undefined,
    );

    expect(harmful).toBeDefined();

    const withHarmful =
      compareResponsePaths(scenario, [
        ...clean,
        harmful!.id,
      ]);

    const influence =
      withHarmful.influences.find(
        (candidate) =>
          candidate.actionId ===
          harmful!.id,
      );

    expect(influence?.performed).toBe(
      true,
    );

    expect(
      influence?.delta,
    ).toBeLessThan(0);

    expect(
      withHarmful.optimal,
    ).toBe(false);
  });

  it("is deterministic", () => {
    expect(
      compareResponsePaths(scenario, []),
    ).toEqual(
      compareResponsePaths(scenario, []),
    );
  });

  it("reports whether the best path was proven or approximated", () => {
    const comparison =
      compareResponsePaths(scenario, []);

    // A handful of actions is searched exhaustively, so optimality is
    // established rather than assumed.
    expect(comparison.exhaustive).toBe(
      true,
    );
  });
});

describe("scoring a path from a prebuilt opening world", () => {
  /*
    Counterfactual scoring used to re-validate the scenario and re-replay
    every opening event for each candidate ordering. On a generated scenario
    that is 12,722 events replayed 65 times to answer a question about four
    actions, and it is where the twenty-two second pause after finalizing
    came from.

    The opening history is identical for every path, so it is now built once.
    That is only safe if the shortcut produces the same answer as the full
    validated replay, for every ordering rather than for the one that happens
    to be interesting -- which is what this checks.
  */
  function* orderings(
    candidates: readonly string[],
    prefix: readonly string[] = [],
  ): Generator<readonly string[]> {
    yield prefix;

    for (const candidate of candidates) {
      if (prefix.includes(candidate)) {
        continue;
      }

      yield* orderings(candidates, [
        ...prefix,
        candidate,
      ]);
    }
  }

  it("agrees with a full replay on every ordering", () => {
    const openingWorld =
      replayOpeningWorld(scenario);

    let checked = 0;

    for (const ordering of orderings(
      responseIds,
    )) {
      let reference;

      try {
        reference =
          finalizeScenarioState(
            scenario,
            ordering,
          );
      } catch {
        // A path the runtime refuses is not a counterfactual worth scoring;
        // the shortcut must refuse it too.
        expect(() =>
          scoreResponsePathFrom(
            scenario,
            openingWorld,
            ordering,
          ),
        ).toThrow();

        continue;
      }

      const fast = scoreResponsePathFrom(
        scenario,
        openingWorld,
        ordering,
      );

      expect({
        ordering,
        percentage:
          fast.score.percentage,
        status: fast.status,
      }).toEqual({
        ordering,
        percentage:
          reference.score.percentage,
        status: reference.outcome.status,
      });

      checked += 1;
    }

    // Orderings, not subsets: the same actions in a different sequence score
    // differently, so this must have compared more than 2^n paths.
    expect(checked).toBeGreaterThan(
      2 ** responseIds.length,
    );
  });

  it("does not mutate the world it is given", () => {
    // Every path replays onto the same opening world. If that world were
    // mutated rather than folded into a new one, each path would be scored
    // against the leftovers of the last.
    const openingWorld =
      replayOpeningWorld(scenario);

    const before = JSON.stringify(
      openingWorld,
    );

    for (const ordering of orderings(
      responseIds,
    )) {
      try {
        scoreResponsePathFrom(
          scenario,
          openingWorld,
          ordering,
        );
      } catch {
        continue;
      }
    }

    expect(
      JSON.stringify(openingWorld),
    ).toBe(before);
  });
});
