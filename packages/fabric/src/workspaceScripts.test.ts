import {
  describe,
  expect,
  it,
} from "vitest";

import {
  readFileSync,
} from "node:fs";

import {
  join,
} from "node:path";

/**
 * Workspace scripts have to survive the shell CI runs them in.
 *
 * This exists because of a failure that cost 72 consecutive red builds without
 * anyone noticing. The root build script filtered packages with
 * `--filter ./packages/**`, unquoted. On Windows npm scripts run through
 * cmd.exe, which does no globbing, so the literal pattern reached pnpm and
 * everything worked. On Linux they run through sh, which expands the pattern
 * into four directory paths, so pnpm received one filter and three stray
 * positional arguments and exited 1.
 *
 * The failure mode is the dangerous kind: every local gate passes, the change
 * looks correct in review, and only the runner disagrees. A guard has to live
 * somewhere the local suite runs, or it guards nothing.
 */

function workspaceRoot(): string {
  // packages/fabric/src -> repository root
  return join(
    import.meta.dirname,
    "..",
    "..",
    "..",
  );
}

function scriptsFrom(
  relativePath: string,
): Record<string, string> {
  const raw = readFileSync(
    join(workspaceRoot(), relativePath),
    "utf8",
  );

  return (
    (
      JSON.parse(raw) as {
        scripts?: Record<string, string>;
      }
    ).scripts ?? {}
  );
}

const MANIFESTS = [
  "package.json",
  "packages/domain/package.json",
  "packages/schema/package.json",
  "packages/simulation/package.json",
  "packages/fabric/package.json",
  "apps/web/package.json",
];

describe("workspace scripts", () => {
  it("quotes every glob so a POSIX shell cannot expand it first", () => {
    const offenders: string[] = [];

    for (const manifest of MANIFESTS) {
      for (const [name, script] of Object.entries(
        scriptsFrom(manifest),
      )) {
        /*
          Look for a glob character that is not inside quotes. Walking the
          string is worth the few lines: a regex that tried to express "a star
          outside quotes" would be the sort of thing nobody can check by
          reading, in a test whose whole job is to be obviously right.
        */
        let quote: string | undefined;

        for (const character of script) {
          if (
            quote === undefined &&
            (character === '"' ||
              character === "'")
          ) {
            quote = character;
            continue;
          }

          if (quote === character) {
            quote = undefined;
            continue;
          }

          if (
            quote === undefined &&
            character === "*"
          ) {
            offenders.push(
              `${manifest} :: ${name} :: ${script}`,
            );

            break;
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  it("still filters the packages the build depends on", () => {
    /*
      Quoting is only half of it. Someone fixing the glob by deleting it would
      make this test pass and the build wrong, because the web app is built
      after the packages it imports and after the scenarios are generated.
    */
    const build = scriptsFrom(
      "package.json",
    ).build;

    expect(build).toContain(
      '"./packages/**"',
    );

    expect(
      build.indexOf("packages"),
    ).toBeLessThan(
      build.indexOf("@endomorph/web"),
    );

    expect(
      build.indexOf("generate:all"),
    ).toBeLessThan(
      build.indexOf("@endomorph/web"),
    );
  });
});
