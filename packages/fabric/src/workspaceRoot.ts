import {
  existsSync,
} from "node:fs";

import {
  dirname,
  resolve,
} from "node:path";

import {
  fileURLToPath,
} from "node:url";

/**
 * Resolves the workspace root by walking up from this module.
 *
 * `pnpm --filter` runs a package script with the package directory as cwd,
 * so a relative path on the command line resolves inside packages/fabric
 * rather than where the user typed it. Every CLI path flag has to go through
 * here; the third one that did not silently looked in the wrong place and
 * reported the file missing.
 */
export function findWorkspaceRoot(): string {
  let directory = dirname(
    fileURLToPath(import.meta.url),
  );

  for (
    let depth = 0;
    depth < 10;
    depth += 1
  ) {
    if (
      existsSync(
        resolve(
          directory,
          "pnpm-workspace.yaml",
        ),
      )
    ) {
      return directory;
    }

    const parent = dirname(directory);

    if (parent === directory) {
      break;
    }

    directory = parent;
  }

  return process.cwd();
}

/** Resolves a user-supplied path against the workspace root. */
export function resolveFromRoot(
  path: string,
): string {
  return resolve(
    findWorkspaceRoot(),
    path,
  );
}
