/**
 * Builds a single self-contained HTML file containing the whole product.
 *
 * The hosted app fetches its scenarios over HTTP. A standalone build has no
 * origin to fetch from, so every asset and every scenario is inlined and the
 * page runs with no network access whatsoever -- which is also the right
 * posture for a security tool: nothing about a run leaves the browser.
 *
 *   pnpm bundle:standalone
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";

import {
  gzipSync,
} from "node:zlib";

import {
  dirname,
  join,
  resolve,
} from "node:path";

import {
  fileURLToPath,
} from "node:url";

function findWorkspaceRoot(): string {
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

/**
 * JSON embedded in a script tag only needs protecting from a literal
 * `</script>` and from HTML comment openers. Escaping the `/` and `!` keeps
 * the payload valid JSON while making both impossible.
 */
function escapeForScriptTag(
  json: string,
): string {
  return json
    .replace(/<\/(script)/gi, "<\\/$1")
    .replace(/<!--/g, "<\\!--");
}

function main(): void {
  const root = findWorkspaceRoot();

  const distDir = join(
    root,
    "apps",
    "web",
    "dist",
  );

  const indexPath = join(
    distDir,
    "index.html",
  );

  if (!existsSync(indexPath)) {
    throw new Error(
      "apps/web/dist/index.html not found. Run pnpm build first.",
    );
  }

  let html = readFileSync(
    indexPath,
    "utf8",
  );

  const assetsDir = join(
    distDir,
    "assets",
  );

  const assets = readdirSync(assetsDir);

  // -- inline styles ----------------------------------------------------
  for (const asset of assets.filter(
    (name) => name.endsWith(".css"),
  )) {
    const css = readFileSync(
      join(assetsDir, asset),
      "utf8",
    );

    // The replacement MUST be a function. Minified bundles contain `$&`
    // and `` $` `` sequences, and String.replace interprets those inside a
    // replacement *string* -- splicing the matched tag into the middle of
    // the asset and silently corrupting it.
    html = html.replace(
      new RegExp(
        `<link[^>]*href="[^"]*${asset}"[^>]*>`,
      ),
      () => `<style>\n${css}\n</style>`,
    );
  }

  // -- inline scripts ---------------------------------------------------
  for (const asset of assets.filter(
    (name) => name.endsWith(".js"),
  )) {
    const js = readFileSync(
      join(assetsDir, asset),
      "utf8",
    );

    html = html.replace(
      new RegExp(
        `<script[^>]*src="[^"]*${asset}"[^>]*></script>`,
      ),
      () =>
        `<script type="module">\n${escapeForScriptTag(js)}\n</script>`,
    );
  }

  // -- inline scenarios --------------------------------------------------
  const scenarioDir = join(
    distDir,
    "scenarios",
  );

  const scenarioFiles = existsSync(
    scenarioDir,
  )
    ? readdirSync(scenarioDir).filter(
        (name) => name.endsWith(".json"),
      )
    : [];

  const embedded = scenarioFiles
    .map((name) => {
      const json = readFileSync(
        join(scenarioDir, name),
        "utf8",
      );

      // Scenario JSON is enormously repetitive and compresses roughly 11x.
      // Embedding it as plain text put a four-scenario bundle within 2MB of
      // the size ceiling, which would have capped the plan library rather
      // than the product capping it.
      const compressed = gzipSync(
        Buffer.from(json.trim(), "utf8"),
        { level: 9 },
      ).toString("base64");

      return `<script type="application/octet-stream" data-encoding="gzip+base64" id="endomorph-scenario:/scenarios/${name}">${compressed}</script>`;
    })
    .join("\n");

  // Scenario payloads must be in the DOM before the app boots, so they are
  // placed ahead of the module script rather than at the end of the body.
  // Anchored on the </head> boundary so this cannot accidentally match a
  // `<script type="module">` occurring inside already-inlined bundle text.
  if (embedded.length > 0) {
    html = html.replace(
      "</head>",
      () => `${embedded}\n</head>`,
    );
  }

  // -- artifact fragment -------------------------------------------------
  // The artifact host supplies its own <!doctype>/<html>/<head>/<body>, so
  // the published file must be page *content* only. Extract the head
  // contents and body contents and concatenate them, dropping the document
  // scaffolding and the favicon link, whose relative path has no origin to
  // resolve against.
  const headMatch =
    /<head>([\s\S]*?)<\/head>/i.exec(
      html,
    );

  const bodyMatch =
    /<body[^>]*>([\s\S]*?)<\/body>/i.exec(
      html,
    );

  const fragment = [
    (headMatch?.[1] ?? "")
      .replace(
        /<link[^>]*rel="icon"[^>]*>/gi,
        "",
      )
      .replace(
        /<meta[^>]*charset[^>]*>/gi,
        "",
      )
      .replace(
        /<meta[^>]*viewport[^>]*>/gi,
        "",
      )
      .replace(
        /<title>[\s\S]*?<\/title>/i,
        "<title>Endomorph Security Console</title>",
      )
      .trim(),
    (bodyMatch?.[1] ?? "").trim(),
  ]
    .filter((part) => part.length > 0)
    .join("\n");

  const outputDir = join(
    root,
    "dist-standalone",
  );

  mkdirSync(outputDir, {
    recursive: true,
  });

  const outputPath = join(
    outputDir,
    "endomorph.html",
  );

  writeFileSync(
    outputPath,
    html,
    "utf8",
  );

  const artifactPath = join(
    outputDir,
    "endomorph-artifact.html",
  );

  writeFileSync(
    artifactPath,
    fragment,
    "utf8",
  );

  // Check for tags that would actually cause a network request. A bare
  // occurrence of "/assets/" inside inlined bundle text is harmless; a
  // <script src> or stylesheet <link> pointing at one is not.
  const externalTag =
    /<script[^>]+src=|<link[^>]+rel="stylesheet"/i.exec(
      html,
    );

  const remainingRefs =
    externalTag !== null;

  process.stdout.write(
    [
      "Standalone bundle written",
      `  scenarios inlined  ${scenarioFiles.length}`,
      `  size               ${(html.length / 1024 / 1024).toFixed(2)} MB`,
      `  external refs      ${remainingRefs ? "PRESENT (bundle is incomplete)" : "none"}`,
      `  standalone         dist-standalone/endomorph.html`,
      `  artifact fragment  dist-standalone/endomorph-artifact.html (${(fragment.length / 1024 / 1024).toFixed(2)} MB)`,
      "",
    ].join("\n"),
  );

  if (remainingRefs) {
    throw new Error(
      `Bundle still references an external asset: ${externalTag?.[0]}`,
    );
  }
}

main();
