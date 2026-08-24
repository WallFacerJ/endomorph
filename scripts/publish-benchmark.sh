#!/usr/bin/env bash
#
# Package the Endomorph Detection Benchmark and publish it as a GitHub release.
#
#   scripts/publish-benchmark.sh [tag]
#
# Default tag is benchmark-v1.0. Requires the GitHub CLI (`gh`) to be installed
# and authenticated; if it is not, the script stops after building the artifacts
# and prints the manual steps, so nothing is half-published.
set -euo pipefail

TAG="${1:-benchmark-v1.0}"
NAME="endomorph-benchmark-v1"
OUT_DIR="dist/${NAME}"
ARCHIVE="dist/${NAME}.tgz"

echo "Building the generator…"
pnpm --filter @endomorph/fabric build >/dev/null

echo "Generating the benchmark to ${OUT_DIR}…"
rm -rf "${OUT_DIR}" "${ARCHIVE}"
node packages/fabric/dist/evaluateCli.js --benchmark "${OUT_DIR}"

echo "Packaging ${ARCHIVE}…"
tar -czf "${ARCHIVE}" -C dist "${NAME}"

echo
echo "Artifacts ready:"
echo "  ${ARCHIVE}                 (full corpus, all six intrusions)"
echo "  ${OUT_DIR}/benchmark.json  (manifest, attached uncompressed so it is browsable)"
echo

if ! command -v gh >/dev/null 2>&1; then
  cat <<EOF
The GitHub CLI (gh) is not installed, so the release was not created.

To publish manually:
  1. Create a release for tag ${TAG} at
     https://github.com/WallFacerJ/endomorph/releases/new
  2. Paste docs/benchmark-release.md as the description.
  3. Attach ${ARCHIVE} and ${OUT_DIR}/benchmark.json.

Or install gh (https://cli.github.com), authenticate, and re-run this script.
EOF
  exit 0
fi

echo "Creating release ${TAG}…"
gh release create "${TAG}" \
  "${ARCHIVE}" \
  "${OUT_DIR}/benchmark.json" \
  --title "Endomorph Detection Benchmark v1.0" \
  --notes-file docs/benchmark-release.md

echo "Published: https://github.com/WallFacerJ/endomorph/releases/tag/${TAG}"
