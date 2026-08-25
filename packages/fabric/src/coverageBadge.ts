/**
 * A README coverage badge, generated as a self-contained SVG.
 *
 * A detection-rules repo lives on its coverage: "how many of the techniques in
 * the benchmark do our rules actually catch". The evaluator already computes
 * that number; this renders it as a shields-style badge a CI job can commit
 * next to the README, so the answer is visible on the repo's front page and
 * moves every time the rules do. The SVG carries no external references, so it
 * renders offline and cannot leak a request when embedded.
 */

/** shields.io's flat colour ramp, worst to best. */
function colorFor(ratio: number): string {
  if (ratio >= 1) {
    return "#4c1"; // brightgreen
  }
  if (ratio >= 0.8) {
    return "#97ca00"; // green
  }
  if (ratio >= 0.6) {
    return "#dfb317"; // yellow
  }
  if (ratio >= 0.4) {
    return "#fe7d37"; // orange
  }
  return "#e05d44"; // red
}

function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * A rough advance width for 11px Verdana, the face shields renders in. Digits
 * and lowercase sit near 7px; wider glyphs are approximated generously so the
 * text never clips its pill.
 */
function textWidth(text: string): number {
  let width = 0;
  for (const char of text) {
    if (/[iIl.:'|]/.test(char)) {
      width += 3;
    } else if (/[mwMW]/.test(char)) {
      width += 10;
    } else if (/[A-Z]/.test(char)) {
      width += 8;
    } else {
      width += 6.5;
    }
  }
  return Math.ceil(width);
}

export interface CoverageBadgeOptions {
  readonly covered: number;
  readonly total: number;
  /** Left-hand label; defaults to "detection coverage". */
  readonly label?: string;
  /**
   * Right-hand value; defaults to `covered/total techniques`. The colour is
   * still driven by covered/total regardless of the text.
   */
  readonly value?: string;
}

export function renderCoverageBadge(
  options: CoverageBadgeOptions,
): string {
  const { covered, total } = options;
  const ratio =
    total > 0 ? covered / total : 0;

  const label =
    options.label ??
    "detection coverage";
  const value =
    options.value ??
    `${covered}/${total} techniques`;

  const padding = 10;
  const labelWidth =
    textWidth(label) + padding * 2;
  const valueWidth =
    textWidth(value) + padding * 2;
  const width = labelWidth + valueWidth;

  const color = colorFor(ratio);

  // Text anchors sit at the centre of each half; the *10 scale matches the
  // transform shields uses to keep the type crisp.
  const labelAnchor =
    (labelWidth / 2) * 10;
  const valueAnchor =
    (labelWidth + valueWidth / 2) * 10;
  const labelTextLength =
    (labelWidth - padding * 2) * 10;
  const valueTextLength =
    (valueWidth - padding * 2) * 10;

  const safeLabel = escapeXml(label);
  const safeValue = escapeXml(value);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="${safeLabel}: ${safeValue}">
  <title>${safeLabel}: ${safeValue}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${labelAnchor}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${labelTextLength}">${safeLabel}</text>
    <text x="${labelAnchor}" y="140" transform="scale(.1)" textLength="${labelTextLength}">${safeLabel}</text>
    <text aria-hidden="true" x="${valueAnchor}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${valueTextLength}">${safeValue}</text>
    <text x="${valueAnchor}" y="140" transform="scale(.1)" textLength="${valueTextLength}">${safeValue}</text>
  </g>
</svg>
`;
}
