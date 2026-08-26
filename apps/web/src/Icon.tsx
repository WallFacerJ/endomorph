/**
 * The console's icon set.
 *
 * Inline SVG rather than a font or a sprite file: the product ships as a
 * single self-contained HTML file with no external references, and an icon
 * font would be either another asset to inline or a dependency that silently
 * fails to load and leaves boxes behind.
 *
 * All of them are stroked, on a 24-unit grid, drawn in `currentColor` so a
 * chip or a button controls its own icon colour. They are decorative by
 * default, `aria-hidden`, because in every place they are used here the
 * adjacent text already names the thing. Pass a `title` only where an icon
 * stands alone.
 */

export type IconName =
  | "alert"
  | "shield"
  | "search"
  | "endpoint"
  | "identity"
  | "case"
  | "clock"
  | "chevron-right"
  | "chevron-down"
  | "process"
  | "network"
  | "file"
  | "key"
  | "user"
  | "server"
  | "check"
  | "close"
  | "warning"
  | "info"
  | "play"
  | "rewind"
  | "filter"
  | "external"
  | "chart"
  | "target"
  | "pin"
  | "book";

const PATHS: Readonly<
  Record<IconName, string>
> = {
  alert: "M12 3 2.5 20h19L12 3Zm0 6v5m0 3v.5",
  shield:
    "M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6L12 3Z",
  search:
    "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM20 20l-4-4",
  endpoint:
    "M3 5h18v11H3zM3 16h18M9 20h6M12 16v4",
  identity:
    "M12 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM4 21c0-3.9 3.6-6.5 8-6.5s8 2.6 8 6.5",
  case: "M3 7h18v13H3zM9 7V4h6v3M3 12h18",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM12 7v5l3.5 2",
  "chevron-right": "M9 5l7 7-7 7",
  "chevron-down": "M5 9l7 7 7-7",
  process:
    "M4 4h7v7H4zM13 13h7v7h-7zM7.5 11v4.5H13",
  network:
    "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3Z",
  file: "M6 3h8l4 4v14H6zM14 3v4h4",
  key: "M15 3a6 6 0 1 0-4.2 10.3L4 20v1h4v-2h2v-2h2l1.2-1.2A6 6 0 0 0 15 3Zm1.5 4.5h.01",
  user: "M12 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM5 20c0-3.3 3.1-5.5 7-5.5s7 2.2 7 5.5",
  server:
    "M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01",
  check: "M4 12.5 9.5 18 20 6.5",
  close: "M6 6l12 12M18 6 6 18",
  warning:
    "M12 4 3 20h18L12 4Zm0 5.5v5m0 2.5v.5",
  info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 4v.5m0 3V17",
  play: "M7 4l12 8-12 8V4Z",
  rewind: "M11 5 3 12l8 7V5ZM21 5l-8 7 8 7V5Z",
  filter: "M3 5h18l-7 8v6l-4 2v-8L3 5Z",
  external:
    "M14 4h6v6M20 4l-9 9M18 14v6H4V6h6",
  chart: "M4 20V9M10 20V4M16 20v-7M22 20H2",
  target:
    "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 4.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Zm0 4h.01",
  pin: "M12 21s7-6.2 7-11a7 7 0 1 0-14 0c0 4.8 7 11 7 11Zm0-13.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5Z",
  book: "M4 4h6a3 3 0 0 1 3 3v13a2.5 2.5 0 0 0-2.5-2.5H4V4Zm16 0h-6a3 3 0 0 0-3 3v13a2.5 2.5 0 0 1 2.5-2.5H20V4Z",
};

interface IconProps {
  readonly name: IconName;

  /** Pixel size; the stroke scales with it. */
  readonly size?: number;

  /** Only for an icon with no adjacent text. */
  readonly title?: string;

  readonly className?: string;
}

export function Icon({
  name,
  size = 16,
  title,
  className,
}: IconProps) {
  return (
    <svg
      className={
        className
          ? `icon ${className}`
          : "icon"
      }
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={
        title ? undefined : true
      }
      role={title ? "img" : undefined}
      focusable="false"
    >
      {title && <title>{title}</title>}
      <path d={PATHS[name]} />
    </svg>
  );
}
