import {
  useRef,
  useState,
} from "react";

import {
  Icon,
} from "./Icon";

import "./CaseReportPanel.css";

interface CaseReportPanelProps {
  readonly markdown: string;

  /**
   * The same run, structured.
   *
   * The Markdown is for a person; this is for an instructor collecting
   * thirty of them or a hiring process comparing candidates, which needs
   * something a spreadsheet can read.
   */
  readonly buildAssessmentJson: (
    label: string,
  ) => string;
}

/**
 * The case report, in a form somebody can actually take away.
 *
 * Deliberately copy-and-select rather than a download. The product ships as
 * a single self-contained page, and in that sandbox a download the page
 * starts itself never reaches the viewer, the link is inert and nothing
 * says why. A button that appears to work and does nothing is worse than no
 * button.
 *
 * So: the text is on the page, selectable, with a copy button that falls
 * back to selecting it when the clipboard API is unavailable, which it can
 * be inside an embedded frame.
 */
export function CaseReportPanel({
  markdown,
  buildAssessmentJson,
}: CaseReportPanelProps) {
  const [open, setOpen] =
    useState(false);

  const [format, setFormat] = useState<
    "markdown" | "assessment"
  >("markdown");

  const [label, setLabel] =
    useState("");

  const [copied, setCopied] =
    useState(false);

  const textRef =
    useRef<HTMLTextAreaElement>(null);

  const shown =
    format === "markdown"
      ? markdown
      : buildAssessmentJson(label);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(
        shown,
      );

      setCopied(true);
      window.setTimeout(
        () => setCopied(false),
        2000,
      );
    } catch {
      // Clipboard access can be refused outright in an embedded frame.
      // Selecting the text leaves the reader one keystroke away rather than
      // silently failing.
      textRef.current?.select();
    }
  };

  return (
    <section
      className="case-report"
      aria-label="Case report"
    >
      <div className="case-report-head">
        <div>
          <p className="t-eyebrow">
            Coordinate / Report
          </p>

          <h4 className="t-title">
            <Icon
              name="book"
              size={16} />
            Take the case with you
          </h4>

          <p className="t-note">
            The write-up is for a person
            to read. The assessment record
            is the same run structured, for
            an instructor collecting
            several or a hiring process
            comparing candidates, it
            carries the seed, so two
            results are only comparable
            when they came from the same
            telemetry.
          </p>
        </div>

        <div className="case-report-actions">
          <div
            className="case-report-format"
            role="radiogroup"
            aria-label="Report format"
          >
            {(
              [
                ["markdown", "Write-up"],
                [
                  "assessment",
                  "Assessment",
                ],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                role="radio"
                aria-checked={
                  format === id
                }
                className={
                  format === id
                    ? "case-report-format-option active"
                    : "case-report-format-option"
                }
                onClick={() => {
                  setFormat(id);
                  setCopied(false);
                }}
              >
                {label}
              </button>
            ))}
          </div>

          <button
            type="button"
            className="secondary-button"
            onClick={() =>
              setOpen(
                (current) => !current,
              )
            }
            aria-expanded={open}
          >
            {open ? "Hide" : "Show"}{" "}
            report
          </button>

          <button
            type="button"
            className="primary-button"
            onClick={copy}
          >
            <Icon
              name={
                copied
                  ? "check"
                  : "external"
              }
              size={14}
            />
            {copied
              ? "Copied"
              : format === "markdown"
                ? "Copy Markdown"
                : "Copy JSON"}
          </button>
        </div>
      </div>

      {format === "assessment" && (
        <label className="case-report-label">
          <span>Label this result</span>
          <input
            type="text"
            value={label}
            placeholder="Optional, so an instructor can tell results apart"
            onChange={(event) => {
              setLabel(
                event.target.value,
              );
              setCopied(false);
            }}
          />
        </label>
      )}

      {open && (
        <textarea
          ref={textRef}
          className="case-report-text"
          readOnly
          value={shown}
          aria-label={
            format === "markdown"
              ? "Case report Markdown"
              : "Assessment record JSON"
          }
          rows={18}
          onFocus={(event) =>
            event.currentTarget.select()
          }
        />
      )}
    </section>
  );
}
