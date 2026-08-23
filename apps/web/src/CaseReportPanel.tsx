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
}

/**
 * The case report, in a form somebody can actually take away.
 *
 * Deliberately copy-and-select rather than a download. The product ships as
 * a single self-contained page, and in that sandbox a download the page
 * starts itself never reaches the viewer -- the link is inert and nothing
 * says why. A button that appears to work and does nothing is worse than no
 * button.
 *
 * So: the text is on the page, selectable, with a copy button that falls
 * back to selecting it when the clipboard API is unavailable, which it can
 * be inside an embedded frame.
 */
export function CaseReportPanel({
  markdown,
}: CaseReportPanelProps) {
  const [open, setOpen] =
    useState(false);

  const [copied, setCopied] =
    useState(false);

  const textRef =
    useRef<HTMLTextAreaElement>(null);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(
        markdown,
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
            Everything you collected and
            decided, as Markdown. Nothing
            in it was typed twice &mdash;
            it is the case state, written
            out.
          </p>
        </div>

        <div className="case-report-actions">
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
              : "Copy Markdown"}
          </button>
        </div>
      </div>

      {open && (
        <textarea
          ref={textRef}
          className="case-report-text"
          readOnly
          value={markdown}
          aria-label="Case report Markdown"
          rows={18}
          onFocus={(event) =>
            event.currentTarget.select()
          }
        />
      )}
    </section>
  );
}
