import "./FirstRun.css";

/**
 * What to do when you have never seen this before.
 *
 * The five-step orientation used to live behind a "Quick test" dropdown in
 * the control row, which made onboarding copy look like a setting. It sat
 * between Assistance and Style with no relationship to either, and someone
 * arriving cold had no reason to open it.
 *
 * It is now the first thing on the alert queue, dismissible, and it stays
 * dismissed. The steps name the console each one happens in, so it doubles
 * as a map of the sidebar rather than a list of instructions.
 */

export interface FirstRunProps {
  onDismiss: () => void;
}

const STEPS: ReadonlyArray<{
  where: string;
  action: string;
}> = [
  {
    where: "Alerts",
    action:
      "Read the alert. It names a host and an account, and almost nothing else — that is the point.",
  },
  {
    where: "Brief",
    action:
      "Read the brief. The questions tell you what you are expected to establish; you cannot answer them from the alert.",
  },
  {
    where: "SIEM Search",
    action:
      "Find a value worth pivoting on — an address, a hostname, a command — and query it. The stream is far too large to scroll.",
  },
  {
    where: "Endpoint / Identity",
    action:
      "Follow the entity. Endpoint shows what ran on a host; Identity shows where an account signed in from and whether that is normal for it.",
  },
  {
    where: "Live Response",
    action:
      "Ask the host what is true on it now, rather than what it did. Run the same command against a machine you do not suspect: knowing what ordinary looks like is most of the job.",
  },
  {
    where: "Case",
    action:
      "Collect evidence as you go. The case builds the entity graph and indicators from whatever you collected.",
  },
];

export function FirstRun({
  onDismiss,
}: FirstRunProps) {
  return (
    <section
      className="first-run"
      aria-label="How to work this incident"
    >
      <div className="first-run-head">
        <div>
          <p className="first-run-eyebrow">
            New here
          </p>
          <h3>
            How to work this incident
          </h3>
          <p className="first-run-copy">
            Roughly thirty minutes if
            you work it properly. There
            is no single correct path —
            these are the tools and
            what each is for.
          </p>
        </div>

        <button
          type="button"
          onClick={onDismiss}
        >
          Got it
        </button>
      </div>

      <ol className="first-run-steps">
        {STEPS.map((step, index) => (
          <li key={step.where}>
            <span className="first-run-index">
              {index + 1}
            </span>
            <span className="first-run-body">
              <span className="first-run-where">
                {step.where}
              </span>
              <span className="first-run-action">
                {step.action}
              </span>
            </span>
          </li>
        ))}
      </ol>

      <p className="first-run-foot">
        Stuck? Switch <strong>Assistance</strong> to{" "}
        <strong>Guided</strong> for
        objectives and a running score,
        or <strong>Instructor</strong>{" "}
        to open a step-by-step
        walkthrough of what actually
        happened.
      </p>
    </section>
  );
}
