import "./LandingPage.css";

/**
 * The front door.
 *
 * The app root used to drop a first-time visitor straight into an investigation
 * with no explanation of what Endomorph is or why the data is different from any
 * other SOC exercise. This is the ten-second pitch instead: what it is, the one
 * claim that matters (ground truth by construction), and two doors, score a
 * rule in the lab, or play an investigation. Shown only at the bare root; any
 * `?scenario`/`?mode`/`?app` param still goes straight to the app, and `?lab`
 * to the lab, so no existing link changes.
 */

const base = import.meta.env.BASE_URL;

interface Stat {
  readonly figure: string;
  readonly label: string;
}

const STATS: readonly Stat[] = [
  { figure: "12", label: "intrusions" },
  {
    figure: "41",
    label: "ATT&CK techniques",
  },
  {
    figure: "57k",
    label: "labelled events",
  },
  {
    figure: "6",
    label: "rule languages",
  },
];

interface Differentiator {
  readonly title: string;
  readonly body: string;
}

const DIFFERENTIATORS: readonly Differentiator[] =
  [
    {
      title:
        "Ground truth by construction",
      body: "Every event is labelled benign or malicious and mapped to a technique, decided by the generator before the event was written, not guessed afterwards.",
    },
    {
      title:
        "False-positive realism",
      body: "Benign activity produces the same shapes as the attacks, so a rule's precision is tested against look-alikes the way it would be in production.",
    },
    {
      title: "Zero infrastructure",
      body: "It all runs in this browser tab from a seed, no hosts to stand up, no agents to deploy, and the same seed regenerates the same world.",
    },
  ];

export function LandingPage() {
  return (
    <div className="landing">
      <header className="landing-hero">
        <p className="landing-eyebrow">
          Endomorph
        </p>
        <h1 className="landing-title">
          Detection telemetry that ships
          with the answer key
        </h1>
        <p className="landing-lede">
          Endomorph generates a synthetic
          enterprise under attack and
          labels every event benign or
          malicious <em>before</em> it
          writes it. So when you score a
          detection rule, the precision
          and recall are{" "}
          <strong>counted</strong> from
          ground truth, not estimated
          from a capture nobody fully
          labelled.
        </p>

        <div className="landing-cta">
          <a
            className="landing-btn landing-btn-primary"
            href={`${base}?lab`}
          >
            Open the Detection Lab
            <span aria-hidden="true">
              {" "}
              →
            </span>
          </a>
          <a
            className="landing-btn landing-btn-ghost"
            href={`${base}?app`}
          >
            Try an investigation
            <span aria-hidden="true">
              {" "}
              →
            </span>
          </a>
        </div>

        <dl className="landing-stats">
          {STATS.map((stat) => (
            <div
              key={stat.label}
              className="landing-stat"
            >
              <dt className="landing-stat-figure">
                {stat.figure}
              </dt>
              <dd className="landing-stat-label">
                {stat.label}
              </dd>
            </div>
          ))}
        </dl>
      </header>

      <main className="landing-main">
        <section className="landing-diffs">
          {DIFFERENTIATORS.map((item) => (
            <article
              key={item.title}
              className="landing-diff"
            >
              <h2>{item.title}</h2>
              <p>{item.body}</p>
            </article>
          ))}
        </section>

        <section className="landing-lang">
          <div className="landing-lang-copy">
            <h2>
              Bring a rule in the language
              you already write
            </h2>
            <p>
              Paste Sigma, Kusto (KQL),
              Splunk (SPL), or Elastic
              (EQL). Endomorph scores it
              against the labelled corpus
              in under two seconds and
              shows the exact benign events
              it fired on and the malicious
              ones it missed.
            </p>
            <a
              className="landing-inline-link"
              href={`${base}?lab`}
            >
              Score a rule now →
            </a>
          </div>
          <pre className="landing-code">
            <code>
              {`process where
  process.name : "*powershell.exe"
  and process.command_line : "*-enc*"

→ TP 1   FP 0   FN 0
  precision 1.000   recall 1.000`}
            </code>
          </pre>
        </section>
      </main>

      <footer className="landing-footer">
        <span>
          Deterministic security-telemetry
          generator &amp; detection-evaluation
          platform.
        </span>
        <a href={`${base}?lab`}>
          Detection Lab
        </a>
        <a href={`${base}?app`}>
          Investigation
        </a>
      </footer>
    </div>
  );
}
