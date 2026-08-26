import { useState } from "react";

import {
  ATTACK_PLANS,
} from "@endomorph/fabric";

import type {
  EvasionLevel,
} from "@endomorph/fabric";

import {
  generateProfileCorpus,
} from "./detectionReview";

import type {
  ProfileCorpusResult,
} from "./detectionReview";

import {
  CustomRuleTester,
} from "./CustomRuleTester";

import "./OrgProfilePanel.css";

/**
 * The digital-twin panel: generate a corpus shaped like your own estate.
 *
 * Everything else in the lab scores against the shipped Acme world. This runs
 * the same deterministic generator in the browser against a client profile --
 * the org's name, size, domain, and a seed -- so a detection engineer can see
 * how their rules do against telemetry shaped like their environment, and prove
 * to themselves that the shipped numbers were not an artifact of one world. The
 * same profile and seed always reproduce the same corpus.
 */
export function OrgProfilePanel() {
  const [organizationName, setOrg] =
    useState("Northwind Health");
  const [domain, setDomain] = useState(
    "northwind.test",
  );
  const [headcount, setHeadcount] =
    useState(120);
  const [seed, setSeed] = useState(4242);
  const [planId, setPlanId] = useState(
    ATTACK_PLANS[0].id,
  );
  const [evasion, setEvasion] =
    useState<EvasionLevel>("standard");

  const [result, setResult] =
    useState<ProfileCorpusResult | null>(
      null,
    );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<
    string | null
  >(null);

  const generate = () => {
    setBusy(true);
    setError(null);

    // Yield once so the "Generating…" state paints before the synchronous
    // generation (tens of ms for a default estate, more for a large one).
    window.setTimeout(() => {
      try {
        setResult(
          generateProfileCorpus({
            seed,
            organizationName:
              organizationName.trim() ||
              "Acme Financial",
            headcount: Math.max(
              10,
              Math.min(2000, headcount),
            ),
            domain:
              domain.trim() || "acme.test",
            planId,
            evasion,
          }),
        );
      } catch (caught) {
        setResult(null);
        setError(
          caught instanceof Error
            ? caught.message
            : "The corpus could not be generated.",
        );
      } finally {
        setBusy(false);
      }
    }, 20);
  };

  return (
    <section
      className="org-panel"
      aria-label="Shape a corpus like your estate"
    >
      <div className="org-panel-head">
        <p className="eyebrow">
          Digital twin
        </p>
        <h3>
          Shape a corpus like your own
          estate
        </h3>
        <p className="org-panel-lede">
          The scenarios above are a
          generated Acme world. Here you
          generate a fresh one from a
          profile of <em>your</em> estate
          — its name, size, and domain —
          entirely in the browser, then
          score your rules against
          telemetry shaped like your
          environment. Set{" "}
          <em>evasion</em> to{" "}
          <em>stealth</em> to render the
          same intrusion with the loud,
          keyable details removed — a rule
          that catches the standard variant
          may miss it. The same profile and
          seed reproduce the same corpus,
          byte for byte.
        </p>
      </div>

      <div className="org-form">
        <label className="org-field">
          <span>Organization</span>
          <input
            type="text"
            value={organizationName}
            onChange={(event) =>
              setOrg(event.target.value)
            }
          />
        </label>

        <label className="org-field">
          <span>Domain</span>
          <input
            type="text"
            value={domain}
            onChange={(event) =>
              setDomain(
                event.target.value,
              )
            }
          />
        </label>

        <label className="org-field org-field-narrow">
          <span>Headcount</span>
          <input
            type="number"
            min={10}
            max={2000}
            value={headcount}
            onChange={(event) =>
              setHeadcount(
                Number(
                  event.target.value,
                ),
              )
            }
          />
        </label>

        <label className="org-field org-field-narrow">
          <span>Seed</span>
          <input
            type="number"
            value={seed}
            onChange={(event) =>
              setSeed(
                Number(
                  event.target.value,
                ),
              )
            }
          />
        </label>

        <label className="org-field">
          <span>Intrusion</span>
          <select
            value={planId}
            onChange={(event) =>
              setPlanId(
                event.target.value,
              )
            }
          >
            {ATTACK_PLANS.map((plan) => (
              <option
                key={plan.id}
                value={plan.id}
              >
                {plan.name}
              </option>
            ))}
          </select>
        </label>

        <label className="org-field org-field-narrow">
          <span>Evasion</span>
          <select
            value={evasion}
            onChange={(event) =>
              setEvasion(
                event.target
                  .value as EvasionLevel,
              )
            }
          >
            <option value="standard">
              Standard
            </option>
            <option value="stealth">
              Stealth
            </option>
          </select>
        </label>

        <button
          type="button"
          className="org-generate"
          onClick={generate}
          disabled={busy}
        >
          {busy
            ? "Generating…"
            : "Generate corpus"}
        </button>
      </div>

      {error && (
        <p className="org-error">
          {error}
        </p>
      )}

      {result && (
        <>
          <p className="org-stats">
            Generated{" "}
            <strong>
              {result.records.length.toLocaleString()}
            </strong>{" "}
            records for{" "}
            <strong>
              {result.organizationName}
            </strong>{" "}
            (
            <strong>
              {result.maliciousCount}
            </strong>{" "}
            malicious)
            {result.sampleHost && (
              <>
                {" "}
                — e.g. host{" "}
                <code>
                  {result.sampleHost}
                </code>
                {result.sampleUser && (
                  <>
                    , user{" "}
                    <code>
                      {result.sampleUser}
                    </code>
                  </>
                )}
              </>
            )}
            . Now score a rule against it:
          </p>

          <CustomRuleTester
            records={result.records}
          />
        </>
      )}
    </section>
  );
}
