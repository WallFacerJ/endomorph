# Endomorph Strategy

Updated: 2026-08-24

This is the decision record for *where Endomorph plays*. `COMPETITIVE_RESEARCH.md`
holds the market evidence; `ENTERPRISE_VISION.md` and `ROADMAP.md` hold the full
product ambition. This document is narrower and more opinionated: given a solo
builder and finite time, it records the one bet worth making and what to build
against it.

## The decision

**Lead with detection engineering, not training.** Endomorph's defensible moat
is not the analyst console — every competitor has one, and the strong ones have
far more content, brand, certifications, and infrastructure. The moat is that
**ground truth is known by construction**: reproducible, seed-varied,
per-event-labelled, ATT&CK-mapped telemetry with realistic false-positive noise,
exportable and scoreable, running in a browser with zero infrastructure.

The investigation console remains — as the demo that makes the data tangible and
the on-ramp to a training product later — but it is not the product to win on.

## Why: two arenas, not one

The market Endomorph *looks* like it is in is not the market it can win.

**Arena A — SOC training and cyber ranges.** TryHackMe, Hack The Box,
CyberDefenders, LetsDefend, RangeForce, Immersive, Cyberbit, SimSpace. They win
on content breadth, brand, certs, real infrastructure, and team features — all
of which take teams and capital and years to seed. A solo project cannot
out-content this arena. Endomorph's only edge here is real but narrow:
unmemorisable, infinitely-varied scenarios where theirs are hand-authored,
finite, and leak to write-ups. Playing to win here is the losing race
`COMPETITIVE_RESEARCH.md` already warned against.

**Arena B — detection data and validation.** Atomic Red Team, Caldera, Splunk
Attack Range, DetectionLab, the BAS vendors (AttackIQ / SafeBreach / Cymulate),
and public datasets (CIC-IDS, Mordor). Everyone here generates or ships
telemetry, but each is weak at the specific job: emulators need real hosts and
label only "what I ran"; detection labs are heavy infrastructure; BAS validates
controls through agents; public datasets are static, dated, and trivially
separable. **None combines ground truth + benign noise + seeded variation + a
scoring harness + zero infra.** That cluster is Endomorph, and only Endomorph.

The two capabilities Endomorph concedes — hands-on depth (real shells) and
content breadth — are exactly the ones that cost teams and capital to close,
which is why chasing them is the wrong fight.

## The capability moat

The full comparison is in the strategy artifact; the short version is the column
cluster no other product is strong across:

- **ground truth by construction** — every event labelled benign/malicious and
  mapped to a technique, decided before it was written;
- **seeded variation** — change the seed and the enterprise changes while the
  technique holds;
- **false-positive realism** — benign activity that produces the same shapes as
  attacks (the "beacon must not be the loudest on its host" invariant);
- **a scoring harness** — precision, recall, technique coverage, and now
  cross-seed robustness;
- **zero infrastructure** — runs in a browser tab; a single-file offline bundle.

## Next steps, in priority order

### Now — sharpen the wedge (weeks, solo-doable)

1. **Make the eval loop a product, not a CLI.** Bring-your-own-Sigma →
   precision/recall/FP/coverage. *Done:* `pnpm evaluate:robustness` scores a
   ruleset across many seeded enterprises and reports whether each rule
   generalises (stable) or memorised one world (fragile). And the hosted app now
   has a **browser Detection Lab** with its own front door at `?lab` — a
   detection engineer opens the link, picks a scenario, and scores a pasted
   Sigma rule against the labelled corpus in under two seconds, no investigation
   to play through and no repo checkout. The pitch is now a thing they just did.
   Remaining: multi-seed robustness in the browser is deferred (each seed
   regenerates a full enterprise, too slow for a UI); it stays a CLI/backend
   job, and a hosted version would run it server-side.
2. **Publish a stable benchmark corpus.** *Generation done:* `pnpm benchmark`
   writes the labelled telemetry as versioned ECS/OCSF NDJSON plus a manifest —
   "the Endomorph Detection Benchmark v1.0: 6 intrusions, 22 techniques, 27.8k
   records, seeded." Remaining is *distribution*: put v1.0 somewhere citable (a
   tagged GitHub release or a public URL) so it becomes a standard others point
   back to, not just a command they could run.
3. **Grow ATT&CK coverage deliberately.** Technique breadth is the number
   detection engineers judge a corpus on. Six plans is the honest gap; each new
   plan is pure event modelling, no infrastructure. (The benchmark manifest now
   makes the number — 22 techniques — visible and diffable.)
4. **Make FP realism a measured headline.** *Done:* `pnpm noise-floor` reports,
   per technique, how many benign events share its event types — the
   false-positive floor for an unspecific rule. At the shipped seed 18/22
   techniques are buried among 10x+ benign look-alikes, a floor a corpus with
   separable malicious traffic cannot offer.

   *The tool's first finding, now acted on:* it flagged two exposed
   identity-lifecycle techniques (T1098, T1098.003) — the background never
   performed benign account-enables or role grants, so a rule keyed on them
   scored a perfect precision it would never see in production. Benign
   `ACCOUNT_ENABLED` / `ROLE_GRANTED` activity was added to
   `generateBackgroundActivity`, designed distinguishable: the crafted
   `privileged-role-grant` rule held at 1.000 (it keys on administrative roles;
   the benign grants were not), while the naive `account-reenabled` rule dropped
   to a realistic ~0.3 (keying on "an account was enabled" catches the ones that
   are supposed to happen too). Baseline regenerated, docs corrected. This is
   the measure → find weakness → improve loop the noise floor exists to drive,
   and it now has one full turn on record.

### Next — deepen where it compounds both audiences (months)

5. **One cross-domain incident into a new event domain** (cloud or
   identity-federation audit — pure events, no interactive infra). Serves the
   benchmark's technique coverage *and* the console's "incident crosses four+
   domains" goal at once.
6. **Seeded attack variation (Phase 4, lite).** Vary the *attack*, not just the
   enterprise: the same plan at different evasion levels. Multiplies benchmark
   size and training replayability with zero infrastructure, and directly
   stresses whether a rule generalises.

### Later — defer (capital-intensive; incumbents already win)

7. **Interactive Range — containers / microVMs.** The most expensive item, in
   the exact arena HTB / RangeForce / SimSpace already own. The synthetic host
   model gives ~80% of the investigative value at 0% of the cost. Build only
   when a paying customer requires real shells.
8. **Enterprise control plane — server, tenants, SSO, teams.** Necessary to sell
   to organisations, pure cost until there is one to sell to. Start only with a
   design partner pulling for it.

## Guardrails

- **Breadth is the enemy.** The nine-phase roadmap is a multi-team plan. As one
  builder, pick the wedge and starve the rest.
- **The gravity of Arena A.** Training is where the visible demos live and will
  keep pulling focus. Every feature should ask whether it strengthens the data
  moat or just polishes the demo.
- **Defend the moat.** Determinism and FP realism are the edge; a careless
  feature can erode either. The "beacon must not be the loudest" discipline is
  exactly the kind of invariant to keep guarding. (A beaconing-detection feature
  was built and reverted this session precisely because it contradicted it.)
- **Validate the buyer before building the product.** Talk to five detection
  engineers and detection-content maintainers. If "score my rule across seeds"
  makes them lean in, the wedge is real; if not, the console-as-training path is
  the fallback, not the lead.

## GTM shape, if the wedge validates

Open-source the generator and benchmark core to earn inbound, citations, and
trust. Monetise what infrastructure cannot cheaply copy: eval-at-scale, private
digital twins of a customer's estate, and hosted continuous rule scoring. The
investigation console stays the thing that makes it tangible in a demo, and the
door into a training product later, once there is a company to build it.


## Build program — "increase value and usefulness" (sequenced)

After validation, these are the value levers in priority order. Each notes what
it builds on so it is not a green field.

1. **Detection-as-code CI — DONE.** Scoring a whole Sigma folder (`--sigma`) and
   gating on regression (`--baseline`) already worked; `docs/detection-as-code.md`
   and `.github/workflows/detection-ci.example.yml` package it so a detection-rules
   repo can adopt it. *Remaining:* publish the generator (npm or a container) so
   the CI job does not have to build from source.

2. **Meet engineers in their own language.** Most write Splunk SPL, Elastic
   EQL/ES|QL, or Sentinel KQL, not Sigma. Add importers/adapters so they can
   score *their* rules. Widest-reach unlock. *Builds on* the rule model and the
   Sigma importer (`packages/fabric/src/sigma.ts`).

3. **Add the domains real detections live in.** Email (headers/links/attachments),
   cloud/SaaS audit (OAuth, IAM, control plane), DNS/proxy, and Sysmon-fidelity
   Windows event codes. Each unlocks many ATT&CK techniques and more addressable
   teams; the noise floor guides each domain's FP realism. Biggest moat-deepener
   (roadmap Phase 3).

4. **Point it at your own org.** Surface the existing `--profile` flag as a
   product feature so a team gets a corpus shaped like their estate. The
   digital-twin/enterprise wedge.

5. **AI detection-agent eval.** Use the labelled corpus as a ground-truth eval
   set for LLM-generated detections and AI SOC agents. Timely, and exactly what
   ground-truth-by-construction is for.

6. **Distribution/friction.** A 10-second landing page, shareable result
   permalinks, a coverage badge for a detection repo README, and shipping the
   generator + scorer as an npm package/API.

Still deferred: interactive Range (containers/VMs) and the multi-user enterprise
control plane — capital-intensive, in arenas incumbents own, wrong until a
customer pulls.
