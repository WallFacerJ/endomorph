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
   precision/recall/FP/coverage. *Done in part:* `pnpm evaluate:robustness`
   scores a ruleset across many seeded enterprises and reports whether each rule
   generalises (stable) or memorised one world (fragile) — the measurement no
   fixed corpus can make. Next: a browser-facing version of this, not only a
   CLI.
2. **Publish a stable benchmark corpus.** Ship the labelled telemetry as
   versioned ECS/OCSF NDJSON — "the Endomorph Detection Benchmark: N intrusions,
   M techniques, seeded." Marketing *and* a standard others cite back.
3. **Grow ATT&CK coverage deliberately.** Technique breadth is the number
   detection engineers judge a corpus on. Six plans is the honest gap; each new
   plan is pure event modelling, no infrastructure.
4. **Make FP realism a measured headline.** Quantify and publish the noise floor
   — "malicious traffic is not the loudest on its host" is a claim no static
   dataset can make.

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
