# Endomorph Project State

## Positioning change

Endomorph is positioned as **a generator of labelled security telemetry**, not as a cyber-range competitor.

The range market is not winnable by a solo project: Hack The Box has millions of members, accredited certifications, and framework-mapped enterprise assessments, and CyberDefenders holds the blue-team niche. Competing on lab count is a losing race, because those platforms hand-author labs with teams.

The generator inverts that constraint. Labs are generated, not authored, and ground truth is known by construction rather than annotated afterwards. That supports a second audience the range platforms do not serve: detection engineers who need labelled corpora to measure rule efficacy, and who currently have almost nothing to measure against.

The investigation console remains, as one consumer of a generated world. Detection evaluation is the other.

## Project identity

Endomorph is evolving from a deterministic cybersecurity training simulator into a **deterministic cyber-operations digital twin and enterprise cyber-readiness platform**.

The foundation remains one shared synthetic enterprise world with typed append-only events, deterministic replay, validated declarative scenarios, and multiple security-tool projections over the same history. Post-v1 work now prioritizes substantially deeper investigation, interactive systems, enterprise incident handling, team readiness, and customer-specific digital twins.

Endomorph remains for synthetic, isolated security simulation. It must not become a credential-harvesting product, uncontrolled arbitrary code-execution service, or system for attacking external targets.

## Current milestone

**Enterprise Evolution Phase 1: deep investigation and professional tool identity.**

The SIEM, EDR, and Identity workspaces are delivered. Phase 1 now also covers the deterministic enterprise generator in `packages/fabric`, pulled forward from the Fabric layer because Phase 1's own exit criteria depend on generated scale and noise that the three hand-authored scenarios cannot provide. See the scope change in `ROADMAP.md`.

Generator status: topology, five-day background activity with per-person habits, incident planting, and scenario compilation are all delivered. The shipped generated scenario is 444 entities and 17,904 events against the 15 and 34 of the largest hand-authored one.

Case is now an incident-command graph: entities, connections, and indicators are derived from the analyst's collected evidence rather than retyped, with incident phase, hypotheses, tasks, and decisions as real workflow state.

Remaining in Phase 1: moving response work out of answer cards and into tool context, and scoring investigation coverage. The evidence graph makes coverage measurable for the first time, since it records which entities the analyst actually reached.

Endomorph v1.0.0 is complete. The v1 architecture proved deterministic scenarios, correlated identity/EDR/SIEM projections, analyst case state, response outcomes, instructor review, and browser delivery.

First-time tester feedback exposed the main product gap: the experience is coherent but too shallow, too course-like, too visually uniform, and not sufficiently technical to feel like a serious cyber-operations product.

The current north star and competitive requirements are documented in:

- `COMPETITIVE_RESEARCH.md`
- `ENTERPRISE_VISION.md`
- `ROADMAP.md`

## Direct tester feedback driving the reset

Recurring feedback from first-time users:

- the current investigations feel juvenile and surface-level;
- response selection resembles an entry-level multiple-choice course more than incident response;
- technical depth is too low and the interface feels simplistic;
- SIEM/EDR/identity/case sections do not feel sufficiently differentiated;
- Case feels optional rather than necessary to operate the investigation;
- the product does not yet have a strong identity or sense of scale;
- testers want the ability to enter isolated synthetic/virtualized enterprise systems, acquire evidence, and perform red/blue incident work directly.

These are now product requirements, not polish suggestions.

## Product north star

A mature Endomorph run should feel like operating a living enterprise during an incident:

- investigate an ambiguous alert among normal/noisy activity;
- query a real-feeling SIEM rather than scroll a curated event list;
- pivot into distinct EDR, Identity, Network, Email, Cloud, Threat Intel, and other tools;
- inspect deep entity history and relationships;
- enter isolated investigation-critical systems through a safe Range layer;
- inspect processes, files, configuration, logs, services, connections, and artifacts;
- build and manage a connected incident case with evidence, hypotheses, tasks, owners, actions, and decisions;
- contain, eradicate, recover, validate, and document the incident;
- replay or branch the run later to understand alternative outcomes;
- support teams, instructors/managers, red/purple exercises, and eventually AI-agent validation over the same deterministic enterprise.

## Existing foundation

### Deterministic runtime

- pnpm workspace/monorepo
- canonical normalized `WorldState`
- deterministic virtual clock and seeded pseudo-random generator
- deterministic enterprise generator (`packages/fabric`): splittable random cursor, topology, multi-day background activity, incident planting, scenario compilation, and a generator CLI
- typed authentication, identity, session, process, file, network, endpoint, and alert events
- append-only event store
- deterministic reducers, replay, snapshots, and snapshot-assisted replay
- semantic world/event/reference validation
- deterministic serialization/deserialization
- synchronous event bus
- pure replayable projection contract
- identity projection
- EDR projection
- SIEM projection
- cross-projection coherence tests over shared event IDs/entity IDs

### Declarative scenario runtime

- versioned Zod-backed JSON scenario contract
- semantic scenario compiler
- author-friendly world seeds compiled into canonical world state
- ordered opening event history
- ordered deterministic response actions
- investigation focus metadata
- declarative account/session objectives
- deterministic active/finalized outcome evaluation
- deterministic scoring and response-quality penalties
- optional ground-truth incident metadata
- semantic validation of response actions, objectives, and ground-truth references

### Current analyst/instructor surface

- alert-first browser workspace
- correlated timeline
- endpoint and identity pivots
- evidence collection by event ID
- analyst findings linked to evidence
- response-action chooser
- explicit finalization and score/result
- finalized read-only case
- instructor ground-truth review
- three JSON-authored scenarios
- scenario selector and visual themes
- Playwright browser-regression suite
- GitHub Pages/public testing workflow

This surface is now considered the v1 baseline to be replaced/refactored where needed for enterprise depth.

## Immediate implementation priorities

Items 1-3 are delivered. The generator now supplies them with data at a scale that requires analysis rather than scrolling.

1. ~~Build a real SIEM workspace with search/query, time controls, facets, raw events, pivots, and enough noisy telemetry to require analysis.~~ **Done.**
2. ~~Build a real EDR workspace with endpoint inventory, process trees, file/network context, and endpoint-scoped actions.~~ **Done.**
3. ~~Expand Identity into account/session/access/risk/history analysis rather than a summary panel.~~ **Done.**
4. ~~Redesign Case into an incident-command graph connecting evidence, entities, hypotheses, tasks, findings, decisions, and response actions.~~ **Done.**
5. Move professional response work out of obvious multiple-choice cards and into the relevant tool/system context. **Next.**
   Professional mode itself is done: runs hide the live objective checklist and running score until finalization, with guided mode available for onboarding.
6. ~~Hide explicit objectives/scores during active professional-mode runs by default; preserve guided assistance as an optional mode.~~ **Done.**
7. Design and build the Synthetic Infrastructure Fabric fidelity ladder: deterministic synthetic hosts -> isolated containers -> microVM/full VM where necessary.
8. Add telemetry domains and scenario complexity only in service of genuinely deeper incidents.

## Enterprise requirements are now first-class

The product is intended to become marketable/sellable to organizations. Future architecture must account for:

- durable server-backed runs;
- organizations/tenants;
- teams, users, cohorts, and roles;
- SSO/SAML/OIDC and SCIM;
- server-enforced authorization;
- auditability and retention;
- assignments/campaigns and collaboration;
- readiness baselines and skill-gap analytics;
- ATT&CK/NICE mapping;
- incident-process metrics and reporting;
- APIs/webhooks/integrations;
- managed/private/on-prem deployment options when justified;
- capacity/cost controls for interactive range infrastructure.

## Architecture policy change after v1 feedback

Earlier project guidance intentionally deferred heavy infrastructure until a demonstrated requirement existed. That requirement now exists for interactive enterprise systems and durable multi-user operation.

Therefore:

- container-backed and eventually VM-backed range infrastructure is explicitly in scope;
- a server runtime and database are explicitly in scope;
- orchestration, queues, caches, search engines, and service decomposition may be introduced when measured scale/reliability requirements justify them;
- Kubernetes, Redis, Kafka, OpenSearch, etc. are still implementation choices rather than status symbols and should not be added prematurely.

## Product identity

Working product layers are documented in `ENTERPRISE_VISION.md`:

- **Endomorph Fabric** - shared enterprise digital twin
- **Endomorph Ops** - distinct professional security applications
- **Endomorph Range** - interactive isolated systems
- **Endomorph Case** - investigation/incident command graph
- **Endomorph Replay** - rewind/branch/compare time machine
- **Endomorph Forge** - scenario/digital-twin authoring
- **Endomorph Control** - enterprise management/readiness plane

These names are working architecture/product concepts, not locked branding.

## Known debt

Recorded so it is decided deliberately rather than discovered later.

- **`moduleResolution: "Bundler"` repo-wide.** Built packages cannot run under plain node, which is why `packages/fabric` carries explicit `.js` import extensions and the rest of the repo does not. Phases 5 and 7 assume a server runtime and headless authoring; `NodeNext` everywhere is the fix and it gets more expensive the longer it waits.
- **Event vocabulary lives in `packages/simulation`.** `simulationEvent.ts` is pure type definitions importing only from `@endomorph/domain`, which already owns `DomainEvent`. Today `fabric` depends on the whole runtime for type names alone. Moving the vocabulary down into `domain` is a mechanical 29-import refactor.
- **Business context is surfaced on the entity consoles, not yet in SIEM or Case.** `packages/fabric` emits asset criticality, rationale, and business unit keyed by entity id; it now rides on the scenario as an optional `assets` block and the Endpoint and Identity consoles badge and triage by it. SIEM results do not yet flag events that touch a critical asset, and Case does not weight a finding by the criticality of what it reached.
- **The incident plan library is six hand-written plans, not a generator.** `packages/fabric` now carries an ATT&CK-mapped plan library (`ATTACK_PLANS`: credential compromise, privileged insider, service-account abuse, dormant-account revival, macro execution, cloud-role elevation), so the earlier "one hardcoded chain" gap is closed. The remaining gap is that new incident shapes are still authored by hand rather than composed from a technique catalogue -- Phase 4's concern.
- **SIEM search is a linear scan.** Fine at 17.9k events; the cross-domain incidents Phase 3 describes will need an index.

## Technology currently in use

- React
- TypeScript
- Vite
- pnpm workspaces
- Zod
- Vitest
- Playwright
- GitHub Actions
- GitHub Pages
- Oxlint

Expected future technologies will be selected per the enterprise roadmap, with server/runtime and isolated execution infrastructure now justified.

## Continuity rule

At the beginning of future development sessions, read:

1. `PROJECT_STATE.md`
2. `ENTERPRISE_VISION.md`
3. `COMPETITIVE_RESEARCH.md`
4. `ROADMAP.md`
5. `ARCHITECTURE.md`
6. the latest open issues/PRs and tester feedback

Future feature proposals should be evaluated against one question:

> **Does this make Endomorph feel more like a living, technically deep enterprise cyber-operations environment and less like a quiz or course?**
