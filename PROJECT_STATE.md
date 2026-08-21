# Polymorph Project State

## Project identity

Polymorph is evolving from a deterministic cybersecurity training simulator into a **deterministic cyber-operations digital twin and enterprise cyber-readiness platform**.

The foundation remains one shared synthetic enterprise world with typed append-only events, deterministic replay, validated declarative scenarios, and multiple security-tool projections over the same history. Post-v1 work now prioritizes substantially deeper investigation, interactive systems, enterprise incident handling, team readiness, and customer-specific digital twins.

Polymorph remains for synthetic, isolated security simulation. It must not become a credential-harvesting product, uncontrolled arbitrary code-execution service, or system for attacking external targets.

## Current milestone

**Enterprise Evolution Phase 1: deep investigation and professional tool identity.**

Polymorph v1.0.0 is complete. The v1 architecture proved deterministic scenarios, correlated identity/EDR/SIEM projections, analyst case state, response outcomes, instructor review, and browser delivery.

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

A mature Polymorph run should feel like operating a living enterprise during an incident:

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

1. Build a real SIEM workspace with search/query, time controls, facets, raw events, pivots, and enough noisy telemetry to require analysis.
2. Build a real EDR workspace with endpoint inventory, process trees, file/network context, and endpoint-scoped actions.
3. Expand Identity into account/session/access/risk/history analysis rather than a summary panel.
4. Redesign Case into an incident-command graph connecting evidence, entities, hypotheses, tasks, findings, decisions, and response actions.
5. Move professional response work out of obvious multiple-choice cards and into the relevant tool/system context.
6. Hide explicit objectives/scores during active professional-mode runs by default; preserve guided assistance as an optional mode.
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

- **Polymorph Fabric** - shared enterprise digital twin
- **Polymorph Ops** - distinct professional security applications
- **Polymorph Range** - interactive isolated systems
- **Polymorph Case** - investigation/incident command graph
- **Polymorph Replay** - rewind/branch/compare time machine
- **Polymorph Forge** - scenario/digital-twin authoring
- **Polymorph Control** - enterprise management/readiness plane

These names are working architecture/product concepts, not locked branding.

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

> **Does this make Polymorph feel more like a living, technically deep enterprise cyber-operations environment and less like a quiz or course?**
