# Polymorph Project State

## Project Identity

Polymorph is a deterministic, schema-driven cybersecurity simulation and training runtime. It models one shared synthetic enterprise world, applies typed append-only events, rebuilds security-application projections from that history, and runs validated declarative scenarios through student and instructor workflows.

Polymorph is not a phishing kit, credential-harvesting system, arbitrary code-execution environment, or production security-control platform. Current scenarios and data are synthetic only.

## Current Milestone

**Polymorph v1 product scope is complete.**

The active release slice is the final v1 packaging, browser-regression, documentation, and public-hosting pass. The release branch is `release/v1` and the release PR is #40.

The v1 exit condition is:

- frozen dependency install succeeds;
- workspace build succeeds;
- lint succeeds;
- deterministic unit/integration suite succeeds;
- Chromium Playwright critical-path suite succeeds;
- the hosted GitHub Pages build loads all three scenarios correctly under the repository base path;
- first-time tester documentation is published;
- the release PR is merged and tagged `v1.0.0`.

## V1 Product Surface

### Deterministic runtime

- pnpm workspace/monorepo
- canonical normalized `WorldState`
- deterministic virtual clock and seeded pseudo-random generator
- typed authentication, identity, session, process, file, network, endpoint, and alert events
- append-only in-memory event store
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
- explicit finalization boundary that does not append fake simulation events
- deterministic partial/full objective scoring
- optional authored response-quality penalties and rationale
- optional ground-truth incident summary and event annotations
- semantic validation of response actions, objectives, and ground-truth references

### Student investigation experience

- alert-first workspace
- correlated SIEM timeline
- endpoint and identity pivots
- evidence collection by immutable event ID
- analyst case state separate from canonical world state
- analyst-authored findings linked to collected evidence
- scenario-declared response-action chooser
- beneficial and harmful response choices
- explicit investigation finalization
- 0%, partial, and full objective outcomes
- post-finalization response-quality penalty and final score
- finalized case becomes read-only until reset
- reset reconstructs a clean deterministic run

### Instructor review

- explicit local Instructor mode
- ground truth hidden during active student workflow
- post-finalization ground-truth incident summary
- annotated source-event timeline
- performed response-action review
- authored rationale for assessed actions
- objective score, penalty, and final score review

Instructor mode in v1 is a presentation boundary, not real authentication/authorization.

### V1 scenario set

1. Finance account compromise with suspicious login, encoded PowerShell, and correlated outbound activity.
2. HR malware-beacon incident with a compromised session and unsigned executable activity.
3. Cloud-admin compromise with suspicious privileged tooling and outbound activity.

All three are ordinary JSON scenarios using the same compiler/runtime/UI; there is no scenario-specific TypeScript execution path.

### Release/testability

- in-product scenario selector
- Student/Instructor mode control
- preserved scenario deep links
- first-time tester guide with feedback template
- Playwright browser-regression suite for the critical v1 workflows
- GitHub Actions CI
- GitHub Pages deployment workflow for a no-install friend-testing URL
- base-path-safe Vite/scenario loading for repository-hosted deployment

## Post-v1 Priorities

Do not expand architecture merely to make the repository look larger. The next work should be driven by actual tester feedback and concrete product needs.

Likely post-v1 sequence:

1. Collect first-time user feedback and fix usability defects exposed by real testers.
2. Add durable run persistence and a small server runtime when saved/resumable runs are required.
3. Add real student/instructor authentication and authorization before using hidden answers for real assessment.
4. Add a headless scenario validation/run CLI.
5. Expand scenario transitions, triggers, branches, and telemetry only when new scenarios require them.
6. Add additional projections such as email or endpoint inventory only when a scenario needs them.
7. Design a plugin SDK only after at least one external extension requirement is concrete.
8. Explore AI-assisted scenario compilation only as an untrusted compiler frontend into validated declarative specs.

## Explicitly Deferred

Until requirements justify them, do not add:

- Kafka
- Kubernetes
- Redis
- RabbitMQ
- microservices
- GraphQL
- OpenSearch / Elasticsearch
- Temporal
- multiple databases
- service meshes
- arbitrary generated code execution

## Technology In Use

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

## Continuity Rule

At the beginning of future development sessions, read:

1. `PROJECT_STATE.md`
2. `ROADMAP.md`
3. `ARCHITECTURE.md`
4. `TESTER_GUIDE.md`
5. the latest open issues/PRs and recent tester feedback

The immediate post-v1 planning input should be real tester feedback, not speculative infrastructure work.
