# Polymorph Roadmap

Polymorph follows one rule: **complexity should emerge from demonstrated product requirements.** Infrastructure or abstractions are not milestones by themselves.

## V1 - Local deterministic training product

Status: **complete; release validation/deployment in progress on PR #40.**

V1 proves that one reusable deterministic runtime can power a student investigation, a scored response, an instructor review, and multiple declarative cybersecurity scenarios without hardcoding each incident into the UI.

### Foundation - complete

- pnpm workspace with `apps/web`, `packages/domain`, `packages/schema`, and `packages/simulation`
- TypeScript, React, Vite, Zod, Vitest, Oxlint, GitHub Actions
- canonical normalized synthetic world models
- semantic entity/reference validation
- deterministic virtual clock and seeded random foundation
- deterministic serialization/deserialization

### Event/runtime - complete for v1

- typed authentication, account, session, process, file, network, endpoint, and alert event families
- append-only event store
- deterministic world reducers
- replay and snapshots
- synchronous event bus
- pure projection framework
- identity, EDR, and SIEM projections
- cross-projection event/entity coherence coverage

### Declarative scenarios - complete for v1

- versioned JSON scenario contract
- Zod structural validation
- semantic scenario compiler
- opening timelines and deterministic response actions
- investigation focus metadata
- declarative objectives
- explicit finalization
- deterministic objective scoring
- authored response-quality penalties
- authored ground-truth timeline metadata
- validation of objective, response-action, and ground-truth references

### Analyst experience - complete for v1

- alert-first investigation workspace
- SIEM timeline
- endpoint and identity pivots
- evidence collection
- analyst-authored findings with evidence links
- beneficial and harmful response choices
- partial/full objective progress
- explicit investigation submission
- success/failure results
- transparent objective score, response penalty, and final score
- finalized read-only case
- deterministic reset

### Instructor experience - complete for v1

- explicit local Instructor mode
- ground truth hidden during the active student workflow
- post-finalization incident summary and annotated source timeline
- performed-action review and authored penalty rationale
- deterministic score review

V1 instructor mode is intentionally **not** a real authorization boundary.

### V1 content - complete

- Finance account compromise / encoded PowerShell
- HR malware beacon / unsigned updater
- privileged cloud-admin compromise / suspicious administrative tooling

All are JSON-authored and execute through the same compiler/runtime/UI.

### V1 release quality - final release slice

- scenario selector
- Student/Instructor mode control
- first-time tester guide and feedback template
- Playwright critical-path browser suite
- CI coverage for build, lint, unit/integration, and browser tests
- GitHub Pages deployment for public friend testing
- v1.0.0 package/release marker

Exit criteria:

- fresh clone installs with the frozen lockfile;
- root build/lint/unit/integration tests pass;
- Chromium browser tests pass;
- all three scenarios work in the hosted build;
- public test URL and tester guide are shareable;
- release is tagged `v1.0.0`.

---

## Post-v1 Phase A - Tester-driven polish

Status: next.

Goal: learn from people who were not involved in development.

Priorities:

- run first-time student tests with several people;
- categorize confusion vs bugs vs content issues;
- improve onboarding and navigation where evidence supports it;
- tune scenario difficulty and response wording where tests show the answer is too obvious or unclear;
- expand accessibility/keyboard/mobile behavior if testers need it;
- add browser coverage for every regression discovered in real tests.

Exit criteria:

- recurring first-time-user blockers are resolved;
- test feedback shows users can understand the investigation/submission loop without coaching.

## Post-v1 Phase B - Server runtime and durable runs

Status: not started.

Add only when saved/resumable or multi-user runs are required.

Likely scope:

- small API service, probably Fastify;
- durable storage, probably PostgreSQL + Drizzle;
- persisted scenarios, runs, events, case state, findings, and scores;
- resume/replay across process/browser restarts;
- server-side validation at trust boundaries.

Exit criteria:

- a run survives browser/process restart;
- deterministic replay from persisted data matches the original run.

## Post-v1 Phase C - Real student/instructor roles

Status: not started.

Requires the server/runtime work above.

Scope:

- authentication;
- real authorization/capability checks;
- server-enforced separation of student-visible data and instructor ground truth;
- instructor run management and review;
- durable assessment history.

Exit criteria:

- a student cannot retrieve hidden ground truth through the client;
- instructors can manage/review assigned runs through enforced roles.

## Post-v1 Phase D - Headless tooling

Status: not started.

Potential commands:

- `polymorph validate <scenario>`
- `polymorph run <scenario>`
- `polymorph replay <run>`
- `polymorph inspect <entity>`

Goal: make scenario validation and deterministic execution useful outside React/browser workflows.

## Post-v1 Phase E - Richer scenario engine

Status: deferred until scenario requirements justify it.

Possible additions:

- preconditions;
- triggers;
- branches;
- richer state transitions;
- time controls;
- more objective kinds;
- MITRE ATT&CK metadata;
- seeded generated variation.

XState belongs here only if authored statecharts become complex enough to justify it.

## Post-v1 Phase F - More telemetry and projections

Status: demand-driven.

Potential additions:

- email activity/projection;
- endpoint inventory;
- cloud-specific events/projections;
- file activity depth;
- richer detection/correlation metadata.

New event families should be added because scenarios need them, not to maximize schema size.

## Post-v1 Phase G - Plugin SDK

Status: not started.

Design only after at least one concrete external extension needs to add routes, projections, commands, or event producers without modifying core.

## Post-v1 Phase H - AI-assisted compilation

Status: not started.

Goal: natural-language scenario/environment requests compile into validated declarative Polymorph definitions.

Required boundary:

`natural language -> generated definition -> structural validation -> semantic validation -> deterministic runtime`

AI output remains untrusted data. It must not become arbitrary generated host execution.

## Advanced engineering - deferred until measured need

Do not add these just because they are common platform technologies:

- Kafka
- Kubernetes
- Redis
- RabbitMQ
- microservices
- GraphQL
- OpenSearch / Elasticsearch
- Temporal
- service meshes
- multiple databases
- Rust / WebAssembly

Add observability, search, performance infrastructure, or alternative runtimes only when profiling or product requirements justify them.
