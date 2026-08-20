# Polymorph Project State

## Current Goal

Build a deterministic cybersecurity simulation platform capable of rendering multiple interconnected applications over one shared synthetic enterprise world.

## Current Milestone

Evolve the first playable investigation into a complete analyst loop with evidence-backed findings, explicit response outcomes, and deterministic scoring while preserving the separation between canonical world state, scenario ground truth, and analyst knowledge.

## Completed

- GitHub repository established
- React + TypeScript + Vite frontend prototype
- Schema-driven page renderer
- Reusable component renderer
- Behavior engine
- Chained actions
- Initial security-console style demo
- pnpm workspace/monorepo established
- Existing React application moved to `apps/web`
- `@polymorph/schema` package created
- Zod runtime validation added for application specifications
- `@polymorph/domain` package created
- Initial Organization, User, Account, Device, File, Session, Application, and Event models
- Initial interconnected synthetic enterprise fixture
- Vitest testing foundation established
- GitHub Actions CI established
- `@polymorph/simulation` package created
- Normalized `WorldState`
- Deterministic `VirtualClock`
- Deterministic seeded pseudo-random generator
- Append-only in-memory event store
- Deterministic event replay
- Simulation snapshots and snapshot-assisted replay
- Typed cybersecurity event families for authentication, identity, sessions, processes, files, network activity, endpoints, and alerts
- Exhaustive event classification with compiler-enforced handling
- Deterministic account enable/disable reducers
- Deterministic session creation/revocation reducers
- Reusable semantic event validation for world/entity references
- Deterministic synchronous in-memory event bus with registration-order delivery and unsubscribe support
- Generic pure projection contract with live application and ordered-history rebuild
- Identity activity projection over authentication, account, and session events
- EDR telemetry projection over endpoint, process, file, network, and alert events
- Latest endpoint observations plus ordered EDR telemetry with shared event correlation ids
- SIEM normalized event projection across all current event families
- Deterministic SIEM event-family/type counters and alert correlation metadata
- Live/replay projection equivalence coverage
- Multi-subscriber and multi-projection observation of shared events
- Correlated login → process execution → alert coherence proof across identity, EDR, and SIEM
- Live/replay equivalence for the correlated cross-projection incident history
- Deterministic derived relationship indexes across organizations, users, accounts, devices, files, applications, and sessions
- Reusable semantic world validation for missing references, organization consistency, bidirectional relationships, and session time invariants
- Versioned deterministic JSON serialization for world state and simulation snapshots
- Structural and semantic validation of untrusted serialized runtime state
- Canonical serialized object-key ordering for stable equivalent-state bytes
- Minimal deterministic scenario runtime with ordered opening history and analyst response actions
- First playable alert-first account-compromise investigation across identity, EDR, and SIEM views
- Deterministic containment that revokes the compromised session and disables the account
- Browser reset/replay for the playable scenario
- Manual browser validation of the first playable investigation
- Versioned Zod-backed JSON scenario file contract for all current world entities and event families
- Semantic scenario compiler that normalizes author-friendly world seeds and reuses runtime validation/replay
- Investigation focus metadata that removes hardcoded scenario entity ids from the analyst workspace
- Editable account-compromise JSON scenario with browser loading and validation feedback
- Scenario selection through local `/scenarios/` query paths for contributor-authored variants
- Scenario authoring guide and automated fixture-compilation coverage
- First-class analyst case state separated from canonical world state and scenario ground truth
- Evidence collection by immutable simulation event id without duplicating telemetry payloads
- Evidence collection from SIEM timeline, endpoint telemetry, and identity activity
- Analyst-authored findings with validated links to collected evidence
- Case state that survives containment and clears on scenario reset
- Automated analyst-case invariants for missing, duplicate, and uncollected evidence references
- Automated test coverage across domain, schema, simulation, scenario, and analyst-case boundaries

## Next Milestones

1. Formalize `apps/web` consumption of `@polymorph/simulation` through the pnpm workspace package boundary
2. Turn response actions into explicit scenario commands with success/failure conditions
3. Add deterministic scoring and post-incident outcome summaries after response outcomes are explicit
4. Add hidden ground-truth metadata and instructor-facing evaluation only after the student investigation loop is stable
5. Add branching, triggers, and richer scenario state transitions only when the first investigation loop requires them
6. Expand cybersecurity telemetry only where scenario or projection requirements justify it

## Architectural Direction

Polymorph should evolve around these principles:

- Deterministic simulation
- Seeded randomness
- Virtual simulation clock
- Shared synthetic world state
- Append-only event history
- Event sourcing and replayable projections
- Typed cybersecurity event contracts
- Schema validation plus semantic validation
- Ground truth separated from analyst-visible knowledge
- Capability-based authorization
- Plugin SDK
- Headless API and CLI support
- AI as a compiler frontend rather than the runtime
- UI as a projection of state rather than the source of truth
- Strict simulation boundaries with synthetic data and no arbitrary generated host execution

## Technology In Use

- React
- TypeScript
- Vite
- pnpm workspaces
- Zod
- Vitest
- GitHub Actions
- Oxlint

## Planned Technology Direction

Add technologies only when the architecture needs them.

Likely future additions:

- XState when scenario statecharts justify it
- Fastify when a backend API is introduced
- PostgreSQL when durable persistence is required
- Drizzle for typed database access
- TanStack Query for server-state synchronization in the web app
- Playwright for end-to-end workflows
- Storybook when the component library becomes substantial
- Docker Compose when API + database infrastructure exists
- OpenTelemetry when backend/runtime observability becomes useful

## Explicitly Deferred

Do not introduce these unless a concrete requirement or measurement justifies them:

- Kafka
- Kubernetes
- Redis
- RabbitMQ
- Microservices
- GraphQL
- OpenSearch / Elasticsearch
- Temporal
- Rust / WebAssembly
- Service meshes
- Multiple databases

## Project Identity

Polymorph is a deterministic, schema-driven cybersecurity simulation runtime.

It is not an AI website generator, phishing kit, credential-harvesting platform, arbitrary code execution environment, or collection of unrelated fake dashboards.

## Continuity Rule

This file is the canonical short-form handoff document for future development sessions.

At the beginning of a new session, read:

1. `PROJECT_STATE.md`
2. `ROADMAP.md`
3. `ARCHITECTURE.md`
4. The latest commits and open pull requests

Update this file whenever a substantial milestone is completed or the architectural direction changes.
