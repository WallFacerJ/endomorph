# Polymorph Project State

## Current Goal

Build a deterministic cybersecurity simulation platform capable of rendering multiple interconnected applications over one shared synthetic enterprise world.

## Current Milestone

Add deterministic serialization/deserialization for world state and snapshots, then begin declarative scenario design and analyst-facing workflows.

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
- Automated test coverage across domain and simulation packages

## Next Milestones

1. Add serialization/deserialization for world state and snapshots
2. Expand cybersecurity telemetry families where scenario/projection requirements justify them
3. Begin the declarative scenario schema and scenario runtime

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
