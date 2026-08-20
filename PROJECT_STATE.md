# Polymorph Project State

## Current Goal

Build a deterministic cybersecurity simulation platform capable of rendering multiple interconnected applications over one shared synthetic enterprise world.

## Current Milestone

Expand event-driven security projections over shared simulation history, starting with EDR and SIEM on top of the deterministic event bus and projection foundation.

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
- Live/replay projection equivalence coverage
- Multi-subscriber and multi-projection observation of one shared event
- Automated test coverage across domain and simulation packages

## Next Milestones

1. Build an EDR projection from shared events
2. Build a SIEM projection from shared events
3. Prove that one underlying security event produces coherent identity, EDR, and SIEM views
4. Add relationship indexes and broader world semantic validation
5. Add serialization/deserialization for world state and snapshots
6. Expand cybersecurity telemetry families where projections require them
7. Begin the declarative scenario schema and scenario runtime

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
