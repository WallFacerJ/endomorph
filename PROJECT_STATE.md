# Polymorph Project State

## Current Goal

Build a deterministic cybersecurity simulation platform capable of rendering multiple interconnected applications over one shared synthetic enterprise world.

## Current Milestone

Complete the deterministic simulation runtime foundation, then expand the typed cybersecurity event model and begin building projections over shared world state.

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
- Domain relationship tests added
- GitHub Actions CI added for build, lint, and tests
- `@polymorph/simulation` package created
- Normalized `WorldState`
- Deterministic `VirtualClock`
- Deterministic seeded pseudo-random generator
- Typed `SimulationEvent` foundation
- Pure deterministic event reducer
- Append-only in-memory event store
- Deterministic event replay
- Simulation snapshots and snapshot-assisted replay
- 40 automated tests passing across domain and simulation packages

## Next Milestones

1. Expand `SimulationEvent` into typed cybersecurity event families
2. Add authentication and identity lifecycle events
3. Add process, file, session, and endpoint events
4. Expand deterministic reducers for those event families
5. Add semantic validation for entity references and world invariants
6. Add relationship indexes and serialization/deserialization for world state
7. Add an event bus abstraction
8. Build initial SIEM, EDR, and identity projections from shared events
9. Prove that one event can consistently affect multiple projections
10. Begin the declarative scenario schema and scenario runtime

## Architectural Direction

Polymorph should evolve around these principles:

- Deterministic simulation
- Seeded randomness
- Virtual simulation clock
- Shared synthetic world state
- Append-only event history
- Event sourcing and replayable projections
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
