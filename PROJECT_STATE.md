# Polymorph Project State

## Current Goal

Build a deterministic cybersecurity simulation platform capable of rendering multiple interconnected applications over one shared synthetic enterprise world.

## Current Milestone

Build the shared synthetic enterprise domain model, then establish automated testing before implementing the deterministic simulation runtime.

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

## Next Milestones

1. Add Vitest
2. Test domain relationships and deterministic behavior
3. Add GitHub Actions for build, type-check, lint, and tests
4. Create `packages/simulation`
5. Add `WorldState`
6. Add `VirtualClock`
7. Add seeded randomness
8. Add deterministic event reducers
9. Add event store and replay
10. Add projections for SIEM, EDR, identity, and other simulated applications
11. Add event store and replay
12. Add projections for SIEM, EDR, identity, and other simulated applications

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

## Planned Technology Direction

Use technologies only when the architecture needs them.

Likely additions:

- pnpm workspaces
- Zod
- Vitest
- GitHub Actions
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
