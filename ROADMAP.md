# Polymorph Roadmap

## Phase 0 - Prototype Foundation

Status: substantially complete.

- React + TypeScript + Vite
- Schema-driven page rendering
- Reusable components
- Behavior engine
- Chained actions

## Phase 1 - Platform Foundation

Status: substantially complete.

Goal: separate the product into clear packages and establish runtime validation and automated quality gates.

Completed:

- Convert repository to pnpm workspaces
- Move frontend to `apps/web`
- Add `packages/schema`
- Add Zod schemas for externally supplied application configuration
- Add `packages/domain`
- Add Vitest
- Add root build, lint, and test commands
- Add GitHub Actions CI
- Begin Architecture Decision Records (ADRs)

Remaining:

- Expand semantic validation for cross-references and invariants
- Improve fresh-clone development/build ergonomics where needed

Exit criteria:

- Fresh clone installs with one command
- One root command builds all packages
- CI runs on every pull request
- Invalid application/scenario definitions are rejected before runtime

## Phase 2 - Synthetic World Engine

Status: in progress.

Goal: establish one authoritative enterprise world that all applications read from.

Implemented entities:

- Organization
- User
- Account
- Device
- Application
- Session
- File

Planned entities and concepts:

- Department
- Role
- Capability

Implemented runtime:

- `WorldState`
- Entity identifiers and references
- Normalized entity collections
- Initial deterministic reducer foundation

Remaining:

- Relationship indexes
- Semantic reference validation
- Serialization/deserialization
- Additional entity invariants
- Broader deterministic reducers

Exit criteria:

- A seeded world can be generated and serialized
- Multiple UI projections can read the same entities
- Entity references are validated

## Phase 3 - Deterministic Simulation Runtime

Status: in progress, core foundation established.

Goal: make scenarios reproducible and replayable.

Implemented:

- `VirtualClock`
- Seeded pseudo-random generator
- Typed `SimulationEvent` families
- Append-only in-memory event store
- Deterministic world reducer
- Snapshots
- Replay
- Snapshot-assisted replay
- Deterministic synchronous in-memory event bus
- Generic pure projection contract
- Live projection application and ordered-history rebuild
- Automated determinism and replay-equivalence tests

Remaining:

- Additional deterministic reducers
- Persistent event store abstraction
- Time controls: pause, resume, speed, and jump via snapshot/replay
- End-to-end proof that same scenario + same seed produces identical event history and final world state

Exit criteria:

- Same scenario + same seed produces identical events and final world state
- A saved snapshot plus subsequent events reproduces the same state
- Tests verify determinism

## Phase 4 - Cybersecurity Telemetry and Projections

Status: in progress.

Goal: make the synthetic world observable through security applications.

Implemented synthetic event families:

- Authentication
- Process execution
- File access
- Network activity
- Account/permission changes
- Endpoint state changes
- Security detections

Planned event families:

- Email activity
- Additional telemetry required by projections and scenarios

Implemented projections:

- Identity activity/audit projection over authentication, account, and session events
- EDR telemetry projection over endpoint, process, file, network, and alert events
- SIEM normalized event projection over all current event families
- Shared-event multi-projection delivery foundation

Remaining projections:

- Email
- Endpoint inventory

Exit criteria:

- One underlying event can affect multiple projections
- No application maintains a contradictory private copy of canonical world data

## Phase 5 - Scenario Engine

Status: not started.

Goal: represent incidents as declarative scenarios rather than hardcoded scripts.

- Scenario schema
- Timeline events
- Preconditions
- Triggers
- State transitions
- Branches
- Success/failure conditions
- Ground-truth timeline
- Analyst-visible evidence model
- MITRE ATT&CK mappings where appropriate
- Scenario compiler and linter

Potential XState adoption belongs here if statecharts provide clear value.

Exit criteria:

- Scenario files can be validated and executed headlessly
- Ground truth and analyst knowledge remain separate
- Scenario authors receive useful validation errors

## Phase 6 - Analyst and Instructor Experience

Status: not started.

Goal: turn the runtime into a usable cyber-range training platform.

- Analyst workspace
- Incident queue
- Evidence collection
- Notes/findings
- Containment/remediation actions
- Instructor controls
- Scenario reset/replay
- Hidden ground truth
- Scoring
- Timeline comparison
- Post-incident report

Exit criteria:

- A student can complete an investigation without access to ground truth
- An instructor can replay and grade the same deterministic scenario

## Phase 7 - Persistence and Server Runtime

Status: not started.

Goal: support durable, multi-session simulations.

Likely stack when needed:

- Fastify API
- PostgreSQL
- Drizzle
- TanStack Query in web client
- Docker Compose for local API/database stack

Persist:

- Worlds
- Events
- Snapshots
- Scenarios
- Runs
- Users/roles
- Findings/scores

Exit criteria:

- Simulation can survive process restarts
- Runs can be resumed and replayed

## Phase 8 - Plugin SDK

Status: not started.

Goal: make Polymorph extensible without modifying core runtime code.

Plugin capabilities may include:

- Routes/views
- UI components
- Event subscriptions
- Event producers
- Commands
- Projections
- Capabilities/permissions
- Scenario extensions

Exit criteria:

- A new simulated application can be added through a documented plugin API

## Phase 9 - Headless CLI and Automation

Status: not started.

Potential commands:

- `polymorph validate <scenario>`
- `polymorph run <scenario>`
- `polymorph inspect <entity>`
- `polymorph events ...`
- `polymorph snapshot ...`
- `polymorph replay ...`

Exit criteria:

- Core simulation does not depend on React or a browser

## Phase 10 - AI-Assisted Compilation

Status: not started.

Goal: use AI to author structured simulations without making AI-generated executable code the core architecture.

Pipeline:

Natural language -> generated definition -> schema validation -> semantic validation -> Polymorph IR -> deterministic runtime

Potential inputs:

- Natural-language scenario descriptions
- Synthetic organization requirements
- Authorized screenshots/reference layouts for visual approximation

Exit criteria:

- AI output is treated as untrusted input
- Invalid or unsafe definitions never reach the runtime

## Phase 11 - Advanced Engineering

Status: deferred until justified.

Add only when justified:

- OpenTelemetry for platform traces/metrics/logs
- Playwright end-to-end suites
- Storybook for mature component library
- Schema migrations/versioning
- Performance profiling and load testing
- Search infrastructure if event volumes require it
- Alternative execution runtimes only if profiling proves a need

## Guiding Rule

Complexity should emerge from requirements. Do not add technologies solely to make the repository appear advanced.
