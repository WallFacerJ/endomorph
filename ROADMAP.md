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
- Add Zod structural validation for versioned scenario files
- Add `packages/domain`
- Add Vitest
- Add root build, lint, and test commands
- Add GitHub Actions CI
- Begin Architecture Decision Records (ADRs)
- Formalize `apps/web` consumption of `@polymorph/simulation` through the workspace package boundary
- Declare the simulation package's schema/runtime dependency graph explicitly
- Regenerate and validate the workspace lockfile with pnpm

Remaining:

- Expand semantic validation for externally supplied definitions and invariants as new definition families are added
- Improve fresh-clone development/build ergonomics where needed

Exit criteria:

- Fresh clone installs with one command
- One root command builds all packages
- CI runs on every pull request
- Invalid application/scenario definitions are rejected before runtime

## Phase 2 - Synthetic World Engine

Status: core exit criteria established; extension work remains.

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
- Deterministic derived relationship indexes
- Semantic world/reference validation
- Organization and bidirectional relationship consistency checks
- Session temporal invariant validation
- Versioned deterministic world-state serialization/deserialization
- Structural and semantic validation at the serialization boundary
- Author-friendly scenario world seeds compiled into canonical `WorldState`

Remaining:

- Additional entity invariants as scenario requirements expose them
- Broader deterministic reducers as scenario requirements expose them

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
- Versioned deterministic snapshot serialization/deserialization
- Minimal deterministic scenario runtime over opening history and response events
- Pure deterministic scenario objective/outcome evaluation
- Pure equal-weight deterministic scenario scoring from objective completion
- Deterministic alternate-order response replay with equivalent final world state
- Explicit deterministic run finalization that does not append simulation events or mutate canonical world state
- Automated determinism and replay-equivalence tests

Remaining:

- Additional deterministic reducers
- Persistent event store abstraction when durable persistence is required
- Time controls: pause, resume, speed, and jump via snapshot/replay
- End-to-end proof that same scenario + same seed produces identical generated event history and final world state once scenario generation uses seeded variability

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
- Correlated login → process execution → alert coherence proof across identity, EDR, and SIEM

Remaining projections:

- Email
- Endpoint inventory

Exit criteria:

- One underlying event can affect multiple projections
- No application maintains a contradictory private copy of canonical world data

## Phase 5 - Scenario Engine

Status: in progress.

Goal: represent incidents as declarative scenarios rather than hardcoded scripts.

Implemented:

- Versioned JSON scenario-file envelope
- Zod structural schema for current world entity and simulation event families
- Author-friendly initial world seed
- Ordered opening event timeline
- Deterministic analyst response actions
- Investigation focus metadata for alert/user/account/device/session/action pivots
- Ordered multi-action investigation response metadata with backward-compatible primary-action normalization
- Semantic validation for response-action collection uniqueness and declared-action references
- Semantic scenario compiler using canonical world/event validation and replay
- Clear browser validation failures for malformed or semantically invalid scenario files
- Editable account-compromise example scenario
- Contributor-selectable local scenario files under `/scenarios/`
- Scenario authoring documentation
- Typed declarative account-status and session-status objectives
- Unique objective-id and semantic target validation
- Deterministic active `in_progress | succeeded` outcome evaluation from canonical state
- Explicit finalized `failed` outcome when the analyst submits incomplete exposed objectives
- Account-compromise response objectives for compromised-session revocation and account disablement
- Independent deterministic session-revocation and account-disablement response actions

Remaining:

- Preconditions
- Triggers
- Richer state transitions
- Branches
- Genuinely harmful/unnecessary response choices and explicit authored consequences when scenarios require them
- Ground-truth timeline metadata distinct from analyst-visible evidence
- MITRE ATT&CK mappings where appropriate
- Dedicated scenario linter/headless validation entry point

Potential XState adoption belongs here if statecharts provide clear value.

Exit criteria:

- Scenario files can be validated and executed headlessly
- Ground truth and analyst knowledge remain separate
- Scenario authors receive useful validation errors

## Phase 6 - Analyst and Instructor Experience

Status: in progress; the first evidence-backed analyst loop now supports analyst-selected remediation, explicit submission, deterministic success/failure, and deterministic scoring.

Goal: turn the runtime into a usable cyber-range training platform.

Implemented analyst slice:

- Alert-first investigation workspace
- Correlated SIEM timeline
- Identity and endpoint pivots
- Synthetic process/network evidence views
- Analyst-selected deterministic remediation actions
- Response-action chooser with descriptions and performed state
- Deterministic 50% partial objective score after either account-compromise response action
- Full 100% objective completion after both response actions in either order
- Explicit `Finalize investigation` submission boundary
- Finalized incomplete responses render failed results while preserving their partial score
- Finalized complete responses render succeeded results at 100%
- Finalized runs freeze further remediation actions until reset
- Post-incident result panel distinguishes succeeded and failed submissions
- Scenario reset/replay
- Manual browser testing of the first investigation
- First-class analyst case state separate from canonical world state and scenario ground truth
- Evidence collection by immutable simulation event id
- Evidence collection from investigation, endpoint, and identity views
- Analyst-authored findings with validated evidence links
- Case state preserved through remediation/finalization and cleared by reset
- Analyst-visible response objectives driven by runtime outcome state
- Equal-weight deterministic objective-completion score
- Evidence and findings remain visible in results but are not secretly graded
- Reset returns objective progress, score, and finalization to their deterministic initial state

Remaining:

- Manual browser validation of zero-, partial-, and full-score finalization paths
- Response-quality scoring only after scenarios include genuinely unnecessary or harmful choices
- Instructor controls
- Hidden ground truth
- Timeline comparison
- Richer post-incident report

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
