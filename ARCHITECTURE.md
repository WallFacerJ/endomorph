# Polymorph Architecture

## Architectural Intent

Polymorph is designed as a deterministic cybersecurity simulation runtime rather than a collection of hardcoded demo applications.

The UI should ultimately be a projection of shared synthetic state. The authoritative behavior belongs in reusable domain and simulation packages that can also run headlessly.

## Target Repository Shape

```text
polymorph/
├── apps/
│   ├── web/
│   └── api/                 # introduced when server persistence is needed
├── packages/
│   ├── schema/
│   ├── domain/
│   ├── simulation/
│   ├── event-store/
│   ├── plugin-sdk/
│   ├── ui/
│   └── testing/
├── plugins/
├── scenarios/
├── docs/
│   ├── architecture/
│   └── decisions/
├── infra/
└── .github/workflows/
```

This structure is a target, not an instruction to create empty packages prematurely.

## Core Layers

### 1. Definition Layer

Accepts declarative descriptions of synthetic applications, worlds, and scenarios.

Responsibilities:

- Runtime schema validation
- Schema version detection
- Structural normalization
- Semantic validation
- Conversion into Polymorph intermediate representations

AI-generated content, user-authored JSON/YAML, and future plugin definitions are treated as untrusted inputs.

### 2. Domain Layer

Contains pure domain types and invariants.

Initial entities:

- Organization
- Department
- User
- Account
- Device
- Application
- Session
- File
- Role
- Capability
- Event

This package must not depend on React.

### 3. Simulation Layer

Owns deterministic execution.

Responsibilities:

- `WorldState`
- `VirtualClock`
- Seeded pseudo-randomness
- Reducers/state transitions
- Scenario execution
- Commands
- Event emission
- Snapshot and replay orchestration

Given identical initial state, seed, and event sequence, the resulting world must be identical.

### 4. Event Layer

Polymorph should evolve toward an append-only typed event history.

Conceptually:

```text
Commands / Scenario Inputs
          ↓
      Simulation
          ↓
       Events
          ↓
   Append-only history
          ↓
 ┌────────┼────────┐
 ↓        ↓        ↓
World    SIEM     EDR ...
Projection Projection Projection
```

The event history explains how the world reached its current state and enables deterministic replay.

### 5. Projection Layer

Different simulated applications derive purpose-specific views from the same world/events.

Examples:

- SIEM projection
- EDR projection
- Identity projection
- Email projection
- HR projection
- Cloud administration projection

A projection must not silently become a second source of truth for canonical entities.

### 6. Application Runtime / UI Layer

The current React renderer belongs here.

It should render application specifications and projections but should not contain the authoritative cybersecurity/business logic.

Over time, UI components should consume commands and queries from the runtime rather than mutating shared state directly.

### 7. Persistence Layer

Introduced when durable simulations are required.

Expected responsibilities:

- Event persistence
- Snapshot persistence
- Scenario storage
- Simulation run metadata
- User/instructor state
- Findings and scores

PostgreSQL is the current likely database choice. This decision remains deferred until persistence exists.

### 8. Plugin Layer

Future plugins should extend Polymorph through explicit contracts rather than imports into internal implementation details.

Potential extension points:

- Application views
- Components
- Queries
- Commands
- Event subscriptions
- Event producers
- Projections
- Capabilities
- Scenario definitions

## Ground Truth vs Analyst Knowledge

Polymorph must distinguish between what actually happened in the simulation and what an analyst has discovered.

```text
Ground Truth
- account compromised
- credential access occurred
- lateral movement occurred

Analyst Knowledge
- anomalous login observed
- suspicious process observed
- root cause unknown
```

This separation is essential for investigation training and scoring.

## Security Boundary

Polymorph simulations should remain synthetic by default.

Core restrictions:

- Do not collect real credentials
- Do not turn generated UI into a credential-harvesting workflow
- Do not execute arbitrary AI-generated shell commands on the host
- Do not silently perform real actions against external systems
- Treat generated schemas/configurations as untrusted input
- Route simulated actions through explicit runtime commands/capabilities

## Determinism

Determinism is a first-class requirement, not an optimization.

Avoid uncontrolled sources such as:

- Direct `Date.now()` usage inside simulation logic
- Unseeded `Math.random()` inside simulation logic
- Hidden external dependencies that alter scenario state

Instead use injected abstractions such as:

- `VirtualClock`
- Seeded RNG
- Explicit event sequence numbers

## Authorization Model

Future simulated operations should be capability-based.

Example:

```text
SOC Analyst
- read:alerts
- read:endpoints
- isolate:endpoint
- NOT disable:identity
```

This allows permissions and authorization failures to be part of scenarios rather than merely UI decoration.

## AI Integration Principle

AI should compile intent into structured definitions.

```text
Natural language
      ↓
AI-generated definition
      ↓
Runtime validation
      ↓
Semantic validation
      ↓
Polymorph IR
      ↓
Deterministic runtime
```

The runtime should not depend on arbitrary model-generated executable source code.

## Technology Selection Rule

New infrastructure must solve a demonstrated architectural requirement.

Prefer:

Problem -> measurement/requirement -> technology decision

Avoid:

Interesting technology -> invent a reason to use it

Architecture decisions with meaningful tradeoffs should be captured in `docs/decisions/`.
