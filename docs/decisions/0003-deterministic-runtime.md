# ADR-0003: Make Simulation Deterministic

## Status

Accepted

## Context

Cyber-range scenarios need reproducibility for testing, instruction, scoring, debugging, and replay. Uncontrolled wall-clock time or random values would cause the same scenario to produce inconsistent evidence.

## Decision

The simulation runtime will use injected deterministic primitives:

- A virtual simulation clock instead of direct wall-clock access
- Seeded pseudo-randomness instead of uncontrolled random generation
- Ordered event identifiers/sequence numbers
- Pure deterministic reducers wherever practical

Given the same starting world, scenario definition, seed, and ordered inputs, Polymorph should produce the same resulting event stream and state.

## Consequences

### Positive

- Reproducible investigations
- Strong automated tests
- Reliable instructor/student comparisons
- Easier scenario debugging
- Snapshot/replay becomes tractable

### Negative

- Runtime code must avoid convenient global sources such as `Date.now()` and unseeded `Math.random()`
- External integrations must be isolated from authoritative scenario execution

## Guardrail

Real UI timestamps and operational telemetry about Polymorph itself may use wall-clock time. Authoritative simulation state must use the simulation clock.
