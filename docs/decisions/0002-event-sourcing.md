# ADR-0002: Use an Append-Only Event History

## Status

Accepted in principle; implementation deferred until the simulation runtime exists.

## Context

Polymorph needs deterministic incident replay, multiple application projections, auditability, and the ability to explain how a synthetic world reached its current state.

A model that stores only current state would make replay, debugging, and timeline reconstruction significantly harder.

## Decision

Evolve the simulation around an append-only typed event history. World state and application-specific views will be derived by replaying events through deterministic reducers/projections, with snapshots used later for efficiency.

## Consequences

### Positive

- Deterministic replay
- Complete scenario history
- Natural support for timelines and auditability
- Multiple projections can derive from the same source events
- Easier debugging of scenario behavior

### Negative

- More complex than direct state mutation
- Requires careful event versioning
- Projection rebuilds and snapshot strategy must be designed

## Guardrail

Do not force every piece of UI state into the event store. The event history is for authoritative simulation/domain changes, not transient browser concerns such as selected tabs or open modals.
