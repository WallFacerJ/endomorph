# ADR-0004: Validate Definitions at Runtime

## Status

Accepted

## Context

Polymorph will eventually ingest JSON/YAML definitions authored by users, plugins, and AI systems. TypeScript types alone do not validate data at runtime and cannot protect the engine from malformed or unsafe input.

## Decision

Use runtime schemas at the boundary between external definitions and the Polymorph runtime. Zod is the current preferred library.

Validation will occur in two stages:

1. Structural validation: types, required fields, enums, shapes, and bounds
2. Semantic validation: referenced entities exist, identifiers are unique, capabilities are valid, timelines are coherent, and domain invariants hold

Only validated/normalized data is converted into Polymorph intermediate representations and runtime objects.

## Consequences

### Positive

- Safer AI-assisted generation
- Better authoring errors
- Clear trust boundary
- Easier schema versioning and migrations later
- Runtime code can rely on stronger invariants

### Negative

- Some definitions exist in both runtime schema and derived TypeScript types
- Semantic validation requires additional code beyond schema parsing

## Guardrail

Never treat model-generated or user-provided configuration as executable code. Definitions describe allowed Polymorph concepts and must pass validation before execution.
