# ADR-0001: Use a Workspace Monorepo

## Status

Accepted

## Context

Polymorph is evolving from a single React prototype into a platform with distinct schema, domain, simulation, UI, testing, and future API/plugin concerns.

Keeping all logic inside one frontend package would tightly couple the simulation runtime to React and make headless execution, testing, reuse, and package boundaries harder to maintain.

## Decision

Adopt a pnpm workspace/monorepo structure with application code under `apps/` and reusable runtime packages under `packages/`.

Initial target packages:

- `packages/schema`
- `packages/domain`
- `packages/simulation`

Other packages will be introduced only when needed.

## Consequences

### Positive

- Clear dependency boundaries
- Core runtime can remain independent from React
- Easier unit testing
- Supports future CLI/API consumers
- Makes ownership and architecture easier to understand

### Negative

- More repository configuration
- Requires workspace-aware build/test tooling
- Premature package splitting could create unnecessary complexity

## Guardrail

Do not create empty packages solely to match the target architecture diagram. Introduce packages when there is real code and a clear boundary to move into them.
