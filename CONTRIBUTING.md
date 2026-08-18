# Contributing to Polymorph

## Development Principles

- Keep the simulation/runtime independent from React wherever practical.
- Prefer deterministic, testable domain logic.
- Treat external/generated definitions as untrusted input.
- Add technology because it solves a concrete requirement, not because it looks impressive.
- Keep synthetic simulation state separate from real external systems.
- Capture meaningful architecture tradeoffs as ADRs in `docs/decisions/`.

## Git Workflow

For meaningful changes:

1. Update local `main`.
2. Create a focused branch such as `feat/world-state` or `chore/monorepo-migration`.
3. Make the change with tests where applicable.
4. Update `PROJECT_STATE.md` and `ROADMAP.md` if the milestone or architecture changes.
5. Push the branch.
6. Open a pull request into `main`.
7. Ensure CI passes before merge once CI is established.

Small typo/documentation corrections may be committed directly when appropriate, but architectural or functional work should prefer pull requests.

## Commit Messages

Use concise conventional-style messages when practical:

- `feat: add virtual simulation clock`
- `fix: preserve deterministic event ordering`
- `test: add replay determinism coverage`
- `docs: record event sourcing decision`
- `chore: migrate repository to pnpm workspaces`

## Definition of Done

A meaningful milestone is not complete until:

- The implementation builds and type-checks
- Relevant automated tests exist and pass
- Public/runtime contracts are documented where necessary
- `PROJECT_STATE.md` reflects the new current state
- `ROADMAP.md` is updated if priorities changed
- New architectural tradeoffs are captured in an ADR when appropriate

## Safety Boundary

Do not contribute features whose purpose is to collect real credentials, execute arbitrary generated commands on a host, or silently perform actions against external systems. Polymorph should model such interactions synthetically through controlled runtime concepts.
