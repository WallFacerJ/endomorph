# Changelog

## v1.0.0

Polymorph v1 is the first shareable local/static cybersecurity training release.

### Student workflow

- Investigate a synthetic security alert across SIEM, endpoint, and identity views.
- Collect immutable event-backed evidence.
- Write analyst findings linked to collected evidence.
- Choose deterministic scenario-authored response actions.
- Finalize an investigation into a reproducible succeeded/failed result.
- Review objective completion, response-quality penalties, and final score.
- Reset to a clean deterministic run or switch scenarios.

### Instructor workflow

- Explicit local Instructor mode.
- Ground truth remains hidden during the active student workflow.
- After finalization, review the authored incident summary, annotated event timeline, performed actions, penalty rationale, and deterministic score.

### Scenario set

- Finance account compromise with suspicious login, encoded PowerShell, and outbound activity.
- HR malware beacon with a compromised session and unsigned updater execution.
- Cloud-admin compromise with suspicious privileged tooling and outbound activity.

### Runtime

- Canonical normalized synthetic world.
- Typed append-only simulation events.
- Deterministic reducers, replay, snapshots, and serialization.
- Replayable identity, EDR, and SIEM projections.
- Versioned Zod-backed JSON scenario contract and semantic compiler.
- Declarative objectives, response-quality metadata, and ground truth.

### Release quality

- In-product scenario selector and Student/Instructor controls.
- First-time tester protocol and feedback template.
- Vitest deterministic unit/integration coverage.
- Playwright critical-path browser coverage.
- GitHub Actions quality gates.
- GitHub Pages deployment for zero-install friend testing.

### Known v1 boundaries

- Runs are client-only and in memory; refresh starts a fresh run.
- Instructor mode is a presentation feature, not real authorization.
- No backend, durable persistence, real user accounts, plugin SDK, or AI scenario authoring in v1.
- Synthetic data only; do not enter real credentials, secrets, personal information, or production incident data.
