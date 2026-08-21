# Polymorph

Polymorph v1 is a deterministic, schema-driven cybersecurity training simulation. A student investigates synthetic identity, endpoint, and SIEM telemetry over one shared world, collects evidence, writes findings, chooses response actions, submits the investigation, and receives a reproducible result. In instructor mode, a completed run can be compared with authored ground truth.

## Try Polymorph v1

**Hosted app:** https://wallfacerj.github.io/polymorph/

The hosted build is deployed from `main` with GitHub Pages. If the deployment is temporarily unavailable, use the local quick start below.

If you are testing Polymorph for the first time, start with [TESTER_GUIDE.md](TESTER_GUIDE.md). It includes a 10–15 minute unscripted test, edge cases worth trying, and a copy/paste feedback template.

## What ships in v1

Polymorph v1 includes:

- one deterministic synthetic enterprise world per scenario;
- shared identity, EDR, and SIEM projections over the same event history;
- an alert-first analyst workspace with timeline, endpoint, identity, and case views;
- evidence collection by immutable event ID;
- analyst-authored findings linked to collected evidence;
- multiple deterministic response choices, including an intentionally harmful choice;
- explicit investigation finalization with success/failure and partial completion;
- transparent objective score, response-quality penalty, and final score;
- a read-only finalized case until reset;
- post-finalization instructor ground-truth review;
- three JSON-authored scenarios selectable in the UI;
- deterministic replay/unit/integration coverage plus browser-level Playwright tests.

## Included scenarios

1. **Finance account compromise** — suspicious login, encoded PowerShell, and correlated outbound activity.
2. **HR malware beacon** — compromised HR session, unsigned executable activity, and an outbound beacon.
3. **Cloud-admin compromise** — privileged identity compromise followed by suspicious administrative tooling and network activity.

Use the **Scenario** selector in the application to switch between them. Direct deep links using `?scenario=/scenarios/<file>.json` are also supported for local/custom authoring.

## Student workflow

A normal run is intentionally simple:

1. Open an alert.
2. Investigate the correlated timeline.
3. Pivot to endpoint and identity context as needed.
4. Collect evidence.
5. Build an evidence-backed case finding.
6. Choose response actions based on the evidence.
7. Finalize the investigation.
8. Review objective completion, any response penalty, and the final score.
9. Reset or switch scenarios for another deterministic run.

Student mode does not reveal ground truth or authored response-quality rationale before submission.

## Instructor mode

Use the **Instructor mode** control in the app, or add `?mode=instructor` to a scenario URL. Ground truth is shown only after the investigation is finalized.

Instructor mode is a **presentation boundary, not an authentication/security boundary** in v1. The current product is a local/static client application. Do not use this mode to protect assessment answers in a real classroom deployment; real role enforcement belongs in a future server-backed runtime.

## Local quick start

Requirements:

- Node.js 24
- pnpm 11.22.0 (the repository declares the package-manager version)

```bash
git clone https://github.com/WallFacerJ/polymorph.git
cd polymorph
pnpm install --frozen-lockfile
pnpm dev
```

Open the Vite URL printed in the terminal, normally `http://localhost:5173`.

## Validation commands

```bash
pnpm build
pnpm lint
pnpm test:run
```

For browser regression tests:

```bash
pnpm exec playwright install chromium
pnpm test:e2e
```

CI runs frozen dependency installation, build, lint, deterministic unit/integration tests, and the Chromium Playwright suite.

## First-time user testing

For friend/user testing, share two things:

1. the hosted app: https://wallfacerj.github.io/polymorph/
2. the first-time protocol: [TESTER_GUIDE.md](TESTER_GUIDE.md)

The most valuable first test is **not** a guided demo. Ask the tester to stay in Student mode, investigate one scenario without being told the correct response, finalize it, then explain where they were confused and whether the result made sense. The guide includes a structured feedback template and optional failure/penalty/read-only checks.

## Scenario authoring

Shipped scenarios live in `apps/web/public/scenarios/` and use the versioned `polymorph-scenario` JSON contract. The scenario compiler performs structural validation with Zod, semantic world/event/reference validation, deterministic replay validation, objective validation, response-action validation, and ground-truth reference validation before a scenario is allowed into the workspace.

See [SCENARIO_AUTHORING.md](SCENARIO_AUTHORING.md) for the authoring contract and workflow.

## Architecture boundaries

Polymorph v1 deliberately keeps these concepts separate:

- **World state** is the canonical synthetic enterprise state.
- **Simulation events** form append-only deterministic history.
- **Identity / EDR / SIEM** are projections of shared history, not private sources of truth.
- **Analyst case state** stores collected event IDs and analyst-authored findings, not duplicated canonical telemetry.
- **Objectives** grade resulting canonical state.
- **Response-quality penalties** come only from declarative scenario metadata for performed actions.
- **Ground truth** is authored assessment metadata and is not student-visible during an active investigation.

The current hosted application is intentionally client-only and in-memory. Refreshing the page starts a fresh run. Durable users/runs, real authentication/authorization, persistence, plugins, and server APIs are post-v1 work.

## Safety boundary

Polymorph is for synthetic simulation only. It is not a phishing kit, credential-capture system, arbitrary code-execution framework, or production security-control platform. Do not enter real credentials, secrets, personal information, or production incident data into test findings.

## Repository map

- `apps/web` — React + TypeScript + Vite analyst/instructor experience
- `packages/domain` — canonical synthetic enterprise domain models
- `packages/schema` — versioned external/scenario validation contracts
- `packages/simulation` — deterministic world/event/replay/projection/scenario runtime
- `e2e` — Playwright v1 browser regression tests

For architectural continuity and future work, see [PROJECT_STATE.md](PROJECT_STATE.md), [ROADMAP.md](ROADMAP.md), and [ARCHITECTURE.md](ARCHITECTURE.md).
