# Changelog

## Unreleased

Renamed to **Endomorph**, and the enterprise generator arrives.

### Renamed

- `@polymorph/*` packages are now `@endomorph/*`, and every Polymorph identifier across code, config, workflows, and documentation is now Endomorph.
- The scenario file discriminator changed from `polymorph-scenario` to `endomorph-scenario`. **Externally authored scenario files must update this field.**
- The GitHub Pages base path moved from `/polymorph/` to `/endomorph/`, correcting a value that no longer matched the repository name.

### Added, `packages/fabric`, the deterministic enterprise generator

- `RandomCursor`, a splittable seeded PRNG addressed by fork path rather than draw order. Sibling streams cannot disturb each other, so editing content does not resequence the world.
- Topology generation: staff across nine weighted departments, accounts, workstations, datacenter servers, the application estate, classified documents, and per-department network segments. 444 entities at default settings.
- Five days of background activity with stable per-person habits, same workstation, same source address, habitual applications, recognisable arrival time, and quiet weekends. The baseline that makes an anomaly detectable.
- Incident planting: password spray, sign-in from hosting infrastructure, encoded PowerShell, C2 beacon, domain-admin enumeration, restricted-document access, and SMB lateral movement, cast entirely from real generated entities.
- Scenario compilation into the existing versioned contract, so generated worlds are playable by the current runtime with no parallel pipeline.
- A generator CLI: `pnpm generate:scenario`.
- A fourth shipped scenario: **Generated enterprise**, 444 entities and 17,904 events, of which 14 are the attack.

### Added, Case as incident command

- The evidence graph derives entities and their connections from collected evidence alone; every node and edge carries the event ids that justify it, so any relationship pivots back to its source.
- Indicators are extracted from collected evidence, with addresses outside every corporate subnet flagged external.
- Incident phase, hypotheses with supported/refuted status, tasks with owners, and decisions are real workflow state.
- The incident report is assembled from case state rather than authored separately.

### Changed, professional mode is the default

- Runs no longer show a live objective checklist or a running score above the response cards during active work. Both turned remediation into optimising a visible number rather than judging an incident.
- Assessment still appears in full at finalization; it just stops being available to optimise against mid-run.
- Guided mode restores the scaffolding on the same environment, and the choice persists across reloads.

### Fixed

- The SIEM rendered a table row per match, blocking for 6.5 seconds against a generated world. Results are now capped at 200 rendered rows with counts and facets still computed in full, a ~10x improvement.
- `pnpm generate:scenario -- --flag` failed with "Missing value for --", because the forwarded separator was parsed as a flag.

### Changed

- `pnpm lint` now covers all five packages instead of `apps/web` alone, and warnings fail the build.

### Added, threat intelligence on external indicators

- External addresses now carry a reputation, not just an "external" flag. The generator classifies the adversary infrastructure it plants -- Tor exit, bulletproof hosting, anonymising VPN, datacenter hosting -- and the Case indicator list tags each recognised address with its category and the reasoning on hover. The classification is gathered from the addresses actually present in the incident, so it never labels an ordinary corporate or residential address as malicious.

### Added, containment where the judgement is formed

- The live-response console can now isolate the host it examined. Its header always called it the console that decides whether a machine goes back to its owner; the containment that follows from looking now lives there rather than on a console the analyst had to leave for. It reads the isolation back off the event history like everything else, so the host reports itself contained without a local flag.

### Added, asset criticality on the entity consoles

- Business context the generator has always produced -- criticality, a rationale, and a business unit for every entity -- now rides on the scenario as an optional `assets` block and reaches the runtime, closing the "generated but unread" gap. The schema accepts a closed set of four criticality tiers; the runtime compiler carries the block onto the definition the app reads.
- The EDR endpoint inventory badges each host's criticality in the existing status palette, shows its business unit, carries the generator's rationale on hover, and sorts the inventory by criticality so the domain controllers and privileged hosts rise to the top and the list reads as a triage order.
- The Identity directory badges each person's criticality beside their name and a privileged account's on its row, so the consequential accounts stand out from a wall of ordinary staff logins.

### Added, the assessment record and case report tell the whole story

- Investigation coverage -- how much of the incident the analyst's evidence reached, and which entities it never opened -- now appears in both the machine-readable assessment record and the human-readable case report, not only in the on-screen result.
- Performed responses are annotated with quality: which action carried an authored penalty, how much, and the rationale, so a dented score is explained rather than opaque. The report names harmful actions in their own section.
- Each generated scenario now records the seed it was produced from, so the assessment record's comparability claim -- two analysts worked byte-identical telemetry -- is true rather than asserted over an empty field. The record and report state plainly when a scenario is hand-authored and records no seed, instead of promising identical replay for one that cannot deliver it.
- Key-evidence capture: which of the incident's ground-truth events the analyst actually collected, and which were missed, named by what they were and their ATT&CK technique. It appears in the record, the case report, and the finalized on-screen result beside coverage -- coverage says which entities were reached, key evidence says whether the smoking guns were banked, and the two diverge exactly when an analyst finalises on the right hosts with none of the proof.

### Fixed

- The orientation-map e2e guard read its steps before the orientation had compiled and painted, so it flaked under parallel workers while passing alone. It now waits for the first step to be visible.

## v1.0.0

Endomorph v1 is the first shareable local/static cybersecurity training release.

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
