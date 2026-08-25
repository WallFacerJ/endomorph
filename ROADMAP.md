# Endomorph Roadmap

> **Current working roadmap — as of 2026-08-25.** This section is the plan we are
> actually executing; it reconciles the `STRATEGY.md` build program (the wedge)
> with the enterprise phases below (the north star). The phased enterprise vision
> that follows is the longer-horizon ambition, deliberately deferred.

## The bet

**Lead with detection engineering, not training.** The defensible edge is that
*ground truth is known by construction* — labelled, seeded, ATT&CK-mapped
telemetry with realistic false-positive noise, scoreable in a browser with zero
infrastructure. No competitor combines ground truth + benign noise + seeded
variation + a scoring harness + zero infra. The investigation console stays the
demo that makes it tangible, and the door into a training product later.

At a glance: **8 intrusions · 28 ATT&CK techniques · ~37.3k labelled events ·
4 rule languages · 6 event domains · 0 infrastructure.**

### Lane 1 — Shipped (the wedge is real)

- **Deterministic generator + labelled corpus** — every event benign/malicious and
  ATT&CK-mapped, seeded, exports ECS / OCSF / Splunk. *Done.*
- **Detection-eval harness** — counted precision/recall/coverage, cross-seed
  `robustness`, and a `noise-floor` that measures FP realism (20/24 techniques
  buried among 10x+ look-alikes). *Done.*
- **Browser Detection Lab (`?lab`)** — score a pasted rule in under two seconds,
  drill into the exact benign hits and missed events, share the result as a link. *Done.*
- **Rule importers — Sigma, KQL, SPL, EQL** — write in your own language; each
  compiles to one internal rule and refuses what it can't express by name. *Done.*
- **Detection-as-code CI + coverage badge** — `--sigma/--kql/--spl/--eql` +
  `--baseline` regression gate + `--badge`. *Done.*
- **AI detection-eval harness** — `--ai-eval` exports label-stripped tasks + hidden
  key; `--rubric` grades generated detections *N/M techniques to standard*. *Done.*
- **Event domains** — endpoint, identity, network, file, **mail**, **cloud**. Mail
  added a credential-phishing intrusion (T1566.002, T1204.001); cloud added an
  OAuth-consent control-plane intrusion (T1528, T1098.001, T1526, T1537). *Done.*
- **Landing page + benchmark v1.0 generation.** *Done.*

### Lane 2 — Now → Next (sharpen the wedge, priority order)

1. **Publish benchmark v1.0 as a citable release.** *Gated on `gh` auth.* Artifacts
   build clean; cutting the release makes it a dataset others cite, not a command.
2. **More event domains — the deepest moat.** Mail and cloud/SaaS control-plane
   are shipped; **DNS / proxy** and Sysmon-fidelity Windows codes are next. Each
   new domain unlocks many ATT&CK techniques and more addressable teams.
3. **Point it at your own org.** Surface `--profile` as a product feature — the
   digital-twin wedge, determinism intact.
4. **Ship the generator + scorer as an npm package / API.** *Gated on npm auth.*
5. **Grow ATT&CK coverage deliberately** — more intrusions, pure event modelling.
6. **Seeded attack variation** — vary the attack (evasion levels), not just the
   enterprise; stresses whether a rule generalises.
7. **Elastic ES|QL** — completes the vendor-language set (small).

### Lane 3 — Later (enterprise north star, deferred until a customer pulls)

Interactive Range (Phase 2) · scenario/adversary engine (Phase 4) · enterprise
control plane (Phase 5) · replay/branch/compare (Phase 6) · Forge authoring
(Phase 7) · AI proving ground (Phase 9). Detailed below.

### Guardrails

Breadth is the enemy · defend determinism + FP realism · validate the buyer before
building · synthetic & isolated only (never a credential-harvesting product,
code-execution service, or tool aimed at real targets).

---

# Enterprise north star (the full ambition)

Endomorph v1 proved the deterministic scenario/runtime architecture. Tester feedback and competitive research now justify a broader product goal: **build a deterministic cyber-operations digital twin and enterprise cyber-readiness platform, not a shallow training website.**

See `COMPETITIVE_RESEARCH.md` and `ENTERPRISE_VISION.md` for the market evidence and product north star.

## Historical milestone - v1 deterministic training product

Status: **complete.**

V1 established:

- canonical synthetic enterprise world state;
- deterministic events/replay/snapshots/serialization;
- identity, EDR, and SIEM projections over shared history;
- declarative JSON scenarios;
- analyst evidence/findings and response actions;
- objective/result evaluation;
- student and instructor views;
- three scenarios;
- Playwright browser coverage and public/static deployment support.

V1 should now be treated as a proof of the runtime model, not the target enterprise experience.

---

# Enterprise evolution

## Phase 1 - Deep investigation and professional tool identity

Status: **in progress.**

Goal: eliminate the "juvenile / surface-level / multiple-choice" feel before adding expensive infrastructure.

Delivered: the SIEM, EDR, and Identity workspaces, the Fabric generator, the Case / incident command redesign, and professional mode. Remaining: moving response work into tool context, and coverage-based scoring.

### Scope change - the Fabric generator moved into Phase 1

The Fabric layer described in `ENTERPRISE_VISION.md` was originally sequenced after this phase. The deterministic **enterprise generator** half of it has been pulled forward into Phase 1, and now lives in `packages/fabric`.

Reason: this phase's own exit criteria cannot be met without it. Phase 1 requires "noise/benign events mixed with malicious activity", datasets "large enough that an analyst has to search rather than scroll a curated list", and at least 30 minutes of investigation before the evidence surface is exhausted. The shipped content cannot support that and cannot be hand-authored to. Measured across the three v1 scenarios:

| Scenario | Entities | Opening events |
| --- | --- | --- |
| `account-compromise` | 15 | 34 |
| `cloud-admin-compromise` | 7 | 6 |
| `hr-malware-beacon` | 7 | 6 |

The latter two are structurally identical - the same world template with names and identifiers swapped, and the same six opening-event types in the same order. The deep tool workspaces now exist and are starving for data, so a generated enterprise is the blocking dependency for this phase, not a later luxury.

This moves only the world/activity **generator**. The interactive runtime work - synthetic hosts, containers, microVMs - remains in Phase 2 as written.

### SIEM workspace

- query language/search bar with useful operators;
- time-range controls;
- filters/facets;
- saved searches;
- event detail drawer/raw record view;
- field pivots and entity pivots;
- correlations and grouped timelines;
- noise/benign events mixed with malicious activity;
- large enough datasets that an analyst has to search rather than scroll a curated list.

### EDR workspace

- endpoint inventory;
- process tree;
- parent/child process pivots;
- command lines, users, hashes, signatures, network/file activity;
- endpoint timeline;
- response operations attached to the endpoint context;
- artifact acquisition hooks for the future Range layer.

### Identity workspace

- users/accounts/sessions/applications;
- authentication history;
- source/device/location/risk context;
- privilege/group/role relationships;
- session lifecycle;
- identity-specific containment and access review.

### Case / incident command redesign

Status: **delivered.**

- evidence graph instead of a simple list -- derived from collected evidence, not authored;
- hypotheses with supported/refuted status, and findings;
- indicators extracted from evidence, with values outside every corporate subnet flagged external;
- tasks, owners, status, and incident phase as real workflow state;
- decisions and response actions;
- bidirectional pivots: every node and edge carries the event ids that justify it, and entities pivot back into SIEM;
- unified incident timeline;
- generated incident report from actual case state.

### Assessment model

Status: **partially delivered.**

- ~~professional mode hides explicit score/objectives during active work by default~~ **done** -- runs default to professional; the live objective checklist and running score are hidden until finalization;
- ~~retain optional guided mode for learning~~ **done** -- guided restores the scaffolding on the same environment, persisted across reloads;
- response actions move into relevant tool/system context rather than obvious answer cards -- **remaining**;
- score investigation coverage, state outcomes, harmful actions, timing/process, and evidence quality where deterministically measurable -- **coverage, harmful actions, and evidence quality done; timing remaining.** Investigation coverage (which entities the analyst's evidence reached, and which it missed), response quality (which performed actions carried an authored penalty, and why), and key-evidence capture (which of the incident's ground-truth events were actually collected, and which were missed) now appear in the machine-readable assessment record, the human-readable case report, and the on-screen finalized result, alongside state outcomes and objective score. Evidence quality is measured as key-evidence capture rather than a signal-to-noise ratio, because collecting a legitimate baseline is real investigative work and a ratio would penalise it. The seed each generated scenario was produced from now rides on the file, so the record's comparability claim is finally true rather than asserted over an empty field. Timing is the one dimension still not deterministically measurable per analyst -- actions replay at fixed scenario times, not wall-clock -- so it is deliberately left out rather than faked.

Exit criteria:

- an experienced tester can spend at least 30 minutes investigating the default scenario without exhausting the evidence surface;
- the SIEM, EDR, Identity, and Case sections feel like different professional applications;
- a tester can explain why Case is operationally useful;
- successful response does not feel like choosing the obvious answer from a list.

---

## Phase 2 - Synthetic Infrastructure Fabric

Status: **planned; now justified by tester feedback.**

Goal: let analysts enter and manipulate investigation-critical systems rather than only reading dashboards.

Note: the deterministic world/activity generator that was previously grouped under this heading has moved into Phase 1 (see the scope change above). What remains here is the interactive runtime fidelity ladder.

### Stage 2A - deterministic synthetic hosts

Implement a safe host runtime attached to Fabric assets:

- virtual filesystem;
- files and hashes/metadata;
- processes and parent/child relationships;
- services;
- users/groups;
- configuration/registry-like state;
- local event logs;
- connections/listeners;
- controlled investigation command API;
- deterministic snapshots/reset;
- host actions recorded into run history.

This stage provides depth cheaply and preserves deterministic replay.

### Stage 2B - ephemeral container-backed assets

Add server-side isolated workloads for scenarios requiring real Linux/service behavior:

- prebuilt immutable images;
- per-run network namespaces;
- CPU/memory/time quotas;
- denied unrestricted internet by default;
- health checks and deterministic reset/snapshot strategy;
- terminal streaming through the product;
- instrumentation into Endomorph telemetry;
- automatic teardown/cleanup.

### Stage 2C - microVM/full-VM fidelity

Use Firecracker/QEMU/other VM technology only where containers are insufficient, especially Windows/AD/appliance fidelity.

Requirements before broad rollout:

- strong isolation model;
- capacity scheduling;
- image versioning;
- snapshot/startup SLOs;
- observability;
- cost controls;
- environment cleanup guarantees.

Exit criteria:

- a scenario can mix inexpensive synthetic assets with one or more interactive runtime-backed systems;
- an analyst can acquire evidence from an instance and have it appear coherently in Case and tool projections;
- containment/recovery actions materially change both the system and its telemetry;
- reset restores a known-good scenario state reliably.

---

## Phase 3 - Enterprise telemetry breadth and digital-twin depth

Status: planned.

Expand the shared Fabric only where it enables deeper incidents.

Domains:

- email/mailboxes/messages/headers/attachments/links;
- DNS/DHCP/proxy/firewall/NDR/PCAP-like network evidence;
- cloud resources, IAM, control plane, audit logs, storage, workloads;
- SaaS applications and OAuth/service principals;
- Active Directory-style domain relationships and policy;
- vulnerability/asset/configuration context;
- data stores and sensitive-data/business criticality;
- security controls/detections and control-health state;
- background user/service behavior and normal traffic.

Applications:

- Email Security;
- Network/NDR;
- Cloud Security;
- Threat Intelligence;
- Malware/Sandbox;
- Asset/Vulnerability context.

Exit criteria:

- at least one multi-stage incident crosses four or more distinct security domains;
- every view remains explainably derived from the same run/world state;
- raw evidence can be traced back to its causal event/system state.

---

## Phase 4 - Rich scenario engine and adversary orchestration

Status: planned.

Goal: incidents evolve rather than replaying a static opening timeline.

Capabilities:

- preconditions;
- triggers;
- branches;
- virtual-time scheduling;
- asynchronous background activity;
- attacker/adversary plans mapped to ATT&CK;
- adaptive paths based on defender action;
- delayed/missing telemetry;
- false positives and benign administrative behavior;
- seeded variation;
- recovery and re-compromise possibilities;
- multi-stage incident objectives hidden from participants.

Red/blue/purple support:

- deterministic/sandboxed adversary actions;
- live red-team operator actions where an interactive range is provisioned;
- purple-team detection/control validation;
- replayable attack-vs-response timeline.

Exit criteria:

- the same scenario can meaningfully diverge based on defender choices;
- different runs remain reproducible when given the same seed/actions;
- attack, system, and defense actions share one audit/replay model.

---

## Phase 5 - Enterprise server and control plane

Status: planned.

Goal: make Endomorph deployable, governable, and purchasable by organizations.

Core platform:

- API/service runtime;
- PostgreSQL-backed durable state;
- run persistence/resume/replay;
- organizations/tenants;
- users, teams, cohorts, and roles;
- SSO (SAML/OIDC) and SCIM;
- real authorization boundaries;
- assignments/campaigns/exercises;
- run scheduling and concurrency/capacity management;
- audit logs;
- retention/data governance;
- API/webhooks;
- export/reporting.

Manager/instructor experience:

- readiness baseline and progression;
- ATT&CK/NICE coverage;
- skill gaps by team/role;
- investigation/containment/recovery metrics;
- MTTD/MTTR and incident-process metrics;
- case quality and missed-scope review;
- run playback/comparison;
- organization content library and approvals.

Exit criteria:

- multiple users can collaborate on/resume a durable exercise;
- tenant/role boundaries are enforced server-side;
- managers can answer whether their team is improving and where it is weak;
- enterprise data lifecycle is auditable.

---

## Phase 6 - Replay, rewind, branch, and compare

Status: architecture-supported, product work not started.

This should become a signature Endomorph capability.

Capabilities:

- point-in-time state inspection;
- replay scrubbing;
- branch from checkpoint;
- compare alternative response paths;
- explain why a tool displayed an observation;
- compare analyst/team decisions;
- instructor playback;
- export/import deterministic run bundles;
- after-action timeline reconstruction.

Exit criteria:

- an instructor can rewind a completed incident, fork an alternative containment decision, and compare resulting impact;
- any scored result can be explained and reproduced from run data.

---

## Phase 7 - Endomorph Forge: digital-twin/scenario authoring

Status: planned.

Goal: make deep enterprise ranges cheaper to create than incumbent high-touch cyber ranges.

Capabilities:

- topology/world visual builder;
- reusable enterprise templates;
- identity/network/cloud/application templates;
- security-stack templates;
- scenario/adversary timeline builder;
- ATT&CK mapping;
- normal-activity generators;
- telemetry-source selection;
- per-asset fidelity selection: synthetic / container / VM;
- authored assessment policies;
- validation and preview;
- versioning, review, approvals, publishing;
- customer environment import/adapters where safe and appropriate.

Exit criteria:

- a trained author can create a multi-domain scenario without editing application code;
- changing an asset's fidelity does not require redesigning the scenario's logical world.

---

## Phase 8 - Deployment, integrations, and enterprise ecosystem

Potential scope:

- managed cloud;
- private cloud/VPC deployment;
- on-prem installation where customers require it;
- SIEM/EDR/security-tool adapters;
- LMS/LTI integrations where training buyers need them;
- ticketing/case-platform integrations;
- identity-provider integrations;
- reporting/data export;
- plugin/extension SDK once external integration requirements are concrete.

Infrastructure such as Kubernetes, Redis, queues, search engines, or service decomposition is allowed when scale/reliability requirements justify it. They are still implementation choices, not product goals.

---

## Phase 9 - AI and autonomous-agent proving ground

Status: future.

Use cases:

- AI-assisted scenario/digital-twin authoring as untrusted compilation into validated definitions;
- analyst copilots with measurable effects on performance;
- adversary-agent simulation within isolated range policy;
- evaluation of AI SOC agents against deterministic incidents;
- human-vs-agent and human+agent comparison;
- precision-labeled synthetic telemetry/training data generated from known ground truth.

Safety boundary:

AI output must remain constrained by validated scenario/range capabilities. No unrestricted arbitrary host execution or uncontrolled external attack capability.

---

# Product rules going forward

1. **Depth over scenario count.** A deeply explorable incident is worth more than many shallow exercises.
2. **Professional work over courseware.** The platform should feel like cyber operations first.
3. **One causal world.** Tool views must stay interconnected.
4. **Interactive systems where they create real investigative value.**
5. **Reliability is a feature.** High-fidelity labs that do not start/reset reliably fail the product.
6. **Progressive assistance, not forced simplicity.** Beginners and experts use the same underlying world at different assistance levels.
7. **Deterministic replay remains non-negotiable wherever technically possible.**
8. **Enterprise requirements are now first-class:** security, roles, auditability, readiness analytics, integrations, deployment controls, and cost/capacity management.
9. **Do not copy competitors' surface UI.** Adopt proven strengths while using Endomorph's coherent digital twin and replay architecture to create a distinct experience.
10. **Every major feature should answer:** does this make Endomorph feel more like a living enterprise and less like a quiz?
