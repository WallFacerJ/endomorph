# Polymorph Roadmap

Polymorph v1 proved the deterministic scenario/runtime architecture. Tester feedback and competitive research now justify a broader product goal: **build a deterministic cyber-operations digital twin and enterprise cyber-readiness platform, not a shallow training website.**

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

Status: **next.**

Goal: eliminate the "juvenile / surface-level / multiple-choice" feel before adding expensive infrastructure.

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

- evidence graph instead of a simple list;
- hypotheses and findings;
- indicators;
- tasks, owners, status, and incident phase;
- decisions and response actions;
- bidirectional pivots to source evidence/tools;
- unified incident timeline;
- generated incident report from actual case state.

### Assessment model

- professional mode hides explicit score/objectives during active work by default;
- response actions move into relevant tool/system context rather than obvious answer cards;
- retain optional guided mode for learning;
- score investigation coverage, state outcomes, harmful actions, timing/process, and evidence quality where deterministically measurable.

Exit criteria:

- an experienced tester can spend at least 30 minutes investigating the default scenario without exhausting the evidence surface;
- the SIEM, EDR, Identity, and Case sections feel like different professional applications;
- a tester can explain why Case is operationally useful;
- successful response does not feel like choosing the obvious answer from a list.

---

## Phase 2 - Synthetic Infrastructure Fabric

Status: **planned; now justified by tester feedback.**

Goal: let analysts enter and manipulate investigation-critical systems rather than only reading dashboards.

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
- instrumentation into Polymorph telemetry;
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

Goal: make Polymorph deployable, governable, and purchasable by organizations.

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

This should become a signature Polymorph capability.

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

## Phase 7 - Polymorph Forge: digital-twin/scenario authoring

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
9. **Do not copy competitors' surface UI.** Adopt proven strengths while using Polymorph's coherent digital twin and replay architecture to create a distinct experience.
10. **Every major feature should answer:** does this make Polymorph feel more like a living enterprise and less like a quiz?
